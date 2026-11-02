"""A single compressed stream that holds a file, not a tar: `install.js.gz`, `dump.sql.gz` (item 30).

`ArchiveReader.extract` sent every compressed stream to the tar reader, so a gzip of one file failed
as "not a readable archive" and was reported unread: `scr-database` 1.0.0's 956,126-byte
`scr-database.sql.gz` was never decompressed (the npm reading screen, 1 Nov). Read here through the
same metered stream a tar is read through (`_BudgetedStream`), so the expansion cap, the total
budget and the deadline hold exactly as they do for a tar.

```
  compressed bytes ──► holds_tar? ── yes / name claims a tar ──► ArchiveReader._extract_tar
                           │ no
                           ▼
                     LoneStream.extract ──► one member, the stream's name less its suffix
                           │
           the stream ends before its end marker, every compressed byte read
                           ▼
           kept, with an info note (COMPRESSED_TRUNCATED): nothing is left unread
```

A cut stream is complete here and not in a tar on purpose: a lone stream that simply ends has no
byte left that nobody read, while a tar cut mid-member, a zip with no directory or a bound reached
leaves content unread, and stays the gap it always was.
"""

from __future__ import annotations

import bz2
import lzma
import zlib
from typing import TYPE_CHECKING, Any

from cordon_scanner.foundation.errors import ArchiveError
from cordon_scanner.sources.base import RejectedMember, Rejection
from cordon_scanner.sources.budget import READ_CHUNK, BudgetExceeded, _BudgetedStream, _BytesReader
from cordon_scanner.sources.signatures import ArchiveSignatures, CompressedHeader

if TYPE_CHECKING:
    from collections.abc import Callable

    from cordon_scanner.foundation.limits import Limits
    from cordon_scanner.sources.archive import ExtractionResult

#: Names that say a compressed stream is a tar: read as one whatever its first block holds, so a cut
#: .tgz is never taken for a lone stream (the killer suite's cut-archive probe).
TAR_NAMES = (
    ".tar",
    ".tgz",
    ".tbz",
    ".tbz2",
    ".txz",
    ".tzst",
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
    ".tar.zst",
    ".tar.zstd",
    ".tar.gzip",
)


class _Decompressing:
    """A gzip, bzip2 or xz stream decompressed incrementally, so a stream that ends before its end
    marker returns every byte it holds and records that it was `cut`: the library file readers
    raise EOFError on the read that meets the end and drop what that read had decompressed.

    Several streams back to back are read as one, as `gzip -d` reads them; zero bytes after the
    last are padding. Anything else after it was never decompressed, so it raises: a payload
    appended past the end marker must not pass as read."""

    _INPUT = READ_CHUNK

    def __init__(self, data: bytes, kind: str) -> None:
        self.data, self.kind, self.pos, self.cut = data, kind, 0, False
        self.decoder: Any = self._decoder()

    def _decoder(self) -> Any:
        if self.kind == "gzip":
            return zlib.decompressobj(31)
        if self.kind == "bzip2":
            return bz2.BZ2Decompressor()
        if self.kind == "lzma":
            return lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        return lzma.LZMADecompressor(format=lzma.FORMAT_XZ)

    def read(self, size: int = -1) -> bytes:
        size = READ_CHUNK if size is None or size < 0 else size
        out: list[bytes] = []
        produced = 0
        try:
            while produced < size:
                if self.decoder.eof and not self._next_stream():
                    break
                piece = self._step(size - produced)
                if piece is None:
                    break
                out.append(piece)
                produced += len(piece)
        except (zlib.error, lzma.LZMAError, OSError, EOFError) as exc:
            raise ValueError(f"a corrupt {self.kind} stream: {exc}") from exc
        return b"".join(out)

    def _step(self, room: int) -> bytes | None:
        """Up to `room` decompressed bytes; None when the input ran out before the end marker."""
        if self.kind == "gzip":
            pending = self.decoder.unconsumed_tail
            if not pending:
                pending = self._take()
                if pending is None:
                    return None
            return bytes(self.decoder.decompress(pending, room))
        feed = b""
        if self.decoder.needs_input:
            taken = self._take()
            if taken is None:
                return None
            feed = taken
        return bytes(self.decoder.decompress(feed, max_length=room))

    def _take(self) -> bytes | None:
        if self.pos >= len(self.data):
            self.cut = True
            return None
        chunk = self.data[self.pos : self.pos + self._INPUT]
        self.pos += len(chunk)
        return chunk

    def _next_stream(self) -> bool:
        """Past one stream's end marker: whether another stream of the same format follows."""
        rest = bytes(self.decoder.unused_data) + self.data[self.pos :]
        if not rest.strip(b"\x00"):
            return False
        if CompressedHeader.format_of(rest) != self.kind:
            raise ValueError(f"{len(rest)} bytes follow the {self.kind} stream's end marker")
        self.data, self.pos = rest, 0
        self.decoder = self._decoder()
        return True


class _CutTolerant:
    """A zstd stream whose early end reads as an end, recorded (the decoder has no incremental
    form here, so a cut zstd keeps what its earlier reads returned)."""

    def __init__(self, stream: Any) -> None:
        self.stream, self.cut = stream, False

    def read(self, size: int = -1) -> bytes:
        try:
            chunk: bytes = self.stream.read(size)
        except EOFError:
            self.cut = True
            return b""
        return chunk


class LoneStream:
    """A compressed stream of one file, read as that file."""

    @staticmethod
    def _open(
        data: bytes, *, path: str, limits: Limits, deadline: float | None, cap: int = 0
    ) -> tuple[Any, Any]:
        """The stream metered as a tar's is (`_BudgetedStream`), and what records a cut."""
        kind = CompressedHeader.format_of(data)
        if kind in ("gzip", "bzip2", "xz", "lzma"):
            inner: Any = _Decompressing(data, kind)
            return _BudgetedStream(inner, _BytesReader(data), limits, deadline, path, cap), inner
        tolerant = _CutTolerant(
            _BudgetedStream.open(data, limits=limits, deadline=deadline, path=path, cap=cap)
        )
        return tolerant, tolerant

    @staticmethod
    def bare_header(data: bytes) -> bool:
        """A gzip member's fixed ten-byte header (deflate, no optional fields) and nothing after it."""
        return len(data) == 10 and data[:3] == b"\x1f\x8b\x08" and data[3] == 0

    @staticmethod
    def holds_tar(data: bytes, *, path: str, limits: Limits, deadline: float | None) -> bool:
        """Whether a compressed stream is a tar: its name says so, or its first decompressed block
        is a tar header (`ArchiveSignatures.tar_header`). A stream that cannot be read at all is
        left to the tar reader, which reports it as it always has."""
        if path.rsplit("!", 1)[-1].lower().endswith(TAR_NAMES):
            return True
        stream, _ = LoneStream._open(data, path=path, limits=limits, deadline=deadline)
        head = b""
        try:
            while len(head) < 512:
                chunk = stream.read(512 - len(head))
                if not chunk:
                    break
                head += chunk
        except (ArchiveError, OSError, ValueError):
            return True
        return ArchiveSignatures.tar_header(head)

    @staticmethod
    def extract(
        data: bytes,
        path: str,
        limits: Limits,
        result: ExtractionResult,
        deadline: float | None,
        *,
        read: Callable[..., bytes | None],
        member: Callable[..., Any],
    ) -> None:
        """The one member a lone stream holds, read within the archive bounds. A bound or the
        deadline stops it as it stops a tar (recorded, nothing kept); a corrupt stream raises.
        `read` is the archive reader's bounded member read and `member` its member type, handed
        in so this module never imports the reader that imports it."""
        name = ArchiveSignatures.inner_name(path)
        stream, cut = LoneStream._open(
            data, path=path, limits=limits, deadline=deadline, cap=result.expansion_cap
        )
        try:
            payload = read(stream, limits, len(data), result, name)
        except BudgetExceeded as exc:
            result.truncated = True
            shape = Rejection.PADDED if exc.padded else Rejection.SIZE
            result.rejected.append(RejectedMember(path, shape, str(exc)))
            return
        except ArchiveError as exc:  # the deadline
            result.truncated = True
            result.rejected.append(RejectedMember(path, Rejection.ENTRIES, str(exc)))
            return
        except (OSError, ValueError) as exc:
            raise ArchiveError(f"{path}: not a readable compressed stream: {exc}") from exc
        if payload is None:
            return
        if cut.cut and not payload and LoneStream.bare_header(data):
            # Nothing past the header at all (npm's cache leaves `package.tgz.<n>` so when a write
            # is cut): no compressed byte exists, so none is unread (item 76).
            result.rejected.append(
                RejectedMember(
                    path,
                    Rejection.COMPRESSED_TRUNCATED,
                    "the stream ends at its header; it holds no byte",
                )
            )
            return
        if cut.cut and not payload:
            # A stream cut before its first byte holds nothing anyone read: not a file read to its
            # end but a compressed stream that would not open, so a typed error (and a blocking gap
            # where the scan reads it), never an empty member marked complete.
            raise ArchiveError(f"{path}: a compressed stream cut before its first byte")
        if cut.cut:
            result.rejected.append(
                RejectedMember(
                    name,
                    Rejection.COMPRESSED_TRUNCATED,
                    f"the stream ends before its end marker; the {len(payload)} bytes it holds "
                    "were read",
                )
            )
        result.members.append(
            member(
                name=name,
                data=payload,
                compressed_size=len(data),
                uncompressed_size=len(payload),
            )
        )


__all__ = ["TAR_NAMES", "LoneStream"]
