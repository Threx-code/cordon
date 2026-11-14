"""A compressed archive's decompressed bytes, metered as they are produced: the total budget, the
expansion cap and the deadline bind while tarfile reads, not after.
"""

from __future__ import annotations

import lzma
import time
import zlib
from typing import TYPE_CHECKING, Any, cast

from cordon_scanner.foundation.errors import ArchiveError
from cordon_scanner.foundation.limits import Limits
from cordon_scanner.sources.base import RejectedMember, Rejection

if TYPE_CHECKING:
    from cordon_scanner.sources.archive import ExtractionResult

READ_CHUNK = 65536


ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


class BudgetExceeded(ArchiveError):
    """A decompressed budget was reached. `padded` when it was the expansion cap."""

    def __init__(self, message: str, *, hint: str = "", padded: bool = False) -> None:
        super().__init__(message, hint=hint)
        self.padded = padded


class BlockRuns:
    """Meters a byte stream's runs of identical 4 KB blocks (reviews/pypi-98/26).

    The bytes themselves are never changed or dropped. The first two blocks of a run are charged as
    ordinary bytes; every further block equal to the one before it is counted as `elided` instead. A
    block that differs by one byte is not equal, so near-identical filler is charged in full and meets
    the budget as before. The answer does not depend on how the stream is cut into chunks."""

    BLOCK = 4096

    def __init__(self) -> None:
        self.total = 0
        self.elided = 0
        self._tail = b""
        self._previous: bytes | None = None
        self._streak = 0

    @property
    def charged(self) -> int:
        """Bytes counted against the expansion cap and the total budget."""
        return self.total - self.elided

    def feed(self, chunk: bytes) -> None:
        self.total += len(chunk)
        data = self._tail + chunk if self._tail else chunk
        whole = len(data) - len(data) % self.BLOCK
        view = memoryview(data)
        for start in range(0, whole, self.BLOCK):
            block = view[start : start + self.BLOCK]
            if self._previous is not None and block == self._previous:
                self._streak += 1
                if self._streak >= 2:
                    self.elided += self.BLOCK
            else:
                self._previous, self._streak = bytes(block), 0
        self._tail = bytes(view[whole:])


class ByteBudget:
    """The ceilings an archive's extraction is judged against as its members are read."""

    @staticmethod
    def declared_over_budget(
        result: ExtractionResult, limits: Limits, name: str, declared: int
    ) -> bool:
        """Whether a member's DECLARED size is past the total uncompressed budget, so nothing of it
        can be read within it: refused before any byte is inflated, as padding when the size is also
        past what the archive's own size allows to expand (`expansion_cap`), else as a size. Metering
        applies only to what is read within the budget, never to what a header declares."""
        if declared <= limits.max_uncompressed_bytes:
            return False
        padded = 0 < result.expansion_cap < declared
        result.truncated = True
        result.rejected.append(
            RejectedMember(
                name,
                Rejection.PADDED if padded else Rejection.SIZE,
                f"archive exceeds the total uncompressed budget (declared {declared} bytes)",
            )
        )
        return True

    @staticmethod
    def over_elided(result: ExtractionResult, limits: Limits, name: str, elided: int) -> bool:
        """Whether the identical-block runs of this member, or of the archive with it, pass their own
        ceilings: filler is read and metered apart from the expansion cap, but a zero bomb ends here."""
        if elided <= limits.max_elided_member_bytes and (
            result.elided + elided <= limits.max_elided_bytes
        ):
            return False
        result.truncated = True
        result.rejected.append(
            RejectedMember(
                name,
                Rejection.PADDED,
                f"{elided} bytes of identical blocks, over the elided-bytes ceilings",
            )
        )
        return True

    @staticmethod
    def over_budget(
        result: ExtractionResult, limits: Limits, name: str, read_total: int, elided: int = 0
    ) -> bool:
        """Whether reading `read_total` bytes of `name` (`elided` of them runs of identical blocks)
        passes the archive's expansion cap or its total budget -- the decompression-bomb ceilings,
        which no member is read past. The expansion cap leaves the elided runs out
        (`over_elided` bounds those); the total budget counts every byte read, as it bounds what is
        held and spilled."""
        charged = result.total_uncompressed - result.elided + read_total - elided
        if 0 < result.expansion_cap < charged:
            result.truncated = True
            result.rejected.append(
                RejectedMember(
                    name,
                    Rejection.PADDED,
                    f"the archive expanded past {result.expansion_cap} bytes, over "
                    f"{limits.max_archive_ratio} times its size",
                )
            )
            return True
        if result.total_uncompressed + read_total > limits.max_uncompressed_bytes:
            result.truncated = True
            result.rejected.append(
                RejectedMember(
                    name, Rejection.SIZE, "archive exceeds the total uncompressed budget"
                )
            )
            return True
        return False


class _BudgetedStream:
    """A tar archive's DECOMPRESSED bytes, metered as they are produced.

    Every byte tarfile reads - a header, a member it hands back, or the data of a member it skips -
    passes through `read`, so three limits hold whatever tarfile does with the bytes:

    * the expansion cap, `ArchiveReader.expansion_cap`, judged from the whole archive's size;
    * a total decompressed budget, `Limits.max_uncompressed_bytes`;
    * the deadline.

    Each raises; the members read before it are kept (`ArchiveReader._extract_tar`), as a
    streaming installer would have written them.
    """

    def __init__(
        self,
        inner: Any,
        compressed: _BytesReader | None,
        limits: Limits,
        deadline: float | None,
        path: str,
        cap: int = 0,
    ) -> None:
        self.inner, self.compressed, self.limits, self.deadline, self.path = (
            inner,
            compressed,
            limits,
            deadline,
            path,
        )
        self.cap = cap
        self.runs = BlockRuns() if limits.max_elided_bytes > 0 else None
        self.produced = 0

    @classmethod
    def open(
        cls, data: bytes, *, limits: Limits, deadline: float | None, path: str, cap: int = 0
    ) -> _BudgetedStream:
        import bz2
        import gzip
        import lzma

        raw = _BytesReader(data)
        # Not context-managed: the decompressor is the stream tarfile reads for as long as the
        # archive is open, over bytes already in memory, so there is no descriptor to leak.
        if data[:2] == b"\x1f\x8b":
            inner: Any = gzip.GzipFile(fileobj=cast("Any", raw), mode="rb")
        elif data[:3] == b"BZh":
            inner = bz2.BZ2File(cast("Any", raw), mode="rb")
        elif data[:6] == b"\xfd7zXZ\x00":
            inner = lzma.LZMAFile(cast("Any", raw), mode="rb")  # noqa: SIM115
        elif data[:4] == ZSTD_MAGIC:
            # Past the budget by a read's worth, so `read` reports the budget, not the decoder.
            inner = _BudgetedStream._zstd(raw, limits.max_uncompressed_bytes + READ_CHUNK * 16)
        else:
            return cls(raw, None, limits, deadline, path, cap)
        return cls(inner, raw, limits, deadline, path, cap)

    @staticmethod
    def _zstd(raw: _BytesReader, limit: int) -> Any:
        """A zstd decompressing reader: the standard library's (3.14), else the core's own decoder
        (`intel/store/zstd`), so a `.conda` package is read with no third-party dependency
        (CONSTRAINT C1). The last fails past `limit` bytes."""
        try:
            from compression import zstd  # type: ignore[import-not-found]

            return zstd.ZstdFile(raw, mode="rb")
        except ImportError:
            from cordon_scanner.intel.store.zstd import Zstd

            return Zstd.Reader(raw, limit)

    def read(self, size: int = -1) -> bytes:
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise ArchiveError(f"{self.path}: the time budget ran out while reading the archive")
        if size is None or size < 0:
            size = READ_CHUNK
        try:
            chunk: bytes = self.inner.read(min(size, READ_CHUNK * 16))
        except (zlib.error, lzma.LZMAError) as exc:  # from inside the decompressor (S1 fuzzing)
            raise OSError(f"{self.path}: a damaged compressed stream: {exc}") from exc
        self.produced += len(chunk)
        if self.runs is not None:
            self.runs.feed(chunk)
            if self.runs.elided > self.limits.max_elided_bytes:
                raise BudgetExceeded(
                    f"{self.path}: {self.runs.elided} bytes of identical blocks, over the "
                    f"{self.limits.max_elided_bytes}-byte ceiling",
                    hint="This is the shape of padding or a decompression bomb.",
                    padded=True,
                )
        charged = self.runs.charged if self.runs is not None else self.produced
        if self.compressed is not None and 0 < self.cap < charged:
            raise BudgetExceeded(
                f"{self.path}: expanded past {self.cap} bytes, over {self.limits.max_archive_ratio} "
                f"times its size",
                hint="This is the shape of padding or a decompression bomb.",
                padded=True,
            )
        if self.produced > self.limits.max_uncompressed_bytes:
            raise BudgetExceeded(
                f"{self.path}: archive expands past the {self.limits.max_uncompressed_bytes}-byte budget",
                hint="This is the shape of a decompression bomb.",
            )
        return chunk


class _BytesReader:
    """Minimal seekable wrapper, so format sniffing needs no temporary file."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def getvalue(self) -> bytes:
        return self._data

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            chunk = self._data[self._pos :]
            self._pos = len(self._data)
            return chunk
        chunk = self._data[self._pos : self._pos + size]
        self._pos += len(chunk)
        return chunk

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            self._pos = offset
        elif whence == 1:
            self._pos += offset
        else:
            self._pos = len(self._data) + offset
        self._pos = max(0, min(self._pos, len(self._data)))
        return self._pos

    def tell(self) -> int:
        return self._pos

    def seekable(self) -> bool:
        return True


__all__ = ["READ_CHUNK", "ZSTD_MAGIC", "BlockRuns", "BudgetExceeded", "ByteBudget"]
