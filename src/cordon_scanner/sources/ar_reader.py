"""The ar archive: static libraries (`.a`, `.lib`) and Debian packages (`.deb`), read (item 53).

ar was in item 53's list of formats no reader opens, and gapping it would have made every native-addon
package incomplete: 22 of the 29 benign npm units with such a member ship a static library (the
benign cost, 1 Nov). The format needs no library: an 8-byte magic, then members each behind a 60-byte
header, padded to an even offset.

```
  "!<arch>\\n" ─► header[60]: name[16] mtime[12] uid[6] gid[6] mode[8] size[10] "`\\n" ─► body ─► (pad)
       name  "/" or "/SYM64/"      the symbol table: skipped
             "//"                  GNU long-name table, read for the names after it
             "/123"                a GNU long name at offset 123 of that table
             "#1/20"               a BSD long name: its first 20 bytes of body
             anything else         the name, a trailing "/" dropped
```

Members are object files (to the binary detector) or, in a `.deb`, `control.tar.*` and `data.tar.*`,
which the archive walk opens in turn. Everything is already in memory, so the bounds are the entry
count, the member limit and the deadline; a damaged header or a member past the end is the archive's
error, reported unread as any archive that fails to open is.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from cordon_scanner.foundation.errors import ArchiveError
from cordon_scanner.sources.archive_names import MemberNames
from cordon_scanner.sources.base import RejectedMember, Rejection
from cordon_scanner.sources.import_library import ImportLibrary

if TYPE_CHECKING:
    from collections.abc import Callable

    from cordon_scanner.foundation.limits import Limits
    from cordon_scanner.sources.archive import ExtractionResult

MAGIC = b"!<arch>\n"
_HEADER = 60


class ArReader:
    """Reads an ar archive held in memory into the extraction result."""

    @staticmethod
    def is_ar(data: bytes) -> bool:
        """The magic and a first member header that ends as one does: never the magic alone."""
        return data[:8] == MAGIC and data[66:68] == b"`\n"

    @staticmethod
    def extract(
        data: bytes,
        path: str,
        limits: Limits,
        result: ExtractionResult,
        deadline: float | None,
        *,
        member: Callable[..., Any],
    ) -> None:
        position, long_names, count = len(MAGIC), b"", 0
        while position + _HEADER <= len(data):
            if deadline is not None and time.monotonic() > deadline:
                result.truncated = True
                result.rejected.append(
                    RejectedMember(path, Rejection.ENTRIES, "scan budget exhausted")
                )
                return
            header = data[position : position + _HEADER]
            size = ArReader._size(header, path, position)
            start, end = position + _HEADER, position + _HEADER + size
            if end > len(data):
                raise ArchiveError(
                    f"{path}: an ar member at {position} runs past the archive's end"
                )
            raw_name, body = header[:16].rstrip(b" "), data[start:end]
            position = end + (end & 1)
            if raw_name == b"//":
                long_names = body
                continue
            if raw_name in (b"/", b"/SYM64/", b"__.SYMDEF", b"__.SYMDEF SORTED"):
                continue
            name, body = ArReader._name(raw_name, body, long_names)
            count += 1
            if count > limits.max_archive_entries:
                result.truncated = True
                result.rejected.append(
                    RejectedMember(
                        path,
                        Rejection.ENTRIES,
                        f"stopped after {limits.max_archive_entries} entries",
                    )
                )
                return
            ArReader._keep(name, body, result, member)
        if position < len(data) and data[position:].strip(b"\n"):
            raise ArchiveError(f"{path}: bytes after the last ar member that are no member")
        result.import_library = not result.truncated and ImportLibrary.verify(data, limits)

    @staticmethod
    def _size(header: bytes, path: str, position: int) -> int:
        if header[58:60] != b"`\n":
            raise ArchiveError(f"{path}: a damaged ar member header at {position}")
        try:
            return int(header[48:58].strip() or b"0")
        except ValueError as exc:
            raise ArchiveError(
                f"{path}: an ar member size that is no number at {position}"
            ) from exc

    @staticmethod
    def _name(raw: bytes, body: bytes, long_names: bytes) -> tuple[str, bytes]:
        """The member's name, and its body less a BSD long name."""
        if raw.startswith(b"#1/") and raw[3:].isdigit():
            length = int(raw[3:])
            return body[:length].rstrip(b"\x00").decode("utf-8", "replace"), body[length:]
        if raw.startswith(b"/") and raw[1:].isdigit():
            offset = int(raw[1:])
            # GNU ends a long name with "/\n"; Microsoft's lib.exe with a NUL. The first of them
            # ends this one.
            ends = [
                at
                for at in (long_names.find(b"/\n", offset), long_names.find(b"\x00", offset))
                if at != -1
            ]
            named = long_names[offset : min(ends) if ends else len(long_names)]
            return named.decode("utf-8", "replace"), body
        return raw.rstrip(b"/").decode("utf-8", "replace"), body

    @staticmethod
    def _keep(name: str, body: bytes, result: ExtractionResult, member: Callable[..., Any]) -> None:
        """A member kept whole: the archive is in memory already, so a large member costs nothing
        more to hold (a tar's past the limit is spilled and read whole, for the same reason)."""
        safe = MemberNames.safe_member_name(name)
        if safe is None:
            result.rejected.append(
                RejectedMember(
                    name, Rejection.TRAVERSAL, "member name escapes the destination directory"
                )
            )
            return
        result.total_uncompressed += len(body)
        result.members.append(
            member(name=safe, data=body, compressed_size=len(body), uncompressed_size=len(body))
        )


__all__ = ["MAGIC", "ArReader"]
