"""The shipped advisory records of one ecosystem, read by package name from a table built at release.

Every fresh process used to build a 74 MB SQLite index of npm's 246,470 records before its first
look-up (`intel/advisory_index`), and a CI job or a container is a fresh process every time: its
cache seal, keyed to the install, never validates a restored cache, by design. The table is built
once, when the data file is, and ships beside it as package data -- the trust anchor the seal exists
to protect, so it needs none (item 74).

```
  advisories-<eco>.json.gz  (verified against the digest manifest, as before)
        │ release time: ShippedTable.build(records, its sha256)
        ▼
  advisories-<eco>.tbl
    header   magic "CAT1", version, the source file's sha256, record count
    index    zlib(JSON): each block's first name, offset, length         (read once per process)
    blocks   zlib(JSON lines [name, record]), name-sorted, a name never split across two blocks
        │ a look-up: bisect the first names -> one block decompressed -> that name's records
        ▼
  the same records, in the same order, as the SQLite index returns
```

Used only when the table names the verified data file's own digest; a stale or foreign table is not
read and the sealed SQLite path is taken, as before. A feed's local deltas keep that path too.
"""

from __future__ import annotations

import json
import struct
import threading
import zlib
from bisect import bisect_right
from collections.abc import Iterable
from pathlib import Path
from typing import Final

MAGIC: Final = b"CAT1"
VERSION: Final = 1
_HEADER: Final = struct.Struct(">4sH2x32sII")
"""magic, version, the source's sha256 (raw), record count, index length."""

BLOCK_BYTES: Final = 64 * 1024
"""Uncompressed bytes a block holds before it is cut, at a name boundary."""


class ShippedTable:
    """One ecosystem's shipped records by lowercased name, from a release-built table."""

    def __init__(self, data: bytes, count: int, firsts: list[str], spans: list[tuple[int, int]]):
        self._data = data
        self.count = count
        self._firsts = firsts
        self._spans = spans
        self._lock = threading.Lock()
        self._block: tuple[int, dict[str, list[dict[str, object]]]] | None = None

    @staticmethod
    def build(records: Iterable[dict[str, object]], source_sha256: str) -> bytes:
        """The table for `records` (the data file's own order), naming the file it was built from."""
        grouped: dict[str, list[str]] = {}
        count = 0
        for raw in records:
            if not isinstance(raw, dict) or not raw.get("name"):
                continue
            grouped.setdefault(str(raw["name"]).lower(), []).append(json.dumps(raw, sort_keys=True))
            count += 1
        blocks: list[bytes] = []
        index: list[list[object]] = []
        lines: list[str] = []
        first, size = "", 0
        for name in sorted(grouped):
            if lines and size >= BLOCK_BYTES:
                blocks.append(zlib.compress("\n".join(lines).encode("utf-8"), 9))
                index.append([first, len(blocks[-1])])
                lines, size = [], 0
            if not lines:
                first = name
            for record in grouped[name]:
                line = json.dumps([name, record], ensure_ascii=False)
                lines.append(line)
                size += len(line)
        if lines:
            blocks.append(zlib.compress("\n".join(lines).encode("utf-8"), 9))
            index.append([first, len(blocks[-1])])
        packed_index = zlib.compress(json.dumps(index).encode("utf-8"), 9)
        header = _HEADER.pack(
            MAGIC, VERSION, bytes.fromhex(source_sha256), count, len(packed_index)
        )
        return header + packed_index + b"".join(blocks)

    @classmethod
    def write_for(cls, data_dir: Path) -> list[Path]:
        """Release time: a table beside every `advisories-<eco>.json.gz` in `data_dir`, from the
        file's own records and digest (`scripts/build/build_advisory_tables.py`)."""
        from cordon_scanner.intel.advisories.advisories import AdvisoryFiles

        written: list[Path] = []
        for source in sorted(data_dir.glob("advisories-*.json.gz")):
            table = source.with_name(source.name.removesuffix(".json.gz") + ".tbl")
            records = (r for r in AdvisoryFiles.stream_records(source) if isinstance(r, dict))
            table.write_bytes(cls.build(records, AdvisoryFiles.digest_of(source)))
            written.append(table)
        return written

    @classmethod
    def open(cls, path: Path, source_sha256: str) -> ShippedTable | None:
        """The table at `path` if it is one, of this version, built from the file with this digest."""
        try:
            data = path.read_bytes()
            magic, version, source, count, index_length = _HEADER.unpack_from(data, 0)
        except (OSError, struct.error):
            return None
        if magic != MAGIC or version != VERSION or source.hex() != source_sha256:
            return None
        start = _HEADER.size
        try:
            index = json.loads(zlib.decompress(data[start : start + index_length]))
        except (zlib.error, ValueError):
            return None
        firsts: list[str] = []
        spans: list[tuple[int, int]] = []
        offset = start + index_length
        for first, length in index:
            firsts.append(str(first))
            spans.append((offset, int(length)))
            offset += int(length)
        if offset != len(data):
            return None
        return cls(data, int(count), firsts, spans)

    def get(self, name: str) -> tuple[dict[str, object], ...]:
        """Every record stored under this (lowercased) name, in the data file's order."""
        block = bisect_right(self._firsts, name) - 1
        if block < 0:
            return ()
        return tuple(self._records(block).get(name, ()))

    def names(self) -> list[str]:
        """Every name with a record, once each."""
        out: list[str] = []
        for block in range(len(self._spans)):
            out.extend(self._records(block))
        return out

    def count_except(self, identifiers: frozenset[str]) -> int:
        """How many records remain once those with these identifiers are set aside. Exact; reads
        every block when `identifiers` is not empty (a feed's overlay, which takes the SQLite
        path in practice)."""
        if not identifiers:
            return self.count
        removed = 0
        for block in range(len(self._spans)):
            for records in self._records(block).values():
                removed += sum(1 for r in records if str(r.get("id", "")) in identifiers)
        return self.count - removed

    def _records(self, block: int) -> dict[str, list[dict[str, object]]]:
        """One block's records by name, decompressed and kept until another block is asked for."""
        with self._lock:
            if self._block is not None and self._block[0] == block:
                return self._block[1]
            offset, length = self._spans[block]
            grouped: dict[str, list[dict[str, object]]] = {}
            for line in (
                zlib.decompress(self._data[offset : offset + length]).decode("utf-8").split("\n")
            ):
                name, record = json.loads(line)
                grouped.setdefault(name, []).append(json.loads(record))
            self._block = (block, grouped)
            return grouped


__all__ = ["BLOCK_BYTES", "MAGIC", "VERSION", "ShippedTable"]
