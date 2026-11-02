"""The 7z archive, read with the standard library's `lzma` (item 76).

7z was in item 53's list of formats no reader opens, so a package shipping one was incomplete and
blocked whatever it held (`dxrdxrup`'s design files, `@emulatorjs/core-fceumm`'s `.data` packs). The
format is a 32-byte signature header pointing at a header (often itself compressed, "encoded") that
lists packed streams, the folders that decode them, and the files each folder's output splits into:

```
  "7z\\xbc\\xaf\\x27\\x1c" ver crc ─► next-header offset, size, crc ─► Header | EncodedHeader
     Header: MainStreamsInfo (PackInfo, UnPackInfo = folders and coders, SubStreamsInfo) + FilesInfo
```

A folder is read when its coders form one chain the stdlib decodes: LZMA or LZMA2 behind any of the
branch filters (BCJ x86, ARM, ARM-Thumb, PowerPC, SPARC, IA-64) and Delta, all one `lzma` raw chain;
or Copy, Deflate or BZip2 alone. Anything else (AES, PPMd, BCJ2's four streams) is refused by name:
the archive's error, a gap that blocks, as any archive that fails to open is. Sizes are declared up
front, so the archive budget, the expansion cap and the entry count bind before a byte is decoded,
and an LZMA dictionary is never allocated past the folder's own size.
"""

from __future__ import annotations

import bz2
import lzma
import struct
import time
import zlib
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.foundation.errors import ArchiveError
from cordon_scanner.sources.archive_names import MemberNames
from cordon_scanner.sources.base import RejectedMember, Rejection

if TYPE_CHECKING:
    from collections.abc import Callable

    from cordon_scanner.foundation.limits import Limits
    from cordon_scanner.sources.archive import ExtractionResult

MAGIC = b"7z\xbc\xaf\x27\x1c"


class _Cursor:
    """A position in a 7z header, read the format's way: bytes, UINT32/UINT64, and NUMBER."""

    def __init__(self, data: bytes, path: str) -> None:
        self.data, self.at, self.path = data, 0, path

    def fail(self, what: str) -> ArchiveError:
        return ArchiveError(f"{self.path}: a 7z header that does not parse: {what}")

    def byte(self) -> int:
        if self.at >= len(self.data):
            raise self.fail("it ends early")
        self.at += 1
        return self.data[self.at - 1]

    def take(self, count: int) -> bytes:
        if count < 0 or self.at + count > len(self.data):
            raise self.fail("a field runs past its end")
        self.at += count
        return self.data[self.at - count : self.at]

    def uint32(self) -> int:
        return int(struct.unpack("<I", self.take(4))[0])

    def number(self) -> int:
        """A NUMBER: the first byte's leading ones say how many bytes follow."""
        first, mask, value = self.byte(), 0x80, 0
        for index in range(8):
            if not first & mask:
                return value | ((first & (mask - 1)) << (8 * index))
            value |= self.byte() << (8 * index)
            mask >>= 1
        return value

    def count(self, bound: int) -> int:
        value = self.number()
        if value > bound:
            raise self.fail(f"a count of {value}, past {bound}")
        return value

    def bits(self, count: int) -> list[bool]:
        out, mask, current = [], 0, 0
        for _ in range(count):
            if not mask:
                current, mask = self.byte(), 0x80
            out.append(bool(current & mask))
            mask >>= 1
        return out

    def defined(self, count: int) -> list[bool]:
        """An "all defined" byte, else a bit vector."""
        return [True] * count if self.byte() else self.bits(count)

    def digests(self, count: int) -> list[int | None]:
        """`count` CRC32s, each stated or None: the defined vector, then a UINT32 per stated one."""
        return [self.uint32() if stated else None for stated in self.defined(count)]


class _Folder:
    def __init__(self) -> None:
        self.coders: list[tuple[bytes, int, int, bytes]] = []  # id, ins, outs, properties
        self.binds: list[tuple[int, int]] = []  # in index, out index
        self.packed: list[int] = []
        self.sizes: list[int] = []
        self.crc: int | None = None  # the folder's own CRC32, where stated
        self.pack_crc: int | None = None  # its packed stream's CRC32, where stated
        self.stream_crcs: list[int | None] = []  # each substream's CRC32, where stated

    def size(self) -> int:
        """The folder's output size: the out stream no bind pair consumes."""
        bound = {out for _, out in self.binds}
        free = [i for i in range(len(self.sizes)) if i not in bound]
        return self.sizes[free[0]] if len(free) == 1 else -1


class SevenZipReader:
    """Reads a 7z archive held in memory into the extraction result."""

    #: The lzma module's raw filter for each 7z method id it decodes.
    FILTERS: ClassVar[dict[bytes, int]] = {
        b"\x03\x01\x01": lzma.FILTER_LZMA1,
        b"\x21": lzma.FILTER_LZMA2,
        b"\x03\x03\x01\x03": lzma.FILTER_X86,
        b"\x03\x03\x02\x05": lzma.FILTER_POWERPC,
        b"\x03\x03\x04\x01": lzma.FILTER_IA64,
        b"\x03\x03\x05\x01": lzma.FILTER_ARM,
        b"\x03\x03\x07\x01": lzma.FILTER_ARMTHUMB,
        b"\x03\x03\x08\x05": lzma.FILTER_SPARC,
        b"\x03": lzma.FILTER_DELTA,
    }
    ALONE: ClassVar[frozenset[bytes]] = frozenset({b"\x00", b"\x04\x01\x08", b"\x04\x02\x02"})
    NAMES: ClassVar[dict[bytes, str]] = {
        b"\x06\xf1\x07\x01": "AES encryption",
        b"\x03\x04\x01": "PPMd",
        b"\x03\x03\x01\x1b": "BCJ2",
    }

    @staticmethod
    def is_7z(data: bytes) -> bool:
        """The signature and a start header whose CRC holds: never the magic alone."""
        return (
            len(data) >= 32
            and data[:6] == MAGIC
            and zlib.crc32(data[12:32]) == struct.unpack_from("<I", data, 8)[0]
        )

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
        if not SevenZipReader.is_7z(data):
            raise ArchiveError(f"{path}: a 7z start header that does not hold")
        offset, size, crc = struct.unpack_from("<QQI", data, 12)
        start = 32 + offset
        if start + size > len(data):
            raise ArchiveError(f"{path}: a 7z header past the archive's end")
        header = bytes(data[start : start + size])
        if zlib.crc32(header) != crc:
            raise ArchiveError(f"{path}: a 7z header whose CRC does not hold")
        if not header:
            return  # an empty archive
        budget = SevenZipReader._budget(limits, result)
        cursor = _Cursor(header, path)
        kind = cursor.byte()
        if kind == 0x17:  # an encoded header: its own streams, decoded to the real one
            folders, packs, pack_pos = SevenZipReader._streams(cursor, limits)[:3]
            if not folders:
                raise cursor.fail("an encoded header with no folder")
            header = SevenZipReader._decode(data, folders[0], packs, pack_pos, 0, path, budget)
            cursor = _Cursor(header, path)
            kind = cursor.byte()
        if kind != 0x01:
            raise cursor.fail(f"property {kind} where the header begins")
        SevenZipReader._header(data, cursor, path, limits, result, deadline, budget, member)

    @staticmethod
    def _budget(limits: Limits, result: ExtractionResult) -> int:
        cap = getattr(result, "expansion_cap", 0) or limits.max_uncompressed_bytes
        return min(limits.max_uncompressed_bytes, cap)

    @staticmethod
    def _header(
        data: bytes,
        cursor: _Cursor,
        path: str,
        limits: Limits,
        result: ExtractionResult,
        deadline: float | None,
        budget: int,
        member: Callable[..., Any],
    ) -> None:
        folders: list[_Folder] = []
        packs: list[int] = []
        pack_pos, streams = 0, [[]]  # type: ignore[var-annotated]
        kind = cursor.byte()
        if kind == 0x02:  # archive properties: skipped by their sizes
            while cursor.byte():
                cursor.take(cursor.number())
            kind = cursor.byte()
        if kind == 0x03:
            raise cursor.fail("additional streams, which no writer emits")
        if kind == 0x04:
            folders, packs, pack_pos, streams = SevenZipReader._streams(cursor, limits)
            kind = cursor.byte()
        names: list[str] = []
        empty: list[bool] = []
        if kind == 0x05:
            names, empty = SevenZipReader._files(cursor, limits)
            kind = cursor.byte()
        if kind != 0x00:
            raise cursor.fail(f"property {kind} where the header ends")
        sizes = [size for folder in streams for size in folder]
        if sum(not e for e in empty) != len(sizes):
            raise cursor.fail("files and streams that do not match")
        declared = sum(sizes)
        if declared > budget:
            result.truncated = True
            result.rejected.append(
                RejectedMember(
                    path,
                    Rejection.SIZE,
                    f"a 7z archive declaring {declared} bytes, past the {budget}-byte budget",
                )
            )
            return
        outputs = iter(names[i] for i in range(len(names)) if not empty[i])
        for index, folder in enumerate(folders):
            if deadline is not None and time.monotonic() > deadline:
                raise ArchiveError(f"{path}: the time budget ran out while reading the archive")
            out = SevenZipReader._decode(data, folder, packs, pack_pos, index, path, budget)
            at = 0
            for size, crc in zip(streams[index], folder.stream_crcs, strict=False):
                body = out[at : at + size]
                name = next(outputs)
                if crc is not None and zlib.crc32(body) != crc:
                    raise ArchiveError(f"{path}: {name}: a 7z CRC that does not hold")
                SevenZipReader._keep(name, body, result, member)
                at += size
        result.total_compressed = max(result.total_compressed, len(data))

    @staticmethod
    def _streams(
        cursor: _Cursor, limits: Limits
    ) -> tuple[list[_Folder], list[int], int, list[list[int]]]:
        """StreamsInfo: pack sizes, folders, and each folder's split into files."""
        folders: list[_Folder] = []
        packs: list[int] = []
        pack_crcs: list[int | None] = []
        pack_pos = 0
        kind = cursor.byte()
        if kind == 0x06:
            pack_pos = cursor.number()
            count = cursor.count(limits.max_archive_entries)
            kind = cursor.byte()
            while kind != 0x00:
                if kind == 0x09:
                    packs = [cursor.number() for _ in range(count)]
                elif kind == 0x0A:
                    pack_crcs = cursor.digests(count)
                else:
                    raise cursor.fail(f"property {kind} in the pack info")
                kind = cursor.byte()
            kind = cursor.byte()
        if kind == 0x07:
            folders = SevenZipReader._folders(cursor, limits)
            kind = cursor.byte()
        for folder, crc in zip(folders, pack_crcs, strict=False):
            folder.pack_crc = crc
        for folder in folders:
            folder.stream_crcs = [folder.crc]
        streams = [[folder.size()] for folder in folders]
        if kind == 0x08:
            streams = SevenZipReader._substreams(cursor, folders, limits)
            kind = cursor.byte()
        if kind != 0x00:
            raise cursor.fail(f"property {kind} in the streams info")
        return folders, packs, pack_pos, streams

    @staticmethod
    def _folders(cursor: _Cursor, limits: Limits) -> list[_Folder]:
        if cursor.byte() != 0x0B:
            raise cursor.fail("unpack info without its folders")
        count = cursor.count(limits.max_archive_entries)
        if cursor.byte():
            raise cursor.fail("folders kept elsewhere")
        folders = [SevenZipReader._folder(cursor) for _ in range(count)]
        if cursor.byte() != 0x0C:
            raise cursor.fail("folders without their sizes")
        for folder in folders:
            outs = sum(coder[2] for coder in folder.coders)
            folder.sizes = [cursor.number() for _ in range(outs)]
        kind = cursor.byte()
        if kind == 0x0A:
            for folder, crc in zip(folders, cursor.digests(count), strict=True):
                folder.crc = crc
            kind = cursor.byte()
        if kind != 0x00:
            raise cursor.fail(f"property {kind} in the unpack info")
        return folders

    @staticmethod
    def _folder(cursor: _Cursor) -> _Folder:
        folder = _Folder()
        for _ in range(cursor.count(32)):
            flags = cursor.byte()
            method = cursor.take(flags & 0x0F)
            ins, outs = (cursor.count(32), cursor.count(32)) if flags & 0x10 else (1, 1)
            props = cursor.take(cursor.count(1 << 16)) if flags & 0x20 else b""
            if flags & 0x80:
                raise cursor.fail("alternative coders")
            folder.coders.append((method, ins, outs, props))
        total_in = sum(c[1] for c in folder.coders)
        total_out = sum(c[2] for c in folder.coders)
        folder.binds = [(cursor.number(), cursor.number()) for _ in range(total_out - 1)]
        packed = total_in - len(folder.binds)
        if packed == 1:
            bound = {i for i, _ in folder.binds}
            folder.packed = [i for i in range(total_in) if i not in bound][:1]
        else:
            folder.packed = [cursor.number() for _ in range(packed)]
        return folder

    @staticmethod
    def _substreams(cursor: _Cursor, folders: list[_Folder], limits: Limits) -> list[list[int]]:
        counts = [1] * len(folders)
        kind = cursor.byte()
        if kind == 0x0D:
            counts = [cursor.count(limits.max_archive_entries) for _ in folders]
            kind = cursor.byte()
        streams: list[list[int]] = []
        for folder, count in zip(folders, counts, strict=True):
            if not count:
                streams.append([])
                continue
            sizes = [cursor.number() for _ in range(count - 1)] if kind == 0x09 else []
            last = folder.size() - sum(sizes)
            if last < 0:
                raise cursor.fail("substreams larger than their folder")
            streams.append([*sizes, last])
        if kind == 0x09:
            kind = cursor.byte()
        # A folder of one substream whose own CRC is stated takes that one; every other substream
        # takes the next digest listed here, in order.
        for folder, count in zip(folders, counts, strict=True):
            folder.stream_crcs = (
                [folder.crc] if count == 1 and folder.crc is not None else [None] * count
            )
        while kind != 0x00:
            if kind != 0x0A:
                raise cursor.fail(f"property {kind} in the substreams info")
            unknown = sum(
                c
                for f, c in zip(folders, counts, strict=True)
                if not (c == 1 and f.crc is not None)
            )
            listed = iter(cursor.digests(unknown))
            for folder, count in zip(folders, counts, strict=True):
                if not (count == 1 and folder.crc is not None):
                    folder.stream_crcs = [next(listed) for _ in range(count)]
            kind = cursor.byte()
        return streams

    @staticmethod
    def _files(cursor: _Cursor, limits: Limits) -> tuple[list[str], list[bool]]:
        count = cursor.count(limits.max_archive_entries)
        names = [""] * count
        empty = [False] * count
        while (kind := cursor.byte()) != 0x00:
            body = _Cursor(cursor.take(cursor.number()), cursor.path)
            if kind == 0x0E:
                empty = body.bits(count)
            elif kind == 0x11:
                if body.byte():
                    raise cursor.fail("names kept elsewhere")
                text = body.data[body.at :].decode("utf-16-le", "replace")
                found = text.split("\x00")[:count]
                if len(found) < count:
                    raise cursor.fail("fewer names than files")
                names = found
        return names, empty

    @staticmethod
    def _decode(
        data: bytes,
        folder: _Folder,
        packs: list[int],
        pack_pos: int,
        index: int,
        path: str,
        budget: int,
    ) -> bytes:
        """A folder's output, decoded with its declared size as the bound."""
        size = folder.size()
        if size < 0 or size > budget:
            raise ArchiveError(f"{path}: a 7z folder of {size} bytes, past the archive budget")
        if len(folder.packed) != 1:
            raise ArchiveError(f"{path}: a 7z folder of several packed streams (BCJ2), not read")
        start = 32 + pack_pos + sum(packs[:index])
        packed = bytes(data[start : start + (packs[index] if index < len(packs) else 0)])
        if folder.pack_crc is not None and zlib.crc32(packed) != folder.pack_crc:
            raise ArchiveError(f"{path}: a 7z packed stream whose CRC does not hold")
        chain = SevenZipReader._chain(folder, path)
        out = SevenZipReader._run(chain, packed, size, path)
        if len(out) != size:
            raise ArchiveError(f"{path}: a 7z folder that decoded to {len(out)} of {size} bytes")
        if folder.crc is not None and zlib.crc32(out) != folder.crc:
            raise ArchiveError(f"{path}: a 7z folder whose CRC does not hold")
        return out

    @staticmethod
    def _chain(folder: _Folder, path: str) -> list[tuple[bytes, bytes]]:
        """The coders from the folder's output back to its packed stream, as (method, properties)."""
        if any(c[1] != 1 or c[2] != 1 for c in folder.coders):
            raise ArchiveError(f"{path}: a 7z folder whose coders are not one chain, not read")
        for method, _, _, _ in folder.coders:
            name = SevenZipReader.NAMES.get(method)
            if name is not None:
                raise ArchiveError(f"{path}: a 7z folder using {name}, not read")
            if method not in SevenZipReader.FILTERS and method not in SevenZipReader.ALONE:
                raise ArchiveError(f"{path}: a 7z coder {method.hex()} no reader here decodes")
        count = len(folder.coders)
        outs = [o for _, o in folder.binds]
        ins = [i for i, _ in folder.binds]
        if (
            len(set(outs)) != len(outs)
            or len(set(ins)) != len(ins)
            or any(not 0 <= x < count for x in outs + ins)
        ):
            raise ArchiveError(f"{path}: a 7z folder whose bind pairs do not hold")
        free = [i for i in range(count) if i not in set(outs)]
        if len(free) != 1:
            raise ArchiveError(f"{path}: a 7z folder without one output")
        order: list[tuple[bytes, bytes]] = []
        seen: set[int] = set()
        at: int | None = free[0]
        while at is not None:
            if at in seen:
                raise ArchiveError(f"{path}: a 7z folder whose coders loop")
            seen.add(at)
            order.append(folder.coders[at][::3])
            at = next((o for i, o in folder.binds if i == at), None)
        if len(order) != count:
            raise ArchiveError(f"{path}: a 7z folder with coders no chain reaches")
        return order

    @staticmethod
    def _run(chain: list[tuple[bytes, bytes]], packed: bytes, size: int, path: str) -> bytes:
        methods = [m for m, _ in chain]
        try:
            if len(chain) == 1 and methods[0] in SevenZipReader.ALONE:
                if methods[0] == b"\x00":
                    return packed[:size]
                if methods[0] == b"\x04\x01\x08":
                    inflater = zlib.decompressobj(-15)
                    return inflater.decompress(packed, size + 1)
                return bz2.BZ2Decompressor().decompress(packed, size + 1)
            if any(m not in SevenZipReader.FILTERS for m in methods):
                raise ArchiveError(f"{path}: a 7z chain mixing coders the stdlib decodes apart")
            filters = [SevenZipReader._filter(m, p, size) for m, p in chain]
            decoder = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filters)
            return decoder.decompress(packed, size + 1)
        except (lzma.LZMAError, zlib.error, OSError, ValueError, EOFError) as exc:
            raise ArchiveError(f"{path}: a 7z folder that does not decode: {exc}") from exc

    @staticmethod
    def _filter(method: bytes, props: bytes, size: int) -> dict[str, Any]:
        """One raw filter. An LZMA dictionary is held to the folder's own size: decoding needs no
        more, and a declared 4 GB dictionary must not be allocated to read 1 KB."""
        filter_id = SevenZipReader.FILTERS[method]
        floor = max(4096, size)
        if filter_id == lzma.FILTER_LZMA1:
            if len(props) < 5:
                raise ValueError("LZMA properties too short")
            d = props[0]
            dictionary = struct.unpack_from("<I", props, 1)[0]
            return {
                "id": filter_id,
                "lc": d % 9,
                "lp": (d // 9) % 5,
                "pb": d // 45,
                "dict_size": min(dictionary, floor),
            }
        if filter_id == lzma.FILTER_LZMA2:
            p = props[0] if props else 0
            dictionary = 0xFFFFFFFF if p >= 40 else (2 | (p & 1)) << (p // 2 + 11)
            return {"id": filter_id, "dict_size": min(dictionary, floor)}
        if filter_id == lzma.FILTER_DELTA:
            return {"id": filter_id, "dist": (props[0] + 1) if props else 1}
        return {"id": filter_id}

    @staticmethod
    def _keep(name: str, body: bytes, result: ExtractionResult, member: Callable[..., Any]) -> None:
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


__all__ = ["MAGIC", "SevenZipReader"]
