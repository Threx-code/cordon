"""What a zip holds, read by its local file headers (item 76): every extractor reaches an entry's bytes
through the local header in front of them, a directory-reading one (pip, a JAR loader, unzip) by the
offset its central directory records, a streaming one (several JavaScript unzip libraries) by walking
the headers from the front. So bytes holding no well-formed local header hold no entry any extractor
installs, whatever zip signatures they carry: a bundled zip library's constants (`jszip.min.js`, a
Mach-O `Zip.framework`, CPython's `zipimport.pyc`, a 7-Zip `.wasm`). And a zip whose central directory
will not open (an Adobe XFL `.fla`, a hand-built APK) is still read, by its local headers, the way a
streaming extractor installs it.

`ZipEntries.held` is the test; `ZipRepair.rebuild` gives the zip with its directory rebuilt from the
local headers, or None when the headers do not account for the bytes, so what cannot be read stays
refused (a blocking gap) exactly as before.
"""

from __future__ import annotations

import copy
import io
import struct
import zipfile
import zlib
from typing import Any, ClassVar

from cordon_scanner.foundation.limits import Limits
from cordon_scanner.sources.base import RejectedMember, Rejection


class ZipEntries:
    """Whether bytes hold a zip entry: a local file header that could be read as one."""

    LOCAL: ClassVar[bytes] = b"PK\x03\x04"
    HEADER: ClassVar[struct.Struct] = struct.Struct("<4s5H3L2H")
    #: Every compression method a common extractor reads (APPNOTE 4.4.5): stored, shrunk, imploded,
    #: deflate, deflate64, bzip2, lzma, lz77, zstd, mp3, xz, jpeg, wavpack, ppmd and AES's marker.
    METHODS: ClassVar[frozenset[int]] = frozenset(
        {0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 14, 18, 19, 93, 94, 95, 96, 97, 98, 99}
    )

    @staticmethod
    def entry_at(
        data: bytes, at: int, *, whole: bool = True
    ) -> tuple[int, int, int, int, int, int] | None:
        """(flags, method, crc, compressed, name length, extra length) of a local header at `at`
        that could be read as one: a method an extractor knows, a version a writer states (below
        256), its name and extra field inside the bytes, and (`whole`) its data too unless its size
        is deferred (a data descriptor, flag 3, or ZIP64's 0xFFFFFFFF); else None. Not `whole`, an
        entry whose name or data runs past the end still counts: a cut zip is a zip, refused as one
        (basedpyright's `zipfs/corrupt.zip`, a header and a sentence)."""
        if at + ZipEntries.HEADER.size > len(data):
            # A cut zip is cut anywhere, even inside its first header: its signature, version and
            # method are what say it was one.
            return None if whole or at + 10 > len(data) else ZipEntries._cut(data, at)
        sig, version, flags, method, _, _, crc, compressed, _, name_len, extra_len = (
            ZipEntries.HEADER.unpack_from(data, at)
        )
        if sig != ZipEntries.LOCAL or version >= 0x100 or method not in ZipEntries.METHODS:
            return None
        start = at + ZipEntries.HEADER.size + name_len + extra_len
        if whole and start > len(data):
            return None
        deferred = flags & 0x08 or compressed == 0xFFFFFFFF
        if whole and not deferred and start + compressed > len(data):
            return None
        return flags, method, crc, compressed, name_len, extra_len

    @staticmethod
    def _cut(data: bytes, at: int) -> tuple[int, int, int, int, int, int] | None:
        version, flags, method = struct.unpack_from("<3H", data, at + 4)
        if version >= 0x100 or method not in ZipEntries.METHODS:
            return None
        return flags, method, 0, 0, 0, 0

    @staticmethod
    def held(data: bytes) -> bool:
        """Whether any local header in `data` could be read as an entry. One linear search: each
        signature found is checked in constant time."""
        at = data.find(ZipEntries.LOCAL)
        while at != -1:
            if ZipEntries.entry_at(data, at, whole=False) is not None:
                return True
            at = data.find(ZipEntries.LOCAL, at + 1)
        return False

    @staticmethod
    def listed(data: bytes) -> bool:
        """Whether a central directory opens and points at a local header: a directory-reading
        extractor takes an entry's method and sizes from the directory, not the header, so a zip
        whose headers carry nonsense in those fields is still one (Python's reader is that kind)."""
        import io

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                return any(
                    data.startswith(ZipEntries.LOCAL, info.header_offset)
                    for info in archive.infolist()
                )
        except (
            zipfile.BadZipFile,
            OSError,
            ValueError,
            EOFError,
            struct.error,
            NotImplementedError,
        ):
            return False

    @staticmethod
    def present(data: bytes) -> bool:
        """Whether any extractor finds an entry in `data`: by walking its local headers, or by a
        directory that opens and points at one."""
        return ZipEntries.held(data) or ZipEntries.listed(data)


class ZipRepair:
    """A zip whose central directory would not open, with one rebuilt from its local headers."""

    DESCRIPTOR: ClassVar[bytes] = b"PK\x07\x08"
    #: What may follow the last entry: a central directory, an end record (ZIP64's or the plain
    #: one), or nothing. Anything else is bytes no header accounts for, and the zip stays refused.
    ENDINGS: ClassVar[tuple[bytes, ...]] = (b"PK\x01\x02", b"PK\x05\x06", b"PK\x06\x06")
    #: An APK's signing block sits between the entries and the directory and ends in this magic.
    APK_MAGIC: ClassVar[bytes] = b"APK Sig Block 42"
    CENTRAL: ClassVar[struct.Struct] = struct.Struct("<4s6H3L5H2L")
    END: ClassVar[struct.Struct] = struct.Struct("<4s4H2LH")

    @staticmethod
    def rebuild(data: bytes, limits: Limits) -> bytes | None:
        """The zip with its central directory rebuilt from the local headers walked from offset 0,
        or None: a header that does not parse, an entry whose end cannot be known (stored behind a
        data descriptor, ZIP64), more entries than the limit, an inflate past the archive budget, or
        bytes after the last entry that are not a directory, an end record or an APK signing block.
        Each entry keeps its own header's fields; a nameless, empty one (an APK's stub) installs no
        file and is left out. Every read after this one is the ordinary zip path's, with its limits."""
        entries: list[tuple[int, int, int, int, int, int, bytes]] = []
        offset = inflated = 0
        while data.startswith(ZipEntries.LOCAL, offset):
            entry = ZipEntries.entry_at(data, offset)
            if entry is None or len(entries) >= limits.max_archive_entries:
                return None
            flags, method, crc, compressed, name_len, extra_len = entry
            header = ZipEntries.HEADER.unpack_from(data, offset)
            usize = header[8]
            name_at = offset + ZipEntries.HEADER.size
            start = name_at + name_len + extra_len
            if flags & 0x08:
                ended = ZipRepair._deflated_end(data, start, method, limits.max_uncompressed_bytes)
                if ended is None:
                    return None
                end, produced = ended
                inflated += produced
                descriptor = ZipRepair._descriptor(data, end)
                if descriptor is None or descriptor[1] != end - start:
                    return None
                crc, compressed, usize, end = descriptor
            elif compressed == 0xFFFFFFFF:
                return None
            else:
                end = start + compressed
            if inflated > limits.max_uncompressed_bytes:
                return None
            if name_len or compressed:
                entries.append(
                    (
                        offset,
                        flags,
                        method,
                        crc,
                        compressed,
                        usize,
                        bytes(data[name_at : name_at + name_len]),
                    )
                )
            offset = end
        if not entries or not ZipRepair._accounted(data, offset):
            return None
        if not ZipRepair._directory_agrees(data, offset, entries):
            return None
        rebuilt = bytes(data[:offset]) + ZipRepair._directory(data, entries, offset)
        # A directory rebuilt from headers that declare a zip version Python cannot read raised
        # NotImplementedError when reopened (S1 fuzzing, 10 Nov): that is no repair, so refused.
        try:
            zipfile.ZipFile(io.BytesIO(rebuilt)).close()
        except (zipfile.BadZipFile, OSError, ValueError, EOFError, NotImplementedError):
            return None
        return rebuilt

    @staticmethod
    def _directory_agrees(
        data: bytes, offset: int, entries: list[tuple[int, int, int, int, int, int, bytes]]
    ) -> bool:
        """Whether the original directory, read by hand past the last entry, names only entries the
        walk read: an extractor more lenient than Python's may open the directory Python refused,
        and install what it points at (outer review of item 76: an entry inside a signing block or
        inside another entry's data). Every record found must point at a walked entry, under the
        same name less separators; with no record found at all, the directory is unreadable and so
        is the zip."""
        walked = {at: name.replace(b"\\", b"/") for at, *_, name in entries}
        found, at = 0, data.find(b"PK\x01\x02", offset)
        while at != -1:
            if at + 46 > len(data):
                return False
            name_len = struct.unpack_from("<H", data, at + 28)[0]
            local = struct.unpack_from("<L", data, at + 42)[0]
            name = bytes(data[at + 46 : at + 46 + name_len]).replace(b"\\", b"/")
            # A nameless record pointing at a nameless stub the walk left out is the one shape that
            # names nothing: an APK's leading stub.
            stub = name_len == 0 and local < entries[0][0]
            if (local not in walked or walked[local] != name) and not stub:
                return False
            found += 1
            at = data.find(b"PK\x01\x02", at + 46 + name_len)
        return found > 0

    @staticmethod
    def rebuilt(path: str, exc: Exception) -> RejectedMember:
        """The note that `path` was read through a rebuilt directory: nothing left unread."""
        return RejectedMember(
            path,
            Rejection.DIRECTORY_REBUILT,
            f"its central directory would not open ({exc}); every member was read by its local "
            "header, as a streaming extractor installs it",
        )

    @staticmethod
    def _deflated_end(data: bytes, start: int, method: int, budget: int) -> tuple[int, int] | None:
        """Where a deflate stream behind a data descriptor ends, and the bytes it inflated to; None
        for any other method (its end is unknowable) or a stream that is cut, bad, or past `budget`."""
        if method != 8:
            return None
        inflater = zlib.decompressobj(-15)
        produced, fed, step = 0, start, 1 << 20
        try:
            while not inflater.eof:
                if inflater.unconsumed_tail:
                    chunk = inflater.unconsumed_tail
                elif fed < len(data):
                    chunk = bytes(data[fed : fed + step])
                    fed += len(chunk)
                else:
                    return None  # cut: the stream never ends
                produced += len(inflater.decompress(chunk, step))
                if produced > budget:
                    return None
        except zlib.error:
            return None
        return fed - len(inflater.unused_data), produced

    @staticmethod
    def _descriptor(data: bytes, at: int) -> tuple[int, int, int, int] | None:
        """(crc, compressed, uncompressed, end) of the data descriptor at `at`, signed or not."""
        if data.startswith(ZipRepair.DESCRIPTOR, at):
            at += 4
        if at + 12 > len(data):
            return None
        crc, compressed, usize = struct.unpack_from("<3L", data, at)
        return crc, compressed, usize, at + 12

    @staticmethod
    def _accounted(data: bytes, offset: int) -> bool:
        """Whether the bytes after the last entry are a directory, an end record, an APK signing
        block in front of one, or nothing."""
        if offset >= len(data) or data.startswith(ZipRepair.ENDINGS, offset):
            return True
        if offset + 8 > len(data):
            return False
        size = struct.unpack_from("<Q", data, offset)[0]
        block_end = offset + 8 + size
        return (
            block_end <= len(data)
            and data[block_end - len(ZipRepair.APK_MAGIC) : block_end] == ZipRepair.APK_MAGIC
            and (block_end == len(data) or data.startswith(ZipRepair.ENDINGS, block_end))
            # A signing block is checked only by its size and magic: one holding a local header is
            # where an entry the walk never reads would hide.
            and ZipEntries.LOCAL not in data[offset:block_end]
        )

    @staticmethod
    def _directory(
        data: bytes, entries: list[tuple[int, int, int, int, int, int, bytes]], at: int
    ) -> bytes:
        """A central directory and end record for `entries`, the directory placed at `at`."""
        parts: list[bytes] = []
        for offset, flags, method, crc, compressed, usize, name in entries:
            version, _, _, mtime, mdate = ZipEntries.HEADER.unpack_from(data, offset)[1:6]
            parts.append(
                ZipRepair.CENTRAL.pack(
                    b"PK\x01\x02",
                    version,
                    version,
                    flags,
                    method,
                    mtime,
                    mdate,
                    crc,
                    compressed,
                    usize,
                    len(name),
                    0,
                    0,
                    0,
                    0,
                    0,
                    offset,
                )
                + name
            )
        directory = b"".join(parts)
        count = len(entries)
        return directory + ZipRepair.END.pack(
            b"PK\x05\x06", 0, 0, count, count, len(directory), at, 0
        )


class ZipNames:
    """A member opened by its name as a Windows writer gave it."""

    @staticmethod
    def open_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> Any:
        """`archive.open(info)`, and the one name difference every extractor reads past: a Windows
        writer's directory says `FJCore\\IJG.txt` where its local header says `FJCore/IJG.txt`
        (plupload's `Moxie.xap`). Names that differ in anything but the separator stay refused: two
        views naming two files is how one is shown to the scanner and another installed."""
        try:
            return archive.open(info)
        except zipfile.BadZipFile:
            local = ZipNames._local_name(archive, info)
            directory = info.orig_filename.encode(
                "utf-8" if info.flag_bits & 0x800 else "cp437", "replace"
            )
            if (
                local is None
                or local == directory
                or local.replace(b"\\", b"/") != directory.replace(b"\\", b"/")
            ):
                raise
            same = copy.copy(info)
            same.orig_filename = local.decode(
                "utf-8" if info.flag_bits & 0x800 else "cp437", "replace"
            )
            return archive.open(same)

    @staticmethod
    def _local_name(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes | None:
        """The name a member's local header gives it, or None where there is no header to read."""
        handle = archive.fp
        if handle is None:
            return None
        handle.seek(info.header_offset)
        header = handle.read(30)
        if len(header) < 30 or header[:4] != b"PK\x03\x04":
            return None
        name_len = struct.unpack_from("<H", header, 26)[0]
        return bytes(handle.read(name_len))


__all__ = ["ZipEntries", "ZipNames", "ZipRepair"]
