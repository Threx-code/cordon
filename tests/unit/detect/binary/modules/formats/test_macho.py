"""The Mach-O reader (modules.formats.macho) on objects built here byte by byte: a little-endian x86-64
executable with a segment, a section and LC_MAIN; a big-endian PowerPC object whose entry point comes from
LC_UNIXTHREAD through the segment that holds it; a fat file of both; and the reference's bounds and quirks
(the magic read big-endian), and the reader's own strict readings where the reference's are accidents
(a short segment command, a thread state that does not fit its command, a fat entry that is not an object,
an architecture with no entry point). The values asserted are worked from the format and the reference's
declared names; the recorded-reference differential joins the review harness once the reference image
exists."""

from __future__ import annotations

import struct

from cordon_scanner.detect.binary.modules.formats.macho import Macho
from cordon_scanner.detect.binary.modules.formats.macho_tables import MachoTables
from cordon_scanner.detect.binary.modules.values import Data

T = MachoTables.MACHO


class Build:
    """Mach-O bytes: `e` is the struct byte order of the fields ("<" or ">"); the magic bytes are chosen so
    that the reference, reading them big-endian, swaps exactly the big-endian objects."""

    @staticmethod
    def header(e: str, cputype: int, ncmds: int, sizeofcmds: int, *, is64: bool = True) -> bytes:
        magic = {("<", True): b"\xcf\xfa\xed\xfe", (">", True): b"\xfe\xed\xfa\xcf",
                 ("<", False): b"\xce\xfa\xed\xfe", (">", False): b"\xfe\xed\xfa\xce"}[e, is64]  # fmt: skip
        fields = struct.pack(f"{e}6I", cputype, 3, T["MH_EXECUTE"], ncmds, sizeofcmds, T["MH_PIE"])
        return magic + fields + (struct.pack(f"{e}I", 0) if is64 else b"")

    @staticmethod
    def section64(
        e: str, sectname: bytes, segname: bytes, addr: int, size: int, offset: int
    ) -> bytes:
        return (
            sectname.ljust(16, b"\x00") + segname.ljust(16, b"\x00")
            + struct.pack(f"{e}2Q8I", addr, size, offset, 4, 0, 0, T["S_ATTR_PURE_INSTRUCTIONS"], 0, 0, 0)
        )  # fmt: skip

    @staticmethod
    def segment64(
        e: str, name: bytes, vmaddr: int, vmsize: int, fileoff: int, sections: list[bytes]
    ) -> bytes:
        body = struct.pack(f"{e}4Q4I", vmaddr, vmsize, fileoff, vmsize, 7, 5, len(sections), 0)
        cmdsize = 72 + 80 * len(sections)
        return (
            struct.pack(f"{e}2I", MachoTables.LC_SEGMENT_64, cmdsize)
            + name.ljust(16, b"\x00")
            + body
            + b"".join(sections)
        )

    @staticmethod
    def segment32(e: str, name: bytes, vmaddr: int, vmsize: int, fileoff: int) -> bytes:
        body = struct.pack(f"{e}8I", vmaddr, vmsize, fileoff, vmsize, 7, 5, 0, 0)
        return struct.pack(f"{e}2I", MachoTables.LC_SEGMENT, 56) + name.ljust(16, b"\x00") + body

    @staticmethod
    def main(e: str, entryoff: int, stacksize: int) -> bytes:
        return struct.pack(f"{e}2I2Q", MachoTables.LC_MAIN, 24, entryoff, stacksize)

    @staticmethod
    def ppc_thread(e: str, srr0: int) -> bytes:
        state = struct.pack(f"{e}40I", srr0, *([0] * 39))  # 160 bytes: srr0 first
        return struct.pack(f"{e}4I", MachoTables.LC_UNIXTHREAD, 16 + len(state), 1, 40) + state

    @staticmethod
    def x86_64() -> bytes:
        """A little-endian x86-64 executable: __TEXT with __text, then LC_MAIN."""
        e = "<"
        text = Build.section64(e, b"__text", b"__TEXT", 0x100000F00, 0x40, 0xF00)
        seg = Build.segment64(e, b"__TEXT", 0x100000000, 0x1000, 0, [text])
        main = Build.main(e, 0xF00, 0)
        return Build.header(e, T["CPU_TYPE_X86_64"], 2, len(seg) + len(main)) + seg + main

    @staticmethod
    def ppc() -> bytes:
        """A big-endian 32-bit PowerPC object: one segment, then LC_UNIXTHREAD whose srr0 lies in it."""
        e = ">"
        seg = Build.segment32(e, b"__TEXT", 0x1000, 0x2000, 0)
        thread = Build.ppc_thread(e, 0x1040)
        return (
            Build.header(e, T["CPU_TYPE_POWERPC"], 2, len(seg) + len(thread), is64=False)
            + seg
            + thread
        )

    @staticmethod
    def fat(
        objects: list[tuple[int, int, bytes]], extra: tuple[tuple[int, int, int, int], ...] = ()
    ) -> bytes:
        """A 32-bit-entry fat file of `(cputype, cpusubtype, object)` plus `extra` bare entries
        `(cputype, cpusubtype, offset, size)` that point wherever they say."""
        count = len(objects) + len(extra)
        at = 8 + 20 * count
        at = (at + 15) & ~15
        archs, blobs = b"", b""
        for cputype, subtype, data in objects:
            archs += struct.pack(">5I", cputype, subtype, at + len(blobs), len(data), 4)
            blobs += data.ljust((len(data) + 15) & ~15, b"\x00")
        for cputype, subtype, offset, size in extra:
            archs += struct.pack(">5I", cputype, subtype, offset, size, 4)
        head = b"\xca\xfe\xba\xbe" + struct.pack(">I", count) + archs
        return head.ljust(at, b"\x00") + blobs


class TestObjects:
    def test_x86_64_header_segment_section_and_main(self) -> None:
        d = Macho.data(Build.x86_64())
        assert (
            d["magic"] == T["MH_CIGAM_64"]
        )  # the magic bytes read big-endian: a little-endian file is CIGAM
        assert (d["cputype"], d["filetype"], d["ncmds"], d["flags"], d["reserved"]) == (
            T["CPU_TYPE_X86_64"], T["MH_EXECUTE"], 2, T["MH_PIE"], 0
        )  # fmt: skip
        assert d["number_of_segments"] == 1
        seg = d["segments"][0]
        assert (seg["segname"], seg["vmaddr"], seg["vmsize"], seg["fileoff"], seg["fsize"], seg["nsects"]) == (
            b"__TEXT", 0x100000000, 0x1000, 0, 0x1000, 1
        )  # fmt: skip
        sec = seg["sections"][0]
        assert (sec["sectname"], sec["segname"], sec["addr"], sec["size"], sec["offset"], sec["align"]) == (
            b"__text", b"__TEXT", 0x100000F00, 0x40, 0xF00, 4
        )  # fmt: skip
        assert sec["flags"] == T["S_ATTR_PURE_INSTRUCTIONS"] and sec["reserved3"] == 0
        assert (d["entry_point"], d["stack_size"]) == (0xF00, 0)
        assert d["fat_arch"] == {} and d["file"] == {} and "nfat_arch" not in d

    def test_big_endian_ppc_entry_point_through_the_thread_state(self) -> None:
        d = Macho.data(Build.ppc())
        assert d["magic"] == T["MH_MAGIC"] and "reserved" not in d  # 32-bit: no reserved field
        assert d["cputype"] == T["CPU_TYPE_POWERPC"]
        assert d["segments"][0]["vmaddr"] == 0x1000 and d["segments"][0]["sections"] == {}
        assert d["entry_point"] == 0x40  # srr0 0x1040 in a segment at vmaddr 0x1000, fileoff 0
        assert "stack_size" not in d

    def test_a_thread_state_must_fit_its_command(self) -> None:
        """A thread command whose declared size runs past the file ends the command walk, so no entry
        point (the reference reads the size in host order and takes what remains)."""
        e = ">"
        seg = Build.segment32(e, b"__TEXT", 0x1000, 0x2000, 0)
        thread = Build.ppc_thread(e, 0x1040)[:-8]  # the state 8 bytes short: cmdsize says 176
        data = (
            Build.header(e, T["CPU_TYPE_POWERPC"], 2, len(seg) + len(thread), is64=False)
            + seg
            + thread
        )
        assert "entry_point" not in Macho.data(data)

    def test_the_entry_point_outside_every_segment_is_undefined(self) -> None:
        e = ">"
        seg = Build.segment32(e, b"__TEXT", 0x1000, 0x2000, 0)
        thread = Build.ppc_thread(e, 0x9000)
        data = (
            Build.header(e, T["CPU_TYPE_POWERPC"], 2, len(seg) + len(thread), is64=False)
            + seg
            + thread
        )
        assert "entry_point" not in Macho.data(data)

    def test_conforms_to_the_declared_schema(self) -> None:
        for data in (
            Build.x86_64(),
            Build.ppc(),
            Build.fat([(T["CPU_TYPE_X86_64"], 3, Build.x86_64())]),
        ):
            assert Data.conforms(Macho.SCHEMA, Macho.data(data)) == []


class TestBounds:
    def test_not_a_macho_gives_the_constants_alone(self) -> None:
        d = Macho.data(b"MZ this is not an apple binary")
        assert "magic" not in d and d["segments"] == {} and d["MH_EXECUTE"] == 2
        assert d["file_index_for_arch"][0](T["CPU_TYPE_X86_64"]) is None

    def test_an_object_needs_its_own_header_size(self) -> None:
        """32 bytes for a 64-bit object, 28 for a 32-bit one (the reference wants 32 for both)."""
        assert "magic" not in Macho.data(Build.x86_64()[:31])
        thin = b"\xce\xfa\xed\xfe" + struct.pack("<6I", T["CPU_TYPE_X86"], 3, 2, 0, 0, 0)
        assert Macho.data(thin)["ncmds"] == 0 and "reserved" not in Macho.data(thin)
        assert "magic" not in Macho.data(thin[:27])

    def test_the_command_walk_stops_at_a_broken_command(self) -> None:
        e = "<"
        seg = Build.segment64(e, b"__TEXT", 0x100000000, 0x1000, 0, [])
        broken = struct.pack(f"{e}2I", MachoTables.LC_MAIN, 4)  # cmdsize below its own header
        main = Build.main(e, 0xF00, 0)
        data = Build.header(e, T["CPU_TYPE_X86_64"], 3, 0) + seg + broken + main
        d = Macho.data(data)
        assert d["number_of_segments"] == 1 and "entry_point" not in d
        past_end = Build.header(e, T["CPU_TYPE_X86_64"], 2, 0) + seg + main[:20]
        assert "entry_point" not in Macho.data(past_end)

    def test_a_segment_command_shorter_than_a_segment_is_neither_read_nor_counted(self) -> None:
        """The reference reads the 56-byte structure from whatever follows an 8-byte command and counts
        it; this reader reads a command within its own size."""
        e = "<"
        seg = Build.segment32(e, b"__TEXT", 0x1000, 0x2000, 0)
        short = struct.pack(f"{e}2I", MachoTables.LC_SEGMENT, 8) + seg[8:]
        data = Build.header(e, T["CPU_TYPE_X86"], 1, 8, is64=False) + short
        d = Macho.data(data)
        assert d["number_of_segments"] == 0 and d["segments"] == {}


class TestFat:
    def test_architectures_files_and_the_index_and_entry_functions(self) -> None:
        data = Build.fat(
            [(T["CPU_TYPE_X86_64"], 3, Build.x86_64()), (T["CPU_TYPE_POWERPC"], 0, Build.ppc())]
        )
        d = Macho.data(data)
        assert (d["fat_magic"], d["nfat_arch"]) == (T["FAT_MAGIC"], 2)
        assert (
            d["fat_arch"][0]["cputype"] == T["CPU_TYPE_X86_64"]
            and d["fat_arch"][1]["cputype"] == T["CPU_TYPE_POWERPC"]
        )
        assert d["file"][0]["magic"] == T["MH_CIGAM_64"] and d["file"][1]["magic"] == T["MH_MAGIC"]
        assert d["file"][0]["entry_point"] == 0xF00 and d["file"][1]["entry_point"] == 0x40
        assert "magic" not in d and d["segments"] == {}  # the fat file itself has no header fields
        by_type, by_subtype = d["file_index_for_arch"]
        assert by_type(T["CPU_TYPE_X86_64"]) == 0 and by_type(T["CPU_TYPE_POWERPC"]) == 1
        assert by_type(T["CPU_TYPE_ARM64"]) is None
        assert (
            by_subtype(T["CPU_TYPE_X86_64"], 3) == 0 and by_subtype(T["CPU_TYPE_X86_64"], 4) is None
        )
        ep_type, ep_subtype = d["entry_point_for_arch"]
        assert ep_type(T["CPU_TYPE_X86_64"]) == d["fat_arch"][0]["offset"] + 0xF00
        assert ep_subtype(T["CPU_TYPE_POWERPC"], 0) == d["fat_arch"][1]["offset"] + 0x40
        assert ep_type(T["CPU_TYPE_ARM64"]) is None and ep_subtype(T["CPU_TYPE_POWERPC"], 1) is None

    def test_an_architecture_past_the_end_lists_no_file(self) -> None:
        """Its architecture entry stays; both entry-point forms are undefined for it (the reference adds
        its undefined marker to the offset in the one-argument form)."""
        data = Build.fat(
            [(T["CPU_TYPE_X86_64"], 3, Build.x86_64())],
            extra=((T["CPU_TYPE_ARM64"], 0, 1 << 20, 64),),
        )
        d = Macho.data(data)
        assert d["nfat_arch"] == 2 and 1 in d["fat_arch"] and 1 not in d["file"]
        assert d["entry_point_for_arch"][0](T["CPU_TYPE_ARM64"]) is None
        assert d["entry_point_for_arch"][1](T["CPU_TYPE_ARM64"], 0) is None
        assert d["file_index_for_arch"][0](T["CPU_TYPE_ARM64"]) is None

    def test_a_fat_header_without_room_for_its_entries_lists_none(self) -> None:
        d = Macho.data(b"\xca\xfe\xba\xbe" + struct.pack(">I", 3) + b"\x00" * 20)
        assert (d["fat_magic"], d["nfat_arch"], d["fat_arch"], d["file"]) == (
            T["FAT_MAGIC"],
            3,
            {},
            {},
        )
        assert "nfat_arch" not in Macho.data(b"\xca\xfe\xba\xbe\x00\x00\x00")

    def test_a_fat_entry_that_is_not_an_object_lists_no_fields(self) -> None:
        """The reference parses whatever a fat entry points at as a header; this reader reads an object
        only behind an object magic."""
        junk = b"\x00" * 64
        d = Macho.data(Build.fat([(T["CPU_TYPE_ARM"], 0, junk)]))
        assert d["file"][0] == {"segments": {}} and d["fat_arch"][0]["size"] == 64
        assert d["entry_point_for_arch"][0](T["CPU_TYPE_ARM"]) is None
