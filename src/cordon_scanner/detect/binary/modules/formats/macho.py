"""The Mach-O reader for cordon-rule: the `macho` module's values as a condition sees them.

An object is read from its magic (32- or 64-bit, either byte order) through the header and its load
commands in two passes, as the reference does: the segments and their sections first (LC_SEGMENT,
LC_SEGMENT_64), then the entry point, from LC_MAIN's offset or from the program counter in
LC_UNIXTHREAD's thread state, mapped to a file offset through the segments. A fat file lists its
architectures and reads each contained object into `file[i]`. Every structure is a Layout; the Cursor
carries the byte order, chosen from the magic.

The values are the reference's, quirks included: `magic` is the first four bytes read big-endian, so a
little-endian x86-64 object reports MH_CIGAM_64; the thread command's size is read little-endian whatever
the file's order; a segment command shorter than its structure is still read whole from where it starts;
an architecture whose object has no entry point still gives `entry_point_for_arch(type)` the reference's
sum with its undefined marker. A file that is neither an object nor a fat file answers undefined for
everything but the constants.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.formats.macho_tables import MachoTables
from cordon_scanner.detect.binary.modules.layout import U32, U64, Blob, Cursor, Layout
from cordon_scanner.detect.binary.modules.values import Call, Record, Scalar, Seq, Sig

INT, TEXT = Scalar.INT, Scalar.TEXT
T = MachoTables.MACHO

UNDEFINED = 0xFFFABADAFABADAFF
"""The reference's marker for an integer it has not set; its arithmetic carries it like any value."""
MASK64 = (1 << 64) - 1


class Shape:
    """Every Mach-O structure described once (Apple's mach-o/loader.h, mach-o/fat.h)."""

    HEADER: ClassVar[Layout] = Layout((
        ("magic", U32), ("cputype", U32), ("cpusubtype", U32), ("filetype", U32), ("ncmds", U32),
        ("sizeofcmds", U32), ("flags", U32), ("reserved", U32),
    ))  # fmt: skip
    """32 bytes; a 32-bit object's header is the first 28, without `reserved`."""
    COMMAND: ClassVar[Layout] = Layout((("cmd", U32), ("cmdsize", U32)))
    SEGMENT32: ClassVar[Layout] = Layout((
        ("cmd", U32), ("cmdsize", U32), ("segname", Blob(16)), ("vmaddr", U32), ("vmsize", U32),
        ("fileoff", U32), ("filesize", U32), ("maxprot", U32), ("initprot", U32), ("nsects", U32),
        ("flags", U32),
    ))  # fmt: skip
    SEGMENT64: ClassVar[Layout] = Layout((
        ("cmd", U32), ("cmdsize", U32), ("segname", Blob(16)), ("vmaddr", U64), ("vmsize", U64),
        ("fileoff", U64), ("filesize", U64), ("maxprot", U32), ("initprot", U32), ("nsects", U32),
        ("flags", U32),
    ))  # fmt: skip
    SECTION32: ClassVar[Layout] = Layout((
        ("sectname", Blob(16)), ("segname", Blob(16)), ("addr", U32), ("size", U32), ("offset", U32),
        ("align", U32), ("reloff", U32), ("nreloc", U32), ("flags", U32), ("reserved1", U32),
        ("reserved2", U32),
    ))  # fmt: skip
    SECTION64: ClassVar[Layout] = Layout((
        ("sectname", Blob(16)), ("segname", Blob(16)), ("addr", U64), ("size", U64), ("offset", U32),
        ("align", U32), ("reloff", U32), ("nreloc", U32), ("flags", U32), ("reserved1", U32),
        ("reserved2", U32), ("reserved3", U32),
    ))  # fmt: skip
    ENTRY_POINT: ClassVar[Layout] = Layout(
        (("cmd", U32), ("cmdsize", U32), ("entryoff", U64), ("stacksize", U64))
    )
    FAT_ARCH32: ClassVar[Layout] = Layout(
        (("cputype", U32), ("cpusubtype", U32), ("offset", U32), ("size", U32), ("align", U32))
    )
    FAT_ARCH64: ClassVar[Layout] = Layout((
        ("cputype", U32), ("cpusubtype", U32), ("offset", U64), ("size", U64), ("align", U32),
        ("reserved", U32),
    ))  # fmt: skip

    THREAD_STATES: ClassVar[dict[int, tuple[int, int, int]]] = {
        T["CPU_TYPE_MC680X0"]: (72, 68, 4),
        T["CPU_TYPE_MC88000"]: (136, 124, 4),
        T["CPU_TYPE_SPARC"]: (76, 4, 4),
        T["CPU_TYPE_POWERPC"]: (160, 0, 4),
        T["CPU_TYPE_X86"]: (64, 40, 4),
        T["CPU_TYPE_ARM"]: (68, 60, 4),
        T["CPU_TYPE_X86_64"]: (168, 128, 8),
        T["CPU_TYPE_ARM64"]: (268, 256, 8),
        T["CPU_TYPE_POWERPC64"]: (304, 0, 8),
    }
    """Per CPU type, the thread state LC_UNIXTHREAD carries: its size, and where its program counter is
    and how wide (m68k pc, m88k xip, SPARC pc, PowerPC srr0, x86 eip, ARM pc, x86-64 rip, ARM64 pc,
    PowerPC64 srr0), as the reference's packed structures lay them out."""


class Macho:
    """The `macho` module reader."""

    OBJECT_MAGICS: ClassVar[frozenset[int]] = frozenset(
        {T["MH_MAGIC"], T["MH_CIGAM"], T["MH_MAGIC_64"], T["MH_CIGAM_64"]}
    )
    FAT_MAGICS: ClassVar[frozenset[int]] = frozenset(
        {T["FAT_MAGIC"], T["FAT_CIGAM"], T["FAT_MAGIC_64"], T["FAT_CIGAM_64"]}
    )
    SWAPPED: ClassVar[frozenset[int]] = frozenset(
        {T["MH_MAGIC"], T["MH_MAGIC_64"], T["FAT_MAGIC"], T["FAT_MAGIC_64"]}
    )
    """Magics (read big-endian) of the files whose fields are big-endian: the reference swaps these on a
    little-endian host, so their fields read in the file's own order and the others' in the host's."""
    THIN: ClassVar[frozenset[int]] = frozenset({T["MH_MAGIC"], T["MH_CIGAM"]})

    SECTION: ClassVar[Record] = Record({
        "sectname": TEXT, "segname": TEXT, "addr": INT, "size": INT, "offset": INT, "align": INT,
        "reloff": INT, "nreloc": INT, "flags": INT, "reserved1": INT, "reserved2": INT,
        "reserved3": INT,
    })  # fmt: skip
    SEGMENT: ClassVar[Record] = Record({
        "segname": TEXT, "vmaddr": INT, "vmsize": INT, "fileoff": INT, "fsize": INT, "maxprot": INT,
        "initprot": INT, "nsects": INT, "flags": INT, "sections": Seq(SECTION),
    })  # fmt: skip
    OBJECT: ClassVar[dict[str, Any]] = {
        **dict.fromkeys(
            ("magic", "cputype", "cpusubtype", "filetype", "ncmds", "sizeofcmds", "flags", "reserved"),
            INT,
        ),
        "number_of_segments": INT, "segments": Seq(SEGMENT), "entry_point": INT, "stack_size": INT,
    }  # fmt: skip
    """One object's fields: the file's own, and each `file[i]` of a fat file."""
    SCHEMA: ClassVar[Record] = Record({
        **dict.fromkeys(T, INT),
        **OBJECT,
        "fat_magic": INT, "nfat_arch": INT,
        "fat_arch": Seq(Record(dict.fromkeys(("cputype", "cpusubtype", "offset", "size", "align"), INT))),
        "file": Seq(Record(OBJECT)),
        "file_index_for_arch": Call(Sig(("int",), INT), Sig(("int", "int"), INT)),
        "entry_point_for_arch": Call(Sig(("int",), INT), Sig(("int", "int"), INT)),
    })  # fmt: skip

    ARRAYS: ClassVar[tuple[str, ...]] = ("segments", "fat_arch", "file")

    @staticmethod
    def data(file: bytes) -> dict[str, Any]:
        out: dict[str, Any] = dict(T)  # the module constants are present for every file
        for name in (
            Macho.ARRAYS
        ):  # the reference always presents these arrays, empty when nothing fills them
            out[name] = {}
        if len(file) >= 4:
            magic = Cursor(file, big_endian=True).uint(0, 4)
            if magic in Macho.OBJECT_MAGICS:
                Macho._object_values(out, file)
            elif magic in Macho.FAT_MAGICS:
                Macho._fat(out, file)
        Macho._functions(out)
        return out

    @staticmethod
    def _object_values(out: dict[str, Any], data: bytes) -> None:
        """One object's header, segments and entry point, from `data`'s start: the reference reads any
        bytes a fat entry points at this way, whatever their magic."""
        n = len(data)
        if n < Shape.HEADER.stride():
            return
        magic = Cursor(data, big_endian=True).uint(0, 4)  # the magic is always read big-endian
        cur = Cursor(data, big_endian=magic in Macho.SWAPPED)
        header_size = 28 if magic in Macho.THIN else 32
        h = Shape.HEADER.read(cur, 0)
        out.update(
            magic=magic, cputype=h["cputype"], cpusubtype=h["cpusubtype"], filetype=h["filetype"],
            ncmds=h["ncmds"], sizeofcmds=h["sizeofcmds"], flags=h["flags"],
        )  # fmt: skip
        if magic not in Macho.THIN:
            out["reserved"] = h["reserved"]
        commands = list(Macho._commands(cur, header_size, h["ncmds"]))
        segments: dict[int, Any] = {}
        count = 0
        for (
            cmd,
            at,
            remaining,
        ) in commands:  # first pass: the segments, which the second pass maps through
            if cmd == MachoTables.LC_SEGMENT:
                Macho._segment(segments, count, cur, at, remaining, is64=False)
                count += 1
            elif cmd == MachoTables.LC_SEGMENT_64:
                Macho._segment(segments, count, cur, at, remaining, is64=True)
                count += 1
        out["number_of_segments"] = count
        out["segments"] = segments
        for cmd, at, remaining in commands:
            if cmd == MachoTables.LC_UNIXTHREAD:
                Macho._unixthread(out, cur, at, remaining, segments, count)
            elif cmd == MachoTables.LC_MAIN:
                Macho._main(out, cur, at, remaining)

    @staticmethod
    def _commands(cur: Cursor, header_size: int, ncmds: int) -> Iterator[tuple[int, int, int]]:
        """`(cmd, offset, bytes from the command to the end)` for each load command the reference reads:
        the walk stops at one that does not fit, is shorter than its own header, or runs past the end."""
        n = cur.n
        at = header_size
        for _ in range(ncmds):
            if at + 8 > n:
                break
            c = Shape.COMMAND.read(cur, at)
            cmdsize = c["cmdsize"]
            if n - at < cmdsize or cmdsize < 8:
                break
            yield c["cmd"], at, n - at
            at += cmdsize

    @staticmethod
    def _name(blob: bytes) -> bytes:
        """A 16-byte name field: up to its first NUL (the reference's strnlen)."""
        return blob.split(b"\x00", 1)[0]

    @staticmethod
    def _segment(
        segments: dict[int, Any], i: int, cur: Cursor, at: int, remaining: int, *, is64: bool
    ) -> None:
        """A segment command and the sections that fit in its `cmdsize`. The structure is read whole
        wherever `remaining` holds it, as the reference does, even past a shorter `cmdsize`."""
        layout = Shape.SEGMENT64 if is64 else Shape.SEGMENT32
        size = layout.stride()
        if remaining < size:
            return
        sg = layout.read(cur, at)
        seg: dict[str, Any] = {
            "segname": Macho._name(sg["segname"]), "vmaddr": sg["vmaddr"], "vmsize": sg["vmsize"],
            "fileoff": sg["fileoff"], "fsize": sg["filesize"], "maxprot": sg["maxprot"],
            "initprot": sg["initprot"], "nsects": sg["nsects"], "flags": sg["flags"],
        }  # fmt: skip
        sections: dict[int, Any] = {}
        sec_layout = Shape.SECTION64 if is64 else Shape.SECTION32
        sec_size = sec_layout.stride()
        parsed = size
        for j in range(sg["nsects"]):
            parsed += sec_size
            if sg["cmdsize"] < parsed:
                break
            sec = sec_layout.read(cur, at + size + j * sec_size)
            sections[j] = {
                "sectname": Macho._name(sec["sectname"]), "segname": Macho._name(sec["segname"]),
                **{k: v for k, v in sec.items() if k not in ("sectname", "segname")},
            }  # fmt: skip
        seg["sections"] = sections
        segments[i] = seg

    @staticmethod
    def _main(out: dict[str, Any], cur: Cursor, at: int, remaining: int) -> None:
        if remaining < Shape.ENTRY_POINT.stride():
            return
        e = Shape.ENTRY_POINT.read(cur, at)
        out["entry_point"] = e["entryoff"]
        out["stack_size"] = e["stacksize"]

    @staticmethod
    def _unixthread(
        out: dict[str, Any],
        cur: Cursor,
        at: int,
        remaining: int,
        segments: dict[int, Any],
        count: int,
    ) -> None:
        """The entry point from the thread state's program counter, as a file offset through the segment
        that holds it: unset when no segment does."""
        if remaining < 16:
            return
        # The reference takes the thread command's size in host order, little-endian whatever the file's.
        command_size = min(remaining, cur.uint(at + 4, 4, "little"))
        if command_size < 16:
            return
        spec = Shape.THREAD_STATES.get(out["cputype"])
        if spec is None:
            return
        size, pc_at, width = spec
        if command_size - 16 < size:
            return
        address = cur.uint(at + 16 + pc_at, width)
        for i in range(count):
            seg = segments.get(i, {})
            start = seg.get("vmaddr", UNDEFINED)
            end = (start + seg.get("vmsize", UNDEFINED)) & MASK64
            if start <= address < end:
                out["entry_point"] = (seg.get("fileoff", UNDEFINED) + (address - start)) & MASK64
                return

    @staticmethod
    def _fat(out: dict[str, Any], data: bytes) -> None:
        """A fat file's header, its architectures, and each contained object as `file[i]`; an entry
        pointing past the end, or wrapping, lists its architecture and no object."""
        n = len(data)
        big = Cursor(data, big_endian=True)  # fat headers are big-endian throughout
        magic = big.uint(0, 4)
        layout = Shape.FAT_ARCH32 if magic == T["FAT_MAGIC"] else Shape.FAT_ARCH64
        arch_size = layout.stride()
        if n < 8:
            return
        out["fat_magic"] = magic
        count = big.uint(4, 4)
        out["nfat_arch"] = count
        if n < 8 + count * arch_size:
            return
        archs: dict[int, Any] = {}
        files: dict[int, Any] = {}
        for i in range(count):
            a = layout.read(big, 8 + i * arch_size)
            archs[i] = {k: a[k] for k in ("cputype", "cpusubtype", "offset", "size", "align")}
            end = (a["offset"] + a["size"]) & MASK64
            if end < a["offset"] or n < end:
                continue
            entry: dict[str, Any] = {"segments": {}}
            Macho._object_values(entry, data[a["offset"] : end])
            files[i] = entry
        out["fat_arch"] = archs
        out["file"] = files

    @staticmethod
    def _functions(out: dict[str, Any]) -> None:
        """file_index_for_arch and entry_point_for_arch over the architectures read; undefined on a
        file that is not fat. `entry_point_for_arch(type)` adds the reference's undefined marker when
        the object has no entry point, as the reference does; the two-argument form is undefined then."""
        archs: dict[int, Any] = out["fat_arch"]
        files: dict[int, Any] = out["file"]
        fat = "nfat_arch" in out

        def index_by_type(cputype: int) -> int | None:
            if not fat:
                return None
            for i, f in sorted(files.items()):
                if f.get("cputype") == cputype:
                    return i
            return None

        def index_by_subtype(cputype: int, subtype: int) -> int | None:
            if not fat:
                return None
            for i, f in sorted(files.items()):
                if f.get("cputype") == cputype and f.get("cpusubtype") == subtype:
                    return i
            return None

        def entry_by_type(cputype: int) -> int | None:
            if not fat:
                return None
            for i, a in sorted(archs.items()):
                if a["cputype"] == cputype:
                    value = (
                        int(a["offset"] + files.get(i, {}).get("entry_point", UNDEFINED)) & MASK64
                    )
                    return None if value == UNDEFINED else value
            return None

        def entry_by_subtype(cputype: int, subtype: int) -> int | None:
            if not fat:
                return None
            for i, a in sorted(archs.items()):
                if a["cputype"] == cputype and a["cpusubtype"] == subtype:
                    entry = files.get(i, {}).get("entry_point")
                    return None if entry is None else int(a["offset"] + entry) & MASK64
            return None

        out["file_index_for_arch"] = (index_by_type, index_by_subtype)
        out["entry_point_for_arch"] = (entry_by_type, entry_by_subtype)


__all__ = ["Macho"]
