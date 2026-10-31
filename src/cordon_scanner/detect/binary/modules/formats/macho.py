"""The Mach-O reader for cordon-rule: the `macho` module's values as a condition sees them.

An object is read from its magic (32- or 64-bit, either byte order) through its header and load
commands: each command is read within its own declared size, the segments with their sections, the entry
point from LC_MAIN's offset or from the program counter in LC_UNIXTHREAD's thread state mapped to a file
offset through the segment that holds it. A fat file lists its architectures and reads each contained
object, in place, into `file[i]`. Every structure is a Layout; the Cursor carries the byte order, chosen
from the magic; nothing is copied out of the file.

The names and the values a rule reads are the reference's (YARA's `macho` module), and so is the one
quirk rules depend on: `magic` is the first four bytes read big-endian, so a little-endian x86-64 object
reports MH_CIGAM_64. Where the reference's reading is an implementation accident rather than the format,
this reader reads the format and the difference is named here and pinned in its tests: a segment command
shorter than its structure is neither read nor counted (the reference reads the structure from the
following bytes); the thread command's size is read in the file's byte order (the reference reads it in
the host's); a fat entry is read as an object only when it carries an object magic, and a 32-bit object
needs only its 28-byte header; an object with no entry point leaves `entry_point_for_arch` undefined
for its architecture (the reference adds its undefined marker to the offset). A file that is neither an
object nor a fat file answers undefined for everything but the constants.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.formats.macho_tables import MachoTables
from cordon_scanner.detect.binary.modules.layout import U32, U64, Blob, Cursor, Layout
from cordon_scanner.detect.binary.modules.values import Call, Record, Scalar, Seq, Sig

INT, TEXT = Scalar.INT, Scalar.TEXT
T = MachoTables.MACHO


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
    THREAD: ClassVar[Layout] = Layout(
        (("cmd", U32), ("cmdsize", U32), ("flavor", U32), ("count", U32))
    )
    FAT_ARCH32: ClassVar[Layout] = Layout(
        (("cputype", U32), ("cpusubtype", U32), ("offset", U32), ("size", U32), ("align", U32))
    )
    FAT_ARCH64: ClassVar[Layout] = Layout((
        ("cputype", U32), ("cpusubtype", U32), ("offset", U64), ("size", U64), ("align", U32),
        ("reserved", U32),
    ))  # fmt: skip

    PROGRAM_COUNTER: ClassVar[dict[int, tuple[int, int, int]]] = {
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
    """Per CPU type, the thread state LC_UNIXTHREAD carries: its size, where its program counter is and
    how wide (m68k pc, m88k xip, SPARC pc, PowerPC srr0, x86 eip, ARM pc, x86-64 rip, ARM64 pc,
    PowerPC64 srr0), per the kernel's packed thread-state structures."""


class Macho:
    """The `macho` module reader."""

    OBJECT_MAGICS: ClassVar[frozenset[int]] = frozenset(
        {T["MH_MAGIC"], T["MH_CIGAM"], T["MH_MAGIC_64"], T["MH_CIGAM_64"]}
    )
    FAT_MAGICS: ClassVar[frozenset[int]] = frozenset(
        {T["FAT_MAGIC"], T["FAT_CIGAM"], T["FAT_MAGIC_64"], T["FAT_CIGAM_64"]}
    )
    BIG_ENDIAN: ClassVar[frozenset[int]] = frozenset({T["MH_MAGIC"], T["MH_MAGIC_64"]})
    """Magics, read big-endian, of the objects whose fields are big-endian: the bytes spell the magic in
    the file's own order, so MH_MAGIC read big-endian means a big-endian file."""
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
        for name in Macho.ARRAYS:  # the declared arrays are present, empty when nothing fills them
            out[name] = {}
        magic = Cursor(file, big_endian=True).uint(0, 4)
        if magic in Macho.OBJECT_MAGICS:
            Macho._object(out, file, 0, len(file))
        elif magic in Macho.FAT_MAGICS:
            Macho._fat(out, file)
        Macho._functions(out)
        return out

    @staticmethod
    def _object(out: dict[str, Any], data: bytes, base: int, end: int) -> None:
        """One object's header, segments and entry point, from the object magic at `base` to `end`."""
        magic = Cursor(data, big_endian=True).uint(base, 4)  # the magic is always read big-endian
        cur = Cursor(data, big_endian=magic in Macho.BIG_ENDIAN)
        header_size = 28 if magic in Macho.THIN else 32
        if end - base < header_size:
            return
        h = Shape.HEADER.read(cur, base)
        out.update(
            magic=magic, cputype=h["cputype"], cpusubtype=h["cpusubtype"], filetype=h["filetype"],
            ncmds=h["ncmds"], sizeofcmds=h["sizeofcmds"], flags=h["flags"],
        )  # fmt: skip
        if magic not in Macho.THIN:
            out["reserved"] = h["reserved"]
        segments: dict[int, Any] = {}
        later: list[tuple[int, int, int]] = []
        for cmd, at, size in Macho._commands(cur, base + header_size, end, h["ncmds"]):
            if cmd in (MachoTables.LC_SEGMENT, MachoTables.LC_SEGMENT_64):
                segment = Macho._segment(cur, at, size, is64=cmd == MachoTables.LC_SEGMENT_64)
                if segment is not None:
                    segments[len(segments)] = segment
            elif cmd in (MachoTables.LC_UNIXTHREAD, MachoTables.LC_MAIN):
                later.append((cmd, at, size))
        out["number_of_segments"] = len(segments)
        out["segments"] = segments
        for (
            cmd,
            at,
            size,
        ) in later:  # the entry point maps through the segments, so it is read after them
            if cmd == MachoTables.LC_MAIN:
                Macho._main(out, cur, at, size)
            else:
                Macho._unixthread(out, cur, at, size, segments)

    @staticmethod
    def _commands(cur: Cursor, at: int, end: int, ncmds: int) -> Iterator[tuple[int, int, int]]:
        """`(cmd, offset, cmdsize)` for each load command: `ncmds` of them from `at`, each within `end`,
        the walk ending at one that is shorter than its own header or runs past `end`."""
        for _ in range(ncmds):
            if at + Shape.COMMAND.stride() > end:
                return
            c = Shape.COMMAND.read(cur, at)
            size = c["cmdsize"]
            if size < Shape.COMMAND.stride() or at + size > end:
                return
            yield c["cmd"], at, size
            at += size

    @staticmethod
    def _name(blob: bytes) -> bytes:
        """A 16-byte name field: up to its first NUL."""
        return blob.split(b"\x00", 1)[0]

    @staticmethod
    def _segment(cur: Cursor, at: int, size: int, *, is64: bool) -> dict[str, Any] | None:
        """A segment command and the sections that fit within its size; None for a command too short to
        hold a segment (the reference reads one from whatever follows)."""
        layout = Shape.SEGMENT64 if is64 else Shape.SEGMENT32
        if size < layout.stride():
            return None
        sg = layout.read(cur, at)
        seg: dict[str, Any] = {
            "segname": Macho._name(sg["segname"]), "vmaddr": sg["vmaddr"], "vmsize": sg["vmsize"],
            "fileoff": sg["fileoff"], "fsize": sg["filesize"], "maxprot": sg["maxprot"],
            "initprot": sg["initprot"], "nsects": sg["nsects"], "flags": sg["flags"],
        }  # fmt: skip
        sec_layout = Shape.SECTION64 if is64 else Shape.SECTION32
        stride = sec_layout.stride()
        room = (size - layout.stride()) // stride
        sections: dict[int, Any] = {}
        for j in range(min(sg["nsects"], room)):
            sec = sec_layout.read(cur, at + layout.stride() + j * stride)
            sections[j] = {
                "sectname": Macho._name(sec["sectname"]), "segname": Macho._name(sec["segname"]),
                **{k: v for k, v in sec.items() if k not in ("sectname", "segname")},
            }  # fmt: skip
        seg["sections"] = sections
        return seg

    @staticmethod
    def _main(out: dict[str, Any], cur: Cursor, at: int, size: int) -> None:
        if size < Shape.ENTRY_POINT.stride():
            return
        e = Shape.ENTRY_POINT.read(cur, at)
        out["entry_point"] = e["entryoff"]
        out["stack_size"] = e["stacksize"]

    @staticmethod
    def _unixthread(
        out: dict[str, Any], cur: Cursor, at: int, size: int, segments: dict[int, Any]
    ) -> None:
        """The entry point from the thread state's program counter, as a file offset through the segment
        that holds it; unset when the state does not fit the command or no segment holds the address."""
        spec = Shape.PROGRAM_COUNTER.get(out["cputype"])
        if spec is None:
            return
        state_size, pc_at, width = spec
        head = Shape.THREAD.stride()
        if size - head < state_size:
            return
        address = cur.uint(at + head + pc_at, width)
        for seg in segments.values():
            if seg["vmaddr"] <= address < seg["vmaddr"] + seg["vmsize"]:
                out["entry_point"] = seg["fileoff"] + (address - seg["vmaddr"])
                return

    @staticmethod
    def _fat(out: dict[str, Any], data: bytes) -> None:
        """A fat file's header, its architectures, and each contained object as `file[i]`: an entry
        pointing past the end, or at bytes that are not an object, lists its architecture and no object."""
        n = len(data)
        big = Cursor(data, big_endian=True)  # fat headers are big-endian throughout
        magic = big.uint(0, 4)
        layout = Shape.FAT_ARCH32 if magic == T["FAT_MAGIC"] else Shape.FAT_ARCH64
        if n < 8:
            return
        out["fat_magic"] = magic
        count = big.uint(4, 4)
        out["nfat_arch"] = count
        if n < 8 + count * layout.stride():
            return
        archs: dict[int, Any] = {}
        files: dict[int, Any] = {}
        for i in range(count):
            a = layout.read(big, 8 + i * layout.stride())
            archs[i] = {k: a[k] for k in ("cputype", "cpusubtype", "offset", "size", "align")}
            end = a["offset"] + a["size"]
            if n < end:
                continue
            entry: dict[str, Any] = {"segments": {}}
            if big.uint(a["offset"], 4) in Macho.OBJECT_MAGICS:
                Macho._object(entry, data, a["offset"], end)
            files[i] = entry
        out["fat_arch"] = archs
        out["file"] = files

    @staticmethod
    def _functions(out: dict[str, Any]) -> None:
        """file_index_for_arch and entry_point_for_arch over the architectures read: undefined on a file
        that is not fat, for an architecture it lacks, or for one whose object has no entry point."""
        archs: dict[int, Any] = out["fat_arch"]
        files: dict[int, Any] = out["file"]
        fat = "nfat_arch" in out

        def index(cputype: int, subtype: int | None = None) -> int | None:
            if not fat:
                return None
            for i, f in sorted(files.items()):
                if f.get("cputype") == cputype and (
                    subtype is None or f.get("cpusubtype") == subtype
                ):
                    return i
            return None

        def entry(cputype: int, subtype: int | None = None) -> int | None:
            if not fat:
                return None
            for i, a in sorted(archs.items()):
                if a["cputype"] == cputype and (subtype is None or a["cpusubtype"] == subtype):
                    offset = files.get(i, {}).get("entry_point")
                    return None if offset is None else int(a["offset"] + offset)
            return None

        out["file_index_for_arch"] = (index, index)
        out["entry_point_for_arch"] = (entry, entry)


__all__ = ["Macho"]
