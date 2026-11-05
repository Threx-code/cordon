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

The one `macho` name also answers YARA-X's shape, a superset read from the same commands under the
names YARA-X declares: `segments[].filesize` beside `fsize` (one value, two names); `dylibs[]`
(name, timestamp, compatibility_version, current_version as "a.b.c"), `rpaths[]`, `dynamic_linker`,
`source_version` ("a.b.c.d.e"), `uuid` (upper-case hex with dashes), `build_version` (platform, minos,
sdk, ntools, tools[].{tool, version}), `min_version` (device, version, sdk), `linker_options[]`; the
functions has_dylib and has_rpath (ASCII case folded, over the file and every architecture) and
dylib_hash (MD5 of the sorted distinct lower-cased names, joined by commas). Named differences from
YARA-X's reading: a name is read at the offset its command states (YARA-X takes the bytes right after
the fixed fields); a UUID is all sixteen bytes (YARA-X drops trailing zero bytes); linker options are
split at NUL as the format says (YARA-X splits at spaces).
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.formats.macho_tables import MachoTables
from cordon_scanner.detect.binary.modules.formats.macho_x import MachoX
from cordon_scanner.detect.binary.modules.layout import ABSENT, U32, U64, Blob, Cursor, Layout
from cordon_scanner.detect.binary.modules.values import Call, Record, Scalar, Seq, Sig

INT, TEXT, BOOL = Scalar.INT, Scalar.TEXT, Scalar.BOOL
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
    DYLIB: ClassVar[Layout] = Layout((
        ("cmd", U32), ("cmdsize", U32), ("offset", U32), ("timestamp", U32), ("current_version", U32),
        ("compatibility_version", U32),
    ))  # fmt: skip
    NAMED: ClassVar[Layout] = Layout((("cmd", U32), ("cmdsize", U32), ("offset", U32)))
    """LC_RPATH, LC_LOAD_DYLINKER and their kin: one string at an offset from the command's start."""
    UUID: ClassVar[Layout] = Layout((("cmd", U32), ("cmdsize", U32), ("uuid", Blob(16))))
    SOURCE_VERSION: ClassVar[Layout] = Layout((("cmd", U32), ("cmdsize", U32), ("version", U64)))
    BUILD_VERSION: ClassVar[Layout] = Layout((
        ("cmd", U32), ("cmdsize", U32), ("platform", U32), ("minos", U32), ("sdk", U32), ("ntools", U32),
    ))  # fmt: skip
    TOOL: ClassVar[Layout] = Layout((("tool", U32), ("version", U32)))
    MIN_VERSION: ClassVar[Layout] = Layout(
        (("cmd", U32), ("cmdsize", U32), ("version", U32), ("sdk", U32))
    )
    LINKER_OPTION: ClassVar[Layout] = Layout((("cmd", U32), ("cmdsize", U32), ("count", U32)))

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
    DYLIB_COMMANDS: ClassVar[frozenset[int]] = frozenset(
        {0x0C, 0x0D, 0x18 | 0x80000000, 0x1F | 0x80000000, 0x20, 0x23 | 0x80000000}
    )
    """LC_LOAD_DYLIB, LC_ID_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB,
    LC_LOAD_UPWARD_DYLIB: each names a library."""
    DYLINKER_COMMANDS: ClassVar[frozenset[int]] = frozenset({0x0E, 0x0F, 0x27})
    MIN_VERSION_COMMANDS: ClassVar[frozenset[int]] = frozenset({0x24, 0x25, 0x2F, 0x30})
    """LC_VERSION_MIN_MACOSX, _IPHONEOS, _TVOS, _WATCHOS: the command is the device."""
    LC_RPATH: ClassVar[int] = 0x1C | 0x80000000
    LC_UUID: ClassVar[int] = 0x1B
    LC_SOURCE_VERSION: ClassVar[int] = 0x2A
    LC_BUILD_VERSION: ClassVar[int] = 0x32
    LC_LINKER_OPTION: ClassVar[int] = 0x2D

    SECTION: ClassVar[Record] = Record({
        "sectname": TEXT, "segname": TEXT, "addr": INT, "size": INT, "offset": INT, "align": INT,
        "reloff": INT, "nreloc": INT, "flags": INT, "reserved1": INT, "reserved2": INT,
        "reserved3": INT,
    })  # fmt: skip
    SEGMENT: ClassVar[Record] = Record({
        "segname": TEXT, "vmaddr": INT, "vmsize": INT, "fileoff": INT, "fsize": INT, "filesize": INT,
        "maxprot": INT, "initprot": INT, "nsects": INT, "flags": INT, "sections": Seq(SECTION),
    })  # fmt: skip
    VERSIONS: ClassVar[dict[str, Any]] = {
        "build_version": Record({
            "platform": INT, "minos": TEXT, "sdk": TEXT, "ntools": INT,
            "tools": Seq(Record({"tool": INT, "version": TEXT})),
        }),
        "min_version": Record({"device": INT, "version": TEXT, "sdk": TEXT}),
    }  # fmt: skip
    OBJECT: ClassVar[dict[str, Any]] = {
        **dict.fromkeys(
            ("magic", "cputype", "cpusubtype", "filetype", "ncmds", "sizeofcmds", "flags", "reserved"),
            INT,
        ),
        "number_of_segments": INT, "segments": Seq(SEGMENT), "entry_point": INT, "stack_size": INT,
        "dylibs": Seq(Record({
            "name": TEXT, "timestamp": INT, "compatibility_version": TEXT, "current_version": TEXT
        })),
        "rpaths": Seq(TEXT), "dynamic_linker": TEXT, "source_version": TEXT, "uuid": TEXT,
        "linker_options": Seq(TEXT), **VERSIONS, **MachoX.FIELDS,
    }  # fmt: skip
    """One object's fields: the file's own, and each `file[i]` of a fat file."""
    SCHEMA: ClassVar[Record] = Record({
        **dict.fromkeys(T, INT),
        **OBJECT,
        "fat_magic": INT, "nfat_arch": INT,
        "fat_arch": Seq(Record(dict.fromkeys(
            ("cputype", "cpusubtype", "offset", "size", "align", "reserved"), INT
        ))),
        "file": Seq(Record(OBJECT)),
        "file_index_for_arch": Call(Sig(("int",), INT), Sig(("int", "int"), INT)),
        "entry_point_for_arch": Call(Sig(("int",), INT), Sig(("int", "int"), INT)),
        "has_dylib": Call(Sig(("text",), BOOL)), "has_rpath": Call(Sig(("text",), BOOL)),
        "dylib_hash": Call(Sig((), TEXT)), **MachoX.FUNCTIONS,
    })  # fmt: skip

    ARRAYS: ClassVar[tuple[str, ...]] = (
        "segments", "fat_arch", "file", "dylibs", "rpaths", "linker_options", *MachoX.ARRAYS
    )  # fmt: skip
    OBJECT_ARRAYS: ClassVar[tuple[str, ...]] = (
        "segments", "dylibs", "rpaths", "linker_options", *MachoX.ARRAYS
    )  # fmt: skip

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
        linkedit: list[tuple[int, int, int]] = []
        for name in Macho.OBJECT_ARRAYS:
            out.setdefault(name, {})
        for cmd, at, size in Macho._commands(cur, base + header_size, end, h["ncmds"]):
            if cmd in (MachoTables.LC_SEGMENT, MachoTables.LC_SEGMENT_64):
                segment = Macho._segment(cur, at, size, is64=cmd == MachoTables.LC_SEGMENT_64)
                if segment is not None:
                    segments[len(segments)] = segment
            elif cmd in (MachoTables.LC_UNIXTHREAD, MachoTables.LC_MAIN):
                later.append((cmd, at, size))
            elif cmd in MachoX.COMMANDS:
                linkedit.append((cmd, at, size))
            else:
                Macho._named(out, cur, cmd, at, size)
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
        MachoX.fill(out, cur, base, end, linkedit, is64=magic not in Macho.THIN)

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
            "fileoff": sg["fileoff"], "fsize": sg["filesize"], "filesize": sg["filesize"],
            "maxprot": sg["maxprot"], "initprot": sg["initprot"], "nsects": sg["nsects"],
            "flags": sg["flags"],
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
    def _string_at(cur: Cursor, at: int, size: int, offset: int) -> bytes | None:
        """The NUL-terminated string a command keeps at `offset` from its start, within its size."""
        if offset < 0 or offset >= size:
            return None
        text = cur.blob(at + offset, size - offset)
        return None if text is ABSENT else text.split(b"\x00", 1)[0]

    @staticmethod
    def _version(value: int) -> bytes:
        """A packed version `xxxx.yy.zz` as "x.y.z"."""
        return f"{value >> 16}.{(value >> 8) & 0xFF}.{value & 0xFF}".encode()

    @staticmethod
    def _named(out: dict[str, Any], cur: Cursor, cmd: int, at: int, size: int) -> None:
        """The commands that name things: libraries, run paths, the dynamic linker, the UUID, the
        source and build and minimum versions, the linker options; each read within its command."""
        if cmd in Macho.DYLIB_COMMANDS and size >= Shape.DYLIB.stride():
            d = Shape.DYLIB.read(cur, at)
            name = Macho._string_at(cur, at, size, d["offset"])
            if name is not None:
                out["dylibs"][len(out["dylibs"])] = {
                    "name": name, "timestamp": d["timestamp"],
                    "compatibility_version": Macho._version(d["compatibility_version"]),
                    "current_version": Macho._version(d["current_version"]),
                }  # fmt: skip
        elif cmd in Macho.DYLINKER_COMMANDS or cmd == Macho.LC_RPATH:
            if size < Shape.NAMED.stride():
                return
            text = Macho._string_at(cur, at, size, Shape.NAMED.read(cur, at)["offset"])
            if text is None:
                return
            if cmd == Macho.LC_RPATH:
                out["rpaths"][len(out["rpaths"])] = text
            else:
                out["dynamic_linker"] = text
        elif cmd == Macho.LC_UUID and size >= Shape.UUID.stride():
            raw = Shape.UUID.read(cur, at)["uuid"].hex().upper()
            out["uuid"] = "-".join((raw[:8], raw[8:12], raw[12:16], raw[16:20], raw[20:])).encode()
        elif cmd == Macho.LC_SOURCE_VERSION and size >= Shape.SOURCE_VERSION.stride():
            v = Shape.SOURCE_VERSION.read(cur, at)["version"]
            parts = (v >> 40, (v >> 30) & 0x3F, (v >> 20) & 0x3F, (v >> 10) & 0x3F, v & 0x3F)
            out["source_version"] = ".".join(str(p) for p in parts).encode()
        elif cmd == Macho.LC_BUILD_VERSION and size >= Shape.BUILD_VERSION.stride():
            b = Shape.BUILD_VERSION.read(cur, at)
            room = (size - Shape.BUILD_VERSION.stride()) // Shape.TOOL.stride()
            tools = {}
            for i in range(min(b["ntools"], room)):
                t = Shape.TOOL.read(
                    cur, at + Shape.BUILD_VERSION.stride() + i * Shape.TOOL.stride()
                )
                tools[i] = {
                    "tool": t["tool"],
                    "version": f"{t['version'] >> 16}.{(t['version'] >> 8) & 0xFF}".encode(),
                }
            out["build_version"] = {
                "platform": b["platform"], "minos": Macho._version(b["minos"]),
                "sdk": Macho._version(b["sdk"]), "ntools": len(tools), "tools": tools,
            }  # fmt: skip
        elif cmd in Macho.MIN_VERSION_COMMANDS and size >= Shape.MIN_VERSION.stride():
            m = Shape.MIN_VERSION.read(cur, at)
            out["min_version"] = {
                "device": cmd, "version": Macho._version(m["version"]), "sdk": Macho._version(m["sdk"])
            }  # fmt: skip
        elif cmd == Macho.LC_LINKER_OPTION and size >= Shape.LINKER_OPTION.stride():
            count = Shape.LINKER_OPTION.read(cur, at)["count"]
            rest = cur.blob(at + Shape.LINKER_OPTION.stride(), size - Shape.LINKER_OPTION.stride())
            for option in rest.split(b"\x00")[:count]:
                out["linker_options"][len(out["linker_options"])] = option

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
            archs[i]["reserved"] = a.get("reserved", 0)  # YARA-X's name; zero for a 32-bit entry
            end = a["offset"] + a["size"]
            if n < end:
                continue
            entry: dict[str, Any] = {name: {} for name in Macho.OBJECT_ARRAYS}
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
        Macho._library_functions(out)
        MachoX._functions(out)

    @staticmethod
    def _library_functions(out: dict[str, Any]) -> None:
        """has_dylib, has_rpath (ASCII case folded, over the file and every architecture) and
        dylib_hash (MD5 of the file's, else the first architecture's, distinct lower-cased names
        sorted and joined by commas; undefined without any)."""
        files: dict[int, Any] = out["file"]
        everywhere = [out, *files.values()]

        def has(key: str, field: str | None) -> Any:
            def holds(wanted: bytes) -> bool:
                target = wanted.lower()
                for place in everywhere:
                    for item in place.get(key, {}).values():
                        value = item[field] if field else item
                        if value.lower() == target:
                            return True
                return False

            return holds

        def dylib_hash() -> bytes | None:
            dylibs = out["dylibs"] or (files[0]["dylibs"] if 0 in files else {})
            names = sorted({d["name"].strip().lower() for d in dylibs.values()})
            return hashlib.md5(b",".join(names)).hexdigest().encode() if names else None  # noqa: S324

        out["has_dylib"] = (has("dylibs", "name"),)
        out["has_rpath"] = (has("rpaths", None),)
        out["dylib_hash"] = (dylib_hash,)


__all__ = ["Macho"]
