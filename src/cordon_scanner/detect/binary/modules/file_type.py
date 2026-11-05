"""cordon-rule's `magic` module: what kind of file this is, in libmagic's words.

`magic.type()` and `magic.mime_type()` answer as the reference engines do (both call libmagic), but
the answer is our own: the formats are read from their headers here (through `layout.Cursor`, like
every other module), and the description is assembled from what was read. libmagic's database is not
carried; it is the benchmark. Each part of a description below names the header field it comes from,
and the words are the ones libmagic gives for that value on the benchmark files (the R10 magic run).

    ELF  "ELF <32|64>-bit <LSB|MSB> <type>, <machine>[<flags>], version <EI_VERSION> (<OS ABI>)"
    PE   "PE32[+] executable[ (DLL)] (<subsystem>) <machine>[ Mono/.Net assembly]
          [ (stripped to external PDB)], for MS Windows[, <packer>], <n> sections"
    MZ   "MS-DOS executable[, <variant>]"

A file of a kind not read here answers "data" and "application/octet-stream", as libmagic does for
bytes it does not recognise; the kinds it does recognise and this does not are the measured gap.
"""

from __future__ import annotations

from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.layout import ABSENT, Cursor
from cordon_scanner.detect.binary.modules.values import Call, Module, Record, Scalar, Sig

TEXT = Scalar.TEXT
UNKNOWN = ("data", "application/octet-stream")


class ElfNames:
    """The words for an ELF header's fields (machine numbers from the ELF gABI)."""

    TYPES: ClassVar[dict[int, str]] = {
        1: "relocatable", 2: "executable", 3: "shared object", 4: "core file",
    }  # fmt: skip
    MIME: ClassVar[dict[int, str]] = {
        1: "application/x-object", 2: "application/x-executable",
        3: "application/x-sharedlib", 4: "application/x-coredump",
    }  # fmt: skip
    MACHINES: ClassVar[dict[int, str]] = {
        0: "no machine", 2: "SPARC", 3: "Intel 80386", 8: "MIPS", 18: "SPARC32PLUS",
        20: "PowerPC or cisco 4500", 21: "64-bit PowerPC or cisco 7500", 22: "IBM S/390",
        40: "ARM", 42: "Renesas SH", 43: "SPARC V9", 62: "x86-64", 183: "ARM aarch64",
        243: "UCB RISC-V", 247: "eBPF", 258: "LoongArch",
    }  # fmt: skip
    OS_ABI: ClassVar[dict[int, str]] = {
        0: "SYSV", 1: "HP-UX", 2: "NetBSD", 3: "GNU/Linux", 6: "Solaris", 9: "FreeBSD",
        12: "OpenBSD",
    }  # fmt: skip


class Elf:
    """An ELF header in libmagic's words."""

    @staticmethod
    def describe(file: bytes) -> tuple[str, str]:
        width = {1: 32, 2: 64}.get(file[4]) if len(file) > 4 else None
        order = {1: "LSB", 2: "MSB"}.get(file[5]) if len(file) > 5 else None
        if order is None:
            return UNKNOWN
        head = f"ELF {width}-bit {order}" if width else f"ELF {order}"
        cur = Cursor(file, big_endian=order == "MSB")
        kind, machine = cur.uint(16, 2), cur.uint(18, 2)
        flags = cur.uint(36 if width == 32 else 48, 4)
        if width is None or kind is ABSENT or machine is ABSENT or kind not in ElfNames.TYPES:
            return head, "application/octet-stream"
        version, abi = file[6], ElfNames.OS_ABI.get(file[7], f"unknown OS ABI {file[7]}")
        name = ElfNames.MACHINES.get(machine)
        arch = f"*unknown arch {machine:#x}*" if name is None else name
        extra, glue = Elf._flags(machine, 0 if flags is ABSENT else flags, width)
        sep = " " if name is None else glue
        text = f"{head} {ElfNames.TYPES[kind]}, {arch}{extra}{sep}version {version} ({abi})"
        return text, ElfNames.MIME[kind]

    @staticmethod
    def _flags(machine: int, flags: int, width: int) -> tuple[str, str]:
        """What the machine's e_flags add, and what comes before "version": libmagic writes a
        flag that names an ABI version straight before it (", EABI5 version 1")."""
        if machine == 40 and flags >> 24:
            return f", EABI{flags >> 24}", " "
        if machine == 21:
            abi = {
                0: "Unspecified or Power ELF V1 ABI",
                1: "Power ELF V1 ABI",
                2: "OpenPOWER ELF V2 ABI",
            }
            return f", {abi.get(flags & 3, 'unknown ABI')}", ", "
        if machine == 243:
            parts = ["RVC"] if flags & 1 else []
            parts.append(
                {
                    0: "soft-float ABI",
                    2: "single-float ABI",
                    4: "double-float ABI",
                    6: "quad-float ABI",
                }[flags & 6]
            )
            return "".join(f", {p}" for p in parts), ", "
        if machine == 8:
            arch = {0: "MIPS-I", 1: "MIPS-II", 2: "MIPS-III", 3: "MIPS-IV", 4: "MIPS-V",
                    5: "MIPS32", 6: "MIPS64", 7: "MIPS32 rel2", 8: "MIPS64 rel2",
                    9: "MIPS32 rel6", 10: "MIPS64 rel6"}.get(flags >> 28)  # fmt: skip
            return (f", {arch}", " ") if arch else ("", ", ")
        if machine == 18:
            words = [w for bit, w in ((0x100, "V8+ Required"), (0x200, "Sun UltraSPARC1 Extensions Required"), (0x400, "HaL R1 Extensions Required"), (0x800, "Sun UltraSPARC3 Extensions Required")) if flags & bit]  # fmt: skip
            words.append(
                {
                    0: "total store ordering",
                    1: "partial store ordering",
                    2: "relaxed memory ordering",
                }.get(flags & 3, "unknown memory ordering")
            )
            return "".join(f", {w}" for w in words), ", "
        return "", ", "


class PeNames:
    """The words for a PE header's fields (Microsoft's PE format)."""

    MACHINES: ClassVar[dict[int, str]] = {
        0x14C: "Intel 80386", 0x166: "MIPS R4000", 0x1C0: "ARM", 0x1C2: "ARM Thumb",
        0x1C4: "ARMv7 Thumb", 0x200: "Intel Itanium", 0x8664: "x86-64", 0xAA64: "Aarch64",
    }  # fmt: skip
    SUBSYSTEMS: ClassVar[dict[int, str]] = {
        1: "native", 2: "GUI", 3: "console", 5: "OS/2", 7: "POSIX", 9: "Windows CE",
        10: "EFI application", 11: "EFI boot service driver", 12: "EFI runtime driver",
        13: "EFI ROM", 14: "XBOX", 16: "boot application",
    }  # fmt: skip


class Pe:
    """A PE (or a plain MS-DOS) executable in libmagic's words."""

    @staticmethod
    def describe(file: bytes) -> tuple[str, str]:
        cur = Cursor(file)
        at = cur.uint(0x3C, 4)
        if at is ABSENT or cur.blob(at, 4) != b"PE\x00\x00":
            return Pe._dos(cur, at)
        machine, sections, characteristics = (
            cur.uint(at + 4, 2),
            cur.uint(at + 6, 2),
            cur.uint(at + 22, 2),
        )
        opt = at + 24
        magic = cur.uint(opt, 2)
        if ABSENT in (machine, sections, characteristics) or magic not in (0x10B, 0x20B):
            return "MS-DOS executable", "application/octet-stream"
        plus = magic == 0x20B
        subsystem = cur.uint(opt + 68, 2)
        words = ["PE32+" if plus else "PE32", "executable"]
        if characteristics & 0x2000:
            words.append("(DLL)")
        sub = PeNames.SUBSYSTEMS.get(subsystem) if subsystem is not ABSENT else None
        words.append(f"({sub})" if sub else f"(Unknown subsystem {subsystem})")
        # a machine libmagic has no name for (a .NET ReadyToRun image's OS-xored one) is left out
        name = PeNames.MACHINES.get(machine)
        if name:
            words.append(name)
        if Pe._clr(cur, opt, plus):
            words.append("Mono/.Net assembly")
        if characteristics & 0x200:
            words.append("(stripped to external PDB)")
        text = " ".join(words) + ", for MS Windows"
        text += "".join(f", {p}" for p in Pe._packers(file, cur, at))
        table = opt + (cur.uint(at + 20, 2) or 0)
        if cur.fits(table, 40):  # the count is given only when the section table is in the file
            text += f", {sections} sections"
        return text, "application/vnd.microsoft.portable-executable"

    @staticmethod
    def _clr(cur: Cursor, opt: int, plus: bool) -> bool:
        """Whether the CLR (.NET) data directory, the 15th, is present."""
        directories = opt + (112 if plus else 96)
        count = cur.uint(opt + (108 if plus else 92), 4)
        if count is ABSENT or count < 15:
            return False
        size = cur.uint(directories + 14 * 8 + 4, 4)
        return size is not ABSENT and size > 0

    @staticmethod
    def _packers(file: bytes, cur: Cursor, at: int) -> list[str]:
        """What libmagic notes a packer or installer by: "UPX0" where a PE32 image's first section
        name sits (0xF8 past the PE signature; libmagic looks only there, so a PE32+ image, whose
        table starts later, is never called UPX compressed), and Nullsoft's installer signature."""
        found = []
        if cur.blob(at + 0xF8, 4) == b"UPX0":
            found.append("UPX compressed")
        if b"\xef\xbe\xad\xdeNullsoftInst" in file:
            found.append("Nullsoft Installer self-extracting archive")
        return found

    NE_OS: ClassVar[dict[int, str]] = {
        1: "OS/2", 2: "Windows", 3: "European MS-DOS 4.x", 4: "Windows 386",
        5: "Borland Operating System Services",
    }  # fmt: skip

    @staticmethod
    def _dos(cur: Cursor, at: Any) -> tuple[str, str]:
        """An MZ file with no PE header: a 16-bit NE executable where `e_lfanew` names one."""
        if at is not ABSENT and cur.blob(at, 2) == b"NE":
            target, flags = cur.uint(at + 0x36, 1), cur.uint(at + 0x0C, 2)
            major, minor = cur.uint(at + 0x3F, 1), cur.uint(at + 0x3E, 1)
            if ABSENT not in (target, flags, major, minor):
                os_name = Pe.NE_OS.get(target, f"unknown OS {target:#x}")
                kind = "DLL or font" if flags & 0x8000 else "EXE"
                text = f"MS-DOS executable, NE for {os_name} ({major}.{minor}) ({kind})"
                return text, "application/x-ms-ne-executable"
        return "MS-DOS executable", "application/octet-stream"


class FileType:
    """The module: `type()` and `mime_type()`, read once per file."""

    SCHEMA: ClassVar[Record] = Record(
        {"type": Call(Sig((), TEXT)), "mime_type": Call(Sig((), TEXT))}
    )

    @staticmethod
    def describe(file: bytes) -> tuple[str, str]:
        if file[:4] == b"\x7fELF":
            return Elf.describe(file)
        if file[:2] == b"MZ":
            return Pe.describe(file)
        return UNKNOWN

    @staticmethod
    def data(file: bytes) -> dict[str, Any]:
        text, mime = FileType.describe(file)
        t, m = text.encode(), mime.encode()
        return {"type": (lambda: t,), "mime_type": (lambda: m,)}

    @staticmethod
    def module() -> Module:
        return Module(FileType.SCHEMA, FileType.data)


__all__ = ["Elf", "FileType", "Pe"]
