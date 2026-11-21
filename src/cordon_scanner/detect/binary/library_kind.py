"""Whether a native file is a library -- something a program loads -- and not a program a shell can start.

`SUSPECT.BINARY.EXECUTABLE_PATH.001` says an executable sits where a lifecycle step will run it. A shared
object, a DLL or a Mach-O bundle has no entry a lifecycle step starts: it is loaded by a program that asks
for it, and what it can do is read from its imports and strings by the rules that read them. A Python
extension module (`mod.cpython-311-x86_64-linux-gnu.so`) is one, in a package's `hooks/` or `scripts/`
directory because that is what its modules are called.

Read from the header alone, never by name:

```
  ELF       a shared object (e_type 3) with no interpreter (PT_INTERP), that is not marked a program
            (DF_1_PIE in DT_FLAGS_1) and that says it is a library: it defines dynamic symbols (what a
            program loading it can ask for) or names itself (DT_SONAME)
  PE        the DLL bit of the COFF characteristics
  Mach-O    the file type is a dylib or a bundle; a universal binary is a library when every slice is
```

A static position-independent executable (musl, Rust or Go `-static-pie`) is an ELF shared-object type with
no interpreter too, and it runs directly: it carries DF_1_PIE and defines nothing, so it is not excused. A
shared object that defines nothing and names nothing is not shown to be a library either.

A header that is cut short, malformed or of another kind is not a library: what cannot be read is not
excused.
"""

from __future__ import annotations

import struct
from typing import ClassVar, Final

_ELF_DYN: Final = 3
_PT_INTERP: Final = 3
_PT_DYNAMIC: Final = 2
_SHT_DYNSYM: Final = 11
_DT_SONAME: Final = 14
_DT_FLAGS_1: Final = 0x6FFFFFFB
_DF_1_PIE: Final = 0x08000000
_PE_DLL: Final = 0x2000
_MACH_O_LIBRARIES: Final = frozenset({6, 8, 9})  # MH_DYLIB, MH_BUNDLE, MH_DYLIB_STUB


class LibraryKind:
    """`of(raw)`: a native library, from the first bytes of the file."""

    MACH_O: ClassVar[dict[bytes, str]] = {
        b"\xcf\xfa\xed\xfe": "<",
        b"\xce\xfa\xed\xfe": "<",
        b"\xfe\xed\xfa\xcf": ">",
        b"\xfe\xed\xfa\xce": ">",
    }
    FAT: ClassVar[bytes] = b"\xca\xfe\xba\xbe"
    MAX_SLICES: ClassVar[int] = 8

    @staticmethod
    def of(raw: bytes) -> bool:
        if raw[:4] == b"\x7fELF":
            return LibraryKind._elf(raw)
        if raw[:2] == b"MZ":
            return LibraryKind._pe(raw)
        if raw[:4] == LibraryKind.FAT:
            return LibraryKind._fat(raw)
        return raw[:4] in LibraryKind.MACH_O and LibraryKind._mach_o(raw)

    @staticmethod
    def _elf(raw: bytes) -> bool:
        if len(raw) < 64 or raw[4] not in (1, 2) or raw[5] not in (1, 2):
            return False
        wide, order = raw[4] == 2, "<" if raw[5] == 1 else ">"
        if struct.unpack_from(order + "H", raw, 16)[0] != _ELF_DYN:
            return False
        headers = LibraryKind._program_headers(raw, wide, order)
        if headers is None or any(kind == _PT_INTERP for kind, _, _ in headers):
            return False  # unreadable, or a position-independent program asking for its interpreter
        dynamic = next(((at, size) for kind, at, size in headers if kind == _PT_DYNAMIC), None)
        flags, soname = LibraryKind._dynamic(raw, dynamic, wide, order)
        if flags & _DF_1_PIE:
            return False  # a static-PIE program: runs directly, defines nothing
        return soname or LibraryKind._defines_symbols(raw, wide, order)

    @staticmethod
    def _program_headers(raw: bytes, wide: bool, order: str) -> list[tuple[int, int, int]] | None:
        """(type, offset, size) of each program header, or None when the table is not all here."""
        if wide:
            offset = struct.unpack_from(order + "Q", raw, 32)[0]
            size, count = struct.unpack_from(order + "HH", raw, 54)
        else:
            offset = struct.unpack_from(order + "I", raw, 28)[0]
            size, count = struct.unpack_from(order + "HH", raw, 42)
        if not count or size < 32 or offset + size * count > len(raw):
            return None
        out = []
        for i in range(count):
            base = offset + size * i
            kind = struct.unpack_from(order + "I", raw, base)[0]
            if wide:
                at, filesz = (
                    struct.unpack_from(order + "Q", raw, base + 8)[0],
                    struct.unpack_from(order + "Q", raw, base + 32)[0],
                )
            else:
                at, filesz = (
                    struct.unpack_from(order + "I", raw, base + 4)[0],
                    struct.unpack_from(order + "I", raw, base + 16)[0],
                )
            out.append((kind, at, filesz))
        return out

    @staticmethod
    def _dynamic(
        raw: bytes, where: tuple[int, int] | None, wide: bool, order: str
    ) -> tuple[int, bool]:
        """(DT_FLAGS_1, whether DT_SONAME is present) from the dynamic section, (0, False) where it is not here."""
        if where is None:
            return 0, False
        at, size = where
        step, fmt = (16, order + "qQ") if wide else (8, order + "iI")
        flags, soname = 0, False
        for position in range(at, min(at + size, len(raw) - step + 1), step):
            tag, value = struct.unpack_from(fmt, raw, position)
            if tag == 0:
                break
            if tag == _DT_FLAGS_1:
                flags = value
            elif tag == _DT_SONAME:
                soname = True
        return flags, soname

    @staticmethod
    def _defines_symbols(raw: bytes, wide: bool, order: str) -> bool:
        """Whether the dynamic symbol table (`.dynsym`, from the section headers) defines a symbol: what a
        program that loads this file can ask it for. False where the sections are not all here."""
        if wide:
            offset = struct.unpack_from(order + "Q", raw, 40)[0]
            size, count = struct.unpack_from(order + "HH", raw, 58)
        else:
            offset = struct.unpack_from(order + "I", raw, 32)[0]
            size, count = struct.unpack_from(order + "HH", raw, 46)
        if not count or size < 40 or offset + size * count > len(raw):
            return False
        for i in range(count):
            base = offset + size * i
            if struct.unpack_from(order + "I", raw, base + 4)[0] != _SHT_DYNSYM:
                continue
            if wide:
                at, length = (
                    struct.unpack_from(order + "Q", raw, base + 24)[0],
                    struct.unpack_from(order + "Q", raw, base + 32)[0],
                )
                entry, shndx = 24, 6
            else:
                at, length = (
                    struct.unpack_from(order + "I", raw, base + 16)[0],
                    struct.unpack_from(order + "I", raw, base + 20)[0],
                )
                entry, shndx = 16, 14
            if at + length > len(raw):
                return False
            for symbol in range(1, length // entry):  # entry 0 is the null symbol
                if struct.unpack_from(order + "H", raw, at + entry * symbol + shndx)[0] != 0:
                    return True
        return False

    @staticmethod
    def _pe(raw: bytes) -> bool:
        if len(raw) < 0x40:
            return False
        start = struct.unpack_from("<I", raw, 0x3C)[0]
        if start + 24 > len(raw) or raw[start : start + 4] != b"PE\x00\x00":
            return False
        return bool(struct.unpack_from("<H", raw, start + 22)[0] & _PE_DLL)

    @staticmethod
    def _mach_o(raw: bytes) -> bool:
        if len(raw) < 16:
            return False
        order = LibraryKind.MACH_O[raw[:4]]
        return struct.unpack_from(order + "I", raw, 12)[0] in _MACH_O_LIBRARIES

    @staticmethod
    def _fat(raw: bytes) -> bool:
        """A universal binary: a library when it has slices and every one of them is."""
        if len(raw) < 8:
            return False
        count = struct.unpack_from(">I", raw, 4)[0]
        if not 0 < count <= LibraryKind.MAX_SLICES or 8 + 20 * count > len(raw):
            return False  # a Java class shares the magic: its next word is a version, not a count
        for i in range(count):
            offset = struct.unpack_from(">I", raw, 16 + 20 * i)[0]
            part = raw[offset : offset + 64]
            if part[:4] not in LibraryKind.MACH_O or not LibraryKind._mach_o(part):
                return False
        return True


__all__ = ["LibraryKind"]
