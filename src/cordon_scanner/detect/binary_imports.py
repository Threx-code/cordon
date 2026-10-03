"""What a compiled binary imports, read from its own import tables (G12).

Strings and packer signatures say what a binary was built with. Its imports say what it can do:
a program that imports `VirtualAllocEx`, `WriteProcessMemory` and `CreateRemoteThread` injects
code into other processes, whatever its strings say, and one that imports `CryptUnprotectData`
beside a socket reads the browser's saved passwords and sends them somewhere. Those calls are
resolved by the loader from a table in the file, so a stripped or string-encrypted payload still
has to name them -- unless it resolves everything at run time, which is itself a signal
(`dlopen` / `GetProcAddress` with almost nothing else imported).

Parsed with `struct` from the standard library, never by loading or running the file. The input is
attacker-controlled: every offset is bounds-checked, every count is capped, and a malformed table
yields what was read before it went wrong rather than an exception.
"""

from __future__ import annotations

import functools
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

MAX_SYMBOLS = 20_000
MAX_LIBRARIES = 512
MAX_NAME = 256
MAX_SECTIONS = 256
MAX_LOAD_COMMANDS = 4096


@dataclass(frozen=True, slots=True)
class ImportTable:
    """The libraries a binary links and the symbols it imports from them."""

    format: str
    libraries: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()


class _Reader:
    """Bounds-checked reads over attacker-controlled bytes."""

    def __init__(self, data: bytes, little: bool = True) -> None:
        self.data = data
        self.prefix = "<" if little else ">"

    def unpack(self, fmt: str, offset: int) -> tuple[int, ...]:
        size = struct.calcsize(self.prefix + fmt)
        if offset < 0 or offset + size > len(self.data):
            raise struct.error("out of bounds")
        return struct.unpack_from(self.prefix + fmt, self.data, offset)

    def cstring(self, offset: int) -> str:
        if offset < 0 or offset >= len(self.data):
            return ""
        end = self.data.find(b"\x00", offset, offset + MAX_NAME)
        raw = self.data[offset : end if end != -1 else offset + MAX_NAME]
        return raw.decode("ascii", "replace")


class ImportReader:
    """`ImportTable` from ELF, PE or Mach-O bytes, or None for anything else."""

    @classmethod
    def read(cls, data: bytes) -> ImportTable | None:
        try:
            if data[:4] == b"\x7fELF":
                return cls._elf(data)
            if data[:2] == b"MZ":
                return cls._pe(data)
            if data[:4] in (
                b"\xfe\xed\xfa\xce",
                b"\xfe\xed\xfa\xcf",
                b"\xce\xfa\xed\xfe",
                b"\xcf\xfa\xed\xfe",
            ):
                return cls._macho(data, 0)
            if data[:4] == b"\xca\xfe\xba\xbe":
                return cls._fat(data)
        except (struct.error, ValueError, IndexError):
            return None
        return None

    # -- ELF -------------------------------------------------------------------------------

    @staticmethod
    def _elf(data: bytes) -> ImportTable:
        wide = data[4] == 2
        r = _Reader(data, little=data[5] == 1)
        if wide:
            shoff = r.unpack("Q", 0x28)[0]
            shentsize, shnum = r.unpack("HH", 0x3A)
        else:
            shoff = r.unpack("I", 0x20)[0]
            shentsize, shnum = r.unpack("HH", 0x2E)
        sections = []
        for index in range(min(shnum, MAX_SECTIONS)):
            base = shoff + index * shentsize
            if wide:
                _name, kind, _flags, _addr, offset, size, link, _info, _align, entsize = r.unpack(
                    "IIQQQQIIQQ", base
                )
            else:
                _name, kind, _flags, _addr, offset, size, link, _info, _align, entsize = r.unpack(
                    "IIIIIIIIII", base
                )
            sections.append((kind, offset, size, link, entsize))
        symbols: list[str] = []
        libraries: list[str] = []
        for kind, offset, size, link, entsize in sections:
            if link >= len(sections):
                continue
            strtab = sections[link][1]
            if kind == 11 and entsize:  # SHT_DYNSYM
                for i in range(1, min(size // entsize, MAX_SYMBOLS)):
                    base = offset + i * entsize
                    if wide:
                        name, _info, _other, shndx = r.unpack("IBBH", base)
                    else:
                        name, _value, _size, _info, _other, shndx = r.unpack("IIIBBH", base)
                    if shndx == 0 and name:  # undefined: resolved from a library, i.e. imported
                        symbols.append(r.cstring(strtab + name))
            elif kind == 6 and entsize:  # SHT_DYNAMIC
                for i in range(min(size // entsize, MAX_LIBRARIES * 4)):
                    tag, value = r.unpack("qQ" if wide else "iI", offset + i * entsize)
                    if tag == 0:
                        break
                    if tag == 1 and len(libraries) < MAX_LIBRARIES:  # DT_NEEDED
                        libraries.append(r.cstring(strtab + value))
        return ImportTable("ELF", tuple(libraries), tuple(s for s in symbols if s))

    # -- PE --------------------------------------------------------------------------------

    @staticmethod
    def _pe(data: bytes) -> ImportTable:
        r = _Reader(data)
        pe = r.unpack("I", 0x3C)[0]
        if data[pe : pe + 4] != b"PE\x00\x00":
            raise ValueError("not PE")
        (sections_count,) = r.unpack("H", pe + 6)
        (optional_size,) = r.unpack("H", pe + 20)
        optional = pe + 24
        (magic,) = r.unpack("H", optional)
        wide = magic == 0x20B
        directory = optional + (112 if wide else 96)
        import_rva, _import_size = r.unpack("II", directory + 8)
        table = optional + optional_size
        sections = [
            r.unpack("IIII", table + i * 40 + 8) for i in range(min(sections_count, MAX_SECTIONS))
        ]

        def offset_of(rva: int) -> int:
            for virtual_size, virtual_address, raw_size, raw_pointer in sections:
                if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
                    return rva - virtual_address + raw_pointer
            raise ValueError("rva outside every section")

        libraries: list[str] = []
        symbols: list[str] = []
        if not import_rva:
            return ImportTable("PE", (), ())
        cursor = offset_of(import_rva)
        for _ in range(MAX_LIBRARIES):
            original, _stamp, _chain, name_rva, first = r.unpack("IIIII", cursor)
            if not (original or name_rva or first):
                break
            libraries.append(r.cstring(offset_of(name_rva)))
            thunk = offset_of(original or first)
            step, high = (8, 1 << 63) if wide else (4, 1 << 31)
            for _ in range(MAX_SYMBOLS):
                if len(symbols) >= MAX_SYMBOLS:
                    break
                (entry,) = r.unpack("Q" if wide else "I", thunk)
                if entry == 0:
                    break
                if not entry & high:  # by name, not ordinal
                    symbols.append(r.cstring(offset_of(entry & 0x7FFFFFFF) + 2))
                thunk += step
            cursor += 20
        return ImportTable("PE", tuple(libraries), tuple(s for s in symbols if s))

    # -- Mach-O ----------------------------------------------------------------------------

    @staticmethod
    def _macho(data: bytes, start: int) -> ImportTable:
        magic = data[start : start + 4]
        little = magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
        wide = magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
        r = _Reader(data, little=little)
        ncmds, _sizeofcmds = r.unpack("II", start + 16)
        cursor = start + (32 if wide else 28)
        libraries: list[str] = []
        symbols: list[str] = []
        for _ in range(min(ncmds, MAX_LOAD_COMMANDS)):
            command, size = r.unpack("II", cursor)
            if size < 8:
                break
            if (
                command in (0xC, 0x80000018, 0x8000001F, 0x80000023)
                and len(libraries) < MAX_LIBRARIES
            ):
                (name_offset,) = r.unpack("I", cursor + 8)
                libraries.append(r.cstring(cursor + name_offset))
            elif command == 0x2:  # LC_SYMTAB
                symoff, nsyms, stroff, _strsize = r.unpack("IIII", cursor + 8)
                entry = 16 if wide else 12
                for i in range(min(nsyms, MAX_SYMBOLS)):
                    strx, kind, _sect, _desc = r.unpack("IBBH", start + symoff + i * entry)
                    # Undefined and external: resolved from a dylib, i.e. imported.
                    if kind & 0xE0 == 0 and kind & 0x0E == 0 and kind & 0x01 and strx:
                        symbols.append(r.cstring(start + stroff + strx).lstrip("_"))
            cursor += size
        return ImportTable("Mach-O", tuple(libraries), tuple(s for s in symbols if s))

    @classmethod
    def _fat(cls, data: bytes) -> ImportTable:
        r = _Reader(data, little=False)
        (count,) = r.unpack("I", 4)
        libraries: list[str] = []
        symbols: list[str] = []
        for i in range(min(count, 8)):
            _cpu, _sub, offset, _size, _align = r.unpack("IIIII", 8 + i * 20)
            inner = cls._macho(data, offset)
            libraries.extend(inner.libraries)
            symbols.extend(inner.symbols)
        return ImportTable("Mach-O", tuple(dict.fromkeys(libraries)), tuple(dict.fromkeys(symbols)))


@dataclass(frozen=True, slots=True)
class ImportProfile:
    """The capabilities an import table grants, by name, with the symbols that grant each."""

    capabilities: dict[str, tuple[str, ...]] = field(default_factory=dict)
    resolves_at_runtime: bool = False

    def has(self, *names: str) -> bool:
        return all(name in self.capabilities for name in names)


class ImportCapabilities:
    """Imported symbol -> what it lets a program do."""

    #: Imported symbol groups, kept as package data, one file per group
    #: (`detect/data/imports-<group>.json`). Data, not code -- and one group per file, because a
    #: single file listing anti-debugging calls beside networking and credential calls is exactly
    #: the co-occurrence the anti-analysis rules exist to report.
    DATA: ClassVar[Path] = Path(__file__).parent / "data"

    @classmethod
    @functools.cache
    def groups(cls) -> dict[str, frozenset[str]]:
        out: dict[str, frozenset[str]] = {}
        for path in sorted(cls.DATA.glob("imports-*.json")):
            names = json.loads(path.read_text(encoding="utf-8"))
            out[path.stem.removeprefix("imports-")] = frozenset(str(n) for n in names)
        return out

    @classmethod
    def profile(cls, table: ImportTable) -> ImportProfile:
        imported = set(table.symbols)
        found = {
            group: tuple(sorted(imported & names))
            for group, names in cls.groups().items()
            if imported & names
        }
        # A real program imports dozens to thousands of symbols. One that imports little beyond
        # the loader's own lookup resolves everything else at run time, which is how a payload
        # keeps its intentions out of the very table this reads.
        resolves = "dynload" in found and len(imported) <= 12
        return ImportProfile(found, resolves)

    @staticmethod
    def verdicts(profile: ImportProfile) -> list[tuple[str, str]]:
        """`(rule id, detail)` for each combination worth reporting."""
        out: list[tuple[str, str]] = []
        caps = profile.capabilities

        def named(*groups: str) -> str:
            return ", ".join(sorted({s for g in groups for s in caps.get(g, ())}))

        if {"VirtualAllocEx", "WriteProcessMemory"} <= set(caps.get("inject", ())) or (
            profile.has("inject") and len(caps["inject"]) >= 3
        ):
            out.append(("SUSPECT.BINARY.PROCESS_INJECTION.001", f"imports {named('inject')}"))
        if profile.has("credential", "network"):
            out.append(
                ("SUSPECT.BINARY.CREDENTIAL_THEFT.001", f"imports {named('credential', 'network')}")
            )
        if profile.has("keylog", "network"):
            out.append(("SUSPECT.BINARY.KEYLOGGER.001", f"imports {named('keylog', 'network')}"))
        # Not network + execute + registry: that is every installer. Downloading a file and
        # running it, or doing both while checking for a debugger, is what a dropper does.
        if profile.has("download_execute", "execute") or profile.has(
            "network", "execute", "antidebug"
        ):
            out.append(
                (
                    "SUSPECT.BINARY.IMPLANT.001",
                    f"imports {named('network', 'execute', 'persist', 'antidebug', 'download_execute')}",
                )
            )
        if profile.resolves_at_runtime:
            out.append(
                (
                    "SUSPECT.BINARY.HIDDEN_IMPORTS.001",
                    f"imports almost nothing but {named('dynload')}",
                )
            )
        return out
