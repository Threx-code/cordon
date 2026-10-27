"""The ELF reader for cordon-rule: the `elf` module's values as a condition sees them.

An ELF object is read from its identification bytes (class 32/64, little- or big-endian) through the file
header, the section headers (with the section-header string table for names), the symbol and dynamic-symbol
tables, the program headers, and the dynamic array taken from the PT_DYNAMIC segment. Each table is read
with the entry sizes the format fixes and only where the whole table fits the file. Virtual addresses map to
offsets through the program headers for an executable and through the sections otherwise.

The import digest ("telfhash") and import MD5 are built from the dynamic symbols (static otherwise): the
exported, defined, default-visibility function names, lower-cased, with a fixed exclusion list, the common
library prefixes and the 64-suffixed names dropped. Named constants come from ``rule_tables``; the digest
from ``rule_tlsh``. Values follow the published ELF layout; a file that is not an ELF answers every field
undefined.
"""

from __future__ import annotations

import contextlib
import hashlib
import struct
from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_tables import Tables
from cordon_scanner.detect.binary.rule_tlsh import Tlsh
from cordon_scanner.detect.binary.rule_values import UNDEF_INT, UNDEF_STR, Array, Struct, Values


class Elf:
    """The `elf` module reader."""

    SHN_LORESERVE: ClassVar[int] = 0xFF00
    PN_XNUM: ClassVar[int] = 0xFFFF

    @staticmethod
    def schema() -> Struct:
        u, s = UNDEF_INT, UNDEF_STR
        section = Struct({"type": u, "flags": u, "address": u, "name": s, "size": u, "offset": u})
        segment = Struct(dict.fromkeys(("type", "flags", "offset", "virtual_address", "physical_address", "file_size", "memory_size", "alignment"), u))  # fmt: skip
        symbol = Struct({"name": s, "value": u, "size": u, "type": u, "bind": u, "shndx": u})
        fields: dict[str, Any] = dict(Tables.ELF)
        fields |= dict.fromkeys(("type", "machine", "entry_point", "number_of_sections", "sh_offset", "sh_entry_size", "number_of_segments", "ph_offset", "ph_entry_size", "dynamic_section_entries", "symtab_entries", "dynsym_entries"), u)  # fmt: skip
        fields |= {
            "sections": Array(section), "segments": Array(segment),
            "dynamic": Array(Struct({"type": u, "val": u})),
            "symtab": Array(symbol), "dynsym": Array(symbol),
            "telfhash": Values.fn(((), lambda: UNDEF_STR, "str")),
            "import_md5": Values.fn(((), lambda: UNDEF_STR, "str")),
        }  # fmt: skip
        return Struct(fields)

    @staticmethod
    def module(data: bytes) -> Struct:
        root = Elf.schema()
        with contextlib.suppress(IndexError, ValueError, struct.error):
            Elf._parse(root, data)
        return root

    @staticmethod
    def _parse(root: Struct, data: bytes) -> None:
        """The header, section and symbol tables each read with the format's fixed entry sizes when the
        whole table fits; the last symbol table of each kind wins; the dynamic array comes from the
        PT_DYNAMIC segment."""
        f = root.fields
        n = len(data)
        if n < 16 or data[:4] != b"\x7fELF":
            return
        cls, endian = data[4], data[5]
        if cls not in (1, 2) or endian not in (1, 2) or n <= (52 if cls == 1 else 64):
            return
        e = "<" if endian == 1 else ">"
        bits = 32 if cls == 1 else 64
        mask = (1 << bits) - 1
        word = "I" if cls == 1 else "Q"
        (etype, machine, _, entry, phoff, shoff, _, _, phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from(e + "HHI" + word * 3 + "IHHHHHH", data, 16)  # fmt: skip
        # the section-header count is also compared in its raw little-endian form in one place
        raw_shnum = struct.unpack_from(
            "<H", data, 16 + 2 + 2 + 4 + 3 * (bits // 8) + 4 + 2 + 2 + 2 + 2
        )[0]
        f.update(type=etype, machine=machine, sh_offset=shoff, sh_entry_size=shentsize, number_of_sections=shnum,
                 ph_offset=phoff, ph_entry_size=phentsize, number_of_segments=phnum)  # fmt: skip
        sec_size, seg_size, sym_size, dyn_size = (40, 32, 16, 8) if cls == 1 else (64, 56, 24, 16)
        sec_fmt = e + ("IIIIIIIIII" if cls == 1 else "IIQQQQIIQQ")
        seg_fmt = e + ("IIIIIIII" if cls == 1 else "IIQQQQQQ")

        def section(i: int) -> tuple[int, ...]:
            return struct.unpack_from(sec_fmt, data, shoff + i * sec_size)

        def segment(i: int) -> tuple[int, ...]:
            p = struct.unpack_from(seg_fmt, data, phoff + i * seg_size)
            # normalise 32-bit (type, offset, vaddr, paddr, filesz, memsz, flags, align) to the 64-bit order
            return (p[0], p[6], p[1], p[2], p[3], p[4], p[5], p[7]) if cls == 1 else p

        if entry:
            f["entry_point"] = Elf._rva_to_offset(
                data, etype, entry, phoff, phnum, shoff, shnum, section, segment, mask
            )
        symtab: tuple[int, int, int, int] | None = None
        dynsym: tuple[int, int, int, int] | None = None
        if (
            shnum < Elf.SHN_LORESERVE
            and shstrndx < shnum
            and shoff < n
            and shoff + shnum * sec_size <= n
        ):
            names_at = section(shstrndx)[4]
            str_table = names_at if names_at < n else None
            for i in range(shnum):
                name, stype, flags, addr, offset, size, link, _, _, _ = section(i)
                fields: dict[str, Any] = {
                    "type": stype,
                    "flags": flags,
                    "address": addr,
                    "size": size,
                    "offset": offset,
                }
                if name < n and str_table is not None and str_table > 0:
                    fields["name"] = Elf._string(data, str_table, n, name)
                f["sections"].items[i] = Struct(
                    f["sections"].proto.fields | {k: v for k, v in fields.items() if v is not None}
                )
                if stype in (2, 11) and link < raw_shnum:
                    at = shoff + link * sec_size
                    if at + sec_size <= n:
                        linked = struct.unpack_from(sec_fmt, data, at)
                        if linked[1] == 3:
                            table = (offset, size & mask, linked[4], linked[5] & mask)
                            if stype == 2:
                                symtab = table
                            else:
                                dynsym = table
            lists: dict[str, list[tuple[bytes | None, int, int, int, int]]] = {}
            for kind, chosen in (("symtab", symtab), ("dynsym", dynsym)):
                if chosen is None:
                    continue
                sym_at, sym_len, str_at, str_len = chosen
                if not (
                    str_len <= n
                    and str_at + str_len <= n
                    and sym_len <= n
                    and sym_at + sym_len <= n
                ):
                    continue
                symbols = lists[kind] = []
                for j in range(sym_len // sym_size):
                    at = sym_at + j * sym_size
                    if cls == 1:
                        st_name, value, size, info, other, shndx = struct.unpack_from(
                            e + "IIIBBH", data, at
                        )
                    else:
                        st_name, info, other, shndx, value, size = struct.unpack_from(
                            e + "IBBHQQ", data, at
                        )
                    sym_name = Elf._symbol_name(data, str_at, str_at + str_len, st_name)
                    entry_fields: dict[str, Any] = {
                        "bind": info >> 4,
                        "type": info & 0xF,
                        "shndx": shndx,
                        "value": value,
                        "size": size,
                    }
                    if sym_name is not None:
                        entry_fields["name"] = sym_name
                    f[kind].items[j] = Struct(f[kind].proto.fields | entry_fields)
                    symbols.append((sym_name, info >> 4, info & 0xF, shndx, other & 3))
                f[kind + "_entries"] = len(symbols)
            Elf._functions(f, lists)
        if 0 < phnum < Elf.PN_XNUM and phoff < n and phoff + phnum * seg_size <= n:
            for i in range(phnum):
                seg = segment(i)
                f["segments"].items[i] = Struct(dict(zip(("type", "flags", "offset", "virtual_address", "physical_address", "file_size", "memory_size", "alignment"), seg, strict=True)))  # fmt: skip
                if seg[0] == 2:
                    at = seg[2]
                    j = 0
                    # d_tag and d_val are both read unsigned (the reader reports the raw word, not sign-extended)
                    tag_fmt = e + (word + word)
                    while dyn_size <= n and at + dyn_size <= n:
                        tag, val = struct.unpack_from(tag_fmt, data, at)
                        f["dynamic"].items[j] = Struct({"type": tag, "val": val})
                        j += 1
                        at += dyn_size
                        if tag == 0:
                            break
                    f["dynamic_section_entries"] = j

    @staticmethod
    def _rva_to_offset(data: bytes, etype: int, rva: int, phoff: int, phnum: int, shoff: int, shnum: int,
                       section: Any, segment: Any, mask: int) -> Any:  # fmt: skip
        """Through the program headers for an executable, otherwise the sections that hold data; undefined
        where none holds the address."""
        n = len(data)
        if etype == 2:
            if (
                phoff == 0
                or phoff > n
                or phoff + phnum * (32 if mask == 0xFFFFFFFF else 56) > n
                or phnum == 0
            ):
                return UNDEF_INT
            for i in range(phnum):
                _, _, offset, vaddr, _, _, msize, _ = segment(i)
                if vaddr <= rva < (vaddr + msize) & mask:
                    return (offset + (rva - vaddr)) & ((1 << 64) - 1)
            return UNDEF_INT
        if (
            shoff == 0
            or shoff > n
            or shoff + shnum * (40 if mask == 0xFFFFFFFF else 64) > n
            or shnum == 0
        ):
            return UNDEF_INT
        for i in range(shnum):
            _, stype, _, addr, offset, size, _, _, _, _ = section(i)
            if stype not in (0, 8) and addr <= rva < (addr + size) & mask:
                return (offset + (rva - addr)) & ((1 << 64) - 1)
        return UNDEF_INT

    @staticmethod
    def _string(data: bytes, base: int, limit: int, index: int) -> bytes | None:
        """The NUL-terminated string at `index`, when the table starts with NUL and the string ends before
        `limit`."""
        if base >= limit or data[base] != 0 or index >= 1 << 31:
            return None
        at = base + index
        if at >= limit:
            return None
        end = data.find(b"\x00", at, limit)
        return None if end < 0 else data[at:end]

    @staticmethod
    def _symbol_name(data: bytes, base: int, limit: int, index: int) -> bytes | None:
        return Elf._string(data, base, limit, index)

    @staticmethod
    def _functions(
        f: dict[str, Any], lists: dict[str, list[tuple[bytes | None, int, int, int, int]]]
    ) -> None:
        """`telfhash()` and `import_md5()` over the dynamic symbols, else the static ones."""
        symbols = lists.get("dynsym", lists.get("symtab"))
        if symbols is None:
            return
        excluded = {
            b"__libc_start_main", b"main", b"abort", b"cachectl", b"cacheflush", b"puts", b"atol", b"malloc_trim",
        }  # fmt: skip
        clean = sorted(
            Elf._lower(name) for name, bind, kind, _, visibility in symbols
            if name is not None and bind == 1 and kind == 2 and visibility == 0
            and not name.startswith((b".", b"_")) and not name.endswith(b"64")
            and not name.startswith((b"str", b"mem")) and name not in excluded
        )  # fmt: skip
        telfhash: Any = Tlsh.digest(b",".join(clean)) if clean else UNDEF_STR
        imports = sorted(
            Elf._lower(name) for name, _, _, shndx, _ in symbols if name and shndx == 0
        )
        md5: Any = hashlib.md5(b",".join(imports)).hexdigest().encode() if imports else UNDEF_STR  # noqa: S324 - the digest is defined as MD5
        f["telfhash"] = Values.fn(((), lambda: telfhash, "str"))
        f["import_md5"] = Values.fn(((), lambda: md5, "str"))

    @staticmethod
    def _lower(name: bytes) -> bytes:
        return bytes(c + 32 if 0x41 <= c <= 0x5A else c for c in name)


__all__ = ["Elf"]
