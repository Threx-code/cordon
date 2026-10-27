"""The ELF reader for cordon-rule: the `elf` module's values as a condition sees them.

An ELF object is read from its identification bytes (class 32/64, little- or big-endian) through the file
header, the section headers (named through the section-header string table), the symbol and dynamic-symbol
tables, the program headers, and the dynamic array of the PT_DYNAMIC segment. Each structure is described
once as a Layout; the one word-width that 32- and 64-bit ELF differ in is a single entry in a sizes map, so
most structures need only one Layout and the Cursor carries the byte order. The two structures whose field
*order* differs between the classes (program header, symbol) have a Layout per class. A Grid walks each
table, reading only where the whole of a row fits, and the readers turn rows into the rule-visible values.

telfhash and import_md5 are built from the dynamic symbols (static otherwise) through rule_tlsh, unchanged
from the reference; the named constants come from rule_tables. A file that is not an ELF answers undefined.
"""

from __future__ import annotations

import hashlib
from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_layout import (
    U8,
    U16,
    U32,
    U64,
    Cursor,
    Grid,
    Index,
    Layout,
    LazySeq,
    Row,
)
from cordon_scanner.detect.binary.rule_tables import Tables
from cordon_scanner.detect.binary.rule_tlsh import Tlsh
from cordon_scanner.detect.binary.rule_values import Call, Record, Scalar, Seq, Sig

INT, TEXT = Scalar.INT, Scalar.TEXT
_W = Index("w")  # the ELF word: 4 bytes for a 32-bit object, 8 for a 64-bit one


class Shape:
    """Every ELF structure described once (ECMA-less: the published ELF layout). Word-width fields use the
    sizes map; the two structures whose field order differs by class carry a 32- and a 64-bit form."""

    EHDR: ClassVar[Layout] = Layout((
        ("type", U16), ("machine", U16), ("version", U32), ("entry", _W), ("phoff", _W), ("shoff", _W),
        ("flags", U32), ("ehsize", U16), ("phentsize", U16), ("phnum", U16), ("shentsize", U16),
        ("shnum", U16), ("shstrndx", U16),
    ))  # fmt: skip
    SHDR: ClassVar[Layout] = Layout((
        ("name", U32), ("type", U32), ("flags", _W), ("addr", _W), ("offset", _W), ("size", _W),
        ("link", U32), ("info", U32), ("addralign", _W), ("entsize", _W),
    ))  # fmt: skip
    PHDR32: ClassVar[Layout] = Layout((
        ("type", U32), ("offset", U32), ("vaddr", U32), ("paddr", U32), ("filesz", U32), ("memsz", U32),
        ("flags", U32), ("align", U32),
    ))  # fmt: skip
    PHDR64: ClassVar[Layout] = Layout((
        ("type", U32), ("flags", U32), ("offset", U64), ("vaddr", U64), ("paddr", U64), ("filesz", U64),
        ("memsz", U64), ("align", U64),
    ))  # fmt: skip
    SYM32: ClassVar[Layout] = Layout((
        ("name", U32), ("value", U32), ("size", U32), ("info", U8), ("other", U8), ("shndx", U16),
    ))  # fmt: skip
    SYM64: ClassVar[Layout] = Layout((
        ("name", U32), ("info", U8), ("other", U8), ("shndx", U16), ("value", U64), ("size", U64),
    ))  # fmt: skip
    DYN: ClassVar[Layout] = Layout((("tag", _W), ("val", _W)))


class Strings:
    """A string table: the NUL-terminated name at an index, when the table starts with NUL and fits."""

    __slots__ = ("base", "cur", "limit")

    def __init__(self, cur: Cursor, base: int, limit: int) -> None:
        self.cur, self.base, self.limit = cur, base, limit

    def at(self, index: Any) -> bytes | None:
        if not isinstance(index, int) or self.base >= self.limit or index >= 1 << 31:
            return None
        if self.cur.data[self.base] != 0:
            return None
        start = self.base + index
        if start >= self.limit:
            return None
        end = self.cur.data.find(b"\x00", start, self.limit)
        return None if end < 0 else self.cur.data[start:end]


class Elf:
    """The `elf` module reader."""

    SHN_LORESERVE: ClassVar[int] = 0xFF00
    PN_XNUM: ClassVar[int] = 0xFFFF
    MASK64: ClassVar[int] = (1 << 64) - 1
    EXCLUDED: ClassVar[frozenset[bytes]] = frozenset({
        b"__libc_start_main", b"main", b"abort", b"cachectl", b"cacheflush", b"puts", b"atol", b"malloc_trim",
    })  # fmt: skip

    _section = Record(
        {"type": INT, "flags": INT, "address": INT, "name": TEXT, "size": INT, "offset": INT}
    )
    _segment = Record(dict.fromkeys(
        ("type", "flags", "offset", "virtual_address", "physical_address", "file_size", "memory_size", "alignment"), INT
    ))  # fmt: skip
    _symbol = Record(
        {"name": TEXT, "value": INT, "size": INT, "type": INT, "bind": INT, "shndx": INT}
    )
    SCHEMA: ClassVar[Record] = Record({
        **dict.fromkeys(Tables.ELF, INT),
        **dict.fromkeys(
            ("type", "machine", "entry_point", "number_of_sections", "sh_offset", "sh_entry_size",
             "number_of_segments", "ph_offset", "ph_entry_size", "dynamic_section_entries",
             "symtab_entries", "dynsym_entries"), INT,
        ),
        "sections": Seq(_section), "segments": Seq(_segment),
        "dynamic": Seq(Record({"type": INT, "val": INT})),
        "symtab": Seq(_symbol), "dynsym": Seq(_symbol),
        "telfhash": Call(Sig((), TEXT)), "import_md5": Call(Sig((), TEXT)),
    })  # fmt: skip

    ARRAYS: ClassVar[tuple[str, ...]] = ("sections", "segments", "dynamic", "symtab", "dynsym")

    @staticmethod
    def data(file: bytes) -> dict[str, Any]:
        out: dict[str, Any] = dict(Tables.ELF)  # the module constants are present for every file
        for name in (
            Elf.ARRAYS
        ):  # the reference always presents these arrays, empty when nothing fills them
            out[name] = {}
        Elf._read(out, file)
        return out

    @staticmethod
    def _read(out: dict[str, Any], file: bytes) -> None:
        n = len(file)
        if n < 16 or file[:4] != b"\x7fELF":
            return
        cls, endian = file[4], file[5]
        if cls not in (1, 2) or endian not in (1, 2) or n <= (52 if cls == 1 else 64):
            return
        cur = Cursor(file, big_endian=endian == 2)
        word = 4 if cls == 1 else 8
        sizes = {"w": word}
        mask = (1 << (32 if cls == 1 else 64)) - 1
        h = Shape.EHDR.read(cur, 16, sizes)
        shoff, shnum, shstrndx = h["shoff"], h["shnum"], h["shstrndx"]
        phoff, phnum = h["phoff"], h["phnum"]
        out.update(
            type=h["type"], machine=h["machine"], sh_offset=shoff, sh_entry_size=h["shentsize"],
            number_of_sections=shnum, ph_offset=phoff, ph_entry_size=h["phentsize"], number_of_segments=phnum,
        )  # fmt: skip
        sec_size = 40 if cls == 1 else 64
        sections = Grid(cur, shoff, Shape.SHDR, shnum, sizes)
        if h["entry"]:
            ep = Elf._to_offset(cur, h["type"], h["entry"], phoff, phnum, shoff, shnum, sizes, mask)
            if ep is not None:
                out["entry_point"] = ep
        symtab = dynsym = None
        if (
            shnum < Elf.SHN_LORESERVE
            and shstrndx < shnum
            and shoff < n
            and shoff + shnum * sec_size <= n
        ):
            srows = sections.tuples()  # the whole section header table in one struct call
            sp = {name: i for i, name in enumerate(sections.names)}
            sn, st, sf, sa, so, ssz, sl = (
                sp[k] for k in ("name", "type", "flags", "addr", "offset", "size", "link")
            )
            names_at = srows[shstrndx][so] if shstrndx < len(srows) else n
            shstr = Strings(cur, names_at, n) if names_at < n else None

            def section_name(
                t: tuple[Any, ...],
            ) -> bytes | None:  # resolved only when a rule reads it
                return (
                    shstr.at(t[sn]) if t[sn] < n and shstr is not None and shstr.base > 0 else None
                )

            sec_spec: dict[str, Any] = {
                "type": st, "flags": sf, "size": ssz, "offset": so, "address": sa, "name": section_name,
            }  # fmt: skip
            out["sections"] = LazySeq(range(len(srows)), lambda i: Row(srows[i], sec_spec))
            # pick up each SYMTAB(2)/DYNSYM(11)'s linked STRTAB(3); e_shnum read little-endian bounds the link
            raw_off = 36 + 3 * word
            raw_shnum = cur.uint(
                raw_off, 2, "little"
            )  # e_shnum is little-endian regardless of byte order
            for t in srows:
                if (
                    t[st] in (2, 11)
                    and t[sl] < raw_shnum
                    and t[sl] < len(srows)
                    and srows[t[sl]][st] == 3
                ):
                    picked = (t[so], t[ssz] & mask, srows[t[sl]][so], srows[t[sl]][ssz] & mask)
                    if t[st] == 2:
                        symtab = picked
                    else:
                        dynsym = picked
            symbols: dict[str, tuple[Any, ...]] = {}
            for kind, chosen in (("symtab", symtab), ("dynsym", dynsym)):
                Elf._symbols(out, cur, cls, kind, chosen, n, symbols)
            Elf._digests(out, symbols)
        if 0 < phnum < Elf.PN_XNUM and phoff < n and phoff + phnum * (32 if cls == 1 else 56) <= n:
            Elf._segments(out, cur, cls, phoff, phnum, sizes, n)

    @staticmethod
    def _symbols(
        out: dict[str, Any],
        cur: Cursor,
        cls: int,
        kind: str,
        chosen: tuple[int, int, int, int] | None,
        n: int,
        symbols: dict[str, tuple[Any, ...]],
    ) -> None:
        if chosen is None:
            return
        sym_at, sym_len, str_at, str_len = chosen
        if not (str_len <= n and str_at + str_len <= n and sym_len <= n and sym_at + sym_len <= n):
            return
        layout = Shape.SYM32 if cls == 1 else Shape.SYM64
        sym_size = 16 if cls == 1 else 24
        strtab = Strings(cur, str_at, str_at + str_len)
        grid = Grid(cur, sym_at, layout, sym_len // sym_size, {"w": 4 if cls == 1 else 8})
        rows = (
            grid.tuples()
        )  # the whole table in one struct call; no per-row dict (a 100k symtab is one call)
        pos = {name: i for i, name in enumerate(grid.names)}
        ni, vi, zi, ii, xi = (pos[k] for k in ("name", "value", "size", "info", "shndx"))
        spec: dict[str, Any] = {
            "bind": lambda t: t[ii] >> 4,
            "type": lambda t: t[ii] & 0xF,
            "shndx": xi, "value": vi, "size": zi,
            "name": lambda t: strtab.at(t[ni]),  # the string-table name, resolved only when a rule reads it
        }  # fmt: skip
        out[kind] = LazySeq(range(len(rows)), lambda j: Row(rows[j], spec))
        out[kind + "_entries"] = len(rows)
        symbols[kind] = (rows, pos, strtab)

    @staticmethod
    def _segments(
        out: dict[str, Any],
        cur: Cursor,
        cls: int,
        phoff: int,
        phnum: int,
        sizes: dict[str, int],
        n: int,
    ) -> None:
        grid = Grid(cur, phoff, Shape.PHDR32 if cls == 1 else Shape.PHDR64, phnum, sizes)
        prows = grid.tuples()  # the whole program header table in one struct call
        pp = {name: i for i, name in enumerate(grid.names)}
        names = (
            "type", "flags", "offset", "virtual_address", "physical_address", "file_size",
            "memory_size", "alignment",
        )  # fmt: skip
        keys = ("type", "flags", "offset", "vaddr", "paddr", "filesz", "memsz", "align")
        seg_spec: dict[str, Any] = {nm: pp[k] for nm, k in zip(names, keys, strict=True)}
        out["segments"] = LazySeq(range(len(prows)), lambda i: Row(prows[i], seg_spec))
        ti, offi = pp["type"], pp["offset"]
        for t in prows:
            if t[ti] == 2:  # PT_DYNAMIC: parse the dynamic array from this segment
                Elf._dynamic(out, cur, t[offi], sizes, n, cls)

    @staticmethod
    def _dynamic(
        out: dict[str, Any], cur: Cursor, at: int, sizes: dict[str, int], n: int, cls: int
    ) -> None:
        dyn_size = 8 if cls == 1 else 16
        # a later PT_DYNAMIC overwrites low indices but leaves an earlier, longer one's higher entries, so
        # accumulate into the one array rather than replacing it; the count reported is this segment's.
        seq = out["dynamic"]
        j = 0
        while dyn_size <= n and at + dyn_size <= n:
            row = Shape.DYN.read(
                cur, at, sizes
            )  # tag and val both read unsigned, as the reference reports
            seq[j] = {"type": row["tag"], "val": row["val"]}
            j += 1
            at += dyn_size
            if row["tag"] == 0:
                break
        out["dynamic_section_entries"] = j

    @staticmethod
    def _to_offset(
        cur: Cursor,
        etype: int,
        rva: int,
        phoff: int,
        phnum: int,
        shoff: int,
        shnum: int,
        sizes: dict[str, int],
        mask: int,
    ) -> int | None:
        """A virtual address to a file offset: through the program headers for an executable, otherwise the
        sections that hold data; None where none holds the address."""
        n = cur.n
        cls32 = sizes["w"] == 4
        if etype == 2:
            if phoff == 0 or phoff > n or phoff + phnum * (32 if cls32 else 56) > n or phnum == 0:
                return None
            grid = Grid(cur, phoff, Shape.PHDR32 if cls32 else Shape.PHDR64, phnum, sizes)
            for i in range(phnum):
                row = grid.row(i)
                if row is None:
                    break
                if row["vaddr"] <= rva < (row["vaddr"] + row["memsz"]) & mask:
                    return int((row["offset"] + (rva - row["vaddr"])) & Elf.MASK64)
            return None
        if shoff == 0 or shoff > n or shoff + shnum * (40 if cls32 else 64) > n or shnum == 0:
            return None
        grid = Grid(cur, shoff, Shape.SHDR, shnum, sizes)
        for i in range(shnum):
            row = grid.row(i)
            if row is None:
                break
            if (
                row["type"] not in (0, 8)
                and row["addr"] <= rva < (row["addr"] + row["size"]) & mask
            ):
                return int((row["offset"] + (rva - row["addr"])) & Elf.MASK64)
        return None

    @staticmethod
    def _digests(out: dict[str, Any], symbols: dict[str, tuple[Any, ...]]) -> None:
        """telfhash() and import_md5() over the dynamic symbols, else the static ones -- computed only when
        the rule calls them, over the symbol tuples, resolving a name only for a symbol that passes the
        cheap tuple filter first."""
        chosen = symbols.get("dynsym", symbols.get("symtab"))
        if chosen is None:
            return
        rows, pos, strtab = chosen
        ni, ii, xi, oi = pos["name"], pos["info"], pos["shndx"], pos["other"]

        def telfhash() -> bytes | None:
            clean = sorted(  # name.lower() is the reference's case fold (ASCII A-Z only), in C
                name.lower()
                for t in rows
                if (t[ii] >> 4) == 1 and (t[ii] & 0xF) == 2 and (t[oi] & 3) == 0
                for name in (strtab.at(t[ni]),)
                if name is not None and not name.startswith((b".", b"_")) and not name.endswith(b"64")
                and not name.startswith((b"str", b"mem")) and name not in Elf.EXCLUDED
            )  # fmt: skip
            return Tlsh.digest(b",".join(clean)) if clean else None

        def import_md5() -> bytes | None:
            imports = sorted(
                name.lower() for t in rows if t[xi] == 0 for name in (strtab.at(t[ni]),) if name
            )
            return hashlib.md5(b",".join(imports)).hexdigest().encode() if imports else None  # noqa: S324

        out["telfhash"] = (telfhash,)
        out["import_md5"] = (import_md5,)


__all__ = ["Elf"]
