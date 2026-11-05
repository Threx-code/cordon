"""A layout-driven reader for binary formats (cordon-rule).

Each structure is described once as a ``Layout`` — an ordered list of named fields, each a fixed-width
integer, an index whose width comes from a sizes map, or raw bytes. A single ``Cursor`` performs every read
of the file and is the only place that knows about bounds: a read that would fall outside the file returns
``ABSENT``, one module-level sentinel. ``Grid`` walks a run of identical rows, and ``ImageMap`` turns a
virtual address into a file offset. Nothing here knows the rule schema; the module readers assemble plain
data from what these return, mapping ``ABSENT`` to an undefined field so it can never be read as a value.

The design keeps bounds-checking in one place (the Cursor), so the readers describe *what* a structure is,
not how to guard each field — and a format quirk is a commented line in a reader, not scattered arithmetic.
"""

from __future__ import annotations

import struct
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

_FMT = {1: "B", 2: "H", 4: "I", 8: "Q"}


class _Absent:
    """The result of a read that falls outside the file. A single instance, ``ABSENT``; the assembly step
    turns it into an undefined field, so it is never confused with a real 0."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "ABSENT"

    def __bool__(self) -> bool:
        return False


ABSENT: Any = _Absent()


@dataclass(frozen=True)
class Uint:
    """A fixed-width little/big-endian unsigned integer field."""

    width: int


@dataclass(frozen=True)
class Index:
    """A heap or table index; its byte width is taken from the sizes map at read time, under ``key``."""

    key: str


@dataclass(frozen=True)
class Blob:
    """A fixed run of raw bytes."""

    width: int


@dataclass(frozen=True)
class Pad:
    """Bytes skipped without producing a field."""

    width: int


U8, U16, U32, U64 = Uint(1), Uint(2), Uint(4), Uint(8)


class Cursor:
    """The only reader of the file's bytes. Every primitive is bounds-checked against the file length and
    returns ``ABSENT`` when it would read past either end."""

    __slots__ = ("big", "data", "n")

    def __init__(self, data: bytes, big_endian: bool = False) -> None:
        self.data = data
        self.n = len(data)
        self.big = big_endian

    def fits(self, at: int, size: int) -> bool:
        return at >= 0 and 0 <= size <= self.n - at

    def uint(
        self,
        at: int,
        width: int,
        order: Literal["little", "big"] | None = None,
        *,
        signed: bool = False,
    ) -> Any:
        """The integer of ``width`` bytes at ``at``; ``order`` ("little"/"big") overrides the cursor's own
        byte order for a field whose endianness is fixed regardless of the file's (an ELF's little-endian
        e_shnum, a .NET blob's big-endian compressed integers). ``width`` may be any size, so a bignum -- an
        ASN.1 INTEGER's content, an RSA modulus -- is a wide read; ``signed`` reads two's complement."""
        if at < 0 or at + width > self.n:
            return ABSENT
        return int.from_bytes(
            self.data[at : at + width], order or ("big" if self.big else "little"), signed=signed
        )

    def blob(self, at: int, width: int) -> Any:
        if at < 0 or at + width > self.n:
            return ABSENT
        return self.data[at : at + width]

    def cstring(self, at: int, limit: int = 4096) -> Any:
        """The NUL-terminated byte string at ``at``, cut at ``limit``; ABSENT if ``at`` is out of range."""
        if at < 0 or at >= self.n:
            return ABSENT
        end = self.data.find(b"\x00", at, at + limit)
        return self.data[at : end if end >= 0 else min(self.n, at + limit)]


class _RowReader:
    """A Layout compiled for one sizes map and endianness: the whole row read in a single struct unpack,
    which a Grid uses in place of the per-field walk once it has confirmed the row fits."""

    __slots__ = ("names", "size", "struct")

    def __init__(self, layout: Layout, sizes: dict[str, int] | None, big: bool) -> None:
        fmt = ">" if big else "<"
        names: list[str] = []
        for name, spec in layout.fields:
            if isinstance(spec, Pad):
                fmt += "x" * spec.width
            elif isinstance(spec, Blob):
                fmt += f"{spec.width}s"
                names.append(name)
            else:
                # KeyError for an odd width -> Grid keeps the slow path
                fmt += _FMT[Layout.width_of(spec, sizes)]
                names.append(name)
        self.struct = struct.Struct(fmt)
        self.names = tuple(names)
        self.size = self.struct.size

    def read(self, data: bytes, at: int) -> dict[str, Any]:
        return dict(zip(self.names, self.struct.unpack_from(data, at), strict=True))


@dataclass(frozen=True)
class Layout:
    """A structure as data: ordered ``(name, spec)`` fields. ``read`` walks them from an offset, each read
    bounds-checked by the cursor; ``stride`` is the row size for a Grid. A field read past the file end is
    ABSENT and the walk continues, so a truncated structure yields the fields that fit and ABSENT for the
    rest (never a crash)."""

    fields: tuple[tuple[str, Any], ...]

    @staticmethod
    def width_of(spec: Any, sizes: dict[str, int] | None) -> int:
        if isinstance(spec, Index):
            return (sizes or {})[spec.key]
        return int(spec.width)

    def stride(self, sizes: dict[str, int] | None = None) -> int:
        return sum(Layout.width_of(spec, sizes) for _, spec in self.fields)

    def read(self, cur: Cursor, at: int, sizes: dict[str, int] | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {}
        pos = at
        for name, spec in self.fields:
            if isinstance(spec, Pad):
                pos += spec.width
                continue
            if isinstance(spec, Blob):
                out[name] = cur.blob(pos, spec.width)
                pos += spec.width
                continue
            width = Layout.width_of(spec, sizes)
            out[name] = cur.uint(pos, width)
            pos += width
        return out

    def compile(self, sizes: dict[str, int] | None = None, big: bool = False) -> _RowReader | None:
        """A reader that unpacks a whole row at once, or None if a field's width has no struct code (the
        caller then keeps the per-field ``read``). Only sound where the caller has checked the row fits."""
        try:
            return _RowReader(self, sizes, big)
        except KeyError:
            return None


class Grid:
    """A run of ``count`` rows of one Layout starting at ``base``. ``row(i)`` reads the i-th row (None out
    of range); iterating yields each row in turn. The per-row offset uses the Layout's stride."""

    __slots__ = ("_reader", "_stride", "base", "count", "cur", "layout", "sizes")

    def __init__(
        self,
        cur: Cursor,
        base: int,
        layout: Layout,
        count: int,
        sizes: dict[str, int] | None = None,
    ) -> None:
        self.cur = cur
        self.base = base
        self.layout = layout
        self.count = count
        self.sizes = sizes
        self._reader = layout.compile(
            sizes, cur.big
        )  # compiled once per Grid; None keeps the slow path
        self._stride = self._reader.size if self._reader is not None else layout.stride(sizes)

    def offset(self, i: int) -> int:
        return self.base + i * self._stride

    def fits(self, i: int) -> bool:
        """Whether the whole of row ``i`` is within the file — the readers break a walk where it is not."""
        return 0 <= i < self.count and self.cur.fits(self.offset(i), self._stride)

    def row(self, i: int) -> dict[str, Any] | None:
        """The row at ``i``, or None when it is out of range or runs past the end of the file, so a
        reader never sees a half-read row (the same rows the reference's ``fits_in_pe`` check keeps)."""
        if not self.fits(i):
            return None
        if self._reader is not None:
            return self._reader.read(self.cur.data, self.offset(i))
        return self.layout.read(self.cur, self.offset(i), self.sizes)

    def __iter__(self) -> Any:
        for i in range(self.count):
            if not self.fits(i):
                break
            if self._reader is not None:
                yield self._reader.read(self.cur.data, self.offset(i))
            else:
                yield self.layout.read(self.cur, self.offset(i), self.sizes)

    def tuples(self) -> list[tuple[Any, ...]]:
        """Every row that fits, decoded in one ``struct.iter_unpack`` over the contiguous table slice --
        the whole table in one C call, as value tuples aligned to ``names``, with no per-row dict. Empty
        when the Layout did not compile (a caller then falls back to ``row``)."""
        if self._reader is None or self._stride <= 0:
            return []
        fit = min(self.count, max(0, (self.cur.n - self.base) // self._stride))
        if fit <= 0:
            return []
        end = self.base + fit * self._stride
        return list(self._reader.struct.iter_unpack(self.cur.data[self.base : end]))

    @property
    def names(self) -> tuple[str, ...]:
        """Field names positionally aligned with each tuple from ``tuples()``."""
        return self._reader.names if self._reader is not None else ()


class LazySeq(Mapping[int, Any]):
    """A sequence read by index whose values are decoded on first access and cached. The keys are known up
    front, so a rule reads the length (highest key) and iterates the slots without building any value; a
    value is decoded only when its slot is read. Full iteration -- as ``Data.conforms`` and the differential
    harnesses do -- decodes and caches every value, so the result is identical to an eager build, deferred.
    It is a Mapping, not a dict, because a dict cannot defer: ``dict.items()`` reads stored values, not
    ``__getitem__``, so the keys could not be known without the values."""

    __slots__ = ("_cache", "_decode", "_keys", "_keyset")

    def __init__(self, keys: Any, decode: Any) -> None:
        self._keys: tuple[int, ...] = tuple(keys)
        self._keyset = frozenset(self._keys)
        self._decode = decode
        self._cache: dict[int, Any] = {}

    def __getitem__(self, key: int) -> Any:
        if key not in self._keyset:
            raise KeyError(key)
        if key not in self._cache:
            self._cache[key] = self._decode(key)
        return self._cache[key]

    def __contains__(self, key: object) -> bool:
        return key in self._keyset  # membership from keys alone; never decodes a value

    def __iter__(self) -> Any:
        return iter(self._keys)

    def __len__(self) -> int:
        return len(self._keys)


class Row(Mapping[str, Any]):
    """A read-only record view over one decoded tuple, so a table a rule only probes never builds a dict per
    row. A shared spec maps each declared field to how it is read -- an ``int`` position in the tuple, or a
    callable over the tuple for a derived field (``info >> 4``) or a string-table name resolved on access.
    A field resolves on first read and is cached; only fields that resolve to a value are present, so an
    unresolved name is absent exactly as the eager reader omitted it. It is a Mapping so ``Data.conforms``
    and the differential read it through ``__getitem__`` like any record."""

    __slots__ = ("_cache", "_spec", "_t")

    def __init__(self, t: tuple[Any, ...], spec: Mapping[str, Any]) -> None:
        self._t = t
        self._spec = (
            spec  # field -> int position, or callable(tuple) -> value; shared across a table's rows
        )
        self._cache: dict[str, Any] = {}

    def _value(self, key: str) -> Any:
        if key in self._cache:
            return self._cache[key]
        how = self._spec.get(key)
        value = how(self._t) if callable(how) else (self._t[how] if how is not None else None)
        self._cache[key] = value
        return value

    def __getitem__(self, key: str) -> Any:
        value = self._value(key)
        if value is None:
            raise KeyError(key)
        return value

    def get(self, key: str, default: Any = None) -> Any:
        value = self._value(key)
        return default if value is None else value

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key in self._spec and self._value(key) is not None

    def __iter__(self) -> Any:
        return (key for key in self._spec if self._value(key) is not None)

    def __len__(self) -> int:
        return sum(1 for _ in self)


class LazyRecord(Mapping[str, Any]):
    """A record whose cheap fields are ready and whose costly fields are produced together by ``build`` on
    the first read of any of them, then cached -- so a rule that reads only a cheap field never pays for the
    costly ones. The costly field names are declared up front, so membership and iteration never trigger the
    build; ``build`` must return exactly those names. It is a Mapping so ``Data.conforms`` and the differential
    read it like any record (materialising the costly fields, off the hot path)."""

    __slots__ = ("_build", "_deferred", "_eager", "_resolved")

    def __init__(self, eager: dict[str, Any], deferred: tuple[str, ...], build: Any) -> None:
        self._eager = eager
        self._deferred = deferred  # field names produced lazily by build()
        self._build = build  # () -> dict providing exactly the deferred names
        self._resolved: dict[str, Any] | None = None

    def _fields(self) -> dict[str, Any]:
        if self._resolved is None:
            self._resolved = self._build()
        return self._resolved

    def __getitem__(self, key: str) -> Any:
        if key in self._eager:
            return self._eager[key]
        if key in self._deferred:
            return self._fields()[key]
        raise KeyError(key)

    def __iter__(self) -> Any:
        yield from self._eager
        yield from self._deferred

    def __len__(self) -> int:
        return len(self._eager) + len(self._deferred)

    def __contains__(self, key: object) -> bool:
        return key in self._eager or key in self._deferred


class LazyGroups(Mapping[str, Any]):
    """A record whose costly fields come in independent groups, each built by its own function on the first
    read of one of its names and then kept, so a rule that reads one group never pays for another. A group
    declares its names up front, but its build may leave some out (the field is then absent): asking whether
    such a field is present builds its group. Iterating builds every group, off the hot path."""

    __slots__ = ("_built", "_eager", "_groups", "_owner")

    def __init__(self, eager: dict[str, Any], groups: list[tuple[tuple[str, ...], Any]]) -> None:
        self._eager = eager  # holds none of the groups' names
        self._groups = groups  # (names, build): build() -> the group's present fields
        self._owner = {name: i for i, (names, _) in enumerate(groups) for name in names}
        self._built: dict[int, dict[str, Any]] = {}

    def _group(self, i: int) -> dict[str, Any]:
        built = self._built.get(i)
        if built is None:
            built = self._built[i] = self._groups[i][1]()
        return built

    def __getitem__(self, key: str) -> Any:
        if key in self._eager:
            return self._eager[key]
        i = self._owner.get(key)
        if i is None:
            raise KeyError(key)
        return self._group(i)[key]

    def __contains__(self, key: object) -> bool:
        if key in self._eager:
            return True
        i = self._owner.get(key) if isinstance(key, str) else None
        return i is not None and key in self._group(i)

    def __iter__(self) -> Any:
        yield from self._eager
        for i in range(len(self._groups)):
            yield from self._group(i)

    def __len__(self) -> int:
        return len(self._eager) + sum(len(self._group(i)) for i in range(len(self._groups)))


class ImageMap:
    """A PE image's virtual-address space: accepts the header and maps a virtual address (RVA) to a file
    offset through the section table, shared by the ``modules.pe`` and ``modules.dotnet`` readers. Built once from
    the file.

    The two reference modules differ on a truncated section table, so ``to_offset`` takes a ``strict`` mode:
    ``modules.pe`` (strict) stops at the first section header that does not fit the file and returns -1 for every
    address; ``modules.dotnet`` (the default) maps through the headers that do fit and ignores the rest."""

    MAX_SECTIONS = 96

    __slots__ = ("_map", "_sections", "cur", "is64", "n", "nt", "opt", "strict")

    def __init__(self, cur: Cursor, nt: int, is64: bool, strict: bool = False) -> None:
        self.cur = cur
        self.n = cur.n
        self.nt = nt  # file offset of the PE signature
        self.is64 = is64
        self.opt = nt + 24  # start of the optional header
        self.strict = strict
        self._sections: list[tuple[int, int, int, int]] | None = None
        #: What every address lookup shares, worked out once (`_mapping`); None until then.
        self._map: tuple[bool, int, list[tuple[int, int, int, int]]] | None = None

    @staticmethod
    def accept(cur: Cursor, strict: bool = False) -> ImageMap | None:
        """Accept the file as a PE: MZ stub, an e_lfanew to a PE\\0\\0 signature, and a COFF + optional
        header of the magic's width present in the file. ``strict`` selects the ``modules.pe`` RVA rule."""
        if cur.n < 64 or cur.blob(0, 2) != b"MZ":
            return None
        nt = cur.uint(0x3C, 4)
        if nt is ABSENT or nt < 0 or not isinstance(nt, int):
            return None
        if cur.n < nt + 24 or cur.blob(nt, 4) != b"PE\x00\x00":
            return None
        magic = cur.uint(nt + 24, 2)
        if magic is ABSENT:
            return None
        is64 = magic == 0x20B
        if cur.n < nt + 24 + (240 if is64 else 224):
            return None
        return ImageMap(cur, nt, is64, strict)

    def sections(self) -> list[tuple[int, int, int, int]]:
        """(virtual_address, virtual_size, raw_size, raw_offset) for each section header."""
        if self._sections is None:
            cur = self.cur
            count = cur.uint(self.nt + 6, 2)
            first = self.opt + cur.uint(self.nt + 20, 2)
            rows: list[tuple[int, int, int, int]] = []
            if isinstance(count, int) and isinstance(first, int):
                for i in range(min(count, ImageMap.MAX_SECTIONS)):
                    at = first + 40 * i
                    vsize = cur.uint(at + 8, 4)
                    vaddr = cur.uint(at + 12, 4)
                    rsize = cur.uint(at + 16, 4)
                    roff = cur.uint(at + 20, 4)
                    if ABSENT in (vsize, vaddr, rsize, roff):
                        break
                    rows.append((vaddr, vsize, rsize, roff))
            self._sections = rows
        return self._sections

    def to_offset(self, rva: int) -> int:
        """The file offset of a virtual address, or -1 when no section maps it. Follows the loader's choice
        of the highest-based section that still contains the address and its raw-pointer alignment (the
        quirk that an address below every section maps straight through to the same file offset is kept)."""
        usable, lowest, table = self._mapping()
        if not usable:
            return -1
        hit_rva = hit_off = hit_raw = 0
        for vaddr, span, off, rsize in table:
            if vaddr <= rva and rva - vaddr < span and hit_rva <= vaddr:
                hit_rva, hit_off, hit_raw = vaddr, off, rsize
        if rva < lowest:  # below every section: the loader reads it straight from the file start
            hit_rva, hit_off, hit_raw = 0, 0, self.n
        if rva < hit_rva or rva - hit_rva >= hit_raw:
            return -1
        result = hit_off + (rva - hit_rva)
        return result if result < self.n else -1

    def _mapping(self) -> tuple[bool, int, list[tuple[int, int, int, int]]]:
        """What does not depend on the address, worked out on the first lookup and kept: whether any address
        maps at all (in `strict` mode every section header must fit; both alignments must be present), the
        lowest section address, and each section as (address, extent, aligned file offset, raw size)."""
        if self._map is None:
            cur = self.cur
            usable = True
            if (
                self.strict
            ):  # modules.pe: a section header that does not fit the file fails the whole mapping
                count = cur.uint(self.nt + 6, 2)
                first = self.opt + cur.uint(self.nt + 20, 2)
                if not isinstance(count, int) or not isinstance(first, int):
                    usable = False
                else:
                    usable = all(
                        cur.fits(first + 40 * i, 40)
                        for i in range(min(count, ImageMap.MAX_SECTIONS))
                    )
            file_align = cur.uint(self.opt + 36, 4)
            sect_align = cur.uint(self.opt + 32, 4)
            if ABSENT in (file_align, sect_align):
                usable = False
            lowest = 0xFFFFFFFF
            table: list[tuple[int, int, int, int]] = []
            if usable:
                align = min(file_align, 0x200)
                for vaddr, vsize, rsize, roff in self.sections():
                    lowest = min(lowest, vaddr)
                    off = roff
                    if align and off % align:
                        off -= off % align
                    if sect_align >= 0x1000:
                        off &= ~0x1FF
                    table.append((vaddr, max(vsize, rsize), off, rsize))
            self._map = (usable, lowest, table)
        return self._map

    def directory(self, entry: int) -> tuple[int, int] | None:
        """(virtual_address, size) of data directory ``entry``, read where the optional header puts it."""
        at = self.opt + (112 if self.is64 else 96) + 8 * entry
        va = self.cur.uint(at, 4)
        size = self.cur.uint(at + 4, 4)
        if ABSENT in (va, size):
            return None
        return va, size


__all__ = [
    "ABSENT",
    "U8",
    "U16",
    "U32",
    "U64",
    "Blob",
    "Cursor",
    "Grid",
    "ImageMap",
    "Index",
    "Layout",
    "LazyGroups",
    "LazyRecord",
    "LazySeq",
    "Pad",
    "Row",
    "Uint",
]
