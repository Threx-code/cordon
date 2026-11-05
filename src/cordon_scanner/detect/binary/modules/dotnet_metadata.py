"""ECMA-335 metadata, read from a CLI image: the stream headers and heaps (#Strings, #US, #Blob, #GUID),
the compressed integers and blobs they hold, and the metadata tables -- each table's row layout
declared once as data, with the coded indexes that point between them.
"""

from __future__ import annotations

from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.layout import (
    ABSENT,
    U8,
    U16,
    U32,
    Cursor,
    Grid,
    Index,
    Layout,
    Pad,
)

# -- the metadata-table catalog ---------------------------------------------
# Each table id maps to (rule-facing name, Layout). The Layout names a field only where a reader uses it;
# the rest are padding of the right width, so a table contributes the correct row stride either way. Index
# widths are keys resolved from the Sizes map: heaps "string"/"guid"/"blob"; a table's own index e.g.
# "methoddef"; or a coded index e.g. "typedeforref". A table with no reader still has a Layout for stride.
# The row-count field each table bit fills, and whether a large count widens that table's own index.
ROW_FIELDS: dict[int, tuple[str, bool]] = {
    0x00: ("module", True),
    0x01: ("typeref", True),
    0x02: ("typedef", True),
    0x04: ("field", True),
    0x06: ("methoddef", True),
    0x08: ("param", True),
    0x09: ("interfaceimpl", True),
    0x0A: ("memberref", True),
    0x11: ("standalonesig", False),
    0x14: ("event", True),
    0x17: ("property", True),
    0x1A: ("moduleref", True),
    0x1B: ("typespec", True),
    0x20: ("assembly", True),
    0x23: ("assemblyref", True),
    0x24: ("assemblyrefprocessor", True),
    0x26: ("file", False),
    0x27: ("exportedtype", False),
    0x28: ("manifestresource", False),
    0x2A: ("genericparam", True),
    0x2B: ("methodspec", True),
    0x2C: ("genericparamconstraint", False),
}

SIMPLE = ("field", "methoddef", "param", "typedef", "event", "property", "moduleref", "genericparam",
          "assemblyref", "assemblyrefprocessor")  # fmt: skip

#: coded index -> (target tables, tag bits). The Implementation index of ManifestResource is quirky: the
#: reference sizes it from File+AssemblyRef only, leaving ExportedType out, so it is a separate key.
CODED: dict[str, tuple[tuple[str, ...], int]] = {
    "typedeforref": (("typedef", "typeref", "typespec"), 2),
    "hasconstant": (("field", "param", "property"), 2),
    "customattributetype": (("methoddef", "memberref"), 3),
    "hasdeclsecurity": (("typedef", "methoddef", "assembly"), 2),
    "memberrefparent": (("methoddef", "moduleref", "typeref", "typespec"), 3),
    "hassemantics": (("event", "property"), 1),
    "methoddeforref": (("methoddef", "memberref"), 1),
    "memberforwarded": (("field", "methoddef"), 1),
    "implementation": (("file", "assemblyref", "exportedtype"), 2),
    "implementation_resource": (("file", "assemblyref"), 2),  # ManifestResource's, ExportedType excluded
    "hasfieldmarshal": (("field", "param"), 1),
    "typeormethod": (("typedef", "methoddef"), 1),
    "resolutionscope": (("module", "moduleref", "assemblyref", "typeref"), 2),
    "hascustomattribute": (
        ("methoddef", "field", "typeref", "typedef", "param", "interfaceimpl", "memberref", "module",
         "property", "event", "standalonesig", "moduleref", "typespec", "assembly", "assemblyref", "file",
         "exportedtype", "manifestresource", "genericparam", "genericparamconstraint", "methodspec"), 5),
}  # fmt: skip


class Spec:
    """The declarative table catalog, index sizing, and the small name/int helpers for the .NET
    reader, kept off the module root (repository structure rule)."""

    @staticmethod
    def index_sizes(heap_sizes: int, rows: dict[str, int]) -> dict[str, int]:
        """Every index width, computed once (ECMA-335 II.24.2.6). Heaps widen by the heap-size flags; a simple
        index by its own row count; a coded index by the largest of its target tables against (0xFFFF>>bits)."""
        sizes: dict[str, int] = {"string": 4 if heap_sizes & 1 else 2,
                                 "guid": 4 if heap_sizes & 2 else 2,
                                 "blob": 4 if heap_sizes & 4 else 2}  # fmt: skip
        for name in SIMPLE:
            sizes[name] = 4 if rows.get(name, 0) > 0xFFFF else 2
        for key, (targets, bits) in CODED.items():
            biggest = max((rows.get(t, 0) for t in targets), default=0)
            sizes[key] = 4 if biggest > (0xFFFF >> bits) else 2
        return sizes

    @staticmethod
    def qualified(name: bytes | None, namespace: bytes | None) -> bytes | None:
        """`<namespace>.<name>`, cut at the first backtick."""
        if not name:
            return namespace
        joined = name if not namespace else namespace + b"." + name
        cut = joined.find(b"`")
        return joined if cut < 0 else joined[:cut]

    @staticmethod
    def is_nested(flags: int) -> bool:
        return isinstance(flags, int) and flags & 7 in (2, 3, 4, 5, 6, 7)

    @staticmethod
    def i32(value: int) -> int:
        value &= 0xFFFFFFFF
        return value - (1 << 32) if value & 0x80000000 else value


s, g, b = Index("string"), Index("guid"), Index("blob")


class Blob:
    """A compressed-integer reader over a signature blob (ECMA-335 II.23.2): position and bytes left."""

    __slots__ = ("at", "cur", "left")

    def __init__(self, cur: Cursor, at: int, left: int) -> None:
        self.cur, self.at, self.left = cur, at, left

    def _take(self, width: int) -> int:
        v = self.cur.uint(self.at, width, "big")  # blob compressed integers are big-endian
        self.at += width
        self.left -= width
        return 0 if v is ABSENT else v

    def uvint(self) -> int:
        if self.left < 1:
            return 0
        first = self.cur.data[self.at]
        if not first & 0x80:  # the one-byte form (the common case): the byte is already in hand
            self.at += 1
            self.left -= 1
            return first
        if first & 0xC0 == 0x80 and self.left >= 2:
            return self._take(2) & 0x3FFF
        if first & 0xE0 == 0xC0 and self.left >= 4:
            return self._take(4) & 0x1FFFFFFF
        return 0

    def svint(self) -> int:
        if self.left < 1:
            return 0
        first = self.cur.data[self.at]
        if not first & 0x80:
            v = self._take(1)
            t = (v >> 1) | (0xC0 if v & 1 else 0)
            return t - 256 if t & 0x80 else t
        if first & 0xC0 == 0x80 and self.left >= 2:
            v = self._take(2)
            t = ((v >> 1) & 0x3FFF) | (0xE000 if v & 1 else 0)
            return t - 0x10000 if t & 0x8000 else t
        if first & 0xE0 == 0xC0 and self.left >= 4:
            v = self._take(4)
            t = ((v >> 1) & 0x1FFFFFFF) | (0xF0000000 if v & 1 else 0)
            return t - (1 << 32) if t & 0x80000000 else t
        return 0


class Heaps:
    """Readers over the metadata heaps (strings, blobs) once their file offsets are known."""

    __slots__ = ("_blob_cache", "_cache", "blobs", "cur", "str_size", "strings")

    def __init__(self, cur: Cursor, strings: int, str_size: int, blobs: int) -> None:
        self.cur, self.strings, self.str_size, self.blobs = cur, strings, str_size, blobs
        self._cache: dict[
            int, bytes | None
        ] = {}  # one string index is read many times across types
        self._blob_cache: dict[
            int, tuple[int, int]
        ] = {}  # likewise one blob index (shared signatures)

    def text(self, index: Any) -> bytes | None:
        if not isinstance(index, int):  # an index read past the end of the file is undefined
            return None
        if index in self._cache:
            return self._cache[index]
        start = self.strings + index
        result: bytes | None
        if not (0 <= start < self.cur.n and index < self.str_size):
            result = None
        else:
            end = self.cur.data.find(b"\x00", start)
            result = None if end < 0 or end - start > 1024 else self.cur.data[start:end]
        self._cache[index] = result
        return result

    def blob_at(self, index: Any) -> tuple[int, int]:
        """(start-of-bytes, length) for a blob-heap entry; (0, 0) when the prefix does not fit."""
        if not isinstance(index, int):
            return 0, 0
        hit = self._blob_cache.get(index)
        if hit is not None:
            return hit
        result = self._locate_blob(index)
        self._blob_cache[index] = result
        return result

    def _locate_blob(self, index: int) -> tuple[int, int]:
        at = self.blobs + index
        cur = self.cur
        if not cur.fits(at, 1):
            return 0, 0
        first = cur.data[at]
        if first & 0x80 == 0:
            size, length = 1, first
        elif first & 0xC0 == 0x80 and cur.fits(at, 2):
            size, length = 2, ((first & 0x3F) << 8) | cur.data[at + 1]
        elif at + 4 < cur.n and first & 0xE0 == 0xC0 and cur.fits(at, 4):
            size, length = (
                4,
                ((first & 0x1F) << 24)
                | (cur.data[at + 1] << 16)
                | (cur.data[at + 2] << 8)
                | cur.data[at + 3],
            )
        else:
            return 0, 0
        if not cur.fits(at, (size + length) & 0xFFFFFFFF):
            return 0, length
        return at + size, length


class Tables:
    """The "#~" stream walked once: the present tables, their row counts, the index sizes, and a Grid per
    table (driven by the catalog). Nothing here interprets a table — it only locates and sizes them."""

    __slots__ = ("_bulk", "completed", "cur", "grids", "resource_base", "rows", "sizes")

    CATALOG: ClassVar[dict[int, tuple[str | None, Layout]]] = {
        0x00: (
            "module",
            Layout((("gen", U16), ("name", s), ("mvid", g), ("enc", g), ("encbase", g))),
        ),
        0x01: (
            "typeref",
            Layout((("scope", Index("resolutionscope")), ("name", s), ("namespace", s))),
        ),
        0x02: (
            "typedef",
            Layout(
                (
                    ("flags", U32),
                    ("name", s),
                    ("namespace", s),
                    ("extends", Index("typedeforref")),
                    ("fields", Index("field")),
                    ("methods", Index("methoddef")),
                )
            ),
        ),
        0x03: (None, Layout((("_", Index("field")),))),  # FieldPtr
        0x04: ("field", Layout((("flags", U16), ("name", s), ("sig", b)))),
        0x05: (None, Layout((("_", Index("methoddef")),))),  # MethodPtr
        0x06: (
            "methoddef",
            Layout(
                (
                    ("rva", U32),
                    ("impl", U16),
                    ("flags", U16),
                    ("name", s),
                    ("sig", b),
                    ("params", Index("param")),
                )
            ),
        ),
        0x07: (None, Layout((("_", Index("param")),))),  # ParamPtr
        0x08: ("param", Layout((("flags", U16), ("seq", U16), ("name", s)))),
        0x09: (
            "interfaceimpl",
            Layout((("cls", Index("typedef")), ("iface", Index("typedeforref")))),
        ),
        0x0A: (
            "memberref",
            Layout((("cls", Index("memberrefparent")), ("name", s), ("sig", b))),
        ),
        0x0B: (
            "constant",
            Layout((("type", U8), ("pad", U8), ("parent", Index("hasconstant")), ("value", b))),
        ),
        0x0C: (
            "customattribute",
            Layout(
                (
                    ("parent", Index("hascustomattribute")),
                    ("type", Index("customattributetype")),
                    ("value", b),
                )
            ),
        ),
        0x0D: (
            None,
            Layout((("parent", Index("hasfieldmarshal")), ("nativetype", b))),
        ),  # FieldMarshal
        0x0E: (
            None,
            Layout((("action", U16), ("parent", Index("hasdeclsecurity")), ("permset", b))),
        ),
        0x0F: (
            None,
            Layout((("pack", U16), ("size", U32), ("parent", Index("typedef")))),
        ),  # ClassLayout
        0x10: (None, Layout((("offset", U32), ("field", Index("field"))))),  # FieldLayout
        0x11: (None, Layout((("sig", b),))),  # StandAloneSig
        0x12: (
            None,
            Layout((("parent", Index("typedef")), ("events", Index("event")))),
        ),  # EventMap
        0x13: (None, Layout((("_", Index("event")),))),  # EventPtr
        0x14: (
            None,
            Layout((("flags", U16), ("name", s), ("type", Index("typedeforref")))),
        ),  # Event
        0x15: (
            None,
            Layout((("parent", Index("typedef")), ("props", Index("property")))),
        ),  # PropertyMap
        0x16: (None, Layout((("_", Index("property")),))),  # PropertyPtr
        0x17: (None, Layout((("flags", U16), ("name", s), ("type", b)))),  # Property
        0x18: (
            None,
            Layout(
                (("sem", U16), ("method", Index("methoddef")), ("assoc", Index("hassemantics")))
            ),
        ),
        0x19: (
            None,
            Layout(
                (
                    ("cls", Index("typedef")),
                    ("body", Index("methoddeforref")),
                    ("decl", Index("methoddeforref")),
                )
            ),
        ),
        0x1A: ("moduleref", Layout((("name", s),))),
        0x1B: ("typespec", Layout((("sig", b),))),
        0x1C: (
            None,
            Layout(
                (
                    ("flags", U16),
                    ("member", Index("memberforwarded")),
                    ("name", s),
                    ("scope", Index("moduleref")),
                )
            ),
        ),
        0x1D: ("fieldrva", Layout((("rva", U32), ("field", Index("field"))))),
        0x1E: (None, Layout((("_", Pad(8)),))),  # EncLog (4+4)
        0x1F: (None, Layout((("_", Pad(4)),))),  # EncMap
        0x20: (
            "assembly",
            Layout(
                (
                    ("hashalg", U32),
                    ("major", U16),
                    ("minor", U16),
                    ("build", U16),
                    ("rev", U16),
                    ("flags", U32),
                    ("pubkey", b),
                    ("name", s),
                    ("culture", s),
                )
            ),
        ),
        0x21: (None, Layout((("_", Pad(4)),))),  # AssemblyProcessor
        0x22: (None, Layout((("_", Pad(12)),))),  # AssemblyOS
        0x23: (
            "assemblyref",
            Layout(
                (
                    ("major", U16),
                    ("minor", U16),
                    ("build", U16),
                    ("rev", U16),
                    ("flags", U32),
                    ("pubkey", b),
                    ("name", s),
                    ("culture", s),
                    ("hash", b),
                )
            ),
        ),
        0x24: (
            None,
            Layout((("_", Pad(4)), ("ref", Index("assemblyref")))),
        ),  # AssemblyRefProcessor
        0x25: (None, Layout((("_", Pad(12)), ("ref", Index("assemblyref"))))),  # AssemblyRefOS
        0x26: (None, Layout((("flags", U32), ("name", s), ("hash", b)))),  # File
        0x27: (
            None,
            Layout(
                (
                    ("flags", U32),
                    ("typedefid", U32),
                    ("name", s),
                    ("namespace", s),
                    ("impl", Index("implementation")),
                )
            ),
        ),
        0x28: (
            "manifestresource",
            Layout(
                (
                    ("offset", U32),
                    ("flags", U32),
                    ("name", s),
                    ("impl", Index("implementation_resource")),
                )
            ),
        ),
        0x29: (
            "nestedclass",
            Layout((("nested", Index("typedef")), ("enclosing", Index("typedef")))),
        ),
        0x2A: (
            "genericparam",
            Layout(
                (("number", U16), ("flags", U16), ("owner", Index("typeormethod")), ("name", s))
            ),
        ),
        0x2B: (None, Layout((("method", Index("methoddeforref")), ("sig", b)))),  # MethodSpec
        0x2C: (
            None,
            Layout((("owner", Index("genericparam")), ("constraint", Index("typedeforref")))),
        ),  # GenericParamConstraint
    }

    def __init__(
        self,
        cur: Cursor,
        grids: dict[str, Grid],
        rows: dict[str, int],
        sizes: dict[str, int],
        resource_base: int,
        completed: bool = True,
    ) -> None:
        self.cur, self.grids, self.rows, self.sizes, self.resource_base = (
            cur,
            grids,
            rows,
            sizes,
            resource_base,
        )
        #: whether the directory walk finished every present table; the reference reads the class table
        #: (its post-walk pass) only when it did, so a walk cut short by a huge count yields no classes.
        self.completed = completed
        #: a table read once in bulk (tuples, name->position, declared count), cached across the classes
        #: that index into it; a method- or parameter-heavy assembly decodes each table a single time.
        self._bulk: dict[str, tuple[list[tuple[Any, ...]], dict[str, int], int] | None] = {}

    def grid(self, name: str) -> Grid | None:
        return self.grids.get(name)

    def bulk(self, name: str) -> tuple[list[tuple[Any, ...]], dict[str, int], int] | None:
        """Table `name` read once with ``Grid.tuples`` (one struct call for the whole table), with its
        name->position map and declared row count; None when the table is absent. Cached per Tables."""
        if name not in self._bulk:
            grid = self.grids.get(name)
            self._bulk[name] = (
                (grid.tuples(), {n: i for i, n in enumerate(grid.names)}, grid.count)
                if grid is not None
                else None
            )
        return self._bulk[name]

    @staticmethod
    def walk(
        cur: Cursor, header: int, resource_base: int, heaps_at: tuple[int, int]
    ) -> Tables | None:
        """Read the "#~" header, the row counts and the table directory; place a Grid at each present
        table using the catalog's Layout. `heaps_at` is unused here but kept for symmetry."""
        if not cur.fits(header, 24):
            return None
        heap_sizes = cur.data[header + 6]
        valid = cur.uint(header + 8, 8)
        if valid is ABSENT:
            return None
        counts = header + 24
        present = [bit for bit in range(64) if (valid >> bit) & 1]
        rows: dict[str, int] = {}
        for i, bit in enumerate(present):
            n = cur.uint(counts + 4 * i, 4)
            name = ROW_FIELDS.get(bit, (None, False))[0]
            if name is not None and n is not ABSENT:
                rows[name] = n
        sizes = Spec.index_sizes(heap_sizes, rows)
        at = counts + 4 * len(present) + (4 if heap_sizes & 0x40 else 0)
        grids: dict[str, Grid] = {}
        for i, bit in enumerate(present):
            n = cur.uint(counts + 4 * i, 4)
            # a count past the end, or one the reference rejects as too large, cuts the walk short
            if n is ABSENT or n > 10000:
                return Tables(cur, grids, rows, sizes, resource_base, completed=False)
            entry = Tables.CATALOG.get(bit)
            if entry is None:
                return Tables(cur, grids, rows, sizes, resource_base, completed=False)
            name, layout = entry
            if name is not None:
                grids[name] = Grid(cur, at, layout, n, sizes)
            at += layout.stride(sizes) * n
        return Tables(cur, grids, rows, sizes, resource_base)


__all__ = ["CODED", "ROW_FIELDS", "SIMPLE", "Blob", "Heaps", "Spec", "Tables", "b", "g", "s"]
