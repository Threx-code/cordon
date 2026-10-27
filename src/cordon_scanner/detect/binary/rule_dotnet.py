"""The .NET reader for cordon-rule: the `dotnet` module's values, built from a declared schema.

A .NET assembly is reached through the PE COM-descriptor directory (ImageMap): the CLI header, the metadata
root ("BSJB"), the stream headers, and from them the string/GUID/blob/user-string heaps and the "#~" table
stream. Each metadata structure is described once as a Layout (ECMA-335 II.22-24); one index-size table,
computed once from the heap-size flags and the row counts, gives every heap index, table index and coded
index its width, so the table rows are read as data, not by hand-written offset arithmetic. Readers grouped
by responsibility — Metadata, Tables, Heaps, Signatures, Members — turn the rows into the rule-visible
values, and `data()` returns plain dicts and lists (an absent key or None is undefined).

Values follow ECMA-335; the element-type names and visibility words are its own. Bounds live in the Cursor,
so a truncated or corrupt assembly yields a defined, partial result rather than a crash.
"""

from __future__ import annotations

from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_layout import (
    ABSENT,
    U8,
    U16,
    U32,
    Cursor,
    Grid,
    ImageMap,
    Index,
    Layout,
    Pad,
)
from cordon_scanner.detect.binary.rule_values import Record, Scalar, Seq

INT, TEXT = Scalar.INT, Scalar.TEXT

# -- constants (ECMA-335 names) ---------------------------------------------

#: signature element type -> the name it prints as (ECMA-335 II.23.1.16)
PRIMITIVES: dict[int, bytes] = {
    0x1: b"void", 0x2: b"bool", 0x3: b"char", 0x4: b"sbyte", 0x5: b"byte", 0x6: b"short",
    0x7: b"ushort", 0x8: b"int", 0x9: b"uint", 0xA: b"long", 0xB: b"ulong", 0xC: b"float",
    0xD: b"double", 0xE: b"string", 0x16: b"TypedReference", 0x18: b"IntPtr", 0x19: b"UIntPtr",
    0x1C: b"object",
}  # fmt: skip
TYPE_VISIBILITY: dict[int, bytes] = {
    3: b"private", 1: b"public", 2: b"public", 4: b"protected", 0: b"internal", 5: b"internal",
    6: b"private protected", 7: b"protected internal",
}  # fmt: skip
METHOD_VISIBILITY: dict[int, bytes] = {
    1: b"private", 2: b"private protected", 3: b"internal", 4: b"protected",
    5: b"protected internal", 6: b"public",
}  # fmt: skip

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
#: Every index whose width is 2 by default and 4 when a relevant row count overflows it. A coded index
#: widens when the largest of its target tables passes (0xFFFF >> tag_bits); a simple index when its own
#: table does. (string/guid/blob come from the heap-size flags instead.)
HEAPS = ("string", "guid", "blob")
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
    def catalog() -> dict[int, tuple[str | None, Layout]]:
        """The declarative catalog: table id -> (reader name or None, row Layout)."""
        s, g, b = Index("string"), Index("guid"), Index("blob")
        return {
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


CATALOG = Spec.catalog()


class Blob:
    """A compressed-integer reader over a signature blob (ECMA-335 II.23.2): position and bytes left."""

    __slots__ = ("at", "cur", "left")

    def __init__(self, cur: Cursor, at: int, left: int) -> None:
        self.cur, self.at, self.left = cur, at, left

    def _take(self, width: int) -> int:
        v = int.from_bytes(self.cur.data[self.at : self.at + width], "big")
        self.at += width
        self.left -= width
        return v

    def uvint(self) -> int:
        if self.left < 1:
            return 0
        first = self.cur.data[self.at]
        if not first & 0x80:
            return self._take(1)
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

    __slots__ = ("blobs", "cur", "str_size", "strings")

    def __init__(self, cur: Cursor, strings: int, str_size: int, blobs: int) -> None:
        self.cur, self.strings, self.str_size, self.blobs = cur, strings, str_size, blobs

    def text(self, index: Any) -> bytes | None:
        if not isinstance(index, int):  # an index read past the end of the file is undefined
            return None
        start = self.strings + index
        if not (0 <= start < self.cur.n and index < self.str_size):
            return None
        end = self.cur.data.find(b"\x00", start)
        if end < 0 or end - start > 1024:
            return None
        return self.cur.data[start:end]

    def blob_at(self, index: Any) -> tuple[int, int]:
        """(start-of-bytes, length) for a blob-heap entry; (0, 0) when the prefix does not fit."""
        if not isinstance(index, int):
            return 0, 0
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


# -- name and signature helpers ---------------------------------------------

MAX_TYPE_DEPTH = 0x10
MAX_NAMESPACE_DEPTH = 0x0A
MAX_ARRAY_RANK = 50
MAX_GEN_PARAM = 1000
MAX_PARAMS = 2000
MAX_METHODS = 20000


class Tables:
    """The "#~" stream walked once: the present tables, their row counts, the index sizes, and a Grid per
    table (driven by the catalog). Nothing here interprets a table — it only locates and sizes them."""

    __slots__ = ("completed", "cur", "grids", "resource_base", "rows", "sizes")

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

    def grid(self, name: str) -> Grid | None:
        return self.grids.get(name)

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
            entry = CATALOG.get(bit)
            if entry is None:
                return Tables(cur, grids, rows, sizes, resource_base, completed=False)
            name, layout = entry
            if name is not None:
                grids[name] = Grid(cur, at, layout, n, sizes)
            at += layout.stride(sizes) * n
        return Tables(cur, grids, rows, sizes, resource_base)


class Signatures:
    """The element-type decoder (ECMA-335 II.23.2.12): one type from a signature blob, spelled as C#."""

    __slots__ = ("heaps", "resolve_name", "tables")

    def __init__(self, heaps: Heaps, tables: Tables, resolve_name: Any) -> None:
        self.heaps, self.tables, self.resolve_name = heaps, tables, resolve_name

    #: element kinds that wrap one inner type in a fixed prefix/suffix (ECMA-335 II.23.2.12)
    WRAP: ClassVar[dict[int, tuple[bytes, bytes]]] = {
        0x0F: (b"Ptr<", b">"),  # PTR
        0x10: (b"ref ", b""),  # BYREF
        0x1D: (b"", b"[]"),  # SZARRAY
    }
    NAMED: ClassVar[frozenset[int]] = frozenset(
        {0x11, 0x12}
    )  # CLASS / VALUETYPE: a TypeDefOrRef index
    GENVAR: ClassVar[dict[int, bool]] = {
        0x13: False,
        0x1E: True,
    }  # VAR (class) / MVAR (method) parameter
    MODIFIER: ClassVar[frozenset[int]] = frozenset(
        {0x1F, 0x20}
    )  # CMOD_REQD / CMOD_OPT: a skipped token

    def type(
        self, blob: Blob, class_gp: list[bytes], method_gp: list[bytes] | None, depth: int
    ) -> bytes | None:
        """One type, dispatched by element kind through the tables above; the three compound kinds
        (array, generic instance, function pointer) have their own shape below."""
        cur = self.heaps.cur
        if blob.left < 1 or not cur.fits(blob.at, 1) or depth > MAX_TYPE_DEPTH:
            return None
        kind = cur.data[blob.at]
        blob.at += 1
        blob.left -= 1
        if kind in PRIMITIVES:
            return PRIMITIVES[kind]
        if kind in Signatures.WRAP:
            inner = self.type(blob, class_gp, method_gp, depth + 1)
            if inner is None:
                return None
            prefix, suffix = Signatures.WRAP[kind]
            return prefix + inner + suffix
        if kind in Signatures.NAMED:
            named: bytes | None = self.resolve_name(blob.uvint(), class_gp, method_gp, depth + 1)
            return named
        if kind in Signatures.GENVAR:
            params = method_gp if Signatures.GENVAR[kind] else class_gp
            index = blob.uvint()
            return params[index] if params is not None and index < len(params) else None
        if kind in Signatures.MODIFIER:
            blob.uvint()
            return self.type(blob, class_gp, method_gp, depth + 1)
        if kind == 0x14:  # ARRAY
            return self._sized_array(blob, self.type(blob, class_gp, method_gp, depth + 1))
        if kind == 0x15:  # GENERICINST: base<arg,arg,...>
            base = self.type(blob, class_gp, method_gp, depth + 1)
            if base is None:
                return None
            count = blob.uvint()
            if count > MAX_GEN_PARAM:
                return None
            return base + b"<" + self._list(blob, count, b",", class_gp, method_gp, depth) + b">"
        if kind == 0x1B:  # FNPTR: a method signature, FnPtr<return(params)>
            if blob.left <= 0:
                return None
            blob.at += 1  # the calling convention byte
            blob.left -= 1
            count = blob.uvint()
            if count > MAX_PARAMS:
                return None
            ret = self.type(blob, class_gp, method_gp, depth + 1)
            if ret is None:
                return None
            return (
                b"FnPtr<"
                + ret
                + b"("
                + self._list(blob, count, b", ", class_gp, method_gp, depth)
                + b")>"
            )
        return None

    def _list(
        self,
        blob: Blob,
        count: int,
        sep: bytes,
        class_gp: list[bytes],
        method_gp: list[bytes] | None,
        depth: int,
    ) -> bytes:
        """`count` inner types joined by `sep`; the separator is placed before every item past the first
        by position (so a dropped None still leaves its separator, as the reference builds the text)."""
        out = b""
        for i in range(count):
            part = self.type(blob, class_gp, method_gp, depth + 1)
            if part is not None:
                out += (sep if i else b"") + part
        return out

    def _sized_array(self, blob: Blob, element: bytes | None) -> bytes | None:
        if element is None:
            return None
        rank = blob.uvint()
        if not rank or rank > MAX_ARRAY_RANK:
            return None
        n_sizes = blob.uvint()
        if n_sizes > rank:
            return None
        sizes = [Spec.i32(blob.uvint()) for _ in range(n_sizes)]
        n_lo = blob.uvint()
        if n_lo > rank:
            return None
        lo = []
        for i in range(n_lo):
            bound = blob.svint()
            lo.append(bound)
            if n_sizes > i and bound != 0:
                sizes[i] = Spec.i32(sizes[i] + bound - 1)
        out = element + b"["
        for i in range(rank):
            if n_sizes > i or n_lo > i:
                if n_lo > i and lo[i] != 0:
                    out += b"%d..." % lo[i]
                if n_sizes > i:
                    out += b"%d" % sizes[i]
            if i + 1 != rank:
                out += b","
        return out + b"]"


class Names:
    """Type-name resolution over the typedef/typeref/typespec tables and nested-type chains."""

    __slots__ = ("enclosing", "heaps", "interfaces", "signatures", "tables")

    def __init__(self, heaps: Heaps, tables: Tables) -> None:
        self.heaps, self.tables = heaps, tables
        self.signatures = Signatures(heaps, tables, self.coded)
        # one pass each, so name resolution is a lookup rather than a per-type table scan
        self.enclosing: dict[int, int] = {}  # a nested type index -> its first enclosing type index
        ng = tables.grid("nestedclass")
        if ng is not None:
            for row in ng:
                self.enclosing.setdefault(row["nested"], row["enclosing"])
        self.interfaces: dict[
            int, list[int]
        ] = {}  # a class index -> the interface indices it implements
        ig = tables.grid("interfaceimpl")
        if ig is not None:
            for row in ig:
                self.interfaces.setdefault(row["cls"], []).append(row["iface"])

    def coded(
        self, coded: Any, class_gp: list[bytes], method_gp: list[bytes] | None, depth: int
    ) -> bytes | None:
        """A TypeDefOrRef coded index resolved to a full name."""
        if not isinstance(coded, int):
            return None
        index = coded >> 2
        if not index:
            return None
        table = coded & 3
        if table == 0:
            row = self._row("typedef", index)
            if row is None:
                return None
            name = self.heaps.text(row["name"])
            namespace = self.heaps.text(row["namespace"])
            if Spec.is_nested(row["flags"]):
                return Spec.qualified(name, Spec.qualified(namespace, self.nesting(index, 1)))
            return Spec.qualified(name, namespace)
        if table == 1:
            row = self._row("typeref", index)
            if row is None:
                return None
            return Spec.qualified(self.heaps.text(row["name"]), self.heaps.text(row["namespace"]))
        if table == 2:
            row = self._row("typespec", index)
            if row is None:
                return None
            start, length = self.heaps.blob_at(row["sig"])
            if start:
                return self.signatures.type(
                    Blob(self.heaps.cur, start, length), class_gp, None, depth
                )
        return None

    def _row(self, name: str, index: int) -> dict[str, Any] | None:
        grid = self.tables.grid(name)
        return grid.row(index - 1) if grid is not None else None

    def nesting(self, nested_idx: int, depth: int) -> bytes | None:
        if depth > MAX_NAMESPACE_DEPTH:
            return None
        enc = self.enclosing.get(nested_idx)
        if enc is None:
            return None
        outer = self._row("typedef", enc)
        if outer is None:
            return None
        name = self.heaps.text(outer["name"])
        if name == b"<Module>":
            return None
        namespace = self.heaps.text(outer["namespace"])
        if Spec.is_nested(outer["flags"]) and enc != nested_idx:
            return Spec.qualified(name, Spec.qualified(namespace, self.nesting(enc, depth + 1)))
        return Spec.qualified(name, namespace)


class Dotnet:
    """The `dotnet` module reader."""

    CLI_SIZE: ClassVar[int] = 72
    MD_MAGIC: ClassVar[int] = 0x424A5342

    _version = Record({"major": INT, "minor": INT, "build_number": INT, "revision_number": INT})
    _method = Record({
        "generic_parameters": Seq(TEXT), "number_of_generic_parameters": INT,
        "parameters": Seq(Record({"name": TEXT, "type": TEXT})), "number_of_parameters": INT,
        "return_type": TEXT, "abstract": INT, "final": INT, "virtual": INT, "static": INT, "visibility": TEXT, "name": TEXT,
    })  # fmt: skip
    _class = Record({
        "fullname": TEXT, "name": TEXT, "namespace": TEXT, "visibility": TEXT, "type": TEXT, "abstract": INT, "sealed": INT,
        "number_of_generic_parameters": INT, "generic_parameters": Seq(TEXT), "number_of_base_types": INT,
        "base_types": Seq(TEXT), "number_of_methods": INT, "methods": Seq(_method),
    })  # fmt: skip
    SCHEMA: ClassVar[Record] = Record({
        "is_dotnet": INT, "version": TEXT, "module_name": TEXT,
        "streams": Seq(Record({"name": TEXT, "offset": INT, "size": INT})), "number_of_streams": INT,
        "guids": Seq(TEXT), "number_of_guids": INT,
        "resources": Seq(Record({"offset": INT, "length": INT, "name": TEXT})), "number_of_resources": INT,
        "classes": Seq(_class), "number_of_classes": INT,
        "assembly_refs": Seq(Record({"version": _version, "public_key_or_token": TEXT, "name": TEXT})),
        "number_of_assembly_refs": INT,
        "assembly": Record({"version": _version, "name": TEXT, "culture": TEXT}),
        "modulerefs": Seq(TEXT), "number_of_modulerefs": INT, "user_strings": Seq(TEXT),
        "number_of_user_strings": INT, "typelib": TEXT, "constants": Seq(TEXT), "number_of_constants": INT,
        "field_offsets": Seq(INT), "number_of_field_offsets": INT,
    })  # fmt: skip

    #: the sequence fields the reference always presents (empty when nothing fills them)
    ARRAYS: ClassVar[tuple[str, ...]] = (
        "streams", "guids", "resources", "classes", "assembly_refs", "modulerefs",
        "user_strings", "constants", "field_offsets",
    )  # fmt: skip

    @staticmethod
    def data(file: bytes) -> dict[str, Any]:
        out: dict[str, Any] = {k: {} for k in Dotnet.ARRAYS}
        out["assembly"] = {}
        cur = Cursor(file)
        img = ImageMap.accept(cur)
        if img is not None:
            Dotnet._read(out, cur, img)
        return out

    @staticmethod
    def _read(out: dict[str, Any], cur: Cursor, img: ImageMap) -> None:
        d = img.directory(14)
        if (
            d is None
        ):  # the directory entry itself is unreachable: the reference leaves is_dotnet unset
            return
        if (
            d[0] == 0
            or (cli := img.to_offset(d[0])) < 0
            or not cur.fits(cli, Dotnet.CLI_SIZE)
            or cur.uint(cli, 4) != Dotnet.CLI_SIZE
        ):
            out["is_dotnet"] = 0
            return
        md = img.to_offset(cur.uint(cli + 8, 4))
        if md < 0 or not cur.fits(md, 16) or cur.uint(md, 4) != Dotnet.MD_MAGIC:
            out["is_dotnet"] = 0
            return
        md_len = cur.uint(md + 12, 4)
        if not (0 < md_len <= 255 and md_len % 4 == 0 and cur.fits(md + 16, md_len)):
            out["is_dotnet"] = 0
            return
        if img.is64 and cur.uint(img.opt + 108, 4) < 14:  # NumberOfRvaAndSizes (PE32+ offset)
            out["is_dotnet"] = 0
            return
        out["is_dotnet"] = 1
        version = cur.blob(md + 16, md_len)
        if version is not ABSENT:
            nul = version.find(b"\x00")
            if nul >= 0:  # the reference records the version only when it is NUL-terminated
                out["version"] = version[:nul]
        at = md + 16 + md_len + 2
        if not cur.fits(at, 2):
            return
        streams = Dotnet._stream_headers(out, cur, at + 2, md, cur.data[at])
        if "guid" in streams:
            Dotnet._guid_heap(out, cur, md, streams["guid"])
        if {"tilde", "string", "blob"} <= streams.keys():
            resource_base = img.to_offset(cur.uint(cli + 24, 4))
            Dotnet._table_stream(out, cur, md, streams, resource_base, img)
        if "us" in streams:
            Dotnet._us_heap(out, cur, md, streams["us"])

    @staticmethod
    def _stream_headers(
        out: dict[str, Any], cur: Cursor, at: int, root: int, count: int
    ) -> dict[str, tuple[int, int]]:
        found: dict[str, tuple[int, int]] = {}
        seq: dict[int, Any] = {}
        i = 0
        while i < count:
            if not cur.fits(at, 8) or not cur.fits(at + 8, 32):
                break
            raw = cur.data[at + 8 : at + 8 + 32]
            nul = raw.find(b"\x00")
            if nul < 0:
                break
            name = raw[:nul]
            offset, size = cur.uint(at, 4), cur.uint(at + 4, 4)
            seq[i] = {"name": name, "offset": root + offset, "size": size}
            for prefix, key in ((b"#~", "tilde"), (b"#-", "tilde"), (b"#GUID", "guid"), (b"#Strings", "string"),
                                (b"#Blob", "blob"), (b"#US", "us")):  # fmt: skip
                if name.startswith(prefix) and key not in found:
                    found[key] = (offset, size)
                    break
            at += 8 + len(name) + 4 - (len(name) % 4)
            i += 1
        out["streams"] = seq
        out["number_of_streams"] = i
        return found

    @staticmethod
    def _guid_heap(out: dict[str, Any], cur: Cursor, root: int, stream: tuple[int, int]) -> None:
        at = root + stream[0]
        size = min(stream[1], 256)
        seq: dict[int, Any] = {}
        i = 0
        while size >= 16 and cur.fits(at, 16):
            a, b, c = cur.uint(at, 4), cur.uint(at + 4, 2), cur.uint(at + 6, 2)
            rest = cur.data[at + 8 : at + 16]
            seq[i] = b"%08x-%04x-%04x-%s-%s" % (
                a,
                b,
                c,
                rest[:2].hex().encode(),
                rest[2:].hex().encode(),
            )
            i += 1
            size -= 16
            at += 16
        out["guids"] = seq
        out["number_of_guids"] = i

    @staticmethod
    def _us_heap(out: dict[str, Any], cur: Cursor, root: int, stream: tuple[int, int]) -> None:
        size = stream[1]
        at = root + stream[0]
        end = at + size
        if size == 0 or not cur.fits(at, size) or cur.data[at] != 0:
            return
        at += 1
        heap = Heaps(
            cur, 0, 0, root + stream[0]
        )  # reuse the blob-prefix decode over the #US stream
        seq: dict[int, Any] = {}
        i = 0
        while at < end:
            start, length = heap.blob_at(at - heap.blobs)
            if not start:  # an invalid prefix or a blob running past the end stops the walk
                break
            at = start
            if length > 0:  # a user string's terminal byte is not kept
                length -= 1
            if length > 0 and cur.fits(at, length):
                seq[i] = cur.data[at : at + length]
                at += length
                i += 1
        out["user_strings"] = seq
        out["number_of_user_strings"] = i

    @staticmethod
    def _table_stream(
        out: dict[str, Any],
        cur: Cursor,
        root: int,
        streams: dict[str, tuple[int, int]],
        resource_base: int,
        img: ImageMap,
    ) -> None:
        header = root + streams["tilde"][0]
        strings = root + streams["string"][0]
        str_size = streams["string"][1]
        blobs = root + streams["blob"][0]
        tables = Tables.walk(cur, header, resource_base, (strings, str_size))
        if tables is None:
            return
        heaps = Heaps(cur, strings, str_size, blobs)
        Dotnet._module_name(out, heaps, tables)
        Dotnet._modulerefs(out, heaps, tables)
        Dotnet._field_offsets(out, img, tables)
        Dotnet._assembly(out, heaps, tables)
        Dotnet._assembly_refs(out, heaps, tables)
        Dotnet._literals(out, cur, heaps, tables)
        Dotnet._resources(out, cur, heaps, tables, resource_base)
        Dotnet._library_guid(out, cur, heaps, tables)
        if (
            tables.completed
        ):  # classes are the reference's post-walk pass, skipped if the walk was cut short
            Dotnet._members(out, heaps, tables)

    @staticmethod
    def _module_name(out: dict[str, Any], heaps: Heaps, tables: Tables) -> None:
        # the module table is a singleton the reference reads at its offset, not by row count
        grid = tables.grid("module")
        if grid is None or not grid.cur.fits(grid.base, 18):
            return
        row = grid.layout.read(grid.cur, grid.base, grid.sizes)
        name = heaps.text(row["name"])
        if name is not None:
            out["module_name"] = name

    @staticmethod
    def _modulerefs(out: dict[str, Any], heaps: Heaps, tables: Tables) -> None:
        grid = tables.grid("moduleref")
        if grid is None:
            return
        seq: dict[int, Any] = {}
        for row in grid:
            name = heaps.text(row["name"])
            if name is not None:
                seq[len(seq)] = name
        out["modulerefs"] = seq
        out["number_of_modulerefs"] = len(seq)

    @staticmethod
    def _field_offsets(out: dict[str, Any], img: ImageMap, tables: Tables) -> None:
        grid = tables.grid("fieldrva")
        if grid is None:
            return
        seq: dict[int, Any] = {}
        for row in grid:
            rva = row["rva"]  # FieldRVA.rva is a virtual address; keep only those that resolve
            off = img.to_offset(rva) if rva is not ABSENT else -1
            if off >= 0:
                seq[len(seq)] = off
        out["field_offsets"] = seq
        out["number_of_field_offsets"] = len(seq)

    @staticmethod
    def _assembly(out: dict[str, Any], heaps: Heaps, tables: Tables) -> None:
        # the assembly table is a singleton read at its offset whenever it fits, not by row count
        grid = tables.grid("assembly")
        if grid is None or not grid.cur.fits(grid.base, grid.layout.stride(grid.sizes)):
            return
        row = grid.layout.read(grid.cur, grid.base, grid.sizes)
        asm: dict[str, Any] = {"version": {"major": row["major"], "minor": row["minor"],
                                           "build_number": row["build"], "revision_number": row["rev"]}}  # fmt: skip
        name = heaps.text(row["name"])
        if name is not None:
            asm["name"] = name
        culture = heaps.text(row["culture"])
        if culture:
            asm["culture"] = culture
        out["assembly"] = asm

    @staticmethod
    def _assembly_refs(out: dict[str, Any], heaps: Heaps, tables: Tables) -> None:
        grid = tables.grid("assemblyref")
        if grid is None:
            return
        seq: dict[int, Any] = {}
        count = 0
        for i in range(grid.count):
            row = grid.row(i)  # None once a row runs past the end of the file
            if row is None:
                break
            count += 1
            ref: dict[str, Any] = {"version": {"major": row["major"], "minor": row["minor"],
                                               "build_number": row["build"], "revision_number": row["rev"]}}  # fmt: skip
            seq[i] = ref
            start, length = heaps.blob_at(row["pubkey"])
            if not start:  # an invalid or short public-key blob ends this row at the version
                continue
            if length > 0:
                ref["public_key_or_token"] = heaps.cur.data[start : start + length]
            name = heaps.text(row["name"])
            if name is not None:
                ref["name"] = name
        out["assembly_refs"] = seq
        out["number_of_assembly_refs"] = count

    @staticmethod
    def _literals(out: dict[str, Any], cur: Cursor, heaps: Heaps, tables: Tables) -> None:
        grid = tables.grid("constant")
        if grid is None:
            return
        seq: dict[int, Any] = {}
        for row in grid:
            if (
                row["type"] != 0x0E or row["pad"] != 0
            ):  # the reference tests the type and pad as one u16
                continue
            start, length = heaps.blob_at(row["value"])
            if not start or start + length >= cur.n:
                continue
            seq[len(seq)] = cur.data[start : start + length]
        out["constants"] = seq
        out["number_of_constants"] = len(seq)

    @staticmethod
    def _resources(
        out: dict[str, Any], cur: Cursor, heaps: Heaps, tables: Tables, resource_base: int
    ) -> None:
        grid = tables.grid("manifestresource")
        if grid is None:
            return
        seq: dict[int, Any] = {}
        count = 0
        for i in range(grid.count):
            row = grid.row(i)  # the reference stops the walk where a row no longer fits
            if row is None:
                break
            count += 1  # every visited row counts, even one with no in-file resource
            entry: dict[str, Any] = {}
            name = heaps.text(row["name"])
            if name is not None:
                entry["name"] = name
            if row["impl"] == 0 and row["offset"] is not ABSENT:  # the resource lives in this file
                where = resource_base + row["offset"]
                if cur.fits(where, 4):
                    entry["offset"] = where + 4
                    entry["length"] = cur.uint(where, 4)
            if (
                entry
            ):  # a never-set slot (external, no name) leaves a gap, as the reference callback does
                seq[i] = entry
        out["resources"] = seq
        out["number_of_resources"] = count

    @staticmethod
    def _library_guid(out: dict[str, Any], cur: Cursor, heaps: Heaps, tables: Tables) -> None:
        """The type-library GUID a GuidAttribute on the assembly carries. Each custom attribute whose
        parent is the assembly and whose type is a MemberRef is chased MemberRef -> TypeRef to read the
        attribute class name; a GuidAttribute's value blob holds the GUID string (ECMA-335 II.23.3)."""
        attrs, members, typerefs = (
            tables.grid("customattribute"),
            tables.grid("memberref"),
            tables.grid("typeref"),
        )
        if attrs is None or members is None or typerefs is None:
            return
        s = tables.sizes
        parent_w, type_w = s["hascustomattribute"], s["customattributetype"]
        member_stride, typeref_stride = members.layout.stride(s), typerefs.layout.stride(s)
        stride = attrs.layout.stride(s)
        row = attrs.base
        for _ in range(attrs.count):
            if not cur.fits(row, stride):
                break
            at = row
            row += stride
            if cur.uint(at, parent_w) & 0x1F != 0x0E:  # the parent must be the assembly
                continue
            coded = cur.uint(at + parent_w, type_w)
            if coded & 7 != 3:  # the attribute type must be a MemberRef
                continue
            member = members.base + member_stride * (max(coded >> 3, 1) - 1)
            if not cur.fits(member, member_stride):
                break
            parent = cur.uint(member, s["memberrefparent"])
            if parent & 7 != 1:  # the member's class must be a TypeRef
                continue
            ref = typerefs.base + typeref_stride * (max(parent >> 3, 1) - 1)
            if not cur.fits(ref, typeref_stride):
                break
            name = heaps.text(cur.uint(ref + s["resolutionscope"], s["string"]))
            if name is not None and not name.startswith(b"GuidAttribute"):
                continue
            blob_index = cur.uint(at + parent_w + type_w, s["blob"])
            if not blob_index:
                continue
            start, length = heaps.blob_at(blob_index)
            if (
                not start or length < 3 or cur.uint(start, 2) != 1
            ):  # the attribute-value prolog is 0x0001
                continue
            str_len = cur.data[start + 2]
            text_at = start + 3
            if text_at + str_len > cur.n:
                continue
            if cur.data[text_at] in (0xFF, 0x00):  # a packed-length 0xFF/0x00 means an empty string
                out["typelib"] = b""
            else:
                text = cur.data[text_at : text_at + str_len]
                nul = text.find(b"\x00")
                out["typelib"] = text if nul < 0 else text[:nul]

    @staticmethod
    def _members(out: dict[str, Any], heaps: Heaps, tables: Tables) -> None:
        out["number_of_classes"] = (
            0  # the reference's class pass always reports a count once it runs
        )
        typedef = tables.grid("typedef")
        if typedef is None:
            return
        names = Names(heaps, tables)
        gparams = Dotnet._generic_params(tables, heaps)
        classes: dict[int, Any] = {}
        kept = 0
        for idx in range(typedef.count):
            row = typedef.row(idx)
            if row is None:
                continue
            name = heaps.text(row["name"])
            if not name:
                continue
            tick = name.find(b"`")
            if tick == 0 or name == b"<Module>":
                continue
            flags = row["flags"]
            c: dict[str, Any] = {
                "name": name[:tick] if tick > 0 else name,
                "visibility": TYPE_VISIBILITY[flags & 7],
                "type": {0: b"class", 0x20: b"interface"}[flags & 0x20],
                "abstract": int(bool(flags & 0x80)),
                "sealed": int(bool(flags & 0x100)),
            }
            namespace = heaps.text(row["namespace"])
            if Spec.is_nested(flags):
                namespace = Spec.qualified(namespace, names.nesting(idx + 1, 1))
            if namespace is not None:
                c["namespace"] = namespace
            fn = Spec.qualified(name, namespace)
            if fn is not None:
                c["fullname"] = fn
            gp = gparams.get((0, idx + 1), [])
            c["number_of_generic_parameters"] = len(gp)
            c["generic_parameters"] = dict(enumerate(gp))
            Dotnet._base_types(c, names, tables, row["extends"], idx + 1, gp)
            c[
                "methods"
            ] = {}  # the reference always presents a methods list, even when it stays empty
            count = Dotnet._method_count(tables, typedef, idx, row["methods"])
            if count <= MAX_METHODS:
                Dotnet._build_methods(c, heaps, tables, names, row["methods"], count, gp, gparams)
            classes[kept] = c
            kept += 1
        out["classes"] = classes
        out["number_of_classes"] = kept

    @staticmethod
    def _generic_params(tables: Tables, heaps: Heaps) -> dict[tuple[int, int], list[bytes]]:
        """Every generic parameter grouped by its owner in one pass, keyed by (owner-is-a-method, owner
        index). An owner with an unnamed parameter reports none; a row past the end makes the reference
        report no generic parameters for anything, so the whole map is then empty."""
        grid = tables.grid("genericparam")
        out: dict[tuple[int, int], list[bytes]] = {}
        if grid is None:
            return out
        poisoned: set[tuple[int, int]] = set()
        for i in range(grid.count):
            if not grid.fits(i):
                return {}
            row = grid.row(i)
            if row is None:
                return {}
            key = (row["owner"] & 1, row["owner"] >> 1)
            if key in poisoned:
                continue
            name = heaps.text(row["name"])
            if not name:
                out[key] = []
                poisoned.add(key)
                continue
            out.setdefault(key, []).append(name)
        return out

    @staticmethod
    def _base_types(
        c: dict[str, Any],
        names: Names,
        tables: Tables,
        extends: int,
        type_idx: int,
        gp: list[bytes],
    ) -> None:
        base: dict[int, Any] = {}
        parent = names.coded(extends, gp, None, 0)
        if parent is not None:
            base[len(base)] = parent
        for iface_coded in names.interfaces.get(type_idx, []):
            iface = names.coded(iface_coded, gp, None, 0)
            if iface is not None:
                base[len(base)] = iface
        c["base_types"] = base
        c["number_of_base_types"] = len(base)

    @staticmethod
    def _method_count(tables: Tables, typedef: Grid, idx: int, method_list: int) -> int:
        if idx + 1 < typedef.count:
            nxt = typedef.row(idx + 1)
            if nxt is not None and nxt["methods"] >= method_list:
                return int(nxt["methods"]) - method_list
            return 0
        methoddef = tables.grid("methoddef")
        total = methoddef.count if methoddef else 0
        return total + 1 - method_list if total >= method_list else 0

    @staticmethod
    def _build_methods(
        c: dict[str, Any],
        heaps: Heaps,
        tables: Tables,
        names: Names,
        method_list: int,
        count: int,
        class_gp: list[bytes],
        gparams: dict[tuple[int, int], list[bytes]],
    ) -> None:
        if (
            not method_list
        ):  # a class with no method list reports no method count, as the reference does
            return
        grid = tables.grid("methoddef")
        methods: dict[int, Any] = {}
        kept = 0
        for off in range(count):
            idx = method_list - 1 + off
            if grid is None or not (0 <= idx < grid.count):  # out of range ends the class's methods
                break
            row = grid.row(idx)
            if row is None:  # a row past the end is skipped, as the reference does
                continue
            name = heaps.text(row["name"])
            if not name:
                continue
            method_gp = gparams.get((1, method_list + off), [])
            start, length = heaps.blob_at(row["sig"])
            if not start or length < 3:
                continue
            blob = Blob(heaps.cur, start, length)
            sig_flags = heaps.cur.data[blob.at]
            blob.at += 1
            blob.left -= 1
            if sig_flags & 0x10:
                blob.uvint()
            n_params = blob.uvint()
            ret = names.signatures.type(blob, class_gp, method_gp, 0)
            if ret is None or n_params > MAX_PARAMS:
                continue
            params = Dotnet._build_params(
                heaps, tables, names, row["params"], n_params, blob, class_gp, method_gp
            )
            if params is None:
                continue
            flags = row["flags"]
            m: dict[str, Any] = {
                "name": name,
                "visibility": METHOD_VISIBILITY.get(flags & 7, b"private"),
                "static": int(bool(flags & 0x10)),
                "virtual": int(bool(flags & 0x40)),
                "final": int(bool(flags & 0x20)),
                "abstract": int(bool(flags & 0x400)),
                "number_of_generic_parameters": len(method_gp),
                "generic_parameters": dict(enumerate(method_gp)),
            }
            if isinstance(params, dict):
                m["number_of_parameters"] = n_params
                m["parameters"] = params
            if name not in (b".ctor", b".cctor"):
                m["return_type"] = ret
            methods[kept] = m
            kept += 1
        c["methods"] = methods
        c["number_of_methods"] = kept

    @staticmethod
    def _build_params(
        heaps: Heaps,
        tables: Tables,
        names: Names,
        param_list: int,
        count: int,
        blob: Blob,
        class_gp: list[bytes],
        method_gp: list[bytes],
    ) -> Any:
        if not param_list:
            return True
        grid = tables.grid("param")
        out: dict[int, Any] = {}
        for off in range(count):
            idx = param_list - 1 + off
            if grid is not None and 0 <= idx < grid.count:
                # the row is within the table: it must fit, or the reference drops the whole method
                prow = grid.row(idx)
                if prow is None:
                    return None
                name = heaps.text(prow["name"])
            else:  # no row for this parameter: a synthetic name, as the reference uses
                name = b"P_%d" % off
            kind = names.signatures.type(blob, class_gp, method_gp, 0)
            if kind is None:
                return None
            entry: dict[str, Any] = {"type": kind}
            if name is not None:
                entry["name"] = name
            out[off] = entry
        return out


__all__ = ["Dotnet"]
