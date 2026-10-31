"""The DEX reader for cordon-rule: the `dex` module's values as a condition sees them.

A Dalvik executable (Android's dex format, versions 035 to 039) is read from its header through the
string, type, prototype, field and method id tables, the map list, and the class definitions, whose
class data names each encoded field and method through those tables: the field or method's own name,
its class's descriptor, and its type or prototype's shorty. A method's code item follows when it has
one. Every table is a Layout read in one call; the ULEB128 counts and the encoded entries are read a
byte at a time through the Cursor.

The values are the reference's, quirks included: a string's bytes start one byte after its length,
whatever that length's encoding took; the id tables are read in order and the walk ends at the first
that does not fit; an encoded entry whose ids do not resolve keeps the fields read so far at its index,
which the next entry overwrites; a table index past 0x80000 resolves to nothing. A file that is not a
dex answers undefined for everything but the constants.
"""

from __future__ import annotations

from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.layout import U16, U32, Blob, Cursor, Grid, Layout
from cordon_scanner.detect.binary.modules.values import Call, Record, Scalar, Seq, Sig

INT, TEXT = Scalar.INT, Scalar.TEXT
MASK32 = (1 << 32) - 1


class DexTables:
    """The `dex` module's constants, in the reference's declaration order."""

    MAGICS: ClassVar[dict[str, bytes]] = {
        f"DEX_FILE_MAGIC_{v}": b"dex\n" + v.encode() + b"\x00"
        for v in ("035", "036", "037", "038", "039")
    }
    INTEGERS: ClassVar[dict[str, int]] = {
        "ENDIAN_CONSTANT": 0x12345678,
        "REVERSE_ENDIAN_CONSTANT": 0x78563412,
        "NO_INDEX": 0xFFFFFFFF,
        # access flags
        "ACC_PUBLIC": 0x1,
        "ACC_PRIVATE": 0x2,
        "ACC_PROTECTED": 0x4,
        "ACC_STATIC": 0x8,
        "ACC_FINAL": 0x10,
        "ACC_SYNCHRONIZED": 0x20,
        "ACC_VOLATILE": 0x40,
        "ACC_BRIDGE": 0x40,
        "ACC_TRANSIENT": 0x80,
        "ACC_VARARGS": 0x80,
        "ACC_NATIVE": 0x100,
        "ACC_INTERFACE": 0x200,
        "ACC_ABSTRACT": 0x400,
        "ACC_STRICT": 0x800,
        "ACC_SYNTHETIC": 0x1000,
        "ACC_ANNOTATION": 0x2000,
        "ACC_ENUM": 0x4000,
        "ACC_CONSTRUCTOR": 0x10000,
        "ACC_DECLARED_SYNCHRONIZED": 0x20000,
        # map item types
        "TYPE_HEADER_ITEM": 0x0000,
        "TYPE_STRING_ID_ITEM": 0x0001,
        "TYPE_TYPE_ID_ITEM": 0x0002,
        "TYPE_PROTO_ID_ITEM": 0x0003,
        "TYPE_FIELD_ID_ITEM": 0x0004,
        "TYPE_METHOD_ID_ITEM": 0x0005,
        "TYPE_CLASS_DEF_ITEM": 0x0006,
        "TYPE_CALL_SITE_ID_ITEM": 0x0007,
        "TYPE_METHOD_HANDLE_ITEM": 0x0008,
        "TYPE_MAP_LIST": 0x1000,
        "TYPE_TYPE_LIST": 0x1001,
        "TYPE_ANNOTATION_SET_REF_LIST": 0x1002,
        "TYPE_ANNOTATION_SET_ITEM": 0x1003,
        "TYPE_CLASS_DATA_ITEM": 0x2000,
        "TYPE_CODE_ITEM": 0x2001,
        "TYPE_STRING_DATA_ITEM": 0x2002,
        "TYPE_DEBUG_INFO_ITEM": 0x2003,
        "TYPE_ANNOTATION_ITEM": 0x2004,
        "TYPE_ENCODED_ARRAY_ITEM": 0x2005,
        "TYPE_ANNOTATIONS_DIRECTORY_ITEM": 0x2006,
    }
    MAX_INDEX: ClassVar[int] = 0x80000
    """A table index past this resolves to nothing (the reference's bound on lookups)."""


class Shape:
    """Every dex structure described once (source.android.com's dex-format)."""

    HEADER: ClassVar[Layout] = Layout((
        ("magic", Blob(8)), ("checksum", U32), ("signature", Blob(20)), ("file_size", U32),
        ("header_size", U32), ("endian_tag", U32), ("link_size", U32), ("link_offset", U32),
        ("map_offset", U32), ("string_ids_size", U32), ("string_ids_offset", U32),
        ("type_ids_size", U32), ("type_ids_offset", U32), ("proto_ids_size", U32),
        ("proto_ids_offset", U32), ("field_ids_size", U32), ("field_ids_offset", U32),
        ("method_ids_size", U32), ("method_ids_offset", U32), ("class_defs_size", U32),
        ("class_defs_offset", U32), ("data_size", U32), ("data_offset", U32),
    ))  # fmt: skip
    TYPE_ID: ClassVar[Layout] = Layout((("descriptor_idx", U32),))
    PROTO_ID: ClassVar[Layout] = Layout(
        (("shorty_idx", U32), ("return_type_idx", U32), ("parameters_offset", U32))
    )
    FIELD_ID: ClassVar[Layout] = Layout((("class_idx", U16), ("type_idx", U16), ("name_idx", U32)))
    METHOD_ID: ClassVar[Layout] = Layout(
        (("class_idx", U16), ("proto_idx", U16), ("name_idx", U32))
    )
    CLASS_DEF: ClassVar[Layout] = Layout((
        ("class_idx", U32), ("access_flags", U32), ("super_class_idx", U32), ("interfaces_offset", U32),
        ("source_file_idx", U32), ("annotations_offset", U32), ("class_data_offset", U32),
        ("static_values_offset", U32),
    ))  # fmt: skip
    MAP_ITEM: ClassVar[Layout] = Layout(
        (("type", U16), ("unused", U16), ("size", U32), ("offset", U32))
    )
    CODE_ITEM: ClassVar[Layout] = Layout((
        ("registers_size", U16), ("ins_size", U16), ("outs_size", U16), ("tries_size", U16),
        ("debug_info_off", U32), ("insns_size", U32),
    ))  # fmt: skip

    @staticmethod
    def names(layout: Layout) -> tuple[str, ...]:
        return tuple(name for name, _ in layout.fields)


class Dex:
    """The `dex` module reader: one instance per file read, holding the tables the class data resolves
    its names through."""

    HEADER: ClassVar[Record] = Record({
        "magic": TEXT, "checksum": INT, "signature": TEXT,
        **dict.fromkeys(Shape.names(Shape.HEADER)[3:], INT),
    })  # fmt: skip
    FIELD: ClassVar[Record] = Record({
        "class_name": TEXT, "name": TEXT, "proto": TEXT, "static": INT, "instance": INT,
        "field_idx_diff": INT, "access_flags": INT,
    })  # fmt: skip
    METHOD: ClassVar[Record] = Record({
        "class_name": TEXT, "name": TEXT, "proto": TEXT, "direct": INT, "virtual": INT,
        "method_idx_diff": INT, "access_flags": INT, "code_off": INT,
        "code_item": Record({**dict.fromkeys(Shape.names(Shape.CODE_ITEM), INT), "insns": TEXT}),
    })  # fmt: skip
    SCHEMA: ClassVar[Record] = Record({
        **dict.fromkeys(DexTables.MAGICS, TEXT),
        **dict.fromkeys(DexTables.INTEGERS, INT),
        "header": HEADER,
        "string_ids": Seq(Record({"offset": INT, "size": INT, "value": TEXT})),
        "type_ids": Seq(Record(dict.fromkeys(Shape.names(Shape.TYPE_ID), INT))),
        "proto_ids": Seq(Record(dict.fromkeys(Shape.names(Shape.PROTO_ID), INT))),
        "field_ids": Seq(Record(dict.fromkeys(Shape.names(Shape.FIELD_ID), INT))),
        "method_ids": Seq(Record(dict.fromkeys(Shape.names(Shape.METHOD_ID), INT))),
        "class_defs": Seq(Record(dict.fromkeys(Shape.names(Shape.CLASS_DEF), INT))),
        "class_data_item": Seq(Record(dict.fromkeys(
            ("static_fields_size", "instance_fields_size", "direct_methods_size", "virtual_methods_size"), INT
        ))),
        "map_list": Record({"size": INT, "map_item": Seq(Record(dict.fromkeys(Shape.names(Shape.MAP_ITEM), INT)))}),
        "number_of_fields": INT, "field": Seq(FIELD),
        "has_method": Call(
            Sig(("text",), INT), Sig(("text", "text"), INT), Sig(("regex",), INT), Sig(("regex", "regex"), INT)
        ),
        "has_class": Call(Sig(("text",), INT), Sig(("regex",), INT)),
        "number_of_methods": INT, "method": Seq(METHOD),
    })  # fmt: skip

    TABLES: ClassVar[tuple[tuple[str, Layout], ...]] = (
        ("type_ids", Shape.TYPE_ID), ("proto_ids", Shape.PROTO_ID), ("field_ids", Shape.FIELD_ID),
        ("method_ids", Shape.METHOD_ID),
    )  # fmt: skip
    """The id tables after the strings, in the order the reference reads them."""
    ARRAYS: ClassVar[tuple[str, ...]] = (
        "string_ids", "type_ids", "proto_ids", "field_ids", "method_ids", "class_defs",
        "class_data_item", "field", "method",
    )  # fmt: skip

    __slots__ = ("cur", "n", "out")

    def __init__(self, file: bytes, out: dict[str, Any]) -> None:
        self.cur = Cursor(file)  # dex files are little-endian; the reference reads them so
        self.n = len(file)
        self.out = out

    @staticmethod
    def data(file: bytes) -> dict[str, Any]:
        out: dict[str, Any] = {**DexTables.MAGICS, **DexTables.INTEGERS}
        out["header"] = {}
        out["map_list"] = {"map_item": {}}
        for name in (
            Dex.ARRAYS
        ):  # the reference always presents these arrays, empty when nothing fills them
            out[name] = {}
        if len(file) >= Shape.HEADER.stride() and file[:8] in DexTables.MAGICS.values():
            Dex(file, out).read()
        Dex._functions(out)
        return out

    def fits(self, at: int, size: int) -> bool:
        """The reference's `fits_in_dex`: `size` bytes at `at` lie within the file."""
        return 0 <= size <= self.n and 0 <= at <= self.n - size

    def uleb(self, at: int) -> tuple[int, int] | None:
        """A ULEB128 value as the reference decodes it, with the bytes it took: up to five, the fifth's
        high bits kept (`cur << 28`), the result cut to 32 bits; None where the file ends first."""
        cur = self.cur
        if at >= self.n:
            return None
        result = cur.uint(at, 1)
        size = 1
        if result > 0x7F:
            result &= 0x7F
            for shift in (7, 14, 21):
                if at + size >= self.n:
                    return None
                byte = cur.uint(at + size, 1)
                size += 1
                result |= (byte & 0x7F) << shift
                if byte <= 0x7F:
                    return result & MASK32, size
            if at + size >= self.n:
                return None
            result |= cur.uint(at + size, 1) << 28
            size += 1
        return result & MASK32, size

    def read(self) -> None:
        """The header, then each table in the reference's order, stopping at the first that does not fit;
        the map list and the class definitions last."""
        cur, out = self.cur, self.out
        h = Shape.HEADER.read(cur, 0)
        out["header"] = dict(h)
        if not self.fits(h["string_ids_offset"], h["string_ids_size"] * 4):
            return
        self._strings(h["string_ids_offset"], h["string_ids_size"])
        for name, layout in Dex.TABLES:
            at, count = h[name + "_offset"], h[name + "_size"]
            if not self.fits(at, count * layout.stride()):
                return
            grid = Grid(cur, at, layout, count)
            names = grid.names
            out[name] = {i: dict(zip(names, t, strict=True)) for i, t in enumerate(grid.tuples())}
        if (
            h["map_offset"] != 0
            and self.fits(h["map_offset"], 4)
            and not self._map(h["map_offset"])
        ):
            return
        if not self.fits(h["class_defs_offset"], h["class_defs_size"] * Shape.CLASS_DEF.stride()):
            return
        self._classes(h["class_defs_offset"], h["class_defs_size"])

    def _strings(self, at: int, count: int) -> None:
        """string_ids: each string's offset, its length, and its bytes from one past the length."""
        cur = self.cur
        strings: dict[int, Any] = {}
        for i in range(count):
            offset = cur.uint(at + i * 4, 4)
            if not self.fits(offset, 4):
                continue
            length = self.uleb(offset)
            if length is None or not self.fits(offset + 1, length[0]):
                continue
            strings[i] = {
                "offset": offset,
                "size": length[0],
                "value": cur.blob(offset + 1, length[0]),
            }
        self.out["string_ids"] = strings

    def _map(self, at: int) -> bool:
        """map_list; False when its items do not fit, which ends the read."""
        size = self.cur.uint(at, 4)
        self.out["map_list"]["size"] = size
        if not self.fits(at, 4 + size * Shape.MAP_ITEM.stride()):
            return False
        grid = Grid(self.cur, at + 4, Shape.MAP_ITEM, size)
        names = grid.names
        self.out["map_list"]["map_item"] = {
            i: dict(zip(names, t, strict=True)) for i, t in enumerate(grid.tuples())
        }
        return True

    def _classes(self, at: int, count: int) -> None:
        """class_defs, and each class's data: its counts, then its fields and methods in the reference's
        order (static fields, instance fields, direct methods, virtual methods). A class's data that does
        not fit, or whose counts do not decode, ends the read with the method and field totals unset."""
        out = self.out
        grid = Grid(self.cur, at, Shape.CLASS_DEF, count)
        names = grid.names
        defs = {i: dict(zip(names, t, strict=True)) for i, t in enumerate(grid.tuples())}
        out["class_defs"] = defs
        items: dict[int, Any] = {}
        out["class_data_item"] = items
        fields: dict[int, Any] = {}
        methods: dict[int, Any] = {}
        out["field"], out["method"] = fields, methods
        field_count = method_count = 0
        for d in defs.values():
            data_at = d["class_data_offset"]
            if data_at == 0:
                continue
            if not self.fits(data_at, 16):
                return
            counts: list[int] = []
            pos = data_at
            for _ in range(4):
                decoded = self.uleb(pos)
                if decoded is None:
                    return
                counts.append(decoded[0])
                pos += decoded[1]
            items[len(items)] = dict(zip(
                ("static_fields_size", "instance_fields_size", "direct_methods_size", "virtual_methods_size"),
                counts, strict=True,
            ))  # fmt: skip
            for group, (static, instance) in enumerate(((1, 0), (0, 1))):
                previous = 0
                for _ in range(counts[group]):
                    taken, previous = self._field(
                        fields, pos, previous, field_count, static, instance
                    )
                    if taken == 0:
                        break
                    pos += taken
                    field_count += 1
            for group, (direct, virtual) in enumerate(((1, 0), (0, 1))):
                previous = 0
                for _ in range(counts[2 + group]):
                    taken, previous = self._method(
                        methods, pos, previous, method_count, direct, virtual
                    )
                    if taken == 0:
                        break
                    pos += taken
                    method_count += 1
        out["number_of_methods"] = method_count
        out["number_of_fields"] = field_count

    def _lookup(self, table: str, index: int | None, key: str) -> int | None:
        """`table[index].key`, or None past the table or the reference's index bound."""
        if index is None or not 0 <= index <= DexTables.MAX_INDEX:
            return None
        row = self.out[table].get(index)
        return None if row is None else row.get(key)

    def _string(self, index: int | None) -> bytes | None:
        if index is None or not 0 <= index <= DexTables.MAX_INDEX:
            return None
        row = self.out["string_ids"].get(index)
        return None if row is None else row["value"]

    def _field(
        self, fields: dict[int, Any], at: int, previous: int, index: int, static: int, instance: int
    ) -> tuple[int, int]:
        """One encoded field at `at`: `(bytes taken, the field id it names)`, 0 taken when it does not
        decode or its id is past the table (its decoded values stay at `index`, as the reference leaves
        them)."""
        if not self.fits(at, 8):
            return 0, previous
        diff = self.uleb(at)
        if diff is None:
            return 0, previous
        flags = self.uleb(at + diff[1])
        if flags is None:
            return 0, previous
        entry = fields.setdefault(index, {})
        entry.update(
            field_idx_diff=diff[0], access_flags=flags[0], static=static, instance=instance
        )
        previous = (previous + diff[0]) & MASK32
        name_idx = self._lookup("field_ids", previous, "name_idx")
        if name_idx is None:
            return 0, previous
        self._names(
            entry,
            name_idx,
            self._lookup("field_ids", previous, "class_idx"),
            self._lookup(
                "type_ids", self._lookup("field_ids", previous, "type_idx"), "descriptor_idx"
            ),
        )
        return diff[1] + flags[1], previous

    def _method(
        self, methods: dict[int, Any], at: int, previous: int, index: int, direct: int, virtual: int
    ) -> tuple[int, int]:
        """One encoded method at `at`, and its code item when it has one; as `_field` otherwise."""
        if not self.fits(at, 12):
            return 0, previous
        parts: list[tuple[int, int]] = []
        pos = at
        for _ in range(3):
            decoded = self.uleb(pos)
            if decoded is None:
                return 0, previous
            parts.append(decoded)
            pos += decoded[1]
        (diff, _), (flags, _), (code_off, _) = parts
        entry = methods.setdefault(index, {})
        entry.update(
            method_idx_diff=diff,
            access_flags=flags,
            code_off=code_off,
            direct=direct,
            virtual=virtual,
        )
        previous = (previous + diff) & MASK32
        name_idx = self._lookup("method_ids", previous, "name_idx")
        if name_idx is None:
            return 0, previous
        self._names(
            entry,
            name_idx,
            self._lookup("method_ids", previous, "class_idx"),
            self._lookup(
                "proto_ids", self._lookup("method_ids", previous, "proto_idx"), "shorty_idx"
            ),
        )
        if code_off != 0 and self.fits(code_off, Shape.CODE_ITEM.stride()):
            code = Shape.CODE_ITEM.read(self.cur, code_off)
            item: dict[str, Any] = dict(code)
            entry["code_item"] = item
            length = (code["insns_size"] * 2) & MASK32
            if self.fits(code_off + Shape.CODE_ITEM.stride(), length):
                item["insns"] = self.cur.blob(code_off + Shape.CODE_ITEM.stride(), length)
        return pos - at, previous

    def _names(
        self, entry: dict[str, Any], name_idx: int, class_idx: int | None, shorty_idx: int | None
    ) -> None:
        """The entry's name, its class's descriptor and its type or prototype's shorty, each set when its
        string resolves."""
        name = self._string(name_idx)
        if name is not None:
            entry["name"] = name
        class_name = self._string(self._lookup("type_ids", class_idx, "descriptor_idx"))
        if class_name is not None:
            entry["class_name"] = class_name
        proto = self._string(shorty_idx)
        if proto is not None:
            entry["proto"] = proto

    @staticmethod
    def _cstr(text: bytes) -> bytes:
        """The bytes a C string comparison sees: up to the first NUL."""
        return text.split(b"\x00", 1)[0]

    @staticmethod
    def _functions(out: dict[str, Any]) -> None:
        """has_method and has_class over the methods read (`number_of_methods` of them): by name, by
        class and name, or by regular expression on each; undefined when the file is not a dex."""
        methods, count = out["method"], out.get("number_of_methods")
        cstr = Dex._cstr

        def rows() -> list[tuple[bytes | None, bytes | None]]:
            return [
                (methods.get(i, {}).get("class_name"), methods.get(i, {}).get("name"))
                for i in range(count or 0)
            ]

        def matched(regex: Any, text: bytes) -> bool:
            return int(regex.run(cstr(text))) != -1

        def by_name(name: bytes) -> int | None:
            if count is None:
                return None
            return int(any(n is not None and cstr(n) == cstr(name) for _c, n in rows()))

        def by_class_and_name(cls: bytes, name: bytes) -> int | None:
            if count is None:
                return None
            for c, n in rows():
                if c is not None and cstr(c) != cstr(cls):
                    continue
                if n is not None and cstr(n) == cstr(name):
                    return 1
            return 0

        def by_regex(regex: Any) -> int | None:
            if count is None:
                return None
            return int(any(n is not None and matched(regex, n) for _c, n in rows()))

        def by_class_and_regex(cls_re: Any, name_re: Any) -> int | None:
            if count is None:
                return None
            for c, n in rows():
                if c is not None and not matched(cls_re, c):
                    continue
                if n is not None and matched(name_re, n):
                    return 1
            return 0

        def class_by_name(cls: bytes) -> int | None:
            if count is None:
                return None
            return int(any(c is not None and cstr(c) == cstr(cls) for c, _n in rows()))

        def class_by_regex(regex: Any) -> int | None:
            if count is None:
                return None
            return int(any(c is not None and matched(regex, c) for c, _n in rows()))

        out["has_method"] = (by_name, by_class_and_name, by_regex, by_class_and_regex)
        out["has_class"] = (class_by_name, class_by_regex)


__all__ = ["Dex"]
