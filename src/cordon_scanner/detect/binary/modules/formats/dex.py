"""The DEX reader for cordon-rule: the `dex` module's values as a condition sees them.

A Dalvik executable (Android's dex format, versions 035 to 039) is read from its header through the
string, type, prototype, field and method id tables, the map list, and the class definitions, whose
class data names each encoded field and method through those tables: the entry's own name, its class's
descriptor, and its type's descriptor or its prototype's shorty. A method's code item follows when it
has one. Every table is a Layout read in one call; each distinct class data is decoded once, and the
`field` and `method` sequences present the classes' runs end to end without copying them, so a file whose
classes share one class data costs one decode, not one per class.

The names and the values a rule reads are the reference's (YARA's `dex` module), and so are the two
readings rules depend on: a string's bytes are taken from one byte past the start of its length, whatever
that length's encoding took, and an id past 0x80000 resolves to nothing. Where the reference's reading is
an implementation accident rather than the format, this reader reads the format and the difference is
named here and pinned in its tests: each table is read on its own (the reference stops at the first that
does not fit); an encoded entry is read whenever its varints fit (the reference wants 8 or 12 bytes
first); an entry whose ids do not resolve ends its class's walk and leaves nothing (the reference leaves
its decoded fields at the next index and reads the same bytes again as the next group); a class whose
data does not decode contributes nothing (the reference ends the read with the totals unset); a varint
is at most five bytes with the fifth in range; a name is compared whole. A file that is not a dex answers
undefined for everything but the constants.

The one `dex` name also answers YARA-X's shape (`formats.dex_x`): its names are filled from the same
parse, each under its own engine's bounds, and the two names both engines declare with different types
(`header.magic`, `header.signature`) hold both values for the compiler to pick from.
"""

from __future__ import annotations

import bisect
from collections.abc import Iterator, Mapping
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.formats.dex_x import DexX
from cordon_scanner.detect.binary.modules.layout import U16, U32, Blob, Cursor, Grid, Layout
from cordon_scanner.detect.binary.modules.values import Call, Record, Scalar, Seq, Sig

INT, TEXT = Scalar.INT, Scalar.TEXT


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
    """An id past this resolves to nothing: the reference's bound, which rules see."""


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
    COUNTS: ClassVar[tuple[str, ...]] = (
        "static_fields_size", "instance_fields_size", "direct_methods_size", "virtual_methods_size"
    )  # fmt: skip
    """A class data's four varint counts, in order."""

    @staticmethod
    def names(layout: Layout) -> tuple[str, ...]:
        return tuple(name for name, _ in layout.fields)


class Run:
    """One class data decoded: its counts, and its fields and methods in the order the class lists them.
    Shared by every class whose definition points at the same offset."""

    __slots__ = ("counts", "fields", "methods")

    def __init__(self, counts: dict[str, int]) -> None:
        self.counts = counts
        self.fields: list[dict[str, Any]] = []
        self.methods: list[dict[str, Any]] = []


class Runs(Mapping[int, Any]):
    """`field` or `method`: the classes' runs laid end to end, read by index without a copy. The length
    is the entries of every class, so two classes sharing one class data give its entries twice, at
    different indices, as the reference reports them."""

    __slots__ = ("_runs", "_starts", "total")

    def __init__(self) -> None:
        self._starts: list[int] = []
        self._runs: list[list[dict[str, Any]]] = []
        self.total = 0

    def add(self, entries: list[dict[str, Any]]) -> None:
        if entries:
            self._starts.append(self.total)
            self._runs.append(entries)
            self.total += len(entries)

    def distinct(self) -> Iterator[list[dict[str, Any]]]:
        """Each run once, however many classes share it."""
        seen: set[int] = set()
        for run in self._runs:
            if id(run) not in seen:
                seen.add(id(run))
                yield run

    def __getitem__(self, key: int) -> Any:
        if not isinstance(key, int) or not 0 <= key < self.total:
            raise KeyError(key)
        i = bisect.bisect_right(self._starts, key) - 1
        return self._runs[i][key - self._starts[i]]

    def __contains__(self, key: object) -> bool:
        return isinstance(key, int) and 0 <= key < self.total

    def __iter__(self) -> Iterator[int]:
        return iter(range(self.total))

    def __len__(self) -> int:
        return self.total


class Dex:
    """The `dex` module reader: one instance per file read, holding the tables the class data resolves
    its names through."""

    HEADER: ClassVar[Record] = Record({
        "checksum": INT, **dict.fromkeys(Shape.names(Shape.HEADER)[3:], INT), **DexX.HEADER,
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
        "class_defs": Seq(Record({**dict.fromkeys(Shape.names(Shape.CLASS_DEF), INT), **DexX.CLASS})),
        "class_data_item": Seq(Record(dict.fromkeys(Shape.COUNTS, INT))),
        "map_list": Record({
            "size": INT, "map_item": Seq(Record(dict.fromkeys(Shape.names(Shape.MAP_ITEM), INT))), **DexX.MAP,
        }),
        "number_of_fields": INT, "field": Seq(FIELD),
        "has_method": Call(
            Sig(("text",), INT), Sig(("text", "text"), INT), Sig(("regex",), INT), Sig(("regex", "regex"), INT)
        ),
        "has_class": Call(Sig(("text",), INT), Sig(("regex",), INT)),
        "number_of_methods": INT, "method": Seq(METHOD),
        **DexX.FIELDS,
    })  # fmt: skip

    TABLES: ClassVar[tuple[tuple[str, Layout], ...]] = (
        ("type_ids", Shape.TYPE_ID), ("proto_ids", Shape.PROTO_ID), ("field_ids", Shape.FIELD_ID),
        ("method_ids", Shape.METHOD_ID), ("class_defs", Shape.CLASS_DEF),
    )  # fmt: skip
    """The id tables after the strings, each read whole in one call."""
    ARRAYS: ClassVar[tuple[str, ...]] = (
        "string_ids", "type_ids", "proto_ids", "field_ids", "method_ids", "class_defs",
        "class_data_item", "field", "method",
    )  # fmt: skip

    __slots__ = ("cur", "n", "out", "raw")

    def __init__(self, file: bytes, out: dict[str, Any]) -> None:
        self.cur = Cursor(file)  # the format is little-endian
        self.n = len(file)
        self.out = out
        self.raw: dict[str, Any] = {"map_items": {}}
        """The parse both shapes are filled from: the header, the id tables, the map items."""

    @staticmethod
    def data(file: bytes) -> dict[str, Any]:
        out: dict[str, Any] = {**DexTables.MAGICS, **DexTables.INTEGERS}
        out["header"] = {}
        out["map_list"] = {"map_item": {}}
        for name in Dex.ARRAYS:  # the declared arrays are present, empty when nothing fills them
            out[name] = {}
        DexX.empty(out)
        if len(file) >= Shape.HEADER.stride() and file[:4] == b"dex\n":
            dex = Dex(file, out)
            dex.read(yara=file[:8] in DexTables.MAGICS.values())
            DexX.fill(dex, file)
        Dex._functions(out)
        return out

    def within(self, at: int, size: int) -> bool:
        """Whether `size` bytes at `at` lie inside the file."""
        return 0 <= size <= self.n and 0 <= at <= self.n - size

    def varint(self, at: int) -> tuple[int, int] | None:
        """The ULEB128 value at `at` and the bytes it took: up to five, the fifth within the 32-bit range;
        None where the file ends first or the encoding runs past that."""
        result = 0
        for i in range(5):
            if at + i >= self.n:
                return None
            byte = self.cur.uint(at + i, 1)
            if i == 4 and byte > 0x0F:
                return None
            result |= (byte & 0x7F) << (7 * i)
            if byte < 0x80:
                return result, i + 1
        return None

    def read(self, *, yara: bool) -> None:
        """The header, the strings, each id table, the map list, then the classes and their data, into
        the raw parse; `yara` says whether the file is one YARA's shape reads (a version 035 to 039),
        and then the raw parse is also that shape's tables."""
        cur, out, raw = self.cur, self.out, self.raw
        h = Shape.HEADER.read(cur, 0)
        raw["header"] = dict(h)
        raw["string_ids"] = self._strings(h["string_ids_offset"], h["string_ids_size"])
        for name, layout in Dex.TABLES:
            at, count = h[name + "_offset"], h[name + "_size"]
            raw[name] = {}
            if not self.within(at, count * layout.stride()):
                continue  # a table outside the file is empty; the others are still read
            grid = Grid(cur, at, layout, count)
            names = grid.names
            raw[name] = {i: dict(zip(names, t, strict=True)) for i, t in enumerate(grid.tuples())}
        if h["map_offset"] != 0:
            self._map(h["map_offset"])
        if not yara:
            return
        out["header"] = dict(h)
        for name in ("string_ids", *(name for name, _ in Dex.TABLES)):
            out[name] = raw[name]
        if "map_size" in raw:
            out["map_list"]["size"] = raw["map_size"]
            out["map_list"]["map_item"] = dict(raw["map_items"])
        self._classes()

    def _strings(self, at: int, count: int) -> dict[int, Any]:
        """string_ids: each string's offset, its length, and its bytes from one past the length's
        start (the reference's reading, which rules see)."""
        cur = self.cur
        strings: dict[int, Any] = {}
        if not self.within(at, count * 4):
            return strings
        for i in range(count):
            offset = cur.uint(at + i * 4, 4)
            length = self.varint(offset) if self.within(offset, 1) else None
            if length is None or not self.within(offset + 1, length[0]):
                continue
            strings[i] = {
                "offset": offset,
                "size": length[0],
                "value": cur.blob(offset + 1, length[0]),
            }
        return strings

    def _map(self, at: int) -> None:
        """map_list: its size, and the items that fit."""
        if not self.within(at, 4):
            return
        size = self.cur.uint(at, 4)
        self.raw["map_size"] = size
        if not self.within(at + 4, size * Shape.MAP_ITEM.stride()):
            return
        grid = Grid(self.cur, at + 4, Shape.MAP_ITEM, size)
        names = grid.names
        self.raw["map_items"] = {
            i: dict(zip(names, t, strict=True)) for i, t in enumerate(grid.tuples())
        }

    def _classes(self) -> None:
        """Each class's data, decoded once per distinct offset: its counts as a class_data_item, its
        fields and methods as the next run of `field` and `method`."""
        out = self.out
        runs: dict[int, Run] = {}
        items: dict[int, Any] = {}
        fields, methods = Runs(), Runs()
        for d in self.raw["class_defs"].values():
            at = d["class_data_offset"]
            if at == 0:
                continue
            run = runs.get(at)
            if run is None:
                run = self._class_data(at)
                if run is None:
                    continue
                runs[at] = run
            items[len(items)] = run.counts
            fields.add(run.fields)
            methods.add(run.methods)
        out["class_data_item"] = items
        out["field"], out["method"] = fields, methods
        out["number_of_fields"], out["number_of_methods"] = fields.total, methods.total

    def _class_data(self, at: int) -> Run | None:
        """One class data: four counts, then the static fields, instance fields, direct methods and
        virtual methods, each group's ids relative to the group's start; None when the counts do not
        decode. An entry that does not decode or resolve ends the walk with what came before it."""
        counts = self._varints(at, 4)
        if counts is None:
            return None
        values, pos = counts[0], at + counts[1]
        run = Run(dict(zip(Shape.COUNTS, values, strict=True)))
        for group, (static, instance) in enumerate(((1, 0), (0, 1))):
            previous = 0
            for _ in range(values[group]):
                entry, taken, previous = self._field(pos, previous, static, instance)
                if entry is None:
                    return run
                run.fields.append(entry)
                pos += taken
        for group, (direct, virtual) in enumerate(((1, 0), (0, 1))):
            previous = 0
            for _ in range(values[2 + group]):
                entry, taken, previous = self._method(pos, previous, direct, virtual)
                if entry is None:
                    return run
                run.methods.append(entry)
                pos += taken
        return run

    def _lookup(self, table: str, index: int | None, key: str) -> int | None:
        """`table[index].key`, or None past the table or the reference's index bound."""
        if index is None or not 0 <= index <= DexTables.MAX_INDEX:
            return None
        row = self.raw[table].get(index)
        return None if row is None else row.get(key)

    def _string(self, index: int | None) -> bytes | None:
        if index is None or not 0 <= index <= DexTables.MAX_INDEX:
            return None
        row = self.raw["string_ids"].get(index)
        return None if row is None else row["value"]

    def _varints(self, at: int, count: int) -> tuple[list[int], int] | None:
        """`count` varints from `at` and the bytes they took, or None where one does not decode."""
        values: list[int] = []
        pos = at
        for _ in range(count):
            decoded = self.varint(pos)
            if decoded is None:
                return None
            values.append(decoded[0])
            pos += decoded[1]
        return values, pos - at

    def _field(
        self, at: int, previous: int, static: int, instance: int
    ) -> tuple[dict[str, Any] | None, int, int]:
        """One encoded field: `(entry, bytes taken, the field id it names)`; no entry when its varints do
        not decode or its id is past the table."""
        decoded = self._varints(at, 2)
        if decoded is None:
            return None, 0, previous
        (diff, flags), taken = decoded
        previous += diff
        name_idx = self._lookup("field_ids", previous, "name_idx")
        if name_idx is None:
            return None, 0, previous
        entry: dict[str, Any] = {
            "field_idx_diff": diff, "access_flags": flags, "static": static, "instance": instance
        }  # fmt: skip
        self._names(
            entry,
            name_idx,
            self._lookup("field_ids", previous, "class_idx"),
            self._lookup(
                "type_ids", self._lookup("field_ids", previous, "type_idx"), "descriptor_idx"
            ),
        )
        return entry, taken, previous

    def _method(
        self, at: int, previous: int, direct: int, virtual: int
    ) -> tuple[dict[str, Any] | None, int, int]:
        """One encoded method, and its code item when it has one; as `_field` otherwise."""
        decoded = self._varints(at, 3)
        if decoded is None:
            return None, 0, previous
        (diff, flags, code_off), taken = decoded
        previous += diff
        name_idx = self._lookup("method_ids", previous, "name_idx")
        if name_idx is None:
            return None, 0, previous
        entry: dict[str, Any] = {
            "method_idx_diff": diff, "access_flags": flags, "code_off": code_off,
            "direct": direct, "virtual": virtual,
        }  # fmt: skip
        self._names(
            entry,
            name_idx,
            self._lookup("method_ids", previous, "class_idx"),
            self._lookup(
                "proto_ids", self._lookup("method_ids", previous, "proto_idx"), "shorty_idx"
            ),
        )
        head = Shape.CODE_ITEM.stride()
        item: dict[str, Any] = {}
        entry["code_item"] = item  # the record is present on every method, empty without code
        if code_off != 0 and self.within(code_off, head):
            code = Shape.CODE_ITEM.read(self.cur, code_off)
            item.update(code)
            if self.within(code_off + head, code["insns_size"] * 2):
                item["insns"] = self.cur.blob(code_off + head, code["insns_size"] * 2)
        return entry, taken, previous

    def _names(
        self, entry: dict[str, Any], name_idx: int, class_idx: int | None, shorty_idx: int | None
    ) -> None:
        """The entry's name, its class's descriptor and its type's descriptor or prototype's shorty,
        each set when its string resolves."""
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
    def _functions(out: dict[str, Any]) -> None:
        """has_method and has_class over the methods read: by name, by class and name, or by regular
        expression on each, each distinct run checked once; undefined when the file is not a dex."""
        methods = out["method"]
        read = "number_of_methods" in out

        def entries() -> Iterator[dict[str, Any]]:
            runs = methods.distinct() if isinstance(methods, Runs) else iter(())
            for run in runs:
                yield from run

        def matched(regex: Any, text: bytes) -> bool:
            return int(regex.run(text)) != -1

        def holds(test: Any) -> int | None:
            return int(any(test(m) for m in entries())) if read else None

        def by_class_and_name(cls: bytes, name: bytes) -> int | None:
            return holds(lambda m: m.get("class_name", cls) == cls and m.get("name") == name)

        def by_class_and_regex(cls_re: Any, name_re: Any) -> int | None:
            return holds(
                lambda m: (
                    ("class_name" not in m or matched(cls_re, m["class_name"]))
                    and "name" in m
                    and matched(name_re, m["name"])
                )
            )

        out["has_method"] = (
            lambda name: holds(lambda m: m.get("name") == name),
            by_class_and_name,
            lambda regex: holds(lambda m: "name" in m and matched(regex, m["name"])),
            by_class_and_regex,
        )
        out["has_class"] = (
            lambda cls: holds(lambda m: m.get("class_name") == cls),
            lambda regex: holds(lambda m: "class_name" in m and matched(regex, m["class_name"])),
        )


__all__ = ["Dex"]
