"""The `dex` module's second shape: the names YARA-X declares that YARA does not, filled from the same
parse (`formats.dex`), so a rule written for either engine reads its own value under the one module name.

YARA-X resolves the tables rather than exposing them: `strings[]` are the decoded strings, `types[]`
their descriptors, `protos[]` carry the shorty, return type and parameter types, `fields[]` and
`methods[]` their class, type or prototype, and name, `class_defs[]` gain `class`, `superclass` and
`source_file`, `map_list.items[]` are the map items, and the header gains `version`, `link_off`,
`data_off` (the same values as YARA's link_offset and data_offset) and, from version 041, `container_size`
and `header_offset`. `is_dex` says whether the header passed YARA-X's checks (the magic, a version 035 to
041, the sizes and offsets within the file, type and prototype counts under 65,536). `contains_string`,
`contains_method` and `contains_class` search those tables; `checksum()` and `signature()` compute the
Adler-32 and SHA-1 the header is meant to carry. The two names both engines declare with different types,
`header.magic` and `header.signature`, hold both values (`values.Dual`); the compiler picks one per rule.

Each name keeps its own engine's bounds: these tables stop at a million entries, a string at 65,536
units, a parameter list at 255. Where YARA-X's reading is an accident rather than the format, this
reader reads the format and the difference is named here: an entry that does not resolve leaves its index
empty rather than shifting the entries after it (YARA-X compacts), a map offset of zero gives no items
(YARA-X reads the header as items), and the membership tests are exact rather than a binary search over
tables that need not be sorted. Strings are decoded from modified UTF-8 (CESU-8 with the two-byte NUL)
to UTF-8; a string that is not valid modified UTF-8 is left out, as YARA-X leaves it out.
"""

from __future__ import annotations

import hashlib
import zlib
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.detect.binary.modules.layout import U16, U32, Cursor, Grid, Layout
from cordon_scanner.detect.binary.modules.values import Call, Dual, Record, Scalar, Seq, Sig

if TYPE_CHECKING:
    from cordon_scanner.detect.binary.modules.formats.dex import Dex

INT, TEXT, BOOL = Scalar.INT, Scalar.TEXT, Scalar.BOOL


class DexX:
    """The second shape's declarations and its reading."""

    LABELS: ClassVar[tuple[str, str]] = ("YARA's shape", "YARA-X's shape")
    MAGIC: ClassVar[int] = 0x6465780A
    """`dex\\n` read big-endian: YARA-X's `header.magic`."""
    VERSIONS: ClassVar[dict[bytes, int]] = {
        b"035": 35, b"036": 36, b"037": 37, b"038": 38, b"039": 39, b"040": 40, b"041": 41
    }  # fmt: skip
    MAX_ITEMS: ClassVar[int] = 1_000_000
    MAX_IDS: ClassVar[int] = 0xFFFF
    MAX_STRING: ClassVar[int] = 65536
    MAX_PARAMETERS: ClassVar[int] = 255
    HEADER_SIZE: ClassVar[int] = 0x70
    ENDIAN: ClassVar[frozenset[int]] = frozenset({0x12345678, 0x78563412})
    NO_INDEX: ClassVar[int] = 0xFFFFFFFF
    SHARED: ClassVar[tuple[str, ...]] = (
        "checksum", "file_size", "header_size", "endian_tag", "link_size", "data_size"
    )  # fmt: skip
    """Header names both shapes declare with one value."""

    PROTO: ClassVar[Record] = Record(
        {"shorty": TEXT, "return_type": TEXT, "parameters_count": INT, "parameters": Seq(TEXT)}
    )
    HEADER: ClassVar[dict[str, Any]] = {
        "magic": Dual(TEXT, INT, LABELS, frozenset({"version"})),
        "signature": Dual(TEXT, TEXT, LABELS, frozenset({"signature"})),
        "version": INT, "link_off": INT, "data_off": INT, "container_size": INT, "header_offset": INT,
    }  # fmt: skip
    """Header names of the second shape, and the two names both shapes declare."""
    CLASS: ClassVar[dict[str, Any]] = {"class": TEXT, "superclass": TEXT, "source_file": TEXT}
    MAP: ClassVar[dict[str, Any]] = {
        "items": Seq(Record(dict.fromkeys(("type", "unused", "size", "offset"), INT)))
    }
    FIELDS: ClassVar[dict[str, Any]] = {
        "is_dex": BOOL,
        "strings": Seq(TEXT), "types": Seq(TEXT), "protos": Seq(PROTO),
        "fields": Seq(Record({"class": TEXT, "type": TEXT, "name": TEXT})),
        "methods": Seq(Record({"class": TEXT, "proto": PROTO, "name": TEXT})),
        "contains_string": Call(Sig(("text",), BOOL)),
        "contains_method": Call(Sig(("text",), BOOL)),
        "contains_class": Call(Sig(("text",), BOOL)),
        "checksum": Call(Sig((), INT)), "signature": Call(Sig((), TEXT)),
    }  # fmt: skip
    ARRAYS: ClassVar[tuple[str, ...]] = ("strings", "types", "protos", "fields", "methods")
    TYPE_LIST_SIZE: ClassVar[Layout] = Layout((("size", U32),))
    TYPE_LIST_ITEM: ClassVar[Layout] = Layout((("type_idx", U16),))

    @staticmethod
    def empty(out: dict[str, Any]) -> None:
        """The second shape's presence on every file: `is_dex` false, its arrays empty, its functions
        undefined or false, until a parse fills them."""
        out["is_dex"] = False
        for name in DexX.ARRAYS:
            out[name] = {}
        out["map_list"]["items"] = {}
        DexX._functions(out, None)

    @staticmethod
    def accepted(file: bytes, h: dict[str, Any]) -> int | None:
        """The version when the header passes YARA-X's checks, else None."""
        magic = h["magic"]
        version = DexX.VERSIONS.get(magic[4:7])
        if magic[:4] != b"dex\n" or version is None or magic[7] != 0:
            return None
        n = len(file)
        offsets = (
            "link_offset", "map_offset", "string_ids_offset", "type_ids_offset", "proto_ids_offset",
            "field_ids_offset", "method_ids_offset", "class_defs_offset", "data_offset",
        )  # fmt: skip
        if (
            h["file_size"] > n
            or h["header_size"] != DexX.HEADER_SIZE
            or h["endian_tag"] not in DexX.ENDIAN
            or any(h[name] > h["file_size"] for name in offsets)
            or h["type_ids_size"] > DexX.MAX_IDS
            or h["proto_ids_size"] > DexX.MAX_IDS
            or (version >= 41 and n < DexX.HEADER_SIZE + 8)
        ):
            return None
        return version

    @staticmethod
    def fill(dex: Dex, file: bytes) -> None:
        """The second shape from the raw parse: `is_dex`, the header's extra names, the resolved tables,
        the map items and the functions. The two dual names hold both values."""
        out, raw = dex.out, dex.raw
        h = raw["header"]
        version = DexX.accepted(file, h)
        header = out["header"]
        header["magic"] = (h["magic"], DexX.MAGIC if version is not None else None)
        header["signature"] = (
            h["signature"],
            h["signature"].hex().encode() if version is not None else None,
        )
        if version is None:
            return
        out["is_dex"] = True
        header.update(version=version, link_off=h["link_offset"], data_off=h["data_offset"])
        for (
            name
        ) in DexX.SHARED:  # one value under both shapes, present whichever shape read the file
            header.setdefault(name, h[name])
        if version >= 41:
            cur = Cursor(file)
            header["container_size"] = cur.uint(DexX.HEADER_SIZE, 4)
            header["header_offset"] = cur.uint(DexX.HEADER_SIZE + 4, 4)
        strings = DexX._strings(dex, file)
        out["strings"] = strings
        types = {
            i: strings[t["descriptor_idx"]]
            for i, t in DexX._bounded(raw["type_ids"])
            if t["descriptor_idx"] in strings
        }
        out["types"] = types
        protos = DexX._protos(dex, strings, types)
        out["protos"] = protos
        out["fields"] = {
            i: {
                "class": types[f["class_idx"]],
                "type": types[f["type_idx"]],
                "name": strings[f["name_idx"]],
            }
            for i, f in DexX._bounded(raw["field_ids"])
            if f["class_idx"] in types and f["type_idx"] in types and f["name_idx"] in strings
        }
        out["methods"] = {
            i: {
                "class": types[m["class_idx"]],
                "proto": protos[m["proto_idx"]],
                "name": strings[m["name_idx"]],
            }
            for i, m in DexX._bounded(raw["method_ids"])
            if m["class_idx"] in types and m["proto_idx"] in protos and m["name_idx"] in strings
        }
        for i, d in DexX._bounded(raw["class_defs"]):
            entry = out["class_defs"].get(i)
            if entry is None or d["class_idx"] not in types:
                continue
            entry["class"] = types[d["class_idx"]]
            if d["super_class_idx"] != DexX.NO_INDEX and d["super_class_idx"] in types:
                entry["superclass"] = types[d["super_class_idx"]]
            if d["source_file_idx"] != DexX.NO_INDEX and d["source_file_idx"] in strings:
                entry["source_file"] = strings[d["source_file_idx"]]
        out["map_list"]["items"] = dict(raw["map_items"])
        DexX._functions(out, file)

    @staticmethod
    def _bounded(table: dict[int, Any]) -> list[tuple[int, Any]]:
        """A raw table's rows under the second shape's size bound, in index order."""
        return [(i, row) for i, row in sorted(table.items()) if i < DexX.MAX_ITEMS]

    @staticmethod
    def _strings(dex: Dex, file: bytes) -> dict[int, bytes]:
        """Each string decoded from modified UTF-8, by its id, when its offset is past the header, its
        length within the bound, its bytes within the file and its encoding valid."""
        out: dict[int, bytes] = {}
        for i, row in DexX._bounded(dex.raw["string_ids"]):
            at = row["offset"]
            if at < DexX.HEADER_SIZE:
                continue
            length = DexX.varint(dex, at)
            if length is None or length[0] > DexX.MAX_STRING or length[0] > dex.n:
                continue
            start = at + length[1]
            if not dex.within(start, length[0]):
                continue
            decoded = DexX.mutf8(file[start : start + length[0]])
            if decoded is not None:
                out[i] = decoded
        return out

    @staticmethod
    def _protos(dex: Dex, strings: dict[int, bytes], types: dict[int, bytes]) -> dict[int, Any]:
        protos: dict[int, Any] = {}
        for i, p in DexX._bounded(dex.raw["proto_ids"]):
            if p["shorty_idx"] not in strings or p["return_type_idx"] not in types:
                continue
            parameters = DexX._type_list(dex, p["parameters_offset"], types)
            protos[i] = {
                "shorty": strings[p["shorty_idx"]], "return_type": types[p["return_type_idx"]],
                "parameters_count": len(parameters), "parameters": dict(enumerate(parameters)),
            }  # fmt: skip
        return protos

    @staticmethod
    def _type_list(dex: Dex, at: int, types: dict[int, bytes]) -> list[bytes]:
        """The parameter types at `at`: none for no offset, a list over 255 long, or one past the end."""
        if at == 0 or not dex.within(at, 4):
            return []
        size = DexX.TYPE_LIST_SIZE.read(dex.cur, at)["size"]
        if size > DexX.MAX_PARAMETERS:
            return []
        grid = Grid(dex.cur, at + 4, DexX.TYPE_LIST_ITEM, size)
        return [types[t[0]] for t in grid.tuples() if t[0] in types]

    @staticmethod
    def varint(dex: Dex, at: int) -> tuple[int, int] | None:
        """A ULEB128 value as the second shape reads it (up to ten bytes into 64 bits) and its length."""
        result = 0
        for i in range(10):
            if at + i >= dex.n:
                return None
            byte = dex.cur.uint(at + i, 1)
            result |= (byte & 0x7F) << (7 * i)
            if byte < 0x80:
                return result, i + 1
        return None

    @staticmethod
    def mutf8(raw: bytes) -> bytes | None:
        """Modified UTF-8 to UTF-8: the two-byte NUL restored, surrogate pairs joined; None for an
        encoding that is not valid modified UTF-8 (a lone surrogate, a malformed sequence)."""
        try:
            text = raw.replace(b"\xc0\x80", b"\x00").decode("utf-8", "surrogatepass")
            text = text.encode("utf-16", "surrogatepass").decode("utf-16")
        except UnicodeError:
            return None
        return text.encode("utf-8")

    @staticmethod
    def _functions(out: dict[str, Any], file: bytes | None) -> None:
        """contains_string/method/class over the second shape's tables (false on a file that is not a
        dex), and checksum()/signature() over the file past the fields that hold them (undefined then)."""
        strings = set(out["strings"].values())
        methods, classes = out["methods"], out["class_defs"]
        parsed = file if out["is_dex"] else None

        def contains_method(name: bytes) -> bool:
            return any(m["name"] == name for m in methods.values())

        def contains_class(name: bytes) -> bool:
            return any(c.get("class") == name for c in classes.values())

        def checksum() -> int | None:
            return None if parsed is None else zlib.adler32(parsed[12:]) & 0xFFFFFFFF

        def signature() -> bytes | None:
            return None if parsed is None else hashlib.sha1(parsed[32:]).hexdigest().encode()  # noqa: S324

        out["contains_string"] = (lambda s: s in strings,)
        out["contains_method"] = (contains_method,)
        out["contains_class"] = (contains_class,)
        out["checksum"] = (checksum,)
        out["signature"] = (signature,)


__all__ = ["DexX"]
