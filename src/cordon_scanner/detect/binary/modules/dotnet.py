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

from collections.abc import Mapping
from functools import partial
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.dotnet_metadata import Heaps, Spec, Tables
from cordon_scanner.detect.binary.modules.dotnet_signatures import Names
from cordon_scanner.detect.binary.modules.layout import (
    ABSENT,
    Cursor,
    Grid,
    ImageMap,
    LazyRecord,
    LazySeq,
)
from cordon_scanner.detect.binary.modules.values import Record, Scalar, Seq

INT, TEXT = Scalar.INT, Scalar.TEXT

TYPE_VISIBILITY: dict[int, bytes] = {
    3: b"private", 1: b"public", 2: b"public", 4: b"protected", 0: b"internal", 5: b"internal",
    6: b"private protected", 7: b"protected internal",
}  # fmt: skip

METHOD_VISIBILITY: dict[int, bytes] = {
    1: b"private", 2: b"private protected", 3: b"internal", 4: b"protected",
    5: b"protected internal", 6: b"public",
}  # fmt: skip

#: Every index whose width is 2 by default and 4 when a relevant row count overflows it. A coded index
#: widens when the largest of its target tables passes (0xFFFF >> tag_bits); a simple index when its own
#: table does. (string/guid/blob come from the heap-size flags instead.)
HEAPS = ("string", "guid", "blob")

MAX_METHODS = 20000


class _Method(Mapping[str, Any]):
    """A method record resolved field by field on access, so a rule that reads one method field (a name, a
    count) never builds the rest, and especially not the parameter list. The filter that kept the method
    already decoded its signature and checked its parameters fit; only the parameter dict and the trivial
    flag fields are deferred to the read. Which fields are present follows from the descriptor alone (a
    parameter list, and a return type for all but the constructors), so iteration never builds a value."""

    __slots__ = ("_cache", "_d", "_heaps", "_keys", "_tables")

    _BASE: ClassVar[tuple[str, ...]] = (
        "name", "visibility", "static", "virtual", "final", "abstract",
        "number_of_generic_parameters", "generic_parameters",
    )  # fmt: skip

    # descriptor: (name, flags, method_gp, return_type, param_types, param_list, parameter_count)
    def __init__(self, descriptor: tuple[Any, ...], heaps: Heaps, tables: Tables) -> None:
        self._d = descriptor
        self._heaps = heaps
        self._tables = tables
        self._cache: dict[str, Any] = {}
        name, _flags, _gp, _ret, _pt, param_list, _n = descriptor
        # `parameters` is always there (empty without a parameter list), as the reference reports it; only
        # its count needs the list.
        keys: tuple[str, ...] = _Method._BASE + (
            ("number_of_parameters", "parameters") if param_list else ("parameters",)
        )
        if name not in (b".ctor", b".cctor"):
            keys += ("return_type",)
        self._keys = keys  # the present fields, fixed by the descriptor and built once

    def _value(self, key: str) -> Any:
        name, flags, method_gp, ret, ptypes, param_list, n_params = self._d
        if key == "name":
            return name
        if key == "visibility":
            return METHOD_VISIBILITY.get(flags & 7, b"private")
        if key == "static":
            return int(bool(flags & 0x10))
        if key == "virtual":
            return int(bool(flags & 0x40))
        if key == "final":
            return int(bool(flags & 0x20))
        if key == "abstract":
            return int(bool(flags & 0x400))
        if key == "number_of_generic_parameters":
            return len(method_gp)
        if key == "generic_parameters":
            return dict(enumerate(method_gp))
        if key == "number_of_parameters":
            return n_params if param_list else None
        if key == "parameters":
            return (
                Dotnet._build_params(self._heaps, self._tables, param_list, n_params, ptypes)
                if param_list
                else {}
            )
        if key == "return_type":
            return ret if name not in (b".ctor", b".cctor") else None
        return None

    def __getitem__(self, key: str) -> Any:
        if key not in self._cache:
            self._cache[key] = self._value(key)
        value = self._cache[key]
        if value is None:
            raise KeyError(key)
        return value

    def __iter__(self) -> Any:
        return iter(self._keys)

    def __len__(self) -> int:
        return len(self._keys)

    def __contains__(self, key: object) -> bool:
        return key in self._keys


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
        # which typedef rows are real classes is cheap (a name read + the filter); building a class (its
        # methods and their signatures) is the cost, so classes decode on access -- a rule that reads a
        # count or a few classes never builds the rest, while the reference engine builds them all eagerly.
        kept: list[int] = []
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
            kept.append(idx)
        out["number_of_classes"] = len(kept)
        out["classes"] = LazySeq(
            range(len(kept)),
            lambda ci: Dotnet._decode_class(heaps, tables, names, gparams, typedef, kept[ci]),
        )

    @staticmethod
    def _decode_class(
        heaps: Heaps,
        tables: Tables,
        names: Names,
        gparams: dict[tuple[int, int], list[bytes]],
        typedef: Grid,
        idx: int,
    ) -> Mapping[str, Any]:
        row = typedef.row(idx)
        name = heaps.text(row["name"]) if row is not None else None
        if (
            row is None or name is None
        ):  # the slot was validated when kept, so this is only for the type checker
            return {}
        tick = name.find(b"`")
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
        # the reference always presents a methods list; building it (signatures, parameters) is the cost, so
        # defer it -- a rule reading a class name or a count never parses any method, while a count or a method
        # read triggers the one filter pass. ``number_of_methods`` is present only where the reference sets it.
        method_list = row["methods"]
        count = Dotnet._method_count(tables, typedef, idx, method_list)
        deferred = (
            ("number_of_methods", "methods")
            if method_list and count <= MAX_METHODS
            else ("methods",)
        )
        build = partial(
            Dotnet._methods_block, heaps, tables, names, method_list, count, gp, gparams
        )
        return LazyRecord(c, deferred, build)

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
    def _methods_block(
        heaps: Heaps,
        tables: Tables,
        names: Names,
        method_list: int,
        count: int,
        class_gp: list[bytes],
        gparams: dict[tuple[int, int], list[bytes]],
    ) -> dict[str, Any]:
        """The class's methods and their post-filter count, built on first access (see _decode_class). The
        reference reports an empty methods list and no count where the method list is absent or too long."""
        if not method_list or count > MAX_METHODS:
            return {"methods": {}}
        block = tables.bulk("methoddef")  # the whole methoddef table read once, rows as tuples
        methods: dict[int, Any] = {}
        kept = 0
        if block is not None:
            rows, pos, total = block
            ni, si, qi, fi = pos["name"], pos["sig"], pos["params"], pos["flags"]
            pblock = tables.bulk("param")  # the param table's extent, read once here not per method
            ptotal = pblock[2] if pblock is not None else 0
            pfit = len(pblock[0]) if pblock is not None else 0
            generic = bool(gparams)  # look up generic parameters only if the assembly has any
            for off in range(count):
                idx = method_list - 1 + off
                if not 0 <= idx < total:  # out of the declared table ends the class's methods
                    break
                if idx >= len(rows):
                    continue  # a row past the fitting region is skipped, as the reference does
                t = rows[idx]
                name = heaps.text(t[ni])
                if not name:
                    continue
                method_gp = gparams.get((1, method_list + off), []) if generic else []
                start, length = heaps.blob_at(t[si])
                if not start or length < 3:
                    continue
                sig = names.signatures.method(start, length, class_gp, method_gp)
                if sig is None:  # return type did not decode, or an absurd parameter count
                    continue
                n_params, ret, ptypes = sig
                params = t[qi]
                # the old _params_ok inline: drop the method if a parameter type did not decode, or a
                # parameter row lies within the declared table but past its fitting region
                drop = False
                if params:
                    for poff in range(n_params):
                        pidx = params - 1 + poff
                        if ptypes[poff] is None or (pidx < ptotal and pidx >= pfit):
                            drop = True
                            break
                if drop:
                    continue
                # the method is kept; its fields (its parameter list especially) are built only when read
                descriptor = (name, t[fi], method_gp, ret, ptypes, params, n_params)
                methods[kept] = _Method(descriptor, heaps, tables)
                kept += 1
        return {"methods": methods, "number_of_methods": kept}

    @staticmethod
    def _build_params(
        heaps: Heaps, tables: Tables, param_list: int, count: int, ptypes: list[bytes | None]
    ) -> Any:
        if not param_list:
            return True
        block = tables.bulk("param")
        out: dict[int, Any] = {}
        for off in range(count):
            kind = ptypes[off]  # the type was decoded with the method signature (cached)
            if kind is None:
                return None
            idx = param_list - 1 + off
            name: bytes | None
            if block is not None and 0 <= idx < block[2]:
                # the row is within the table: it must fit, or the reference drops the whole method
                rows, pos, _total = block
                if idx >= len(rows):
                    return None
                name = heaps.text(rows[idx][pos["name"]])
            else:  # no row for this parameter: a synthetic name, as the reference uses
                name = b"P_%d" % off
            entry: dict[str, Any] = {"type": kind}
            if name is not None:
                entry["name"] = name
            out[off] = entry
        return out


__all__ = [
    "HEAPS",
    "INT",
    "MAX_METHODS",
    "METHOD_VISIBILITY",
    "TEXT",
    "TYPE_VISIBILITY",
    "Dotnet",
    "_Method",
]
