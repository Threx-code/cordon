"""YARA's `dotnet` module: a .NET assembly's metadata, read as YARA 4.5.1 reads it.

A port of libyara/modules/dotnet/dotnet.c (Apache License 2.0), guard for guard: the CLI header
and metadata root, the stream headers, the GUID and user-string heaps, the metadata tables with
their index sizes, and from them the module and assembly names, assembly references, manifest
resources, module references, string constants, field offsets, the type library GUID, and every
class with its generic parameters, base types and methods (parameters and return types decoded
from their signatures). Where YARA reads loosely -- one byte of the stream count, a user string
whose terminal byte is not skipped, a table it does not know ending the walk -- this reads the
same way, so a rule sees the values YARA would give it.
"""

from __future__ import annotations

import contextlib
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_values import (
    UNDEF_INT,
    UNDEF_STR,
    Array,
    Struct,
    Values,
)
from cordon_scanner.detect.binary.yara_pe import Image


@dataclass
class Table:
    """`TABLE_INFO`: where a metadata table starts, its rows and the size of one."""

    offset: int = 0
    rows: int = 0
    size: int = 0

    def row(self, index: int) -> int | None:
        """`get_table_offset`: the row at a one-based index, or None."""
        if index < 1 or index > self.rows:
            return None
        return self.offset + self.size * (index - 1)


@dataclass
class Context:
    """`CLASS_CONTEXT`: what decoding classes and signatures needs."""

    img: Image
    tables: dict[str, Table]
    sizes: dict[str, int]
    str_heap: int
    str_size: int
    blob_heap: int


@dataclass
class Generics:
    names: list[bytes] = field(default_factory=list)


class Reader:
    """Little-endian reads that advance, as `read_u16`/`read_u32`/`read_index` do."""

    def __init__(self, img: Image, at: int) -> None:
        self.img, self.at = img, at

    def u8(self) -> int:
        v = self.img.data[self.at]
        self.at += 1
        return v

    def u16(self) -> int:
        v = self.img.u16(self.at)
        self.at += 2
        return v

    def u32(self) -> int:
        v = self.img.u32(self.at)
        self.at += 4
        return v

    def index(self, size: int) -> int:
        return self.u16() if size == 2 else self.u32()


class Blob:
    """A signature being read: its position and the bytes left (`data`, `len`)."""

    def __init__(self, at: int, length: int) -> None:
        self.at, self.length = at, length

    def unsigned(self, data: bytes) -> int:
        """`read_blob_unsigned`."""
        if self.length < 1:
            return 0
        first = data[self.at]
        if not first & 0x80:
            self.at += 1
            self.length -= 1
            return first
        if self.length < 2:
            return 0
        if first & 0xC0 == 0x80:
            v = int.from_bytes(data[self.at : self.at + 2], "big")
            self.at += 2
            self.length -= 2
            return v & 0x3FFF
        if self.length < 4:
            return 0
        if first & 0xE0 == 0xC0:
            v = int.from_bytes(data[self.at : self.at + 4], "big")
            self.at += 4
            self.length -= 4
            return v & 0x1FFFFFFF
        return 0

    def signed(self, data: bytes) -> int:
        """`read_blob_signed`."""
        if self.length < 1:
            return 0
        first = data[self.at]
        if not first & 0x80:
            tmp = first >> 1
            if first & 1:
                tmp |= 0xC0
            self.at += 1
            self.length -= 1
            return tmp - 256 if tmp & 0x80 else tmp
        if self.length < 2:
            return 0
        if first & 0xC0 == 0x80:
            v = int.from_bytes(data[self.at : self.at + 2], "big")
            tmp = (v >> 1) & 0x3FFF
            if v & 1:
                tmp |= 0xE000
            self.at += 2
            self.length -= 2
            return tmp - 0x10000 if tmp & 0x8000 else tmp
        if self.length < 4:
            return 0
        if first & 0xE0 == 0xC0:
            v = int.from_bytes(data[self.at : self.at + 4], "big")
            tmp = (v >> 1) & 0x1FFFFFFF
            if v & 1:
                tmp |= 0xF0000000
            self.at += 4
            self.length -= 4
            return tmp - (1 << 32) if tmp & 0x80000000 else tmp
        return 0


class Dotnet:
    """`Dotnet.module(data)`: the `dotnet` module's values for a file."""

    MAX_ARRAY_RANK: ClassVar[int] = 50
    MAX_PARAM_COUNT: ClassVar[int] = 2000
    MAX_GEN_PARAM_COUNT: ClassVar[int] = 1000
    MAX_METHOD_COUNT: ClassVar[int] = 20000
    MAX_TYPE_DEPTH: ClassVar[int] = 0x10
    MAX_NAMESPACE_DEPTH: ClassVar[int] = 0x0A
    CLI_HEADER_SIZE: ClassVar[int] = 72
    METADATA_MAGIC: ClassVar[int] = 0x424A5342
    #: TYPE_* -> the name a signature's element type prints as
    PRIMITIVES: ClassVar[dict[int, bytes]] = {
        0x1: b"void", 0x2: b"bool", 0x3: b"char", 0x4: b"sbyte", 0x5: b"byte", 0x6: b"short",
        0x7: b"ushort", 0x8: b"int", 0x9: b"uint", 0xA: b"long", 0xB: b"ulong", 0xC: b"float",
        0xD: b"double", 0xE: b"string", 0x16: b"TypedReference", 0x18: b"IntPtr", 0x19: b"UIntPtr",
        0x1C: b"object",
    }  # fmt: skip
    TYPE_VISIBILITY: ClassVar[dict[int, bytes]] = {
        3: b"private", 1: b"public", 2: b"public", 4: b"protected", 0: b"internal", 5: b"internal",
        6: b"private protected", 7: b"protected internal",
    }  # fmt: skip
    METHOD_VISIBILITY: ClassVar[dict[int, bytes]] = {
        1: b"private", 2: b"private protected", 3: b"internal", 4: b"protected",
        5: b"protected internal", 6: b"public",
    }  # fmt: skip
    #: the row-count fields `dotnet_parse_tilde` collects, by table bit, and whether a large
    #: count widens that table's index
    ROW_FIELDS: ClassVar[dict[int, tuple[str, bool]]] = {
        0x00: ("module", True), 0x1A: ("moduleref", True), 0x23: ("assemblyref", True),
        0x24: ("assemblyrefprocessor", True), 0x01: ("typeref", True), 0x06: ("methoddef", True),
        0x0A: ("memberref", True), 0x02: ("typedef_", True), 0x1B: ("typespec", True),
        0x04: ("field", True), 0x08: ("param", True), 0x17: ("property", True),
        0x09: ("interfaceimpl", True), 0x14: ("event", True), 0x11: ("standalonesig", False),
        0x20: ("assembly", True), 0x26: ("file", False), 0x27: ("exportedtype", False),
        0x28: ("manifestresource", False), 0x2A: ("genericparam", True),
        0x2C: ("genericparamconstraint", False), 0x2B: ("methodspec", True),
    }  # fmt: skip
    INDEX_NAMES: ClassVar[tuple[str, ...]] = (
        "string", "guid", "blob", "field", "methoddef", "methodspec", "memberref", "param", "event",
        "typedef_", "typeref", "typespec", "interfaceimpl", "property", "moduleref", "module",
        "assemblyrefprocessor", "assemblyref", "assembly", "genericparam",
    )  # fmt: skip

    # -- schema -------------------------------------------------------------

    @staticmethod
    def schema() -> Struct:
        u, s = UNDEF_INT, UNDEF_STR
        version = Struct({"major": u, "minor": u, "build_number": u, "revision_number": u})
        method = Struct({
            "generic_parameters": Array(s), "number_of_generic_parameters": u,
            "parameters": Array(Struct({"name": s, "type": s})), "number_of_parameters": u,
            "return_type": s, "abstract": u, "final": u, "virtual": u, "static": u, "visibility": s, "name": s,
        })  # fmt: skip
        klass = Struct({
            "fullname": s, "name": s, "namespace": s, "visibility": s, "type": s, "abstract": u, "sealed": u,
            "number_of_generic_parameters": u, "generic_parameters": Array(s), "number_of_base_types": u,
            "base_types": Array(s), "number_of_methods": u, "methods": Array(method),
        })  # fmt: skip
        return Struct({
            "is_dotnet": u, "version": s, "module_name": s,
            "streams": Array(Struct({"name": s, "offset": u, "size": u})), "number_of_streams": u,
            "guids": Array(s), "number_of_guids": u,
            "resources": Array(Struct({"offset": u, "length": u, "name": s})), "number_of_resources": u,
            "classes": Array(klass), "number_of_classes": u,
            "assembly_refs": Array(Struct({"version": version, "public_key_or_token": s, "name": s})),
            "number_of_assembly_refs": u,
            "assembly": Struct({"version": Values.undefined_like(version), "name": s, "culture": s}),
            "modulerefs": Array(s), "number_of_modulerefs": u, "user_strings": Array(s),
            "number_of_user_strings": u, "typelib": s, "constants": Array(s), "number_of_constants": u,
            "field_offsets": Array(u), "number_of_field_offsets": u,
        })  # fmt: skip

    @staticmethod
    def element(array: Array, index: int) -> Struct:
        """The struct at `index`, made (all undefined) when it is first written, as YARA does."""
        if index not in array.items:
            array.items[index] = Values.undefined_like(array.proto)
        item: Struct = array.items[index]
        return item

    @staticmethod
    def module(data: bytes) -> Struct:
        root = Dotnet.schema()
        img = Image.header(data)
        if img is None:
            return root
        with contextlib.suppress(IndexError, struct.error):
            Dotnet._parse_com(root.fields, img)
        return root

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def string(img: Image, heap: int, size: int, index: int) -> bytes | None:
        """`pe_get_dotnet_string`."""
        start = heap + index
        if not (0 <= start < img.n and index < size):
            return None
        end = img.data.find(b"\x00", start)
        if end < 0 or end - start > 1024:
            return None
        return img.data[start:end]

    @staticmethod
    def blob_entry(img: Image, at: int) -> tuple[int, int]:
        """`dotnet_parse_blob_entry`: (bytes of the length prefix, the length); size 0 is none."""
        if not img.fits(at, 1):
            return 0, 0
        first = img.data[at]
        if first & 0x80 == 0:
            size, length = 1, first
        elif first & 0xC0 == 0x80:
            if not img.fits(at, 2):
                return 0, 0
            size, length = 2, ((first & 0x3F) << 8) | img.data[at + 1]
        elif at + 4 < img.n and first & 0xE0 == 0xC0:
            if not img.fits(at, 4):
                return 0, 0
            d = img.data
            size, length = (
                4,
                ((first & 0x1F) << 24) | (d[at + 1] << 16) | (d[at + 2] << 8) | d[at + 3],
            )
        else:
            return 0, 0
        if not img.fits(at, (size + length) & 0xFFFFFFFF):
            return 0, length
        return size, length

    @staticmethod
    def full_name(name: bytes | None, namespace: bytes | None) -> bytes | None:
        """`create_full_name`: `<namespace>.<name>`, cut at the first backtick."""
        if not name:
            return namespace
        joined = name if not namespace else namespace + b"." + name
        cut = joined.find(b"`")
        return joined if cut < 0 else joined[:cut]

    @staticmethod
    def nested(flags: int) -> bool:
        return flags & 7 in (2, 3, 4, 5, 6, 7)

    # -- rows (`read_typedef` and the rest) ----------------------------------

    @staticmethod
    def _wide(ctx: Context, names: tuple[str, ...], shift: int) -> int:
        return 4 if max(ctx.tables[name].rows for name in names) > (0xFFFF >> shift) else 2

    @staticmethod
    def typedef(ctx: Context, at: int | None) -> tuple[int, int, int, int, int, int] | None:
        if at is None or not ctx.img.fits(at, ctx.tables["typedef_"].size):
            return None
        r = Reader(ctx.img, at)
        ext = Dotnet._wide(ctx, ("typedef_", "typeref", "typespec"), 2)
        return (r.u32(), r.index(ctx.sizes["string"]), r.index(ctx.sizes["string"]), r.index(ext),
                r.index(ctx.sizes["field"]), r.index(ctx.sizes["methoddef"]))  # fmt: skip

    @staticmethod
    def typeref(ctx: Context, at: int | None) -> tuple[int, int, int] | None:
        if at is None or not ctx.img.fits(at, ctx.tables["typeref"].size):
            return None
        r = Reader(ctx.img, at)
        res = Dotnet._wide(ctx, ("module", "moduleref", "assemblyref", "typeref"), 2)
        return r.index(res), r.index(ctx.sizes["string"]), r.index(ctx.sizes["string"])

    @staticmethod
    def interfaceimpl(ctx: Context, at: int | None) -> tuple[int, int] | None:
        if at is None or not ctx.img.fits(at, ctx.tables["interfaceimpl"].size):
            return None
        r = Reader(ctx.img, at)
        size = Dotnet._wide(ctx, ("typedef_", "typeref", "typespec"), 2)
        return r.index(ctx.sizes["typedef_"]), r.index(size)

    @staticmethod
    def methoddef(ctx: Context, at: int | None) -> tuple[int, int, int, int, int, int] | None:
        if at is None or not ctx.img.fits(at, ctx.tables["methoddef"].size):
            return None
        r = Reader(ctx.img, at)
        return (r.u32(), r.u16(), r.u16(), r.index(ctx.sizes["string"]), r.index(ctx.sizes["blob"]),
                r.index(ctx.sizes["param"]))  # fmt: skip

    @staticmethod
    def param(ctx: Context, at: int | None) -> tuple[int, int, int] | None:
        if at is None or not ctx.img.fits(at, ctx.tables["param"].size):
            return None
        r = Reader(ctx.img, at)
        return r.u16(), r.u16(), r.index(ctx.sizes["string"])

    @staticmethod
    def genericparam(ctx: Context, at: int | None) -> tuple[int, int, int, int] | None:
        if at is None or not ctx.img.fits(at, ctx.tables["genericparam"].size):
            return None
        r = Reader(ctx.img, at)
        owner = Dotnet._wide(ctx, ("typedef_", "methoddef"), 1)
        return r.u16(), r.u16(), r.index(owner), r.index(ctx.sizes["string"])

    @staticmethod
    def typespec(ctx: Context, at: int | None) -> int | None:
        if at is None or not ctx.img.fits(at, ctx.tables["typespec"].size):
            return None
        return Reader(ctx.img, at).index(ctx.sizes["blob"])

    @staticmethod
    def nestedclass(ctx: Context, at: int | None) -> tuple[int, int] | None:
        if at is None or not ctx.img.fits(at, ctx.tables["nestedclass"].size):
            return None
        r = Reader(ctx.img, at)
        return r.index(ctx.sizes["typedef_"]), r.index(ctx.sizes["typedef_"])

    # -- type names --------------------------------------------------------

    @staticmethod
    def type_name(
        ctx: Context, coded: int, class_gp: Generics | None, method_gp: Generics | None, depth: int
    ) -> bytes | None:
        """`get_type_def_or_ref_fullname`."""
        index = coded >> 2
        if not index:
            return None
        table = coded & 3
        img = ctx.img
        if table == 0:
            row = Dotnet.typedef(ctx, ctx.tables["typedef_"].row(index))
            if row is None:
                return None
            name = Dotnet.string(img, ctx.str_heap, ctx.str_size, row[1])
            namespace = Dotnet.string(img, ctx.str_heap, ctx.str_size, row[2])
            if Dotnet.nested(row[0]):
                enclosing = Dotnet.enclosing(ctx, index, 1)
                return Dotnet.full_name(name, Dotnet.full_name(namespace, enclosing))
            return Dotnet.full_name(name, namespace)
        if table == 1:
            ref = Dotnet.typeref(ctx, ctx.tables["typeref"].row(index))
            if ref is None:
                return None
            name = Dotnet.string(img, ctx.str_heap, ctx.str_size, ref[1])
            namespace = Dotnet.string(img, ctx.str_heap, ctx.str_size, ref[2])
            return Dotnet.full_name(name, namespace)
        if table == 2:
            sig = Dotnet.typespec(ctx, ctx.tables["typespec"].row(index))
            if sig is None:
                return None
            at = ctx.blob_heap + sig
            size, length = Dotnet.blob_entry(img, at)
            if size:
                return Dotnet.signature_type(ctx, Blob(at + size, length), class_gp, None, depth)
        return None

    @staticmethod
    def enclosing(ctx: Context, nested_idx: int, depth: int) -> bytes | None:
        """`parse_enclosing_types`: the names of the types a nested type sits in."""
        if depth > Dotnet.MAX_NAMESPACE_DEPTH:
            return None
        img = ctx.img
        table = ctx.tables["nestedclass"]
        for idx in range(table.rows):
            row = Dotnet.nestedclass(ctx, table.row(idx + 1))
            if row is None:
                continue
            nested_class, enclosing_class = row
            if nested_class != nested_idx:
                continue
            outer = Dotnet.typedef(ctx, ctx.tables["typedef_"].row(enclosing_class))
            if outer is None:
                break
            name = Dotnet.string(img, ctx.str_heap, ctx.str_size, outer[1])
            if name == b"<Module>":
                break
            namespace = Dotnet.string(img, ctx.str_heap, ctx.str_size, outer[2])
            if Dotnet.nested(outer[0]) and enclosing_class != nested_class:
                further = Dotnet.enclosing(ctx, enclosing_class, depth + 1)
                return Dotnet.full_name(name, Dotnet.full_name(namespace, further))
            return Dotnet.full_name(name, namespace)
        return None

    @staticmethod
    def signature_type(
        ctx: Context, blob: Blob, class_gp: Generics | None, method_gp: Generics | None, depth: int
    ) -> bytes | None:
        """`parse_signature_type`: one type from a signature, as C# would spell it."""
        img = ctx.img
        data = img.data
        if blob.length < 1 or not img.fits(blob.at, 1) or depth > Dotnet.MAX_TYPE_DEPTH:
            return None
        kind = data[blob.at]
        blob.at += 1
        blob.length -= 1

        def inner() -> bytes | None:
            return Dotnet.signature_type(ctx, blob, class_gp, method_gp, depth + 1)

        if kind in Dotnet.PRIMITIVES:
            return Dotnet.PRIMITIVES[kind]
        if kind == 0x0F:
            t = inner()
            return None if t is None else b"Ptr<" + t + b">"
        if kind == 0x10:
            t = inner()
            return None if t is None else b"ref " + t
        if kind in (0x11, 0x12):
            coded = blob.unsigned(data)
            return Dotnet.type_name(ctx, coded, class_gp, method_gp, depth + 1)
        if kind in (0x13, 0x1E):
            index = blob.unsigned(data)
            params = class_gp if kind == 0x13 else method_gp
            if params is not None and index < len(params.names):
                return params.names[index]
            return None
        if kind == 0x14:
            return Dotnet._array(blob, data, inner())
        if kind == 0x15:
            t = inner()
            if t is None:
                return None
            count = blob.unsigned(data)
            if count > Dotnet.MAX_GEN_PARAM_COUNT:
                return None
            out = t + b"<"
            for i in range(count):
                p = inner()
                if p is not None:
                    out += (b"," if i > 0 else b"") + p
            return out + b">"
        if kind == 0x1B:
            if blob.length > 0:
                blob.at += 1
                blob.length -= 1
                count = blob.unsigned(data)
                if count > Dotnet.MAX_PARAM_COUNT:
                    return None
                ret = inner()
                if ret is None:
                    return None
                out = b"FnPtr<" + ret + b"("
                for i in range(count):
                    p = inner()
                    if p is not None:
                        out += (b", " if i > 0 else b"") + p
                return out + b")>"
            return None
        if kind == 0x1D:
            t = inner()
            return None if t is None else t + b"[]"
        if kind in (0x1F, 0x20):
            blob.unsigned(data)
            return inner()
        return None

    @staticmethod
    def _array(blob: Blob, data: bytes, element: bytes | None) -> bytes | None:
        """TYPE_ARRAY: `<type>[lo...size, ...]` with the C's 32-bit arithmetic."""
        if element is None:
            return None
        rank = blob.unsigned(data)
        if not rank or rank > Dotnet.MAX_ARRAY_RANK:
            return None
        num_sizes = blob.unsigned(data)
        if num_sizes > rank:
            return None
        sizes = [Dotnet._i32(blob.unsigned(data)) for _ in range(num_sizes)]
        num_lo = blob.unsigned(data)
        if num_lo > rank:
            return None
        lo = []
        for i in range(num_lo):
            bound = blob.signed(data)
            lo.append(bound)
            if num_sizes > i and bound != 0:
                sizes[i] = Dotnet._i32(sizes[i] + bound - 1)
        out = element + b"["
        for i in range(rank):
            if num_sizes > i or num_lo > i:
                if num_lo > i and lo[i] != 0:
                    out += b"%d..." % lo[i]
                if num_sizes > i:
                    out += b"%d" % sizes[i]
            if i + 1 != rank:
                out += b","
        return out + b"]"

    @staticmethod
    def _i32(value: int) -> int:
        value &= 0xFFFFFFFF
        return value - (1 << 32) if value & 0x80000000 else value

    # -- classes -----------------------------------------------------------

    @staticmethod
    def generics(ctx: Context, method: bool, owner: int) -> Generics:
        """`parse_generic_params`: the names of a type's or method's generic parameters."""
        out = Generics()
        table = ctx.tables["genericparam"]
        for idx in range(table.rows):
            at = table.row(idx + 1)
            if at is None:
                return Generics()
            row = Dotnet.genericparam(ctx, at)
            if row is None:
                continue
            _, _, owner_coded, name_index = row
            if (owner_coded & 1) == int(method) and owner_coded >> 1 == owner:
                name = Dotnet.string(ctx.img, ctx.str_heap, ctx.str_size, name_index)
                if not name:
                    return Generics()
                out.names.append(name)
        return out

    @staticmethod
    def user_types(f: dict[str, Any], ctx: Context) -> None:
        """`parse_user_types`: every class and interface, with its members."""
        img = ctx.img
        typedefs = ctx.tables["typedef_"]
        classes: Array = f["classes"]
        out = 0
        for idx in range(typedefs.rows):
            row = Dotnet.typedef(ctx, typedefs.row(idx + 1))
            if row is None:
                continue
            flags, name_index, ns_index, extends, _, method_list = row
            name = Dotnet.string(img, ctx.str_heap, ctx.str_size, name_index)
            kind = {0: b"class", 0x20: b"interface"}[flags & 0x20]
            if not name:
                continue
            tick = name.find(b"`")
            if tick == 0 or name == b"<Module>":
                continue
            c = Dotnet.element(classes, out).fields
            c["name"] = name[:tick] if tick > 0 else name
            namespace = Dotnet.string(img, ctx.str_heap, ctx.str_size, ns_index)
            if Dotnet.nested(flags):
                namespace = Dotnet.full_name(namespace, Dotnet.enclosing(ctx, idx + 1, 1))
            c["namespace"] = namespace if namespace is not None else UNDEF_STR
            fullname = Dotnet.full_name(name, namespace)
            c["fullname"] = fullname if fullname is not None else UNDEF_STR
            c["visibility"] = Dotnet.TYPE_VISIBILITY[flags & 7]
            c["type"] = kind
            c["abstract"] = int(bool(flags & 0x80))
            c["sealed"] = int(bool(flags & 0x100))
            gp = Dotnet.generics(ctx, False, idx + 1)
            c["number_of_generic_parameters"] = len(gp.names)
            for i, gname in enumerate(gp.names):
                c["generic_parameters"].items[i] = gname
            Dotnet._parents(ctx, c, extends, idx + 1, gp)
            count = 0
            if idx + 1 < typedefs.rows:
                following = Dotnet.typedef(ctx, typedefs.row(idx + 2))
                if following is not None and following[5] >= method_list:
                    count = following[5] - method_list
            elif ctx.tables["methoddef"].rows >= method_list:
                count = ctx.tables["methoddef"].rows + 1 - method_list
            if count <= Dotnet.MAX_METHOD_COUNT:
                Dotnet._methods(ctx, c, method_list, count, gp)
            out += 1
        f["number_of_classes"] = out

    @staticmethod
    def _parents(
        ctx: Context, c: dict[str, Any], extends: int, type_idx: int, gp: Generics
    ) -> None:
        """`parse_type_parents`: the base type, then each interface the type implements."""
        n = 0
        parent = Dotnet.type_name(ctx, extends, gp, None, 0)
        if parent is not None:
            c["base_types"].items[n] = parent
            n += 1
        table = ctx.tables["interfaceimpl"]
        for idx in range(table.rows):
            at = table.row(idx + 1)
            if at is None:
                break
            row = Dotnet.interfaceimpl(ctx, at)
            if row is None or row[0] != type_idx:
                continue
            interface = Dotnet.type_name(ctx, row[1], gp, None, 0)
            if interface is not None:
                c["base_types"].items[n] = interface
                n += 1
        c["number_of_base_types"] = n

    @staticmethod
    def _methods(
        ctx: Context, c: dict[str, Any], method_list: int, count: int, class_gp: Generics
    ) -> None:
        """`parse_methods`."""
        if not method_list:
            return
        img = ctx.img
        table = ctx.tables["methoddef"]
        methods: Array = c["methods"]
        out = 0
        for idx in range(count):
            at = table.row(method_list + idx)
            if at is None:
                break
            row = Dotnet.methoddef(ctx, at)
            if row is None:
                continue
            _, _, flags, name_index, sig_index, param_list = row
            name = Dotnet.string(img, ctx.str_heap, ctx.str_size, name_index)
            if not name:
                continue
            method_gp = Dotnet.generics(ctx, True, method_list + idx)
            sig_at = ctx.blob_heap + sig_index
            size, length = Dotnet.blob_entry(img, sig_at)
            blob = Blob(sig_at + size, length)
            if not (size and length >= 3):
                continue
            sig_flags = img.data[blob.at]
            blob.at += 1
            blob.length -= 1
            if sig_flags & 0x10:
                blob.unsigned(img.data)
            param_count = blob.unsigned(img.data)
            return_type = Dotnet.signature_type(ctx, blob, class_gp, method_gp, 0)
            if return_type is None or param_count > Dotnet.MAX_PARAM_COUNT:
                continue
            params = Dotnet._params(ctx, param_list, param_count, blob, class_gp, method_gp)
            if params is None:
                continue
            m = Dotnet.element(methods, out).fields
            if isinstance(params, list):
                m["number_of_parameters"] = param_count
                for i, (pname, ptype) in enumerate(params):
                    p = Dotnet.element(m["parameters"], i).fields
                    p["name"] = pname if pname is not None else UNDEF_STR
                    p["type"] = ptype
            m["name"] = name
            m["visibility"] = Dotnet.METHOD_VISIBILITY.get(flags & 7, b"private")
            m["static"] = int(bool(flags & 0x10))
            m["virtual"] = int(bool(flags & 0x40))
            m["final"] = int(bool(flags & 0x20))
            m["abstract"] = int(bool(flags & 0x400))
            m["number_of_generic_parameters"] = len(method_gp.names)
            for i, gname in enumerate(method_gp.names):
                m["generic_parameters"].items[i] = gname
            if name not in (b".ctor", b".cctor"):
                m["return_type"] = return_type
            out += 1
        c["number_of_methods"] = out

    @staticmethod
    def _params(
        ctx: Context,
        param_list: int,
        count: int,
        blob: Blob,
        class_gp: Generics,
        method_gp: Generics,
    ) -> list[tuple[bytes | None, bytes]] | bool | None:
        """`parse_method_params`: each parameter's name and type; True with no parameter list,
        None where the method is dropped."""
        if not param_list:
            return True
        out: list[tuple[bytes | None, bytes]] = []
        table = ctx.tables["param"]
        for idx in range(count):
            at = table.row(param_list + idx)
            name: bytes | None
            if at is not None:
                row = Dotnet.param(ctx, at)
                if row is None:
                    return None
                name = Dotnet.string(ctx.img, ctx.str_heap, ctx.str_size, row[2])
            else:
                name = b"P_%d" % idx
            kind = Dotnet.signature_type(ctx, blob, class_gp, method_gp, 0)
            if kind is None:
                return None
            out.append((name, kind))
        return out

    # -- the heaps and tables ----------------------------------------------

    @staticmethod
    def _parse_com(f: dict[str, Any], img: Image) -> None:
        """`dotnet_is_dotnet` then `dotnet_parse_com`."""
        directory = img.directory(14)
        cli = metadata = -1
        ok = directory is not None
        if directory is not None:
            cli = img.rva_to_offset(directory[0])
            ok = (
                cli >= 0
                and img.fits(cli, Dotnet.CLI_HEADER_SIZE)
                and img.u32(cli) == Dotnet.CLI_HEADER_SIZE
            )
        if ok:
            metadata = img.rva_to_offset(img.u32(cli + 8))
            ok = img.fits(metadata, 16) and img.u32(metadata) == Dotnet.METADATA_MAGIC
        if ok:
            md_len = img.u32(metadata + 12)
            ok = 0 < md_len <= 255 and md_len % 4 == 0 and img.fits(metadata + 16, md_len)
            if ok and img.is64 and img.number_of_rva_and_sizes() < 14:
                ok = False
        if not ok:
            f["is_dotnet"] = 0
            return
        f["is_dotnet"] = 1
        md_len = img.u32(metadata + 12)
        version = img.data[metadata + 16 : metadata + 16 + md_len]
        end = version.find(b"\x00")
        if end >= 0:
            f["version"] = version[:end]
        at = metadata + 16 + md_len + 2
        if not img.fits(at, 2):
            return
        num_streams = img.data[at]  # one byte, as the C reads it
        streams = Dotnet._streams(f, img, at + 2, metadata, num_streams)
        if "guid" in streams:
            Dotnet._guids(f, img, metadata, streams["guid"])
        if "tilde" in streams and "string" in streams and "blob" in streams:
            Dotnet._tilde(f, img, cli, metadata, streams)
        if "us" in streams:
            Dotnet._user_strings(f, img, metadata, streams["us"])

    @staticmethod
    def _streams(
        f: dict[str, Any], img: Image, at: int, root: int, count: int
    ) -> dict[str, tuple[int, int]]:
        """`dotnet_parse_stream_headers`: each stream's name, offset and size; the heaps found."""
        found: dict[str, tuple[int, int]] = {}
        i = 0
        while i < count:
            if not img.fits(at, 8) or not img.fits(at + 8, 32):
                break
            raw = img.data[at + 8 : at + 8 + 32]
            nul = raw.find(b"\x00")
            if nul < 0:
                break
            name = raw[:nul]
            offset, size = img.u32(at), img.u32(at + 4)
            s = Dotnet.element(f["streams"], i).fields
            s.update(name=name, offset=root + offset, size=size)
            if name.startswith((b"#~", b"#-")) and "tilde" not in found:
                found["tilde"] = (offset, size)
            elif name.startswith(b"#GUID"):
                found["guid"] = (offset, size)
            elif name.startswith(b"#Strings") and "string" not in found:
                found["string"] = (offset, size)
            elif name.startswith(b"#Blob") and "blob" not in found:
                found["blob"] = (offset, size)
            elif name.startswith(b"#US") and "us" not in found:
                found["us"] = (offset, size)
            at += 8 + len(name) + 4 - (len(name) % 4)
            i += 1
        f["number_of_streams"] = i
        return found

    @staticmethod
    def _guids(f: dict[str, Any], img: Image, root: int, stream: tuple[int, int]) -> None:
        at = root + stream[0]
        size = min(stream[1], 256)
        i = 0
        while size >= 16 and img.fits(at, 16):
            a, b, c = struct.unpack_from("<IHH", img.data, at)
            rest = img.data[at + 8 : at + 16]
            f["guids"].items[i] = b"%08x-%04x-%04x-%s-%s" % (
                a,
                b,
                c,
                rest[:2].hex().encode(),
                rest[2:].hex().encode(),
            )
            i += 1
            size -= 16
            at += 16
        f["number_of_guids"] = i

    @staticmethod
    def _user_strings(f: dict[str, Any], img: Image, root: int, stream: tuple[int, int]) -> None:
        """`dotnet_parse_us`, including its not stepping over a string's terminal byte."""
        size = stream[1]
        at = root + stream[0]
        end = at + size
        if size == 0 or not img.fits(at, size) or img.data[at] != 0:
            return
        at += 1
        i = 0
        while at < end:
            prefix, length = Dotnet.blob_entry(img, at)
            if prefix == 0:
                break
            at += prefix
            if length > 0:
                length -= 1
            if length > 0 and img.fits(at, length):
                f["user_strings"].items[i] = img.data[at : at + length]
                at += length
                i += 1
        f["number_of_user_strings"] = i

    @staticmethod
    def _tilde(
        f: dict[str, Any], img: Image, cli: int, root: int, streams: dict[str, tuple[int, int]]
    ) -> None:
        """`dotnet_parse_tilde`: the row counts and index sizes the tables are read with."""
        header = root + streams["tilde"][0]
        if not img.fits(header, 24):
            return
        heap_sizes = img.data[header + 6]
        valid = struct.unpack_from("<Q", img.data, header + 8)[0]
        sizes = dict.fromkeys(Dotnet.INDEX_NAMES, 2)
        if heap_sizes & 1:
            sizes["string"] = 4
        if heap_sizes & 2:
            sizes["guid"] = 4
        if heap_sizes & 4:
            sizes["blob"] = 4
        rows: dict[str, int] = dict.fromkeys((name for name, _ in Dotnet.ROW_FIELDS.values()), 0)
        counts = header + 24
        matched = 0
        for bit in range(64):
            if not (valid >> bit) & 1:
                continue
            entry = Dotnet.ROW_FIELDS.get(bit)
            if entry is not None:
                name, widens = entry
                if img.fits(counts, (matched + 1) * 4):
                    rows[name] = img.u32(counts + 4 * matched)
                if widens and rows[name] > 0xFFFF:
                    sizes[name] = 4
            matched += 1
        resource_base = img.rva_to_offset(img.u32(cli + 24))
        Dotnet._tables(f, img, header, heap_sizes, valid, resource_base, rows, sizes, root, streams)

    @staticmethod
    def _tables(f: dict[str, Any], img: Image, header: int, heap_sizes: int, valid: int, resource_base: int,
                rows: dict[str, int], sizes: dict[str, int], root: int, streams: dict[str, tuple[int, int]]) -> None:  # fmt: skip
        """`dotnet_parse_tilde_2`: walk every table present, reading the ones rules see."""
        data = img.data
        valid_rows = bin(valid).count("1")
        counts = header + 24
        at = counts + 4 * valid_rows + (4 if heap_sizes & 0x40 else 0)
        strings, str_size = root + streams["string"][0], streams["string"][1]
        blob_base = root + streams["blob"][0]
        tables = {name: Table() for name in ("typedef_", "typespec", "typeref", "methoddef", "param", "module",
                                             "moduleref", "assembly", "assemblyref", "interfaceimpl", "genericparam",
                                             "nestedclass")}  # fmt: skip
        s = sizes

        def wide(names: tuple[str, ...], shift: int) -> int:
            return 4 if max(rows[n] for n in names) > (0xFFFF >> shift) else 2

        def name_at(pos: int, size: int) -> bytes | None:
            index = img.u16(pos) if size == 2 else img.u32(pos)
            return Dotnet.string(img, strings, str_size, index)

        def keep(name: str, size: int, count: int) -> None:
            tables[name] = Table(at, count, size)

        typeref_at: int | None = None
        memberref_at: int | None = None
        typeref_size = memberref_size = 0
        matched = 0
        skip: dict[int, Callable[[], int]] = {
            0x03: lambda: s["field"], 0x04: lambda: 2 + s["string"] + s["blob"], 0x05: lambda: s["methoddef"],
            0x0D: lambda: wide(("field", "param"), 1) + s["blob"],
            0x0E: lambda: 2 + wide(("typedef_", "methoddef", "assembly"), 2) + s["blob"],
            0x0F: lambda: 2 + 4 + s["typedef_"], 0x10: lambda: 4 + s["field"], 0x11: lambda: s["blob"],
            0x12: lambda: s["typedef_"] + s["event"], 0x13: lambda: s["event"],
            0x14: lambda: 2 + s["string"] + wide(("typedef_", "typeref", "typespec"), 2),
            0x15: lambda: s["typedef_"] + s["property"], 0x16: lambda: s["property"],
            0x17: lambda: 2 + s["string"] + s["blob"],
            0x18: lambda: 2 + s["methoddef"] + wide(("event", "property"), 1),
            0x19: lambda: s["typedef_"] + 2 * wide(("methoddef", "memberref"), 1),
            0x1C: lambda: 2 + wide(("field", "methoddef"), 1) + s["string"] + s["moduleref"],
            0x1E: lambda: 8, 0x1F: lambda: 4, 0x21: lambda: 4, 0x22: lambda: 12,
            0x24: lambda: 4 + s["assemblyrefprocessor"], 0x25: lambda: 12 + s["assemblyref"],
            0x26: lambda: 4 + s["string"] + s["blob"],
            0x27: lambda: 8 + 2 * s["string"] + wide(("file", "assemblyref", "exportedtype"), 2),
            0x2B: lambda: wide(("methoddef", "memberref"), 1) + s["blob"],
            0x2C: lambda: s["genericparam"] + wide(("typedef_", "typeref", "typespec"), 2),
        }  # fmt: skip
        for bit in range(64):
            if not (valid >> bit) & 1:
                continue
            if not img.fits(counts + 4 * matched, 4):
                return
            num_rows = img.u32(counts + 4 * matched)
            if num_rows > 10000:
                return
            if bit in skip:
                at += skip[bit]() * num_rows
            elif bit == 0x00:
                if not img.fits(at, 18):
                    matched += 1
                    continue
                name = name_at(at + 2, s["string"])
                if name is not None:
                    f["module_name"] = name
                size = 2 + s["string"] + 3 * s["guid"]
                keep("module", size, num_rows)
                at += size * num_rows
            elif bit == 0x01:
                size = wide(("module", "moduleref", "assemblyref", "typeref"), 2) + 2 * s["string"]
                typeref_size, typeref_at = size, at
                keep("typeref", size, num_rows)
                at += size * num_rows
            elif bit == 0x02:
                size = (
                    4
                    + 2 * s["string"]
                    + wide(("typedef_", "typeref", "typespec"), 2)
                    + s["field"]
                    + s["methoddef"]
                )
                keep("typedef_", size, num_rows)
                at += size * num_rows
            elif bit == 0x06:
                size = 8 + s["string"] + s["blob"] + s["param"]
                keep("methoddef", size, num_rows)
                at += size * num_rows
            elif bit == 0x08:
                size = 4 + s["string"]
                keep("param", size, num_rows)
                at += size * num_rows
            elif bit == 0x09:
                size = s["typedef_"] + wide(("typedef_", "typeref", "typespec"), 2)
                keep("interfaceimpl", size, num_rows)
                at += size * num_rows
            elif bit == 0x0A:
                size = (
                    wide(("methoddef", "moduleref", "typeref", "typespec"), 3)
                    + s["string"]
                    + s["blob"]
                )
                memberref_size, memberref_at = size, at
                at += size * num_rows
            elif bit == 0x0B:
                at = Dotnet._constants(
                    f, img, at, num_rows, wide(("param", "field", "property"), 2), s, blob_base
                )
            elif bit == 0x0C:
                size = Dotnet._custom_index(rows) + wide(("methoddef", "memberref"), 3) + s["blob"]
                if typeref_at is not None and memberref_at is not None:
                    Dotnet._typelib(f, img, at, num_rows, rows, s, typeref_at, typeref_size, memberref_at, memberref_size,
                                    strings, str_size, blob_base)  # fmt: skip
                at += size * num_rows
            elif bit == 0x1A:
                counter = 0
                row = at
                for _ in range(num_rows):
                    if not img.fits(row, 4):
                        break
                    name = name_at(row, s["string"])
                    if name is not None:
                        f["modulerefs"].items[counter] = name
                        counter += 1
                    row += s["string"]
                f["number_of_modulerefs"] = counter
                keep("moduleref", s["string"], num_rows)
                at += s["string"] * num_rows
            elif bit == 0x1B:
                keep("typespec", s["blob"], num_rows)
                at += s["blob"] * num_rows
            elif bit == 0x1D:
                size = 4 + s["field"]
                counter = 0
                row = at
                for _ in range(num_rows):
                    if not img.fits(row, 8):
                        break
                    offset = img.rva_to_offset(img.u32(row))
                    if offset >= 0:
                        f["field_offsets"].items[counter] = offset
                        counter += 1
                    row += size
                f["number_of_field_offsets"] = counter
                at += size * num_rows
            elif bit == 0x20:
                size = 4 + 2 + 2 + 2 + 2 + 4 + s["blob"] + 2 * s["string"]
                if not img.fits(at, size):
                    matched += 1
                    continue
                major, minor, build, revision = struct.unpack_from("<HHHH", data, at + 4)
                f["assembly"].fields["version"] = Struct(
                    {
                        "major": major,
                        "minor": minor,
                        "build_number": build,
                        "revision_number": revision,
                    }
                )
                name = name_at(at + 16 + s["blob"], s["string"])
                if name is not None:
                    f["assembly"].fields["name"] = name
                culture = name_at(at + 16 + s["blob"] + s["string"], s["string"])
                if culture:
                    f["assembly"].fields["culture"] = culture
                at += size * num_rows
            elif bit == 0x23:
                size = 2 + 2 + 2 + 2 + 4 + 2 * s["blob"] + 2 * s["string"]
                row = at
                i = 0
                while i < num_rows:
                    if not img.fits(row, size):
                        break
                    ref = Dotnet.element(f["assembly_refs"], i).fields
                    major, minor, build, revision = struct.unpack_from("<HHHH", data, row)
                    ref["version"] = Struct(
                        {
                            "major": major,
                            "minor": minor,
                            "build_number": build,
                            "revision_number": revision,
                        }
                    )
                    key_at = blob_base + (
                        img.u32(row + 12) if s["blob"] == 4 else img.u16(row + 12)
                    )
                    prefix, length = Dotnet.blob_entry(img, key_at)
                    key_at += prefix
                    if prefix == 0 or not img.fits(key_at, length):
                        row += size
                        i += 1
                        continue
                    if length > 0:
                        ref["public_key_or_token"] = data[key_at : key_at + length]
                    name = name_at(row + 12 + s["blob"], s["string"])
                    if name is not None:
                        ref["name"] = name
                    row += size
                    i += 1
                keep("assemblyref", size, num_rows)
                f["number_of_assembly_refs"] = i
                at += size * num_rows
            elif bit == 0x28:
                index_size = wide(("file", "assemblyref"), 2)
                size = 4 + 4 + s["string"] + index_size
                row = at
                i = 0
                while i < num_rows:
                    if not img.fits(row, size):
                        break
                    impl_at = row + 8 + s["string"]
                    implementation = img.u32(impl_at) if index_size == 4 else img.u16(impl_at)
                    entry_at = row
                    row += size
                    name = name_at(entry_at + 8, s["string"])
                    if name is not None:
                        Dotnet.element(f["resources"], i).fields["name"] = name
                    if implementation != 0:
                        i += 1
                        continue
                    resource_offset = img.u32(entry_at)
                    where = resource_base + resource_offset
                    if not img.fits(where, 4):
                        i += 1
                        continue
                    r = Dotnet.element(f["resources"], i).fields
                    r["offset"] = where + 4
                    r["length"] = img.u32(where)
                    i += 1
                f["number_of_resources"] = i
                at += size * num_rows
            elif bit == 0x29:
                keep("nestedclass", 2 * s["typedef_"], num_rows)
                at += 2 * s["typedef_"] * num_rows
            elif bit == 0x2A:
                size = 4 + wide(("typedef_", "methoddef"), 1) + s["string"]
                keep("genericparam", size, num_rows)
                at += size * num_rows
            else:
                return
            matched += 1
        ctx = Context(img, tables, sizes, strings, str_size, blob_base)
        Dotnet.user_types(f, ctx)

    @staticmethod
    def _custom_index(rows: dict[str, int]) -> int:
        """The CustomAttribute parent index: wide past 0xFFFF >> 5 rows in any of 21 tables."""
        names = ("methoddef", "field", "typeref", "typedef_", "param", "interfaceimpl", "memberref", "module",
                 "property", "event", "standalonesig", "moduleref", "typespec", "assembly", "assemblyref", "file",
                 "exportedtype", "manifestresource", "genericparam", "genericparamconstraint", "methodspec")  # fmt: skip
        return 4 if max(rows[n] for n in names) > (0xFFFF >> 5) else 2

    @staticmethod
    def _constants(
        f: dict[str, Any],
        img: Image,
        at: int,
        num_rows: int,
        index_size: int,
        s: dict[str, int],
        blob_base: int,
    ) -> int:
        """The Constant table's string constants (BIT_CONSTANT)."""
        size = 1 + 1 + index_size + s["blob"]
        counter = 0
        row = at
        for _ in range(num_rows):
            if not img.fits(row, size):
                break
            if img.u16(row) != 0x0E:
                row += size
                continue
            index_at = row + 2 + index_size
            index = img.u32(index_at) if s["blob"] == 4 else img.u16(index_at)
            where = blob_base + index
            prefix, length = Dotnet.blob_entry(img, where)
            if prefix == 0:
                row += size
                continue
            where += prefix
            if where + length >= img.n:
                row += size
                continue
            f["constants"].items[counter] = img.data[where : where + length]
            counter += 1
            row += size
        f["number_of_constants"] = counter
        return at + size * num_rows

    @staticmethod
    def _typelib(f: dict[str, Any], img: Image, at: int, num_rows: int, rows: dict[str, int], s: dict[str, int],
                 typeref_at: int, typeref_size: int, memberref_at: int, memberref_size: int, strings: int,
                 str_size: int, blob_base: int) -> None:  # fmt: skip
        """BIT_CUSTOMATTRIBUTE: the GUID a `GuidAttribute` gives the type library."""
        data = img.data
        index_size = Dotnet._custom_index(rows)
        index_size2 = 4 if max(rows["methoddef"], rows["memberref"]) > (0xFFFF >> 3) else 2
        size = index_size + index_size2 + s["blob"]

        def read(pos: int, width: int) -> int:
            return img.u32(pos) if width == 4 else img.u16(pos)

        row = at
        for _ in range(num_rows):
            if not img.fits(row, size):
                break
            if read(row, index_size) & 0x1F != 0x0E:
                row += size
                continue
            coded = read(row + index_size, index_size2)
            if coded & 7 != 3:
                row += size
                continue
            type_index = coded >> 3
            if type_index > 0:
                type_index -= 1
            member = memberref_at + memberref_size * type_index
            if not img.fits(member, memberref_size):
                break
            parent = read(member, s["memberref"])
            if parent & 7 != 1:
                row += size
                continue
            class_index = parent >> 3
            if class_index > 0:
                class_index -= 1
            ref = typeref_at + typeref_size * class_index
            if not img.fits(ref, typeref_size):
                break
            ref += (
                4
                if max(rows["module"], rows["moduleref"], rows["assemblyref"], rows["typeref"])
                > (0xFFFF >> 2)
                else 2
            )
            name = Dotnet.string(img, strings, str_size, read(ref, s["string"]))
            if name is not None and not name.startswith(b"GuidAttribute"):
                row += size
                continue
            blob_index = read(row + index_size + index_size2, s["blob"])
            where = blob_base + blob_index
            if blob_index == 0 or where >= img.n:
                row += size
                continue
            prefix, length = Dotnet.blob_entry(img, where)
            if prefix == 0:
                row += size
                continue
            where += prefix
            if length < 3 or where + length >= img.n:
                row += size
                continue
            if img.u16(where) != 1:
                row += size
                continue
            where += 2
            str_len = data[where]
            where += 1
            if where + str_len > img.n:
                row += size
                continue
            if data[where] in (0xFF, 0x00):
                f["typelib"] = b""
            else:
                text = data[where : where + str_len]
                nul = text.find(b"\x00")
                f["typelib"] = text if nul < 0 else text[:nul]
            row += size


__all__ = ["Dotnet"]
