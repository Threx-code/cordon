"""ECMA-335 signatures and names: method and field signatures decoded to the type strings the dotnet
module reports, and the type, namespace and coded-index names they resolve against the tables.
"""

from __future__ import annotations

from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.dotnet_metadata import Blob, Heaps, Spec, Tables

#: signature element type -> the name it prints as (ECMA-335 II.23.1.16)
PRIMITIVES: dict[int, bytes] = {
    0x1: b"void", 0x2: b"bool", 0x3: b"char", 0x4: b"sbyte", 0x5: b"byte", 0x6: b"short",
    0x7: b"ushort", 0x8: b"int", 0x9: b"uint", 0xA: b"long", 0xB: b"ulong", 0xC: b"float",
    0xD: b"double", 0xE: b"string", 0x16: b"TypedReference", 0x18: b"IntPtr", 0x19: b"UIntPtr",
    0x1C: b"object",
}  # fmt: skip

MAX_TYPE_DEPTH = 0x10

MAX_NAMESPACE_DEPTH = 0x0A

MAX_ARRAY_RANK = 50

MAX_GEN_PARAM = 1000

MAX_PARAMS = 2000


class Signatures:
    """The element-type decoder (ECMA-335 II.23.2.12): one type from a signature blob, spelled as C#."""

    __slots__ = ("_method_cache", "heaps", "resolve_name", "tables")

    def __init__(self, heaps: Heaps, tables: Tables, resolve_name: Any) -> None:
        self.heaps, self.tables, self.resolve_name = heaps, tables, resolve_name
        #: decoded method signatures keyed by (blob start, class/method generic context): methods that
        #: share a signature blob decode it once.
        self._method_cache: dict[
            tuple[int, tuple[bytes, ...], tuple[bytes, ...]],
            tuple[int, bytes, list[bytes | None]] | None,
        ] = {}

    def method(
        self, start: int, length: int, class_gp: list[bytes], method_gp: list[bytes]
    ) -> tuple[int, bytes, list[bytes | None]] | None:
        """A method signature decoded once per (blob, generic context): the parameter count, the return
        type, and each parameter's type. None when the return type does not decode or the count is absurd."""
        key = (start, tuple(class_gp), tuple(method_gp))
        if key in self._method_cache:
            return self._method_cache[key]
        blob = Blob(self.heaps.cur, start, length)
        sig_flags = self.heaps.cur.data[blob.at]
        blob.at += 1
        blob.left -= 1
        if sig_flags & 0x10:  # a generic method: the generic-parameter count, which the names skip
            blob.uvint()
        n_params = blob.uvint()
        ret = self.type(blob, class_gp, method_gp, 0)
        result: tuple[int, bytes, list[bytes | None]] | None
        if ret is None or n_params > MAX_PARAMS:
            result = None
        else:
            result = (
                n_params,
                ret,
                [self.type(blob, class_gp, method_gp, 0) for _ in range(n_params)],
            )
        self._method_cache[key] = result
        return result

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

    __slots__ = ("_name_cache", "enclosing", "heaps", "interfaces", "signatures", "tables")

    def __init__(self, heaps: Heaps, tables: Tables) -> None:
        self.heaps, self.tables = heaps, tables
        self.signatures = Signatures(heaps, tables, self.coded)
        self._name_cache: dict[int, bytes | None] = {}  # typedef/typeref name per coded index
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
        if (
            table == 2
        ):  # typespec is a signature: it depends on the generic context, so it is not cached
            row = self._row("typespec", index)
            if row is None:
                return None
            start, length = self.heaps.blob_at(row["sig"])
            if start:
                return self.signatures.type(
                    Blob(self.heaps.cur, start, length), class_gp, None, depth
                )
            return None
        if (
            coded in self._name_cache
        ):  # typedef/typeref names are the same whatever the generic context
            return self._name_cache[coded]
        name: bytes | None = None
        if table == 0:
            row = self._row("typedef", index)
            if row is not None:
                nm, ns = self.heaps.text(row["name"]), self.heaps.text(row["namespace"])
                name = (
                    Spec.qualified(nm, Spec.qualified(ns, self.nesting(index, 1)))
                    if Spec.is_nested(row["flags"])
                    else Spec.qualified(nm, ns)
                )
        elif table == 1:
            row = self._row("typeref", index)
            if row is not None:
                name = Spec.qualified(
                    self.heaps.text(row["name"]), self.heaps.text(row["namespace"])
                )
        self._name_cache[coded] = name
        return name

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


__all__ = [
    "MAX_ARRAY_RANK",
    "MAX_GEN_PARAM",
    "MAX_NAMESPACE_DEPTH",
    "MAX_PARAMS",
    "MAX_TYPE_DEPTH",
    "PRIMITIVES",
    "Names",
    "Signatures",
]
