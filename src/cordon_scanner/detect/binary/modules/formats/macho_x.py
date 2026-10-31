"""The `macho` module's second shape, the link-edit part: the names YARA-X declares that YARA does not,
read from the object's link-edit commands by the one parse `formats.macho` runs.

`symtab` (symoff, nsyms, stroff, strsize, `entries[]` the symbol names, `nlists[]` each symbol's
n_strx, n_type, n_sect, n_desc, n_value), `dysymtab` (its sixteen counts and offsets), `dyld_info`
(its ten), `code_signature_data` (dataoff, datasize); `exports[]` walked from the export trie
(LC_DYLD_EXPORTS_TRIE, else dyld_info's export range), `imports[]` from the bind, lazy-bind and
weak-bind opcode streams (each symbol once) and from the chained fixups' import table;
`entitlements[]` and `certificates[]` from the code signature's super blob (the entitlements plist's
keys and array strings; the CMS blob's certificates by issuer, subject and whether self-signed). The
functions: has_entitlement, has_import, has_export (ASCII case folded, over the file and every
architecture), entitlement_hash, export_hash, import_hash (MD5 of the sorted distinct lower-cased
trimmed values, joined by commas, from the file else its first architecture) and symhash (the same
over the undefined external symbols, as the names stand).

Named differences from YARA-X's reading: a symbol whose name runs off the string table is skipped
and the table goes on (YARA-X stops there); an export node's flags are read as bits (YARA-X matches
the whole value, so a weak stub is misread); an entitlements plist with an entity declaration is not
parsed (XML entity expansion is unbounded); a name is rendered from its attributes in order with
", " between, as x509-parser prints one, which labels a user id `uid` where OpenSSL says `UID`.
"""

from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.der import BadDer
from cordon_scanner.detect.binary.modules.layout import U8, U16, U32, U64, Cursor, Layout
from cordon_scanner.detect.binary.modules.oids import ObjectIds
from cordon_scanner.detect.binary.modules.signature import Pkcs7
from cordon_scanner.detect.binary.modules.values import Call, Record, Scalar, Seq, Sig
from cordon_scanner.detect.binary.modules.x509 import X500

INT, TEXT, BOOL = Scalar.INT, Scalar.TEXT, Scalar.BOOL


class Shape:
    """The link-edit structures (mach-o/loader.h, mach-o/nlist.h, codesign's blobs)."""

    SYMTAB: ClassVar[Layout] = Layout((
        ("cmd", U32), ("cmdsize", U32), ("symoff", U32), ("nsyms", U32), ("stroff", U32), ("strsize", U32),
    ))  # fmt: skip
    DYSYMTAB_NAMES: ClassVar[tuple[str, ...]] = (
        "ilocalsym", "nlocalsym", "iextdefsym", "nextdefsym", "tocoff", "ntoc", "modtaboff", "nmodtab",
        "extrefsymoff", "nextrefsyms", "indirectsymoff", "nindirectsyms", "extreloff", "nextrel",
        "locreloff", "nlocrel",
    )  # fmt: skip
    DYSYMTAB: ClassVar[Layout] = Layout(
        (("cmd", U32), ("cmdsize", U32), *((n, U32) for n in DYSYMTAB_NAMES))
    )
    DYLD_INFO_NAMES: ClassVar[tuple[str, ...]] = (
        "rebase_off", "rebase_size", "bind_off", "bind_size", "weak_bind_off", "weak_bind_size",
        "lazy_bind_off", "lazy_bind_size", "export_off", "export_size",
    )  # fmt: skip
    DYLD_INFO: ClassVar[Layout] = Layout(
        (("cmd", U32), ("cmdsize", U32), *((n, U32) for n in DYLD_INFO_NAMES))
    )
    LINKEDIT: ClassVar[Layout] = Layout(
        (("cmd", U32), ("cmdsize", U32), ("dataoff", U32), ("datasize", U32))
    )
    NLIST32: ClassVar[Layout] = Layout(
        (("n_strx", U32), ("n_type", U8), ("n_sect", U8), ("n_desc", U16), ("n_value", U32))
    )
    NLIST64: ClassVar[Layout] = Layout(
        (("n_strx", U32), ("n_type", U8), ("n_sect", U8), ("n_desc", U16), ("n_value", U64))
    )
    BLOB: ClassVar[Layout] = Layout((("magic", U32), ("length", U32)))
    SUPERBLOB: ClassVar[Layout] = Layout((("magic", U32), ("length", U32), ("count", U32)))
    INDEX: ClassVar[Layout] = Layout((("type", U32), ("offset", U32)))
    FIXUPS: ClassVar[Layout] = Layout((
        ("fixups_version", U32), ("starts_offset", U32), ("imports_offset", U32), ("symbols_offset", U32),
        ("imports_count", U32), ("imports_format", U32), ("symbols_format", U32),
    ))  # fmt: skip


class MachoX:
    """The link-edit names, their reading, and their functions."""

    LABELS: ClassVar[dict[str, str]] = {"0.9.2342.19200300.100.1.1": "uid"}
    """The attribute labels x509-parser gives otherwise than OpenSSL's short names."""
    LC_SYMTAB: ClassVar[int] = 0x02
    LC_DYSYMTAB: ClassVar[int] = 0x0B
    LC_CODE_SIGNATURE: ClassVar[int] = 0x1D
    LC_DYLD_INFO: ClassVar[frozenset[int]] = frozenset({0x22, 0x22 | 0x80000000})
    LC_DYLD_EXPORTS_TRIE: ClassVar[int] = 0x33 | 0x80000000
    LC_DYLD_CHAINED_FIXUPS: ClassVar[int] = 0x34 | 0x80000000
    COMMANDS: ClassVar[frozenset[int]] = frozenset(
        {
            LC_SYMTAB,
            LC_DYSYMTAB,
            LC_CODE_SIGNATURE,
            *LC_DYLD_INFO,
            LC_DYLD_EXPORTS_TRIE,
            LC_DYLD_CHAINED_FIXUPS,
        }
    )
    EXPORT_REEXPORT: ClassVar[int] = 0x08
    EXPORT_STUB_AND_RESOLVER: ClassVar[int] = 0x10
    BIND_ONE_ULEB: ClassVar[frozenset[int]] = frozenset({0x20, 0x70, 0x80, 0xA0})
    BIND_TWO_ULEB: ClassVar[int] = 0xC0
    BIND_SLEB: ClassVar[int] = 0x60
    BIND_SYMBOL: ClassVar[int] = 0x40
    CS_ENTITLEMENTS: ClassVar[int] = 0xFADE7171
    CS_BLOBWRAPPER: ClassVar[int] = 0xFADE0B01
    N_STAB, N_TYPE, N_EXT = 0xE0, 0x0E, 0x01
    N_DEFINED: ClassVar[frozenset[int]] = frozenset({0x0E, 0x02, 0x0A})
    """N_SECT, N_ABS, N_INDR: the symbol kinds that define a name a file exports."""
    MAX_PLIST: ClassVar[int] = 1 << 20
    MAX_NODES: ClassVar[int] = 1 << 16
    """Export-trie nodes and import entries read at most: a crafted table is cut, not followed."""

    NLIST: ClassVar[Record] = Record(
        dict.fromkeys(("n_strx", "n_type", "n_sect", "n_desc", "n_value"), INT)
    )
    FIELDS: ClassVar[dict[str, Any]] = {
        "symtab": Record({
            "symoff": INT, "nsyms": INT, "stroff": INT, "strsize": INT, "entries": Seq(TEXT), "nlists": Seq(NLIST),
        }),
        "dysymtab": Record(dict.fromkeys(Shape.DYSYMTAB_NAMES, INT)),
        "dyld_info": Record(dict.fromkeys(Shape.DYLD_INFO_NAMES, INT)),
        "code_signature_data": Record({"dataoff": INT, "datasize": INT}),
        "entitlements": Seq(TEXT),
        "certificates": Seq(Record({"issuer": TEXT, "subject": TEXT, "is_self_signed": BOOL})),
        "exports": Seq(TEXT), "imports": Seq(TEXT),
    }  # fmt: skip
    ARRAYS: ClassVar[tuple[str, ...]] = ("entitlements", "certificates", "exports", "imports")
    FUNCTIONS: ClassVar[dict[str, Any]] = {
        "has_entitlement": Call(Sig(("text",), BOOL)), "has_import": Call(Sig(("text",), BOOL)),
        "has_export": Call(Sig(("text",), BOOL)),
        "entitlement_hash": Call(Sig((), TEXT)), "export_hash": Call(Sig((), TEXT)),
        "import_hash": Call(Sig((), TEXT)), "symhash": Call(Sig((), TEXT)),
    }  # fmt: skip

    @staticmethod
    def fill(
        out: dict[str, Any],
        cur: Cursor,
        base: int,
        end: int,
        commands: list[tuple[int, int, int]],
        *,
        is64: bool,
    ) -> None:
        """The link-edit names of one object whose bytes run from `base` to `end`, from its
        `commands` as `(cmd, offset, size)`."""
        for name in MachoX.ARRAYS:
            out.setdefault(name, {})
        exports: list[tuple[int, int]] = []
        binds: list[tuple[int, int]] = []
        fixups: tuple[int, int] | None = None
        for cmd, at, size in commands:
            if cmd == MachoX.LC_SYMTAB and size >= Shape.SYMTAB.stride():
                MachoX._symtab(out, cur, base, end, Shape.SYMTAB.read(cur, at), is64=is64)
            elif cmd == MachoX.LC_DYSYMTAB and size >= Shape.DYSYMTAB.stride():
                d = Shape.DYSYMTAB.read(cur, at)
                out["dysymtab"] = {n: d[n] for n in Shape.DYSYMTAB_NAMES}
            elif cmd in MachoX.LC_DYLD_INFO and size >= Shape.DYLD_INFO.stride():
                d = Shape.DYLD_INFO.read(cur, at)
                out["dyld_info"] = {n: d[n] for n in Shape.DYLD_INFO_NAMES}
                exports.append((d["export_off"], d["export_size"]))
                binds += [(d["bind_off"], d["bind_size"]), (d["lazy_bind_off"], d["lazy_bind_size"]),
                          (d["weak_bind_off"], d["weak_bind_size"])]  # fmt: skip
            elif cmd in (
                MachoX.LC_CODE_SIGNATURE,
                MachoX.LC_DYLD_EXPORTS_TRIE,
                MachoX.LC_DYLD_CHAINED_FIXUPS,
            ):
                if size < Shape.LINKEDIT.stride():
                    continue
                d = Shape.LINKEDIT.read(cur, at)
                if cmd == MachoX.LC_CODE_SIGNATURE:
                    out["code_signature_data"] = {
                        "dataoff": d["dataoff"],
                        "datasize": d["datasize"],
                    }
                    MachoX._signature(out, cur, base, end, d["dataoff"], d["datasize"])
                elif cmd == MachoX.LC_DYLD_EXPORTS_TRIE:
                    exports.insert(0, (d["dataoff"], d["datasize"]))
                else:
                    fixups = (d["dataoff"], d["datasize"])
        for offset, size in exports:
            region = MachoX._region(cur, base, end, offset, size)
            if region is not None:
                MachoX._exports(out, cur, *region)
        seen: set[bytes] = set()
        for offset, size in binds:
            region = MachoX._region(cur, base, end, offset, size)
            if region is not None:
                MachoX._binds(out, cur, *region, seen)
        if fixups is not None:
            region = MachoX._region(cur, base, end, *fixups)
            if region is not None:
                MachoX._fixups(out, cur, *region)
        if (
            not binds and fixups is None
        ):  # no bind streams, no chained fixups: the undefined symbols
            symtab = out.get("symtab", {})
            for i, n in symtab.get("nlists", {}).items():
                if (
                    not n["n_type"] & MachoX.N_TYPE
                    and not n["n_type"] & MachoX.N_STAB
                    and i in symtab["entries"]
                ):
                    out["imports"][len(out["imports"])] = symtab["entries"][i]
        if (
            not exports
        ):  # no export trie and no dyld info: the symbol table's external defined symbols
            symtab = out.get("symtab", {})
            for i, n in symtab.get("nlists", {}).items():
                kind = n["n_type"] & MachoX.N_TYPE
                if (
                    n["n_type"] & MachoX.N_EXT
                    and kind in MachoX.N_DEFINED
                    and not n["n_type"] & MachoX.N_STAB
                    and i in symtab["entries"]
                ):
                    out["exports"][len(out["exports"])] = symtab["entries"][i]

    @staticmethod
    def _region(cur: Cursor, base: int, end: int, offset: int, size: int) -> tuple[int, int] | None:
        """`(start, stop)` of a range the object's commands name, when it lies within the object."""
        start, stop = base + offset, base + offset + size
        return (start, stop) if base <= start <= stop <= end else None

    @staticmethod
    def _cstring(cur: Cursor, at: int, stop: int) -> tuple[bytes, int] | None:
        """The NUL-terminated string at `at` within `stop`, and the position past its NUL."""
        if at < 0 or at >= stop:
            return None
        text = cur.blob(at, stop - at)
        nul = text.find(b"\x00")
        return None if nul < 0 else (text[:nul], at + nul + 1)

    @staticmethod
    def _uleb(cur: Cursor, at: int, stop: int) -> tuple[int, int] | None:
        """A ULEB128 within `stop`, and the position after it; None at the end."""
        result, shift = 0, 0
        for i in range(10):
            if at + i >= stop:
                return None
            byte = cur.uint(at + i, 1)
            result |= (byte & 0x7F) << shift
            if byte < 0x80:
                return result, at + i + 1
            shift += 7
        return None

    @staticmethod
    def _symtab(
        out: dict[str, Any], cur: Cursor, base: int, end: int, s: dict[str, Any], *, is64: bool
    ) -> None:
        """The symbol table: each nlist in turn, its name from the string table; a name that is empty
        or runs off the table gives no entry; the walk ends at the object's end."""
        symtab: dict[str, Any] = {k: s[k] for k in ("symoff", "nsyms", "stroff", "strsize")}
        entries: dict[int, bytes] = {}
        nlists: dict[int, Any] = {}
        symtab["entries"], symtab["nlists"] = entries, nlists
        out["symtab"] = symtab
        strings = MachoX._region(cur, base, end, s["stroff"], s["strsize"])
        layout = Shape.NLIST64 if is64 else Shape.NLIST32
        stride = layout.stride()
        at = base + s["symoff"]
        for _ in range(min(s["nsyms"], MachoX.MAX_NODES)):
            if at + stride > end or at < base:
                return
            n = layout.read(cur, at)
            at += stride
            if strings is None:
                continue
            name = MachoX._cstring(cur, strings[0] + n["n_strx"], strings[1])
            if name is None or not name[0]:
                continue
            entries[len(entries)] = name[0]
            nlists[len(nlists)] = {
                k: n[k] for k in ("n_strx", "n_type", "n_sect", "n_desc", "n_value")
            }

    @staticmethod
    def _exports(out: dict[str, Any], cur: Cursor, start: int, stop: int) -> None:
        """The export trie walked depth first, last child first, each node once; a node with a
        terminal length exports its prefix."""
        exports = out["exports"]
        stack: list[tuple[int, bytes]] = [(0, b"")]
        visited: set[int] = set()
        while stack and len(visited) < MachoX.MAX_NODES:
            offset, prefix = stack.pop()
            if offset in visited:
                continue
            visited.add(offset)
            length = MachoX._uleb(cur, start + offset, stop)
            if length is None:
                return
            pos = length[1]
            if length[0] != 0:
                flags = MachoX._uleb(cur, pos, stop)
                if flags is None:
                    return
                pos = flags[1]
                steps = 2 if flags[0] & MachoX.EXPORT_STUB_AND_RESOLVER else 1
                for _ in range(steps):
                    step = MachoX._uleb(cur, pos, stop)
                    if step is None:
                        return
                    pos = step[1]
                if flags[0] & MachoX.EXPORT_REEXPORT:
                    label = MachoX._cstring(cur, pos, stop)
                    if label is None:
                        return
                    pos = label[1]
            if pos >= stop:
                return
            edges = cur.uint(pos, 1)
            pos += 1
            for _ in range(edges):
                label = MachoX._cstring(cur, pos, stop)
                if label is None:
                    return
                child = MachoX._uleb(cur, label[1], stop)
                if child is None:
                    return
                pos = child[1]
                try:
                    label[0].decode("utf-8")
                except UnicodeDecodeError:
                    continue
                stack.append((child[0], prefix + label[0]))
            if length[0] != 0:
                exports[len(exports)] = prefix

    @staticmethod
    def _binds(out: dict[str, Any], cur: Cursor, start: int, stop: int, seen: set[bytes]) -> None:
        """One bind opcode stream: the symbols it names, each once across the streams."""
        imports = out["imports"]
        pos = start
        while pos < stop:
            opcode = cur.uint(pos, 1) & 0xF0
            pos += 1
            if opcode in MachoX.BIND_ONE_ULEB or opcode == MachoX.BIND_SLEB:
                step = MachoX._uleb(cur, pos, stop)
                if step is None:
                    return
                pos = step[1]
            elif opcode == MachoX.BIND_TWO_ULEB:
                for _ in range(2):
                    step = MachoX._uleb(cur, pos, stop)
                    if step is None:
                        return
                    pos = step[1]
            elif opcode == MachoX.BIND_SYMBOL:
                name = MachoX._cstring(cur, pos, stop)
                if name is None:
                    return
                pos = name[1]
                if name[0] not in seen and MachoX._utf8(name[0]):
                    seen.add(name[0])
                    imports[len(imports)] = name[0]

    @staticmethod
    def _fixups(out: dict[str, Any], cur: Cursor, start: int, stop: int) -> None:
        """The chained fixups' import table: each entry's symbol by its name offset."""
        if start + Shape.FIXUPS.stride() > stop:
            return
        h = Shape.FIXUPS.read(cur, start)
        entry = {1: 4, 2: 8, 3: 16}.get(h["imports_format"], 4)
        wide = h["imports_format"] == 3
        shift, mask = (32, 0xFFFFFFFF) if wide else (9, 0x7FFFFF)
        table = start + h["imports_offset"]
        if table + h["imports_count"] * entry > stop:
            return
        imports = out["imports"]
        for i in range(min(h["imports_count"], MachoX.MAX_NODES)):
            value = cur.uint(table + i * entry, 8 if wide else 4)
            name = MachoX._cstring(
                cur, start + h["symbols_offset"] + ((value >> shift) & mask), stop
            )
            if name is not None and MachoX._utf8(name[0]):
                imports[len(imports)] = name[0]

    @staticmethod
    def _utf8(text: bytes) -> bool:
        try:
            text.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return True

    @staticmethod
    def _signature(
        out: dict[str, Any], cur: Cursor, base: int, end: int, offset: int, size: int
    ) -> None:
        """The code signature's super blob: its entitlements plist and its CMS certificates."""
        region = MachoX._region(cur, base, end, offset, size)
        if region is None:
            return
        start, stop = region
        big = Cursor(cur.data, big_endian=True)
        if start + Shape.SUPERBLOB.stride() > stop:
            return
        count = Shape.SUPERBLOB.read(big, start)["count"]
        for i in range(min(count, 64)):
            at = start + Shape.SUPERBLOB.stride() + i * Shape.INDEX.stride()
            if at + Shape.INDEX.stride() > stop:
                return
            blob_at = start + Shape.INDEX.read(big, at)["offset"]
            if blob_at + Shape.BLOB.stride() > stop:
                continue
            blob = Shape.BLOB.read(big, blob_at)
            body = cur.blob(
                blob_at + Shape.BLOB.stride(),
                max(0, min(blob["length"], stop - blob_at) - Shape.BLOB.stride()),
            )
            if blob["magic"] == MachoX.CS_ENTITLEMENTS:
                MachoX._entitlements(out, body)
            elif blob["magic"] == MachoX.CS_BLOBWRAPPER:
                MachoX._certificates(out, body)

    @staticmethod
    def _entitlements(out: dict[str, Any], xml: bytes) -> None:
        """The plist's `key` texts, and the texts under each `array`, in document order."""
        if len(xml) > MachoX.MAX_PLIST or b"<!ENTITY" in xml:
            return
        try:
            root = ET.fromstring(xml)  # noqa: S314 - entities refused above, size bounded
        except ET.ParseError:
            return
        found = out["entitlements"]
        for node in root.iter():
            if node.tag == "key" and node.text:
                found[len(found)] = node.text.encode("utf-8")
            elif node.tag == "array" and (node.text or len(node)):
                seen: list[bytes] = []
                for inner in node.iter():
                    for text in (inner.text, inner.tail):
                        if text and text.strip() and text.encode("utf-8") not in seen:
                            seen.append(text.encode("utf-8"))
                for value in seen:
                    found[len(found)] = value

    @staticmethod
    def _certificates(out: dict[str, Any], blob: bytes) -> None:
        try:
            _kind, signed = Pkcs7.parse(blob, cms=True)
        except (BadDer, ValueError, IndexError):
            return
        if signed is None:
            return
        certs = out["certificates"]
        for cert in signed.certs:
            issuer, subject = MachoX._name(cert.issuer), MachoX._name(cert.subject)
            certs[len(certs)] = {
                "issuer": issuer,
                "subject": subject,
                "is_self_signed": issuer == subject,
            }

    @staticmethod
    def _name(name: Any) -> bytes:
        """An X.509 name as x509-parser prints it: `label=value` per attribute in order, ", " between."""
        if not isinstance(name, X500):
            return b""
        parts = []
        for rdn in name.rdns:
            for oid, _tag, data in rdn:
                names = ObjectIds.NAMES.get(oid)
                label = MachoX.LABELS.get(oid) or ((names[0] or names[1] or oid) if names else oid)
                parts.append(f"{label}={data.decode('utf-8', 'replace')}")
        return ", ".join(parts).encode("utf-8")

    @staticmethod
    def _functions(out: dict[str, Any]) -> None:
        """The has_* functions over the file and every architecture, and the hashes over the file
        else its first architecture."""
        files: dict[int, Any] = out.get("file", {})
        everywhere = [out, *files.values()]

        def has(key: str) -> Any:
            def holds(wanted: bytes) -> bool:
                target = wanted.lower()
                return any(
                    v.lower() == target for place in everywhere for v in place.get(key, {}).values()
                )

            return holds

        def listed(key: str) -> dict[int, Any]:
            own = out.get(key, {})
            return own or (files[0].get(key, {}) if 0 in files else {})

        def digest(values: list[bytes]) -> bytes | None:
            names = sorted(set(values))
            return hashlib.md5(b",".join(names)).hexdigest().encode() if names else None  # noqa: S324

        def hashed(key: str) -> Any:
            return lambda: digest([v.strip().lower() for v in listed(key).values()])

        def symhash() -> bytes | None:
            symtab = out.get("symtab") or (files[0].get("symtab") if 0 in files else None) or {}
            entries, nlists = symtab.get("entries", {}), symtab.get("nlists", {})
            names = [
                entries[i].strip() for i, n in nlists.items()
                if not n["n_type"] & MachoX.N_STAB and n["n_type"] & MachoX.N_EXT
                and not n["n_type"] & MachoX.N_TYPE and i in entries
            ]  # fmt: skip
            return digest(names)

        out["has_entitlement"] = (has("entitlements"),)
        out["has_import"] = (has("imports"),)
        out["has_export"] = (has("exports"),)
        out["entitlement_hash"] = (hashed("entitlements"),)
        out["export_hash"] = (hashed("exports"),)
        out["import_hash"] = (hashed("imports"),)
        out["symhash"] = (symhash,)


__all__ = ["MachoX"]
