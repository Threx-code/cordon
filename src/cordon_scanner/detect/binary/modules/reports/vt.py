"""cordon-rule's `vt` module: VirusTotal LiveHunt metadata given to the scan, read as YARA-X reads it.

YARA-X's vt module is declared by protobuf (detect/data/vt-schema.json, generated from its .proto
files); the
metadata it answers from is supplied, not fetched: `--rule-module-data vt=livehunt.json`, a
LiveHuntData message in protobuf's JSON form. Every file of the scan is matched against the same
metadata. Without it every field is undefined, as YARA-X's vt is when nothing is supplied.

What a rule sees, as YARA-X lays it out (read from its behaviour, not its code): a message is a
structure of its fields under their YARA names; a repeated field an array, a map a dictionary, an
enum field an integer, a Timestamp its seconds and nanos. Every enum the root message uses or
declares, and every top-level enum of the root's file, is a structure of constants hung from the
module's root: its path is the names of the messages it is declared in (the root left out), then
its own name (left out when the enum is inline); a constant's value is its (yara.enum_value) where
given, else its number. Text fields marked lowercase are lowercased.

The vt.net functions (domain permutations, `in_range`) are declared with the rest and answered by
the network functions module; until it lands they answer undefined.
"""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.reports.vt_net import VtNet
from cordon_scanner.detect.binary.modules.values import (
    Call,
    Keyed,
    Module,
    Record,
    Scalar,
    Seq,
    Sig,
)
from cordon_scanner.foundation.paths import PackagePaths

#: The tables generated from YARA-X's vt .proto files (scripts/reference/vt_schema.py).
SCHEMA_DATA: dict[str, Any] = json.loads(
    (PackagePaths.data("detect") / "vt-schema.json").read_text(encoding="utf-8")
)

_SCALAR = {"int": Scalar.INT, "bool": Scalar.BOOL, "float": Scalar.FLOAT, "text": Scalar.TEXT}
_KIND = {
    "int32": "int", "int64": "int", "uint32": "int", "uint64": "int", "sint32": "int",
    "sint64": "int", "fixed32": "int", "fixed64": "int", "sfixed32": "int", "sfixed64": "int",
    "bool": "bool", "float": "float", "double": "float", "string": "text", "bytes": "text",
}  # fmt: skip
_TIME = ("google.protobuf.Timestamp", "google.protobuf.Duration")
#: The functions YARA-X declares as methods of a message (`module_export(method_of = ...)`), each
#: answered from that structure's own `raw` by `vt_net.VtNet`.
_METHODS: dict[str, dict[str, Call]] = {
    "vt.net.EnrichedIP": {"in_range": Call(Sig(("text",), Scalar.BOOL))},
    "vt.net.EnrichedDomain": {
        "permutation_of": Call(Sig(("text",), Scalar.BOOL), Sig(("text", "int"), Scalar.BOOL))
    },
}


class VtSchema:
    """The declaration and the enum constants, built once from the generated tables."""

    MESSAGES: ClassVar[dict[str, Any]] = SCHEMA_DATA["MESSAGES"]
    ENUMS: ClassVar[dict[str, Any]] = SCHEMA_DATA["ENUMS"]
    ROOT: ClassVar[str] = SCHEMA_DATA["ROOT"]

    @staticmethod
    def decl(target: str, depth: int = 0) -> Any:
        if target in _KIND:
            return _SCALAR[_KIND[target]]
        if target in VtSchema.ENUMS:
            return Scalar.INT
        if depth > 32:
            raise ValueError(f"vt: a type nested past 32 levels: {target}")
        fields: dict[str, Any] = {}
        for rule, _proto, kind, value, *_ in VtSchema.MESSAGES[target]["fields"]:
            inner = VtSchema.decl(value, depth + 1)
            fields[rule] = (
                Seq(inner) if kind == "repeated" else Keyed(inner) if kind == "map" else inner
            )
        fields.update(_METHODS.get(target, {}))
        return Record(fields)

    @staticmethod
    def enums_used(target: str, seen: set[str] | None = None) -> list[str]:
        """Every enum `target` declares or uses, through its fields, in first-seen order."""
        seen = set() if seen is None else seen
        found: list[str] = [e for e in VtSchema.ENUMS if VtSchema.ENUMS[e]["scope"] == target]
        for _rule, _proto, kind, value, *_ in VtSchema.MESSAGES[target]["fields"]:
            if value in VtSchema.ENUMS:
                found.append(value)
            elif value in VtSchema.MESSAGES and kind != "map" and value not in seen:
                seen.add(value)
                found.extend(VtSchema.enums_used(value, seen))
        return list(dict.fromkeys(found))

    @staticmethod
    def constants() -> dict[str, Any]:
        """The enum constants as nested plain data, keyed from the module's root."""
        root_pkg = VtSchema.MESSAGES[VtSchema.ROOT]["scope"]
        chosen = VtSchema.enums_used(VtSchema.ROOT) + [
            e for e, info in VtSchema.ENUMS.items() if info["scope"] == root_pkg
        ]
        out: dict[str, Any] = {}
        for name in dict.fromkeys(chosen):
            info = VtSchema.ENUMS[name]
            path, scope = [], info["scope"]
            while scope in VtSchema.MESSAGES:
                if scope != VtSchema.ROOT:
                    path.append(VtSchema.MESSAGES[scope]["rule_name"])
                scope = VtSchema.MESSAGES[scope]["scope"]
            path.reverse()
            if not info["inline"]:
                path.append(info["rule_name"])
            node = out
            for part in path:
                node = node.setdefault(part, {})
            node.update(info["values"])
        return out

    @staticmethod
    def _shape(data: dict[str, Any]) -> Any:
        return Record(
            {k: VtSchema._shape(v) if isinstance(v, dict) else Scalar.INT for k, v in data.items()}
        )


class VtData:
    """LiveHuntData in protobuf's JSON form, read into the declaration's plain data."""

    @staticmethod
    def camel(name: str) -> str:
        head, *rest = name.split("_")
        return head + "".join(p[:1].upper() + p[1:] for p in rest)

    @staticmethod
    def read(target: str, value: Any, lowercase: bool = False) -> Any:
        if value is None:
            return None
        kind = _KIND.get(target)
        if kind in ("int", "float"):
            # protobuf's JSON form writes 64-bit integers as text; anything else is no value
            if isinstance(value, bool) or not isinstance(value, (int, float, str)):
                return None
            try:
                return int(value) if kind == "int" else float(value)
            except ValueError:
                return None
        if kind == "bool":
            return value if isinstance(value, bool) else None
        if kind == "text":
            if not isinstance(value, str):
                return None
            raw = base64.b64decode(value) if target == "bytes" else value.encode("utf-8")
            return raw.lower() if lowercase else raw
        if target in VtSchema.ENUMS:
            values = VtSchema.ENUMS[target]["values"]
            if isinstance(value, str):
                return values.get(value)
            return value if isinstance(value, int) else None
        if target in _TIME:
            return VtData._time(target, value)
        return VtData.message(target, value)

    @staticmethod
    def _time(target: str, value: Any) -> Any:
        if isinstance(value, dict):
            return {"seconds": int(value.get("seconds", 0)), "nanos": int(value.get("nanos", 0))}
        if not isinstance(value, str):
            return None
        if target.endswith("Duration"):
            m = re.fullmatch(r"(-?\d+)(?:\.(\d{1,9}))?s", value)
            return (
                {"seconds": int(m.group(1)), "nanos": int((m.group(2) or "0").ljust(9, "0"))}
                if m
                else None
            )
        try:
            when = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        frac = re.search(r"\.(\d{1,9})", value)
        return {
            "seconds": int(when.timestamp() // 1),
            "nanos": int((frac.group(1) if frac else "0").ljust(9, "0")),
        }

    @staticmethod
    def message(target: str, obj: Any) -> Any:
        if not isinstance(obj, dict):
            return None
        out: dict[str, Any] = {}
        for rule, proto, kind, value, _key, lowercase, *_ in VtSchema.MESSAGES[target]["fields"]:
            raw = obj.get(proto, obj.get(VtData.camel(proto)))
            if raw is None:
                continue
            if kind == "repeated":
                items = (
                    [VtData.read(value, v, lowercase) for v in raw] if isinstance(raw, list) else []
                )
                out[rule] = {i: v for i, v in enumerate(items) if v is not None}
            elif kind == "map":
                if isinstance(raw, dict):
                    out[rule] = {
                        str(k).encode(): VtData.read(value, v, lowercase) for k, v in raw.items()
                    }
            else:
                read = VtData.read(value, raw, lowercase)
                if read is not None:
                    out[rule] = read
        return VtData._methods(target, out)

    @staticmethod
    def _methods(target: str, out: dict[str, Any]) -> dict[str, Any]:
        """The structure's methods, bound to its `raw` (undefined without one)."""
        raw = out.get("raw")
        if target not in _METHODS or not isinstance(raw, bytes):
            return out
        if target == "vt.net.EnrichedIP":
            out["in_range"] = (lambda cidr: VtNet.in_range(raw, cidr),)
        else:
            out["permutation_of"] = (
                lambda other: VtNet.permutation_of(raw, other),
                lambda other, kinds: VtNet.permutation_of(raw, other, kinds),
            )
        return out


class Vt:
    """The module: the declaration with the enum constants, and its values for one metadata."""

    CONSTANTS: ClassVar[dict[str, Any]] = VtSchema.constants()

    @staticmethod
    def schema() -> Record:
        """The declaration a ruleset matching files sees: YARA-X refuses a root field whose
        access list does not accept files (`vt.net`, for URL, domain and IP rulesets), so it is
        left out and a rule naming it does not compile."""
        root = VtSchema.decl(VtSchema.ROOT)
        assert isinstance(root, Record)  # noqa: S101 - the root is a message
        refused = {row[0] for row in VtSchema.MESSAGES[VtSchema.ROOT]["fields"] if row[7]}
        kept = {name: decl for name, decl in root.fields.items() if name not in refused}
        return Record({**kept, **VtSchema._shape(Vt.CONSTANTS).fields})

    @staticmethod
    def module(raw: bytes | None = None) -> Module:
        """The module for a scan given LiveHuntData JSON `raw` (None: no metadata); ValueError
        when it is not a JSON object."""
        values: dict[str, Any] = dict(Vt.CONSTANTS)
        if raw is not None:
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"the vt metadata is not JSON: {exc.msg}") from exc
            if not isinstance(obj, dict):
                raise ValueError("the vt metadata is not a JSON object")
            values.update(VtData.message(VtSchema.ROOT, obj) or {})
        schema = Vt.schema()
        return Module(schema, lambda file: values)


__all__ = ["Vt", "VtData", "VtSchema"]
