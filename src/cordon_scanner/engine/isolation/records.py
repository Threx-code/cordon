"""Dataclass records as plain data and back (item 56): what a supervised worker's answer carries, rebuilt
field by field against a closed table of declared types, never by pickle or a generic loader.

A leaf of the engine: it imports only the foundation, and the record types it names lazily, so every
module that sends or reads a worker's records can use it without forming an import cycle.
"""

from __future__ import annotations

import base64
import dataclasses
import re
from typing import Any, ClassVar

from cordon_scanner.foundation.models import Scope

LIST_ENTRIES = 1_000_000
"""The most entries any one list in the document may hold."""
STRING_CHARS = 10 << 20
"""The longest string a record may hold: the largest file a scan reads by default
(`Limits.max_file_bytes`), since a field read from a file is never longer than it. The whole
document is bounded on its own (`DOCUMENT_BYTES`). At 65,536 one `postinstall` past 64 KiB refused the
context document, and the whole scan was incomplete (the detector-growth probe, 5 Nov)."""


class Codec:
    """Dataclass records as plain data and back, field by field against their declared types: a
    record crosses only when every field is one of the types listed here."""

    CHECKS: ClassVar[dict[str, Any]] = {
        "str": lambda v: isinstance(v, str) and len(v) <= STRING_CHARS,
        "str | None": lambda v: v is None or (isinstance(v, str) and len(v) <= STRING_CHARS),
        "bool": lambda v: type(v) is bool,
        "int": lambda v: type(v) is int,
        "int | None": lambda v: v is None or type(v) is int,
        "Scope": lambda v: isinstance(v, str) and v in {s.value for s in Scope},
        "tuple[str, ...]": lambda v: (
            isinstance(v, list)
            and len(v) <= LIST_ENTRIES
            and all(isinstance(x, str) and len(x) <= STRING_CHARS for x in v)
        ),
        "frozenset[str]": lambda v: (
            isinstance(v, list)
            and len(v) <= LIST_ENTRIES
            and all(isinstance(x, str) and len(x) <= STRING_CHARS for x in v)
        ),
        "bytes | None": lambda v: (
            v is None
            or (
                isinstance(v, str)
                and len(v) <= STRING_CHARS
                and re.fullmatch(r"(?:[0-9a-f]{2})*", v)
            )
        ),
        "Mapping[str, str]": lambda v: (
            isinstance(v, dict)
            and len(v) <= LIST_ENTRIES
            and all(
                isinstance(k, str)
                and isinstance(x, str)
                and len(k) <= STRING_CHARS
                and len(x) <= STRING_CHARS
                for k, x in v.items()
            )
        ),
        "bool | None": lambda v: v is None or type(v) is bool,
        "list[str]": lambda v: (
            isinstance(v, list)
            and len(v) <= LIST_ENTRIES
            and all(isinstance(x, str) and len(x) <= STRING_CHARS for x in v)
        ),
        "dict[str, int]": lambda v: (
            isinstance(v, dict)
            and len(v) <= LIST_ENTRIES
            and all(
                isinstance(k, str) and len(k) <= STRING_CHARS and type(x) is int
                for k, x in v.items()
            )
        ),
        "dict[str, bytes]": lambda v: (
            isinstance(v, dict)
            and len(v) <= LIST_ENTRIES
            and all(
                isinstance(k, str)
                and isinstance(x, str)
                and len(k) <= STRING_CHARS
                and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", x) is not None
                for k, x in v.items()
            )
        ),
        "tuple[tuple[str, str], ...]": lambda v: (
            isinstance(v, list)
            and len(v) <= LIST_ENTRIES
            and all(
                isinstance(x, list) and len(x) == 2 and all(isinstance(s, str) for s in x)
                for x in v
            )
        ),
    }
    #: Record types a record may hold, by the name its annotation gives: each rebuilt by its own
    #: fields, so the closed table covers every nested type too (note 56, part 2's review,
    #: condition 1). Held as `N`, `N | None`, `tuple[N, ...]` or `list[N]`.
    NESTED: ClassVar[dict[str, tuple[str, str]]] = {
        "Hook": ("cordon_scanner.foundation.models", "Hook"),
        "DeclaredDependency": ("cordon_scanner.ecosystems.base", "DeclaredDependency"),
        "ImageIdentity": ("cordon_scanner.images.identity", "ImageIdentity"),
        "ImageInventory": ("cordon_scanner.images.identity", "ImageInventory"),
        "pkgdb.OsRelease": ("cordon_scanner.images.packages", "OsRelease"),
        "pkgdb.OsPackage": ("cordon_scanner.images.packages", "OsPackage"),
        "langpkgs.LanguagePackage": ("cordon_scanner.images.langpkgs", "LanguagePackage"),
    }

    @staticmethod
    def _nested(annotation: str) -> tuple[str, type] | None:
        """(how it is held, the record type) for an annotation naming a declared record."""
        import importlib

        for how, pattern in (
            ("tuple", r"tuple\[([\w.]+), \.\.\.\]"),
            ("list", r"list\[([\w.]+)\]"),
            ("optional", r"([\w.]+) \| None"),
            ("one", r"([\w.]+)"),
        ):
            match = re.fullmatch(pattern, annotation)
            if match is not None and match.group(1) in Codec.NESTED:
                module, name = Codec.NESTED[match.group(1)]
                return how, getattr(importlib.import_module(module), name)
        return None

    #: How a value of each declared annotation crosses, and how it is rebuilt: a table keyed by the
    #: annotation, so a new type is a new entry. An annotation in neither crosses as itself.
    TO_DATA: ClassVar[dict[str, Any]] = {
        "tuple[tuple[str, str], ...]": lambda v: [list(x) for x in v],
        "dict[str, bytes]": lambda v: {
            k: base64.b64encode(x).decode("ascii") for k, x in v.items()
        },
        "Mapping[str, str]": dict,
        "dict[str, int]": dict,
        "tuple[str, ...]": list,
        "list[str]": list,
        "frozenset[str]": sorted,
        "bytes | None": lambda v: None if v is None else v.hex(),
        "Scope": lambda v: v.value,
    }
    FROM_DATA: ClassVar[dict[str, Any]] = {
        "tuple[tuple[str, str], ...]": lambda v: tuple((a, b) for a, b in v),
        "dict[str, bytes]": lambda v: {k: base64.b64decode(x, validate=True) for k, x in v.items()},
        "Mapping[str, str]": dict,
        "dict[str, int]": dict,
        "tuple[str, ...]": tuple,
        "list[str]": list,
        "frozenset[str]": frozenset,
        "bytes | None": lambda v: None if v is None else bytes.fromhex(v),
        "Scope": Scope,
    }

    @staticmethod
    def encode(record: Any) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for f in dataclasses.fields(record):
            value = getattr(record, f.name)
            annotation = str(f.type)
            nested = Codec._nested(annotation)
            if nested is not None:
                out[f.name] = Codec._encode_nested(nested[0], value)
            elif annotation in Codec.CHECKS:
                out[f.name] = Codec.TO_DATA.get(annotation, lambda v: v)(value)
            else:
                raise TypeError(f"{type(record).__name__}.{f.name}: {f.type} has no declared shape")
        return out

    @staticmethod
    def _encode_nested(how: str, value: Any) -> Any:
        if how in ("tuple", "list"):
            return [Codec.encode(x) for x in value]
        return None if value is None else Codec.encode(value)

    @staticmethod
    def decode(kind: type, data: Any) -> Any:
        """The record, or None when `data` is not exactly its fields, each of its declared type."""
        if not isinstance(data, dict):
            return None
        declared = {f.name: str(f.type) for f in dataclasses.fields(kind)}
        if set(data) != set(declared):
            return None
        values: dict[str, Any] = {}
        for name, annotation in declared.items():
            ok, value = Codec._decode_field(annotation, data[name])
            if not ok:
                return None
            values[name] = value
        # A record its own constructor would refuse is refused: every `__post_init__` that validates
        # runs, on a throwaway (outer-layer review, condition 4). What is held is the worker's values
        # exactly, never normalised again: a `__post_init__` is not idempotent (`Coordinate.integrity`
        # hashes an already-malformed value a second time), so the constructed record is not kept.
        try:
            kind(**values)
        except Exception:  # noqa: BLE001 - any refusal by the constructor refuses the worker's record
            return None
        record: Any = object.__new__(kind)
        for name, value in values.items():
            object.__setattr__(record, name, value)
        return record

    @staticmethod
    def _decode_field(annotation: str, value: Any) -> tuple[bool, Any]:
        nested = Codec._nested(annotation)
        if nested is not None:
            how, kind_of = nested
            if how in ("tuple", "list"):
                if not isinstance(value, list) or len(value) > LIST_ENTRIES:
                    return False, None
                records = [Codec.decode(kind_of, x) for x in value]
                if any(r is None for r in records):
                    return False, None
                return True, tuple(records) if how == "tuple" else records
            if value is None and how == "optional":
                return True, None
            one = Codec.decode(kind_of, value)
            return one is not None, one
        check = Codec.CHECKS.get(annotation)
        if check is None or not check(value):
            return False, None
        try:
            return True, Codec.FROM_DATA.get(annotation, lambda v: v)(value)
        except ValueError:  # base64 that is not (binascii.Error), a value its type refuses
            return False, None


__all__ = ["LIST_ENTRIES", "STRING_CHARS", "Codec"]
