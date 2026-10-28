"""cordon-rule values: the types a module declares, and the data one file gives it.

A module declares its types once, as data: a `Record` of named fields, a `Seq` (read by index), a
`Keyed` table (read by text key), a `Scalar`, or a `Call` with one or more signatures. For each
file it returns plain data shaped by that declaration -- dicts of Python values -- and nothing in
the data says what type it is: the declaration does. So a rule is checked against declarations
alone, before any file is read, and the data carries no bookkeeping. Whatever a file does not
provide is simply absent (or None) and reads as undefined.

    Record({"name": Scalar.TEXT, "sections": Seq(Record({"size": Scalar.INT}))})
    {"name": b"a.dll", "sections": {0: {"size": 512}, 2: {"size": 64}}}

A `Seq` holds the slots a file filled, by index; the rule-visible length is the highest index plus
one. A `Record`, `Seq` or `Keyed` may be any mapping (one that decodes each item, or reads each
field, when it is read, say), not only a dict. A `Call` field holds one callable per signature, in the order declared; a callable returning
None gives undefined, and a missing field makes every call undefined.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from typing import Any, ClassVar


class Scalar:
    """A single value's type: `Scalar.INT`, `FLOAT`, `TEXT` (bytes) or `BOOL`."""

    __slots__ = ("name",)

    INT: ClassVar[Scalar]
    FLOAT: ClassVar[Scalar]
    TEXT: ClassVar[Scalar]
    BOOL: ClassVar[Scalar]
    #: The Python types each scalar's data may have.
    HOLDS: ClassVar[dict[str, tuple[type, ...]]] = {
        "int": (int,),
        "float": (float, int),
        "text": (bytes,),
        "bool": (bool,),
    }

    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return f"Scalar.{self.name.upper()}"


Scalar.INT, Scalar.FLOAT, Scalar.TEXT, Scalar.BOOL = (
    Scalar("int"),
    Scalar("float"),
    Scalar("text"),
    Scalar("bool"),
)


class Record:
    """Named fields, each with its type."""

    __slots__ = ("fields",)

    def __init__(self, fields: dict[str, Any]) -> None:
        self.fields = fields


class Seq:
    """Items read by integer index, all of one type."""

    __slots__ = ("item",)

    def __init__(self, item: Any) -> None:
        self.item = item


class Keyed:
    """Items read by a text key, all of one type."""

    __slots__ = ("item",)

    def __init__(self, item: Any) -> None:
        self.item = item


class Sig:
    """One way to call a function: the kinds of its parameters (`int`, `float`, `text`,
    `bool`, `regex`) and the scalar it returns."""

    __slots__ = ("params", "result")

    def __init__(self, params: tuple[str, ...], result: Scalar) -> None:
        self.params, self.result = params, result


class Call:
    """A function with its signatures, in the order its data holds their callables."""

    __slots__ = ("sigs",)

    def __init__(self, *sigs: Sig) -> None:
        self.sigs = sigs

    def pick(self, kinds: tuple[str | None, ...]) -> int | None:
        """The first signature arguments of these kinds fit, by position: an argument of no
        known kind fits any parameter, and an integer never stands in for a float."""
        for i, sig in enumerate(self.sigs):
            if len(sig.params) == len(kinds) and all(
                got is None or got == want for want, got in zip(sig.params, kinds, strict=True)
            ):
                return i
        return None


class Module:
    """A module as the engine loads it: its declared `schema` (a Record) and `data`, which
    gives one file's values."""

    __slots__ = ("data", "schema")

    def __init__(self, schema: Record, data: Callable[[bytes], dict[str, Any]]) -> None:
        self.schema, self.data = schema, data


class Data:
    """What a value read from module data means to a condition, and whether data fits its
    declaration."""

    @staticmethod
    def signed(value: Any) -> Any:
        """An integer as a condition reads it: two's-complement 64 bits, so a field holding
        2**64 - 1 reads as -1. A NaN reads as undefined (None)."""
        if type(value) is int and not -(1 << 63) <= value < (1 << 63):
            value &= (1 << 64) - 1
            return value - (1 << 64) if value >> 63 else value
        if type(value) is float and math.isnan(value):
            return None
        return value

    @staticmethod
    def length(items: dict[int, Any]) -> int:
        """How many items a sequence holds as a rule sees it: up to its highest filled slot."""
        return max(items) + 1 if items else 0

    @staticmethod
    def conforms(declared: Any, data: Any, where: str = "") -> list[str]:
        """Every place `data` does not fit `declared`, as readable paths; empty when it fits."""
        if data is None:
            return []
        if isinstance(declared, Scalar):
            holds = Scalar.HOLDS[declared.name]
            fits = isinstance(data, holds) and (declared is Scalar.BOOL or type(data) is not bool)
            return [] if fits else [f"{where or '.'}: {type(data).__name__}, not {declared.name}"]
        if isinstance(declared, Record):
            if not isinstance(data, Mapping):  # a dict, or a view that reads its fields lazily
                return [f"{where or '.'}: not a record"]
            out = [f"{where}.{k}: not declared" for k in data if k not in declared.fields]
            for name, kind in declared.fields.items():
                if name in data:
                    out += Data.conforms(kind, data[name], f"{where}.{name}")
            return out
        if isinstance(declared, (Seq, Keyed)):
            key = int if isinstance(declared, Seq) else bytes
            if not isinstance(data, Mapping):  # a dict, or a mapping that decodes on access
                return [f"{where or '.'}: not a table"]
            out = []
            for k, v in data.items():
                if not isinstance(k, key) or (isinstance(k, int) and k < 0):
                    out.append(f"{where}[{k!r}]: a key of the wrong kind")
                else:
                    out += Data.conforms(declared.item, v, f"{where}[{k!r}]")
            return out
        if isinstance(declared, Call):
            ok = isinstance(data, tuple) and len(data) == len(declared.sigs)
            return [] if ok and all(callable(f) for f in data) else [f"{where}: not callables"]
        return [f"{where or '.'}: an unknown declaration"]


__all__ = [
    "Call",
    "Data",
    "Keyed",
    "Module",
    "Record",
    "Scalar",
    "Seq",
    "Sig",
]
