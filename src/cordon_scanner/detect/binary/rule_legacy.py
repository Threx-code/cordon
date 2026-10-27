"""The value trees the executable readers not yet moved to declared schemas build: a structure,
array or dictionary object per value, an undefined that carries its type. `rule_values.Legacy`
turns one into a schema and plain data; this module goes once no reader builds them."""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar


class TypedUndefined:
    """An undefined value of a known type: `int`, `float`, `str`, `bool` or None (any type)."""

    __slots__ = ("kind",)

    def __init__(self, kind: str | None) -> None:
        self.kind = kind

    def __repr__(self) -> str:
        return f"undefined {self.kind}" if self.kind else "undefined"


UNDEFINED = TypedUndefined(None)
UNDEF_INT = TypedUndefined("int")
UNDEF_FLOAT = TypedUndefined("float")
UNDEF_STR = TypedUndefined("str")

INT64_BITS = (1 << 64) - 1


@dataclass
class Struct:
    """Declared fields, each a value, a typed undefined, a container or a function."""

    fields: dict[str, Any]

    def get(self, name: str) -> Any:
        if name not in self.fields:
            raise KeyError(name)
        return self.fields[name]


@dataclass
class Array:
    """Values by index; `proto` is the type of an element (a typed undefined or a Struct)."""

    proto: Any
    items: dict[int, Any] = field(default_factory=dict)

    def element(self, index: int) -> Any:
        return self.items.get(index, Values.undefined_like(self.proto))

    def values(self) -> list[Any]:
        if not self.items:
            return []
        return [self.element(i) for i in range(max(self.items) + 1)]


@dataclass
class Dictionary:
    """Values by string key; `proto` is the type of a value."""

    proto: Any
    items: dict[bytes, Any] = field(default_factory=dict)

    def element(self, key: bytes) -> Any:
        return self.items.get(key, Values.undefined_like(self.proto))


@dataclass
class Function:
    """Overloads by argument types, `{("int", "int"): (callable, "int")}`; `r` is a regular
    expression. An argument of unknown type (undefined) fits any; an integer never fits a
    float parameter."""

    overloads: dict[tuple[str, ...], tuple[Callable[..., Any], str]]

    def resolve(self, kinds: tuple[str | None, ...]) -> tuple[Callable[..., Any], str] | None:
        for signature, target in self.overloads.items():
            if len(signature) == len(kinds) and all(
                want == got or got is None for want, got in zip(signature, kinds, strict=True)
            ):
                return target
        return None


class Values:
    """What a value is: undefined or not, its type, the undefined of its type; and functions."""

    KINDS: ClassVar[tuple[tuple[str, type], ...]] = (
        ("bool", bool),
        ("int", int),
        ("float", float),
        ("str", bytes),
        ("struct", Struct),
        ("array", Array),
        ("dict", Dictionary),
        ("function", Function),
    )

    @staticmethod
    def undefined(value: Any) -> bool:
        return isinstance(value, TypedUndefined)

    @staticmethod
    def kind_of(value: Any) -> str | None:
        """`int`, `float`, `str`, `bool`, `struct`, `array`, `dict`, `function`, or None."""
        if isinstance(value, TypedUndefined):
            return value.kind
        for kind, types in Values.KINDS:
            if isinstance(value, types):
                return kind
        return None

    @staticmethod
    def undefined_like(proto: Any) -> Any:
        """The undefined value of `proto`'s type: a typed undefined, or a structure of them.
        A function stays itself: it is part of a structure's declaration, defined or not."""
        if isinstance(proto, Struct):
            return Struct({k: Values.undefined_like(v) for k, v in proto.fields.items()})
        if isinstance(proto, (Array, Dictionary)):
            return type(proto)(proto.proto)
        if isinstance(proto, (TypedUndefined, Function)):
            return proto
        return TypedUndefined(Values.kind_of(proto))

    @staticmethod
    def int64(value: Any) -> Any:
        """A value as a condition reads it from a module: an integer as a signed 64-bit number (a
        field holding 2**64 - 1 reads as -1), a NaN float as undefined."""
        if isinstance(value, float) and math.isnan(value):
            return UNDEF_FLOAT
        if (
            isinstance(value, int)
            and not isinstance(value, bool)
            and not -(1 << 63) <= value < (1 << 63)
        ):
            value &= INT64_BITS
            return value - (1 << 64) if value >> 63 else value
        return value

    @staticmethod
    def fn(*overloads: tuple[tuple[str, ...], Callable[..., Any], str]) -> Function:
        """A function from its overloads: (argument types, implementation, result type)."""
        return Function({sig: (call, ret) for sig, call, ret in overloads})


__all__ = [
    "UNDEFINED",
    "UNDEF_FLOAT",
    "UNDEF_INT",
    "UNDEF_STR",
    "Array",
    "Dictionary",
    "Function",
    "Struct",
    "TypedUndefined",
    "Values",
]
