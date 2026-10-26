"""YARA's module object model, and the modules Cordon's engine implements.

A module is a tree of typed values: structures with declared fields, arrays and dictionaries that
know the type of what they hold, and functions with typed signatures. Types matter as YARA makes
them matter: a field the module does not declare, a string compared with a number, or a loop over
a dictionary with one variable is refused when the rules compile, not discovered on some file.
A value the module declares but a file does not provide is *undefined* -- typed, so that a
comparison with it is still checked.

Modules: `math`, `hash`, `time`, `console`, `string`; `pe` and `elf` in `yara_pe`; `dotnet` in
`yara_dotnet` -- every module yara-python 4.5.1 ships. A test can add
one (`Rules.compile(..., modules=...)`), as YARA's own suite does with its `tests` module.
"""

from __future__ import annotations

import hashlib
import math
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


class TypedUndefined:
    """An undefined value of a known type: `int`, `float`, `str`, `bool` or `None` (any)."""

    __slots__ = ("kind",)

    def __init__(self, kind: str | None) -> None:
        self.kind = kind

    def __repr__(self) -> str:
        return f"Values.undefined({self.kind})" if self.kind else "undefined"


UNDEFINED = TypedUndefined(None)
UNDEF_INT, UNDEF_FLOAT, UNDEF_STR = (
    TypedUndefined("int"),
    TypedUndefined("float"),
    TypedUndefined("str"),
)


class Values:
    """Typed values: what is undefined, a value's type, a type's undefined, a function."""

    @staticmethod
    def undefined(value: Any) -> bool:
        return isinstance(value, TypedUndefined)

    @staticmethod
    def kind_of(value: Any) -> str | None:
        """`int`, `float`, `str`, `bool`, `struct`, `array`, `dict`, `function`, or None."""
        if isinstance(value, TypedUndefined):
            return value.kind
        if isinstance(value, bool):
            return "bool"
        if isinstance(value, int):
            return "int"
        if isinstance(value, float):
            return "float"
        if isinstance(value, bytes):
            return "str"
        if isinstance(value, Struct):
            return "struct"
        if isinstance(value, Array):
            return "array"
        if isinstance(value, Dictionary):
            return "dict"
        if isinstance(value, Function):
            return "function"
        return None

    @staticmethod
    def undefined_like(proto: Any) -> Any:
        """The undefined value of `proto`'s type: a typed undefined, or a structure of them."""
        if isinstance(proto, Struct):
            return Struct({k: Values.undefined_like(v) for k, v in proto.fields.items()})
        if isinstance(proto, (Array, Dictionary)):
            return type(proto)(proto.proto)
        if isinstance(proto, TypedUndefined):
            return proto
        return TypedUndefined(Values.kind_of(proto))

    @staticmethod
    def int64(value: Any) -> Any:
        """A module integer as YARA holds it: signed 64-bit, so a field read as 2**64 - 1 is -1."""
        if (
            isinstance(value, int)
            and not isinstance(value, bool)
            and not -(1 << 63) <= value < (1 << 63)
        ):
            value &= (1 << 64) - 1
            return value - (1 << 64) if value >> 63 else value
        return value

    @staticmethod
    def fn(*overloads: tuple[tuple[str, ...], Callable[..., Any], str]) -> Function:
        return Function({sig: (call, ret) for sig, call, ret in overloads})


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
    """Overloads by argument types: `{("int", "int"): (callable, "int")}`; `r` is a regex."""

    overloads: dict[tuple[str, ...], tuple[Callable[..., Any], str]]

    def resolve(self, kinds: tuple[str | None, ...]) -> tuple[Callable[..., Any], str] | None:
        for signature, target in self.overloads.items():
            if len(signature) == len(kinds) and all(
                want == got or (want == "float" and got == "int") or got is None
                for want, got in zip(signature, kinds, strict=True)
            ):
                return target
        return None


# -- the modules ---------------------------------------------------------------


class Builtin:
    """Factories `name -> (data -> Struct)` for the modules every install has."""

    @staticmethod
    def _region(data: bytes, offset: int, size: int) -> bytes | None:
        if offset < 0 or size < 0 or offset > len(data):
            return None
        return data[offset : offset + size]

    @staticmethod
    def math(data: bytes) -> Struct:
        def region_or_undef(f: Callable[[bytes], Any], kind: Any = UNDEF_FLOAT) -> Function:
            def over(offset: int, size: int) -> Any:
                r = Builtin._region(data, offset, size)
                return kind if not r else f(r)

            def over_string(s: bytes) -> Any:
                return kind if not s else f(s)

            return Values.fn((("int", "int"), over, "float"), (("str",), over_string, "float"))

        def entropy(r: bytes) -> float:
            n = len(r)
            counts = [0] * 256
            for b in r:
                counts[b] += 1
            return -sum(c / n * math.log2(c / n) for c in counts if c)

        def mean(r: bytes) -> float:
            return sum(r) / len(r)

        def serial(r: bytes) -> float:
            n = len(r)
            sccun = sum(r[i] * r[(i + 1) % n] for i in range(n))
            s, s2 = sum(r), sum(b * b for b in r)
            den = n * s2 - s * s
            return -100000.0 if den == 0 else (n * sccun - s * s) / den

        def monte_carlo(r: bytes) -> Any:
            hits = total = 0
            for i in range(0, len(r) - 5, 6):
                x = int.from_bytes(r[i : i + 3], "big") / 16777215.0
                y = int.from_bytes(r[i + 3 : i + 6], "big") / 16777215.0
                total += 1
                hits += x * x + y * y <= 1.0
            return UNDEF_FLOAT if not total else abs(math.pi - 4.0 * hits / total) / math.pi

        def deviation(offset: int, size: int, m: float) -> Any:
            r = Builtin._region(data, offset, size)
            return UNDEF_FLOAT if not r else sum(abs(b - m) for b in r) / len(r)

        def deviation_s(s: bytes, m: float) -> Any:
            return UNDEF_FLOAT if not s else sum(abs(b - m) for b in s) / len(s)

        def count(byte: int, offset: int | None = None, size: int | None = None) -> Any:
            r = data if offset is None else Builtin._region(data, offset, size or 0)
            if r is None or not 0 <= byte <= 255:
                return UNDEF_INT
            return r.count(bytes([byte]))

        def percentage(byte: int, offset: int | None = None, size: int | None = None) -> Any:
            r = data if offset is None else Builtin._region(data, offset, size or 0)
            if not r or not 0 <= byte <= 255:
                return UNDEF_FLOAT
            return r.count(bytes([byte])) / len(r)

        def mode(offset: int | None = None, size: int | None = None) -> Any:
            r = data if offset is None else Builtin._region(data, offset, size or 0)
            if not r:
                return UNDEF_INT
            counts = [0] * 256
            for b in r:
                counts[b] += 1
            return max(range(256), key=lambda b: (counts[b], -b))

        def to_string(value: int, base: int = 10) -> Any:
            if base not in (2, 8, 10, 16):
                return UNDEF_STR
            if base == 10:
                return str(value).encode()
            digits = {2: "b", 8: "o", 16: "x"}[base]
            return format(value, digits).encode()

        return Struct(
            {
                "MEAN_BYTES": 127.5,
                "entropy": region_or_undef(entropy),
                "mean": region_or_undef(mean),
                "serial_correlation": region_or_undef(serial),
                "monte_carlo_pi": region_or_undef(monte_carlo),
                "deviation": Values.fn(
                    (("int", "int", "float"), deviation, "float"),
                    (("str", "float"), deviation_s, "float"),
                ),
                "in_range": Values.fn(
                    (("float", "float", "float"), lambda v, lo, hi: lo <= v <= hi, "bool")
                ),
                "min": Values.fn((("int", "int"), min, "int")),
                "max": Values.fn((("int", "int"), max, "int")),
                "abs": Values.fn((("int",), abs, "int")),
                "to_number": Values.fn((("bool",), lambda b: int(bool(b)), "int")),
                "count": Values.fn((("int",), count, "int"), (("int", "int", "int"), count, "int")),
                "percentage": Values.fn(
                    (("int",), percentage, "float"), (("int", "int", "int"), percentage, "float")
                ),
                "mode": Values.fn(((), mode, "int"), (("int", "int"), mode, "int")),
                "to_string": Values.fn(
                    (("int",), to_string, "str"), (("int", "int"), to_string, "str")
                ),
            }
        )

    @staticmethod
    def hash(data: bytes) -> Struct:
        def digest(name: str) -> Function:
            def over(offset: int, size: int) -> Any:
                r = Builtin._region(data, offset, size)
                return UNDEF_STR if r is None else hashlib.new(name, r).hexdigest().encode()

            return Values.fn(
                (("int", "int"), over, "str"),
                (("str",), lambda s: hashlib.new(name, s).hexdigest().encode(), "str"),
            )

        def crc(offset: int, size: int) -> Any:
            r = Builtin._region(data, offset, size)
            return UNDEF_INT if r is None else zlib.crc32(r) & 0xFFFFFFFF

        def checksum(offset: int, size: int) -> Any:
            r = Builtin._region(data, offset, size)
            return UNDEF_INT if r is None else sum(r) & 0xFFFFFFFF

        return Struct(
            {
                "md5": digest("md5"),
                "sha1": digest("sha1"),
                "sha256": digest("sha256"),
                "crc32": Values.fn(
                    (("int", "int"), crc, "int"),
                    (("str",), lambda s: zlib.crc32(s) & 0xFFFFFFFF, "int"),
                ),
                "checksum32": Values.fn(
                    (("int", "int"), checksum, "int"),
                    (("str",), lambda s: sum(s) & 0xFFFFFFFF, "int"),
                ),
            }
        )

    @staticmethod
    def time_(data: bytes) -> Struct:
        return Struct({"now": Values.fn(((), lambda: int(time.time()), "int"))})

    @staticmethod
    def console(data: bytes) -> Struct:
        """`console.log` and `console.hex` write nothing here and are true, as YARA's are when no
        callback prints them: a rule's condition must not depend on where its log goes."""
        always = Values.fn(
            (("str",), lambda *_: True, "bool"),
            (("str", "str"), lambda *_: True, "bool"),
            (("int",), lambda *_: True, "bool"),
            (("str", "int"), lambda *_: True, "bool"),
            (("float",), lambda *_: True, "bool"),
            (("str", "float"), lambda *_: True, "bool"),
        )
        return Struct(
            {
                "log": always,
                "hex": Values.fn(
                    (("int",), lambda *_: True, "bool"), (("str", "int"), lambda *_: True, "bool")
                ),
            }
        )

    @staticmethod
    def string(data: bytes) -> Struct:
        def to_int(s: bytes, base: int = 0) -> Any:
            try:
                return int(s.decode("ascii").strip(), base)
            except (UnicodeDecodeError, ValueError):
                return UNDEF_INT

        return Struct(
            {
                "to_int": Values.fn((("str",), to_int, "int"), (("str", "int"), to_int, "int")),
                "length": Values.fn((("str",), len, "int")),
            }
        )

    @staticmethod
    def modules() -> dict[str, Callable[[bytes], Struct]]:
        from cordon_scanner.detect.binary.yara_dotnet import Dotnet
        from cordon_scanner.detect.binary.yara_pe import Elf, Pe

        return {
            "math": Builtin.math,
            "hash": Builtin.hash,
            "time": Builtin.time_,
            "console": Builtin.console,
            "string": Builtin.string,
            "pe": Pe.module,
            "elf": Elf.module,
            "dotnet": Dotnet.module,
        }


__all__ = [
    "UNDEFINED",
    "UNDEF_FLOAT",
    "UNDEF_INT",
    "UNDEF_STR",
    "Array",
    "Builtin",
    "Dictionary",
    "Function",
    "Struct",
    "TypedUndefined",
    "Values",
]
