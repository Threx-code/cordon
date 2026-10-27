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
import struct
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
        if isinstance(proto, (TypedUndefined, Function)):
            return proto  # a function is a declaration: an undefined structure still has it
        return TypedUndefined(Values.kind_of(proto))

    @staticmethod
    def int64(value: Any) -> Any:
        """A module value as YARA reads it (`OP_OBJ_VALUE`): an integer signed 64-bit, so a field
        read as 2**64 - 1 is -1; a float that is NaN undefined, as YARA stores undefined floats."""
        if isinstance(value, float) and math.isnan(value):
            return UNDEF_FLOAT
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
                want == got or got is None  # YARA takes no integer where a float is declared
                for want, got in zip(signature, kinds, strict=True)
            ):
                return target
        return None


# -- the modules ---------------------------------------------------------------


class Builtin:
    """Factories `name -> (data -> Struct)` for the modules every install has."""

    @staticmethod
    def _region(data: bytes, offset: int, size: int) -> bytes | None:
        """The bytes YARA's data functions read for (offset, length) in a file scan: undefined for
        a negative offset or length, or an offset not inside the data; else clipped to it."""
        if offset < 0 or size < 0 or offset >= len(data):
            return None
        return data[offset : offset + size]

    @staticmethod
    def _f32(x: float) -> float:
        """A double rounded to single precision (C's `(float)`)."""
        return float(struct.unpack("<f", struct.pack("<f", x))[0])

    @staticmethod
    def _histogram(r: bytes) -> list[int]:
        counts = [0] * 256
        for b in r:
            counts[b] += 1
        return counts

    @staticmethod
    def _entropy(counts: list[int]) -> float:
        total = sum(counts)
        entropy = 0.0
        for c in counts:
            if c:
                x = c / total
                entropy -= x * math.log2(x)
        return entropy

    @staticmethod
    def _divide(a: float, b: float) -> float:
        """C's double division, NaN or infinity where the divisor is zero."""
        if b == 0:
            return math.nan if a == 0 or math.isnan(a) else math.copysign(math.inf, a)
        return a / b

    @staticmethod
    def _serial(r: bytes) -> float:
        scclast = scct1 = scct2 = scct3 = 0.0
        for b in r:
            sccun = float(b)
            scct1 += scclast * sccun
            scct2 += sccun
            scct3 += sccun * sccun
            scclast = sccun
        if r:
            scct1 += scclast * float(r[0])
        scct2 *= scct2
        n = len(r)
        scc = n * scct3 - scct2
        return -100000.0 if scc == 0 else (n * scct1 - scct2) / scc

    @staticmethod
    def _monte_carlo(r: bytes) -> Any:
        incirc = math.pow(math.pow(256.0, 3.0) - 1, 2.0)
        mcount = inmont = 0
        for i in range(5, len(r), 6):
            mx = my = 0.0
            for j in range(3):
                mx = mx * 256.0 + r[i - 5 + j]
                my = my * 256.0 + r[i - 2 + j]
            mcount += 1
            if mx * mx + my * my <= incirc:
                inmont += 1
        if mcount == 0:
            return UNDEF_FLOAT
        return abs((4.0 * (inmont / mcount) - 3.141592653589793) / 3.141592653589793)

    @staticmethod
    def math(data: bytes) -> Struct:
        """YARA's math module (libyara/modules/math/math.c), operation for operation: sums taken
        over the byte histogram in byte order, `percentage` divided in single precision, `min`
        and `max` comparing as unsigned. A string's bytes are read unsigned (C's `char` on the
        aarch64 build the reference runs; signed on x86 YARA)."""
        B = Builtin

        def ranged(f: Callable[[bytes], Any]) -> Callable[[int, int], Any]:
            def over(offset: int, size: int) -> Any:
                r = B._region(data, offset, size)
                return UNDEF_FLOAT if r is None else f(r)

            return over

        def mean(r: bytes) -> float:
            counts = B._histogram(r)
            return B._divide(sum(float(i) * c for i, c in enumerate(counts)), float(sum(counts)))

        def deviation_of(r: bytes, m: float) -> float:
            counts = B._histogram(r)
            total = 0.0
            for i, c in enumerate(counts):
                total += abs(float(i) - m) * c
            return B._divide(total, float(sum(counts)))

        def deviation_s(s: bytes, m: float) -> float:
            total = 0.0
            for b in s:
                total += abs(float(b) - m)
            return B._divide(total, float(len(s)))

        def mean_s(s: bytes) -> float:
            total = 0.0
            for b in s:
                total += float(b)
            return B._divide(total, float(len(s)))

        def count(byte: int, offset: int | None = None, size: int | None = None) -> Any:
            if not 0 <= byte <= 255:
                return UNDEF_INT
            r = data if offset is None else B._region(data, offset, size or 0)
            return UNDEF_INT if r is None else r.count(bytes([byte]))

        def percentage(byte: int, offset: int | None = None, size: int | None = None) -> Any:
            if not 0 <= byte <= 255:
                return UNDEF_FLOAT
            r = data if offset is None else B._region(data, offset, size or 0)
            if r is None:
                return UNDEF_FLOAT
            a, b = B._f32(float(r.count(bytes([byte])))), B._f32(float(len(r)))
            return B._f32(B._divide(a, b))

        def mode(offset: int | None = None, size: int | None = None) -> Any:
            r = data if offset is None else B._region(data, offset, size or 0)
            if r is None:
                return UNDEF_INT
            counts = B._histogram(r)
            best = 0
            for i in range(256):
                if counts[i] > counts[best]:
                    best = i
            return best

        def unsigned(f: Callable[[int, int], bool]) -> Callable[[int, int], int]:
            return lambda a, b: a if f(a & 0xFFFFFFFFFFFFFFFF, b & 0xFFFFFFFFFFFFFFFF) else b

        def absolute(i: int) -> int:
            return i if i == -(1 << 63) else abs(i)  # llabs(INT64_MIN) is INT64_MIN

        def to_string(value: int, base: int = 10) -> Any:
            if base == 10:
                return str(value).encode()
            if base in (8, 16):
                return format(value & 0xFFFFFFFFFFFFFFFF, "o" if base == 8 else "x").encode()
            return UNDEF_STR

        return Struct(
            {
                "MEAN_BYTES": 127.5,
                "entropy": Values.fn(
                    (("int", "int"), ranged(lambda r: B._entropy(B._histogram(r))), "float"),
                    (("str",), lambda s: B._entropy(B._histogram(s)), "float"),
                ),
                "mean": Values.fn(
                    (("int", "int"), ranged(mean), "float"), (("str",), mean_s, "float")
                ),
                "serial_correlation": Values.fn(
                    (("int", "int"), ranged(B._serial), "float"), (("str",), B._serial, "float")
                ),
                "monte_carlo_pi": Values.fn(
                    (("int", "int"), ranged(B._monte_carlo), "float"),
                    (("str",), B._monte_carlo, "float"),
                ),
                "deviation": Values.fn(
                    (
                        ("int", "int", "float"),
                        lambda o, n, m: ranged(lambda r: deviation_of(r, m))(o, n),
                        "float",
                    ),
                    (("str", "float"), deviation_s, "float"),
                ),
                "in_range": Values.fn(
                    (("float", "float", "float"), lambda v, lo, hi: int(lo <= v <= hi), "int")
                ),
                "min": Values.fn((("int", "int"), unsigned(lambda a, b: a < b), "int")),
                "max": Values.fn((("int", "int"), unsigned(lambda a, b: a > b), "int")),
                "abs": Values.fn((("int",), absolute, "int")),
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
        """YARA's hash module (libyara/modules/hash/hash.c): a range outside the data is
        undefined, a range running past it is clipped; digests in lower-case hex."""

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
    def console(data: bytes, sink: Callable[[str], Any] | None = None) -> Struct:
        """`console.log` and `console.hex`, as YARA's console module: each returns 1 and hands
        its message to `sink` (yara-python's `console_callback`) when there is one. A string is
        logged with each byte outside printable ASCII as `\\xHH`; an integer in decimal; a float
        as C's `%f`; `hex` as `0x` and lower-case hex of the 64-bit value."""

        def emit(text: str) -> int:
            if sink is not None:
                sink(text)
            return 1

        def shown(s: bytes) -> str:
            return "".join(chr(b) if 0x20 <= b <= 0x7E else f"\\x{b:02x}" for b in s)

        def prefix(m: bytes) -> str:
            return m.split(b"\x00", 1)[0].decode("latin-1")

        return Struct(
            {
                "log": Values.fn(
                    (("str",), lambda s: emit(shown(s)), "int"),
                    (("str", "str"), lambda m, s: emit(prefix(m) + shown(s)), "int"),
                    (("int",), lambda i: emit(str(Values.int64(i))), "int"),
                    (("str", "int"), lambda m, i: emit(prefix(m) + str(Values.int64(i))), "int"),
                    (("float",), lambda f: emit(f"{float(f):f}"), "int"),
                    (("str", "float"), lambda m, f: emit(prefix(m) + f"{float(f):f}"), "int"),
                ),
                "hex": Values.fn(
                    (("int",), lambda i: emit(f"0x{i & 0xFFFFFFFFFFFFFFFF:x}"), "int"),
                    (
                        ("str", "int"),
                        lambda m, i: emit(prefix(m) + f"0x{i & 0xFFFFFFFFFFFFFFFF:x}"),
                        "int",
                    ),
                ),
            }
        )

    @staticmethod
    def strtoll(text: bytes, base: int) -> int | None:
        """C's `strtoll` over the whole string (YARA's `string_to_int`): leading white space and
        a sign, `0x` for base 16 or 0, a leading 0 meaning octal in base 0; None for no digits,
        anything after them, or a value outside 64 bits."""
        s = text.split(b"\x00", 1)[0]
        i, n = 0, len(s)
        while i < n and s[i] in b" \t\n\v\f\r":
            i += 1
        negative = False
        if i < n and s[i] in b"+-":
            negative = s[i] == 0x2D
            i += 1

        def digit(c: int) -> int:
            if 0x30 <= c <= 0x39:
                return c - 0x30
            if 0x61 <= c <= 0x7A:
                return c - 0x61 + 10
            if 0x41 <= c <= 0x5A:
                return c - 0x41 + 10
            return 99

        if (
            base in (0, 16)
            and i + 1 < n
            and s[i] == 0x30
            and s[i + 1] in b"xX"
            and i + 2 < n
            and digit(s[i + 2]) < 16
        ):
            i += 2
            base = 16
        elif base == 0:
            base = 8 if i < n and s[i] == 0x30 else 10
        start, value = i, 0
        while i < n and digit(s[i]) < base:
            value = value * base + digit(s[i])
            i += 1
        if i == start or i != n:
            return None
        value = -value if negative else value
        if not -(1 << 63) <= value < (1 << 63):
            return None
        return value

    @staticmethod
    def string(data: bytes) -> Struct:
        """YARA's string module (libyara/modules/string/string.c)."""

        def to_int(s: bytes, base: int = 0) -> Any:
            if not (base == 0 or 2 <= base <= 36):
                return UNDEF_INT
            value = Builtin.strtoll(s, base)
            return UNDEF_INT if value is None else value

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
