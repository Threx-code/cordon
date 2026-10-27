"""cordon-rule's built-in modules: `math`, `hash`, `string`, `console` and `time`.

Every function that reads the scanned data takes an (offset, length) region: undefined when the
offset is negative, the length negative, or the offset not inside the data, and clipped to the data
when it runs past the end. Floating-point results are computed in a fixed order -- statistics over
a region summed byte value by byte value, over a string byte by byte -- so the same rule gives the
same number everywhere; a division by zero gives what IEEE arithmetic gives (NaN reads as
undefined).
"""

from __future__ import annotations

import hashlib
import math
import struct
import time
import zlib
from collections.abc import Callable
from typing import Any

from cordon_scanner.detect.binary.rule_values import (
    UNDEF_FLOAT,
    UNDEF_INT,
    UNDEF_STR,
    Function,
    Struct,
    Values,
)

INT64_BITS = (1 << 64) - 1


class Region:
    """The bytes a data function reads, or None where the region is undefined."""

    @staticmethod
    def of(data: bytes, offset: int, length: int) -> bytes | None:
        if offset < 0 or length < 0 or offset >= len(data):
            return None
        return data[offset : offset + length]


class Arith:
    """IEEE double arithmetic where Python raises, and single-precision rounding."""

    @staticmethod
    def divide(a: float, b: float) -> float:
        if b == 0:
            return math.nan if a == 0 or math.isnan(a) else math.copysign(math.inf, a)
        return a / b

    @staticmethod
    def single(x: float) -> float:
        return float(struct.unpack("<f", struct.pack("<f", x))[0])


class ByteStats:
    """Statistics of a run of bytes. Over a data region they are taken from the byte-value
    tally, value 0 to 255; over a string, byte by byte in order."""

    def __init__(self, run: bytes) -> None:
        self.run = run
        self.tally = [run.count(v) for v in range(256)] if run else [0] * 256

    def entropy(self) -> float:
        total = len(self.run)
        bits = 0.0
        for n in self.tally:
            if n:
                share = n / total
                bits -= share * math.log2(share)
        return bits

    def mean(self) -> float:
        weighted = 0.0
        for value, n in enumerate(self.tally):
            weighted += float(value) * n
        return Arith.divide(weighted, float(len(self.run)))

    def mean_in_order(self) -> float:
        total = 0.0
        for b in self.run:
            total += float(b)
        return Arith.divide(total, float(len(self.run)))

    def deviation(self, centre: float) -> float:
        spread = 0.0
        for value, n in enumerate(self.tally):
            spread += abs(float(value) - centre) * n
        return Arith.divide(spread, float(len(self.run)))

    def deviation_in_order(self, centre: float) -> float:
        spread = 0.0
        for b in self.run:
            spread += abs(float(b) - centre)
        return Arith.divide(spread, float(len(self.run)))

    def serial_correlation(self) -> float:
        """How much each byte predicts the next (the last wrapping round to the first);
        -100000 when the run gives no measure of it."""
        run = self.run
        pairs = level = squares = 0.0
        previous = 0.0
        for b in run:
            here = float(b)
            pairs += previous * here
            level += here
            squares += here * here
            previous = here
        if run:
            pairs += previous * float(run[0])
        level *= level
        count = len(run)
        spread = count * squares - level
        return -100000.0 if spread == 0 else (count * pairs - level) / spread

    def pi_error(self) -> Any:
        """Each six bytes read as a point (two 24-bit coordinates); the share inside the
        quarter circle estimates pi; the relative error of that estimate. Undefined with no
        complete point."""
        radius_squared = math.pow(math.pow(256.0, 3.0) - 1, 2.0)
        run = self.run
        points = inside = 0
        for end in range(5, len(run), 6):
            x = y = 0.0
            for k in range(3):
                x = x * 256.0 + run[end - 5 + k]
                y = y * 256.0 + run[end - 2 + k]
            points += 1
            if x * x + y * y <= radius_squared:
                inside += 1
        if points == 0:
            return UNDEF_FLOAT
        return abs((4.0 * (inside / points) - math.pi) / math.pi)

    def most_common(self) -> int:
        best = 0
        for value in range(256):
            if self.tally[value] > self.tally[best]:
                best = value
        return best


class MathModule:
    """`math`: statistics of the data or of a string, and integer helpers."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def _region_stat(self, stat: Callable[[ByteStats], Any]) -> Callable[[int, int], Any]:
        def over(offset: int, length: int) -> Any:
            run = Region.of(self.data, offset, length)
            return UNDEF_FLOAT if run is None else stat(ByteStats(run))

        return over

    def _run(self, offset: int | None, length: int | None) -> bytes | None:
        return self.data if offset is None else Region.of(self.data, offset, length or 0)

    def count(self, byte: int, offset: int | None = None, length: int | None = None) -> Any:
        run = self._run(offset, length)
        if not 0 <= byte <= 255 or run is None:
            return UNDEF_INT
        return run.count(bytes([byte]))

    def percentage(self, byte: int, offset: int | None = None, length: int | None = None) -> Any:
        """The share of `byte` in the run, in single precision."""
        run = self._run(offset, length)
        if not 0 <= byte <= 255 or run is None:
            return UNDEF_FLOAT
        hits = Arith.single(float(run.count(bytes([byte]))))
        return Arith.single(Arith.divide(hits, Arith.single(float(len(run)))))

    def mode(self, offset: int | None = None, length: int | None = None) -> Any:
        run = self._run(offset, length)
        return UNDEF_INT if run is None else ByteStats(run).most_common()

    @staticmethod
    def smaller(a: int, b: int) -> int:
        return a if a & INT64_BITS < b & INT64_BITS else b

    @staticmethod
    def larger(a: int, b: int) -> int:
        return a if a & INT64_BITS > b & INT64_BITS else b

    @staticmethod
    def magnitude(i: int) -> int:
        return i if i == -(1 << 63) else abs(i)  # the most negative 64-bit value has no opposite

    @staticmethod
    def text_of(value: int, base: int = 10) -> Any:
        if base == 10:
            return str(value).encode()
        if base in (8, 16):
            return format(value & INT64_BITS, "o" if base == 8 else "x").encode()
        return UNDEF_STR

    def struct(self) -> Struct:
        f = Values.fn
        stat = self._region_stat
        return Struct(
            {
                "MEAN_BYTES": 127.5,
                "entropy": f(
                    (("int", "int"), stat(ByteStats.entropy), "float"),
                    (("str",), lambda s: ByteStats(s).entropy(), "float"),
                ),
                "mean": f(
                    (("int", "int"), stat(ByteStats.mean), "float"),
                    (("str",), lambda s: ByteStats(s).mean_in_order(), "float"),
                ),
                "serial_correlation": f(
                    (("int", "int"), stat(ByteStats.serial_correlation), "float"),
                    (("str",), lambda s: ByteStats(s).serial_correlation(), "float"),
                ),
                "monte_carlo_pi": f(
                    (("int", "int"), stat(ByteStats.pi_error), "float"),
                    (("str",), lambda s: ByteStats(s).pi_error(), "float"),
                ),
                "deviation": f(
                    (
                        ("int", "int", "float"),
                        lambda o, n, c: stat(lambda b: b.deviation(c))(o, n),
                        "float",
                    ),
                    (("str", "float"), lambda s, c: ByteStats(s).deviation_in_order(c), "float"),
                ),
                "in_range": f(
                    (("float", "float", "float"), lambda v, lo, hi: int(lo <= v <= hi), "int")
                ),
                "min": f((("int", "int"), MathModule.smaller, "int")),
                "max": f((("int", "int"), MathModule.larger, "int")),
                "abs": f((("int",), MathModule.magnitude, "int")),
                "to_number": f((("bool",), lambda b: int(bool(b)), "int")),
                "count": f(
                    (("int",), self.count, "int"), (("int", "int", "int"), self.count, "int")
                ),
                "percentage": f(
                    (("int",), self.percentage, "float"),
                    (("int", "int", "int"), self.percentage, "float"),
                ),
                "mode": f(((), self.mode, "int"), (("int", "int"), self.mode, "int")),
                "to_string": f(
                    (("int",), MathModule.text_of, "str"),
                    (("int", "int"), MathModule.text_of, "str"),
                ),
            }
        )


class HashModule:
    """`hash`: digests and checksums of a data region or a string, digests in lower-case hex."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def _both(self, of: Callable[[bytes], Any], undefined: Any, kind: str) -> Function:
        def over(offset: int, length: int) -> Any:
            run = Region.of(self.data, offset, length)
            return undefined if run is None else of(run)

        return Values.fn((("int", "int"), over, kind), (("str",), of, kind))

    def struct(self) -> Struct:
        def digest(name: str) -> Function:
            return self._both(lambda b: hashlib.new(name, b).hexdigest().encode(), UNDEF_STR, "str")

        return Struct(
            {
                "md5": digest("md5"),
                "sha1": digest("sha1"),
                "sha256": digest("sha256"),
                "crc32": self._both(lambda b: zlib.crc32(b) & 0xFFFFFFFF, UNDEF_INT, "int"),
                "checksum32": self._both(lambda b: sum(b) & 0xFFFFFFFF, UNDEF_INT, "int"),
            }
        )


class Integers:
    """Text read as a whole integer: optional leading white space and sign, `0x` for base 16
    (or base 0), a leading `0` meaning octal in base 0; the whole text up to its first zero byte
    must be digits; None when it is not, or when the value does not fit 64 bits."""

    SPACE = b" \t\n\v\f\r"

    @staticmethod
    def digit(c: int) -> int:
        if 0x30 <= c <= 0x39:
            return c - 0x30
        if 0x61 <= c <= 0x7A:
            return c - 0x61 + 10
        if 0x41 <= c <= 0x5A:
            return c - 0x41 + 10
        return 99

    @staticmethod
    def parse(text: bytes, base: int) -> int | None:
        s = text.split(b"\x00", 1)[0]
        i, n = 0, len(s)
        while i < n and s[i] in Integers.SPACE:
            i += 1
        negative = i < n and s[i] == 0x2D
        if i < n and s[i] in b"+-":
            i += 1
        hex_prefix = (
            i + 2 < n and s[i] == 0x30 and s[i + 1] in b"xX" and Integers.digit(s[i + 2]) < 16
        )
        if base in (0, 16) and hex_prefix:
            i += 2
            base = 16
        elif base == 0:
            base = 8 if i < n and s[i] == 0x30 else 10
        first, value = i, 0
        while i < n and Integers.digit(s[i]) < base:
            value = value * base + Integers.digit(s[i])
            i += 1
        if i == first or i != n:
            return None
        if negative:
            value = -value
        return value if -(1 << 63) <= value < (1 << 63) else None


class StringModule:
    """`string`: a string's integer value and its length."""

    @staticmethod
    def to_int(s: bytes, base: int = 0) -> Any:
        if not (base == 0 or 2 <= base <= 36):
            return UNDEF_INT
        value = Integers.parse(s, base)
        return UNDEF_INT if value is None else value

    @staticmethod
    def struct() -> Struct:
        f = Values.fn
        return Struct(
            {
                "to_int": f(
                    (("str",), StringModule.to_int, "int"),
                    (("str", "int"), StringModule.to_int, "int"),
                ),
                "length": f((("str",), len, "int")),
            }
        )


class ConsoleModule:
    """`console.log` and `console.hex`: each returns 1 and hands its message to `sink` when
    there is one. A string shows each byte outside printable ASCII as `\\xHH`; an integer is
    written in decimal, a float with six decimals, `hex` as `0x` and the lower-case hex of the
    64-bit value; a leading message stops at its first zero byte."""

    def __init__(self, sink: Callable[[str], Any] | None) -> None:
        self.sink = sink

    def emit(self, text: str) -> int:
        if self.sink is not None:
            self.sink(text)
        return 1

    @staticmethod
    def shown(s: bytes) -> str:
        return "".join(chr(b) if 0x20 <= b <= 0x7E else f"\\x{b:02x}" for b in s)

    @staticmethod
    def lead(m: bytes) -> str:
        return m.split(b"\x00", 1)[0].decode("latin-1")

    def struct(self) -> Struct:
        f, say, lead, shown = Values.fn, self.emit, ConsoleModule.lead, ConsoleModule.shown

        def as_int(i: int) -> str:
            return str(Values.int64(i))

        def as_hex(i: int) -> str:
            return f"0x{i & INT64_BITS:x}"

        return Struct(
            {
                "log": f(
                    (("str",), lambda s: say(shown(s)), "int"),
                    (("str", "str"), lambda m, s: say(lead(m) + shown(s)), "int"),
                    (("int",), lambda i: say(as_int(i)), "int"),
                    (("str", "int"), lambda m, i: say(lead(m) + as_int(i)), "int"),
                    (("float",), lambda x: say(f"{float(x):f}"), "int"),
                    (("str", "float"), lambda m, x: say(lead(m) + f"{float(x):f}"), "int"),
                ),
                "hex": f(
                    (("int",), lambda i: say(as_hex(i)), "int"),
                    (("str", "int"), lambda m, i: say(lead(m) + as_hex(i)), "int"),
                ),
            }
        )


class Builtin:
    """Factories `name -> (data -> Struct)` for the modules every install has."""

    @staticmethod
    def math(data: bytes) -> Struct:
        return MathModule(data).struct()

    @staticmethod
    def hash(data: bytes) -> Struct:
        return HashModule(data).struct()

    @staticmethod
    def string(data: bytes) -> Struct:
        return StringModule.struct()

    @staticmethod
    def time_(data: bytes) -> Struct:
        return Struct({"now": Values.fn(((), lambda: int(time.time()), "int"))})

    @staticmethod
    def console(data: bytes, sink: Callable[[str], Any] | None = None) -> Struct:
        return ConsoleModule(sink).struct()

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


__all__ = ["Builtin", "ByteStats", "Integers"]
