"""cordon-rule's built-in modules: `math`, `hash`, `string`, `console` and `time`.

Every function that reads the scanned data takes an (offset, length) region: undefined when the
offset is negative, the length negative, or the offset not inside the data, and clipped to the data
when it runs past the end. Floating-point results are computed in a fixed order -- statistics over
a region summed byte value by byte value, over a string byte by byte -- so the same rule gives the
same number everywhere; a division by zero gives what IEEE arithmetic gives (NaN reads as
undefined).
"""

from __future__ import annotations

import collections
import hashlib
import math
import struct
import time
import zlib
from collections.abc import Callable
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.values import Call, Data, Module, Record, Scalar, Sig

INT, FLOAT, TEXT = Scalar.INT, Scalar.FLOAT, Scalar.TEXT

INT64_BITS = (1 << 64) - 1


class Region:
    """The bytes a data function reads, or None where the region is undefined."""

    @staticmethod
    def of(data: bytes, offset: int, length: int) -> bytes | None:
        if offset < 0 or length < 0 or offset >= len(data):
            return None
        return data[offset : offset + length]

    @staticmethod
    def span(data: bytes, offset: int, length: int) -> tuple[int, int] | None:
        """The (start, end) `of` reads, clamped to the data: two asks reading the same bytes have
        the same span, an offset or length past the end included. None where `of` is None."""
        if offset < 0 or length < 0 or offset >= len(data):
            return None
        return offset, min(len(data), offset + length)


class Kept:
    """What a module worked out for one region of one file, the last `MOST` regions kept (least
    recently asked first out): a rule set asks the same few regions hundreds of times (668
    hashes of 6 to 37 distinct regions a file, review 6y), while a rule looping over every block
    asks thousands once each, and must not hold them all."""

    MOST: ClassVar[int] = 256

    def __init__(self) -> None:
        self._kept: collections.OrderedDict[Any, Any] = collections.OrderedDict()

    def get(self, key: Any, work: Callable[[], Any]) -> Any:
        if key in self._kept:
            self._kept.move_to_end(key)
            return self._kept[key]
        value = self._kept[key] = work()
        if len(self._kept) > Kept.MOST:
            self._kept.popitem(last=False)
        return value

    def __len__(self) -> int:
        return len(self._kept)


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
    tally, value 0 to 255; over a string, byte by byte in order.

    `run` is the bytes, read in order by the in-order statistics; a region's tally may be given
    (`MathModule` keeps it per file), with `length` the region's size, and then `run` may be
    empty: the tally statistics read only the tally and the length."""

    def __init__(
        self, run: bytes, tally: tuple[int, ...] | None = None, length: int | None = None
    ) -> None:
        self.run = run
        self.tally = ByteStats.tally_of(run) if tally is None else tally
        self.length = len(run) if length is None else length

    @staticmethod
    def tally_of(run: bytes | memoryview) -> tuple[int, ...]:
        """How often each byte value 0 to 255 occurs in `run`, in one pass (`collections.Counter`,
        whose counting is C). It was 256 passes, one `count` a value: 1.754 s against 0.318 s on
        an 8.9 MB file, 7.70 s of the 14 large files' 28.5 (review 6y)."""
        if not run:
            return (0,) * 256
        seen = collections.Counter(run)
        return tuple(seen.get(v, 0) for v in range(256))

    def entropy(self) -> float:
        total = self.length
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
        return Arith.divide(weighted, float(self.length))

    def mean_in_order(self) -> float:
        total = 0.0
        for b in self.run:
            total += float(b)
        return Arith.divide(total, float(len(self.run)))

    def deviation(self, centre: float) -> float:
        spread = 0.0
        for value, n in enumerate(self.tally):
            spread += abs(float(value) - centre) * n
        return Arith.divide(spread, float(self.length))

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
            return None
        return abs((4.0 * (inside / points) - math.pi) / math.pi)

    def most_common(self) -> int:
        best = 0
        for value in range(256):
            if self.tally[value] > self.tally[best]:
                best = value
        return best


class MathModule:
    """`math`: statistics of the data or of a string, and integer helpers."""

    SCHEMA: ClassVar[Record] = Record(
        {
            "MEAN_BYTES": FLOAT,
            **{
                name: Call(Sig(("int", "int"), FLOAT), Sig(("text",), FLOAT))
                for name in ("entropy", "mean", "serial_correlation", "monte_carlo_pi")
            },
            "deviation": Call(Sig(("int", "int", "float"), FLOAT), Sig(("text", "float"), FLOAT)),
            "in_range": Call(Sig(("float", "float", "float"), INT)),
            "min": Call(Sig(("int", "int"), INT)),
            "max": Call(Sig(("int", "int"), INT)),
            "abs": Call(Sig(("int",), INT)),
            "to_number": Call(Sig(("bool",), INT)),
            "count": Call(Sig(("int",), INT), Sig(("int", "int", "int"), INT)),
            "percentage": Call(Sig(("int",), FLOAT), Sig(("int", "int", "int"), FLOAT)),
            "mode": Call(Sig((), INT), Sig(("int", "int"), INT)),
            "to_string": Call(Sig(("int",), TEXT), Sig(("int", "int"), TEXT)),
        }
    )

    def __init__(self, data: bytes) -> None:
        self.data = data
        #: Each region's byte tally, by its clamped span (`Region.span`), for this file.
        self.tallies = Kept()

    def tallied(self, span: tuple[int, int]) -> ByteStats:
        """A region's statistics from its kept tally: no copy of the region is made."""
        start, end = span
        tally = self.tallies.get(span, lambda: ByteStats.tally_of(memoryview(self.data)[start:end]))
        return ByteStats(b"", tally, end - start)

    def _region(
        self, stat: Callable[[ByteStats], Any], *, in_order: bool = False
    ) -> Callable[[int, int], Any]:
        """`stat` over a region. A statistic that reads only the tally is answered from the kept
        one; one that reads the bytes in order (`in_order`) reads them, as before."""

        def over(offset: int, length: int) -> Any:
            if in_order:
                run = Region.of(self.data, offset, length)
                return None if run is None else stat(ByteStats(run))
            span = Region.span(self.data, offset, length)
            return None if span is None else stat(self.tallied(span))

        return over

    def _run(self, offset: int | None, length: int | None) -> bytes | None:
        return self.data if offset is None else Region.of(self.data, offset, length or 0)

    def count(self, byte: int, offset: int | None = None, length: int | None = None) -> Any:
        run = self._run(offset, length)
        if not 0 <= byte <= 255 or run is None:
            return None
        return run.count(bytes([byte]))

    def percentage(self, byte: int, offset: int | None = None, length: int | None = None) -> Any:
        """The share of `byte` in the run, in single precision."""
        run = self._run(offset, length)
        if not 0 <= byte <= 255 or run is None:
            return None
        hits = Arith.single(float(run.count(bytes([byte]))))
        return Arith.single(Arith.divide(hits, Arith.single(float(len(run)))))

    def mode(self, offset: int | None = None, length: int | None = None) -> Any:
        if offset is None:
            span: tuple[int, int] | None = (0, len(self.data))
            if not self.data:
                return ByteStats(b"").most_common()
        else:
            span = Region.span(self.data, offset, length or 0)
        return None if span is None else self.tallied(span).most_common()

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
        return None

    def values(self) -> dict[str, Any]:
        region = self._region

        def per_text(stat: Callable[[ByteStats], Any]) -> Callable[[bytes], Any]:
            return lambda s: stat(ByteStats(s))

        return {
            "MEAN_BYTES": 127.5,
            "entropy": (region(ByteStats.entropy), per_text(ByteStats.entropy)),
            "mean": (region(ByteStats.mean), per_text(ByteStats.mean_in_order)),
            "serial_correlation": (
                region(ByteStats.serial_correlation, in_order=True),
                per_text(ByteStats.serial_correlation),
            ),
            "monte_carlo_pi": (
                region(ByteStats.pi_error, in_order=True),
                per_text(ByteStats.pi_error),
            ),
            "deviation": (
                lambda o, n, c: region(lambda b: b.deviation(c))(o, n),
                lambda s, c: ByteStats(s).deviation_in_order(c),
            ),
            "in_range": (lambda v, lo, hi: int(lo <= v <= hi),),
            "min": (MathModule.smaller,),
            "max": (MathModule.larger,),
            "abs": (MathModule.magnitude,),
            "to_number": (lambda b: int(bool(b)),),
            "count": (self.count, self.count),
            "percentage": (self.percentage, self.percentage),
            "mode": (self.mode, self.mode),
            "to_string": (MathModule.text_of, MathModule.text_of),
        }


class HashModule:
    """`hash`: digests and checksums of a data region or a string, digests in lower-case hex."""

    NAMES: ClassVar[tuple[str, ...]] = ("md5", "sha1", "sha256")
    SCHEMA: ClassVar[Record] = Record(
        {
            **{n: Call(Sig(("int", "int"), TEXT), Sig(("text",), TEXT)) for n in NAMES},
            **{
                n: Call(Sig(("int", "int"), INT), Sig(("text",), INT))
                for n in ("crc32", "checksum32")
            },
        }
    )

    def __init__(self, data: bytes) -> None:
        self.data = data
        #: Each region's result, by (function, clamped span), for this file.
        self.results = Kept()

    def _both(self, name: str, of: Callable[[bytes], Any]) -> tuple[Callable[..., Any], ...]:
        """`of` over a region of the file, kept by the region's span; over a string, worked out
        each time (a string is not a region of the file)."""

        def over(offset: int, length: int) -> Any:
            span = Region.span(self.data, offset, length)
            if span is None:
                return None
            start, end = span
            return self.results.get((name, span), lambda: of(self.data[start:end]))

        return (over, of)

    def values(self) -> dict[str, Any]:
        def digest(name: str) -> tuple[Callable[..., Any], ...]:
            return self._both(name, lambda b: hashlib.new(name, b).hexdigest().encode())

        return {
            **{n: digest(n) for n in HashModule.NAMES},
            "crc32": self._both("crc32", lambda b: zlib.crc32(b) & 0xFFFFFFFF),
            "checksum32": self._both("checksum32", lambda b: sum(b) & 0xFFFFFFFF),
        }


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

    SCHEMA: ClassVar[Record] = Record(
        {
            "to_int": Call(Sig(("text",), INT), Sig(("text", "int"), INT)),
            "length": Call(Sig(("text",), INT)),
        }
    )

    @staticmethod
    def to_int(s: bytes, base: int = 0) -> Any:
        if not (base == 0 or 2 <= base <= 36):
            return None
        return Integers.parse(s, base)

    @staticmethod
    def values() -> dict[str, Any]:
        return {"to_int": (StringModule.to_int, StringModule.to_int), "length": (len,)}


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

    SCHEMA: ClassVar[Record] = Record(
        {
            "log": Call(
                Sig(("text",), INT),
                Sig(("text", "text"), INT),
                Sig(("int",), INT),
                Sig(("text", "int"), INT),
                Sig(("float",), INT),
                Sig(("text", "float"), INT),
            ),
            "hex": Call(Sig(("int",), INT), Sig(("text", "int"), INT)),
        }
    )

    def values(self) -> dict[str, Any]:
        say, lead, shown = self.emit, ConsoleModule.lead, ConsoleModule.shown

        def as_int(i: int) -> str:
            return str(Data.signed(i))

        def as_hex(i: int) -> str:
            return f"0x{i & INT64_BITS:x}"

        return {
            "log": (
                lambda s: say(shown(s)),
                lambda m, s: say(lead(m) + shown(s)),
                lambda i: say(as_int(i)),
                lambda m, i: say(lead(m) + as_int(i)),
                lambda x: say(f"{float(x):f}"),
                lambda m, x: say(lead(m) + f"{float(x):f}"),
            ),
            "hex": (lambda i: say(as_hex(i)), lambda m, i: say(lead(m) + as_hex(i))),
        }


class Builtin:
    """The modules every install has, as the engine loads them."""

    TIME: ClassVar[Record] = Record({"now": Call(Sig((), INT))})

    @staticmethod
    def console(sink: Callable[[str], Any] | None = None) -> Module:
        """`console`, handing each message to `sink`."""
        return Module(ConsoleModule.SCHEMA, lambda file: ConsoleModule(sink).values())

    @staticmethod
    def with_data() -> dict[str, Callable[[bytes], Module]]:
        """The modules that read data given to the scan (a sandbox report, say), each built from
        that data; a module here answers without it too, as `modules()` holds it."""
        from cordon_scanner.detect.binary.modules.formats.androguard import Androguard
        from cordon_scanner.detect.binary.modules.reports.cuckoo import Cuckoo
        from cordon_scanner.detect.binary.modules.reports.vt import Vt

        return {"cuckoo": Cuckoo.module, "vt": Vt.module, "androguard": Androguard.module}

    @staticmethod
    def modules() -> dict[str, Module]:
        from cordon_scanner.detect.binary.modules.dotnet import Dotnet
        from cordon_scanner.detect.binary.modules.elf import Elf
        from cordon_scanner.detect.binary.modules.file_type import FileType
        from cordon_scanner.detect.binary.modules.formats.androguard import Androguard
        from cordon_scanner.detect.binary.modules.formats.crx import Crx
        from cordon_scanner.detect.binary.modules.formats.dex import Dex
        from cordon_scanner.detect.binary.modules.formats.lnk import Lnk
        from cordon_scanner.detect.binary.modules.formats.macho import Macho
        from cordon_scanner.detect.binary.modules.formats.msi import Msi
        from cordon_scanner.detect.binary.modules.formats.olecf import Olecf
        from cordon_scanner.detect.binary.modules.formats.vba import Vba
        from cordon_scanner.detect.binary.modules.formats.zip import Zip
        from cordon_scanner.detect.binary.modules.pe import Pe
        from cordon_scanner.detect.binary.modules.reports.cuckoo import Cuckoo
        from cordon_scanner.detect.binary.modules.reports.vt import Vt
        from cordon_scanner.detect.binary.modules.scanner_facts.js import Js
        from cordon_scanner.detect.binary.modules.scanner_facts.package import Package
        from cordon_scanner.detect.binary.modules.scanner_facts.python import Python

        return {
            "math": Module(MathModule.SCHEMA, lambda file: MathModule(file).values()),
            "hash": Module(HashModule.SCHEMA, lambda file: HashModule(file).values()),
            "string": Module(StringModule.SCHEMA, lambda file: StringModule.values()),
            "time": Module(Builtin.TIME, lambda file: {"now": (lambda: int(time.time()),)}),
            "console": Builtin.console(),
            "pe": Module(Pe.SCHEMA, Pe.data),
            "elf": Module(Elf.SCHEMA, Elf.data),
            "dotnet": Module(Dotnet.SCHEMA, Dotnet.data),
            "lnk": Module(Lnk.SCHEMA, Lnk.data),
            "zip": Module(Zip.SCHEMA, Zip.data),
            "crx": Module(Crx.SCHEMA, Crx.data),
            # with no report given to the scan (`Rules.match(given=...)` gives one)
            "cuckoo": Cuckoo.module(),
            # without LiveHunt metadata: the enum constants, every field undefined
            "vt": Vt.module(),
            "magic": FileType.module(),
            "macho": Module(Macho.SCHEMA, Macho.data),
            "dex": Module(Dex.SCHEMA, Dex.data),
            "olecf": Module(Olecf.SCHEMA, Olecf.data),
            "msi": Module(Msi.SCHEMA, Msi.data),
            "vba": Module(Vba.SCHEMA, Vba.data),
            "androguard": Androguard.module(),
            # the scanner's facts: every field undefined until the rule file's deferred pass
            # gives each file its own (`scanner_facts`)
            "package": Package.EMPTY,
            "js": Js.EMPTY,
            "python": Python.EMPTY,
        }


__all__ = ["Builtin", "ByteStats", "Integers"]
