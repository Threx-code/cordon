"""Obfuscation reversed statically, so the rules read what the code does (review 98).

An obfuscated file was graded for being obfuscated: `SUSPECT.OBFUSCATION.PACKED.001` at HIGH,
whatever the code inside did. Benign packages ship obfuscated builds to protect a licence, and
malware ships them to hide a payload; the shape cannot tell them apart and what the code does can.
This module takes the common obfuscators apart without running anything -- no interpreter, no
`eval` -- and returns readable text the engine reads as a unit of its own
(`<file>#deobfuscated.js`), with the context of the file it came from.

    obfuscator.io (javascript-obfuscator)
        the string array, the decoder that indexes it (plain, base64 or rc4), and the rotation
        loop that shifts the array until a `parseInt` checksum equals a constant. The checksum is
        the oracle: the decoding mode and the rotation are right exactly when it matches, so a
        reversal verifies itself. Every call of the decoder, through any alias, becomes the
        string it returns; `x['prop']` becomes `x.prop`; `'a' + 'b'` becomes `'ab'`.

Bounded throughout: array size, rotations tried, text size. A file this cannot reverse is left as
it is, and its finding keeps its grade.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, ClassVar, Final, cast

MAX_TEXT: Final = 4 << 20
MAX_ARRAY: Final = 200_000
OBFUSCATOR_IO_ALPHABET: Final = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
STANDARD_ALPHABET: Final = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="


class IntegerLiteral:
    """An integer as source code writes it, including the legacy octal `05` that `int(_, 0)`
    refuses: Go reads a leading zero as octal, and so does sloppy-mode JavaScript unless an 8
    or 9 follows. Refusing it made one padded number enough to stop a decoder (and, in Go, to
    fail the capability detector on the whole file)."""

    @staticmethod
    def value(literal: str) -> int:
        digits = literal.strip().replace("_", "")
        if len(digits) > 1 and digits[0] == "0" and digits.isdigit():
            return int(digits, 8) if set(digits) <= set("01234567") else int(digits)
        return int(digits, 0)


@dataclass(frozen=True, slots=True)
class Recovery:
    text: str
    technique: str
    resolved: int
    """Decoder calls replaced by their string."""
    remaining: int
    """Decoder calls left, because their arguments were not literals."""


class JsLiterals:
    """JavaScript string literals, read without an interpreter."""

    _ESCAPE: ClassVar[re.Pattern[str]] = re.compile(
        r"\\(x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|u[0-9a-fA-F]{4}|[0-7]{1,3}|\r\n|[\s\S])"
    )
    _SIMPLE: ClassVar[dict[str, str]] = {
        "n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "\n": "", "\r\n": "",
    }  # fmt: skip

    @classmethod
    def unescape(cls, body: str) -> str:
        def one(match: re.Match[str]) -> str:
            code = match.group(1)
            if code[0] == "x":
                return chr(int(code[1:], 16))
            if code.startswith("u{"):
                return chr(min(int(code[2:-1], 16), 0x10FFFF))
            if code[0] == "u" and len(code) == 5:
                return chr(int(code[1:], 16))
            if code[0] in "01234567":
                return chr(int(code, 8)) if code != "0" else "\0"
            return cls._SIMPLE.get(code, code)

        return cls._ESCAPE.sub(one, body)

    @staticmethod
    def quote(value: str) -> str:
        """A single-quoted literal for `value`, as a reader would write it."""
        out = []
        for char in value:
            if char in "\\'":
                out.append("\\" + char)
            elif char == "\n":
                out.append("\\n")
            elif char == "\r":
                out.append("\\r")
            elif ord(char) < 0x20 or 0x7F <= ord(char) < 0xA0:
                out.append(f"\\x{ord(char):02x}")
            else:
                out.append(char)
        return "'" + "".join(out) + "'"

    @classmethod
    def array(cls, text: str, start: int) -> tuple[list[str], int] | None:
        """The string elements of the array literal opening at `text[start] == '['`, and the
        index after its `]`; None when an element is not a string literal."""
        values: list[str] = []
        index = start + 1
        length = len(text)
        while index < length:
            while index < length and text[index] in " \t\r\n,":
                index += 1
            if index >= length:
                return None
            char = text[index]
            if char == "]":
                return values, index + 1
            if char not in "'\"`":
                return None
            end = index + 1
            while end < length and text[end] != char:
                if text[end] == "\\":
                    end += 1
                elif char == "`" and text.startswith("${", end):
                    return None
                end += 1
            if end >= length:
                return None
            values.append(cls.unescape(text[index + 1 : end]))
            if len(values) > MAX_ARRAY:
                return None
            index = end + 1
        return None


class Checksum:
    """The rotation loop's expression: `-parseInt(f(0x1a9))/0x1*(-parseInt(f(0x194))/0x2)+...`,
    evaluated with JavaScript's number semantics and nothing else."""

    _NUMBER: ClassVar[re.Pattern[str]] = re.compile(
        r"\s*(0x[0-9a-fA-F]+|\d+(?:\.\d+)?(?:e[+-]?\d+)?)"
    )
    _CALL_HEAD: ClassVar[re.Pattern[str]] = re.compile(r"\s*parseInt\s*\(\s*([\w$]+)\s*\(")
    _OP: ClassVar[re.Pattern[str]] = re.compile(r"\s*([-+*/()])")

    def __init__(self, expression: str, *, calls: bool = True) -> None:
        self.tokens: list[tuple[str, object]] = []
        position = 0
        length = len(expression)
        while position < length:
            if not expression[position:].strip():
                break
            head = self._CALL_HEAD.match(expression, position) if calls else None
            if head is not None:
                close = Checksum.closing(expression, head.end() - 1)
                if close is None:
                    raise ValueError("unbalanced call")
                args = tuple(
                    Checksum.literal(a) for a in Checksum.split_args(expression[head.end() : close])
                )
                after = re.match(r"\s*\)", expression[close + 1 :])
                if after is None:
                    raise ValueError("not parseInt(call)")
                self.tokens.append(("call", (head.group(1), args)))
                position = close + 1 + after.end()
                continue
            number = self._NUMBER.match(expression, position)
            if number is not None:
                text = number.group(1)
                self.tokens.append(
                    ("num", float(int(text, 16)) if text.startswith("0x") else float(text))
                )
                position = number.end()
                continue
            op = self._OP.match(expression, position)
            if op is None:
                raise ValueError("not a checksum")
            self.tokens.append(("op", op.group(1)))
            position = op.end()

    @staticmethod
    def closing(text: str, opening: int) -> int | None:
        """The index of the `)` matching the `(` at `opening`, skipping string literals."""
        depth = 0
        index = opening
        while index < len(text):
            char = text[index]
            if char in "'\"`":
                end = index + 1
                while end < len(text) and text[end] != char:
                    end += 2 if text[end] == "\\" else 1
                index = end
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return index
            index += 1
        return None

    @staticmethod
    def split_args(text: str) -> list[str]:
        out, depth, start, index = [], 0, 0, 0
        while index < len(text):
            char = text[index]
            if char in "'\"`":
                end = index + 1
                while end < len(text) and text[end] != char:
                    end += 2 if text[end] == "\\" else 1
                index = end
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            elif char == "," and depth == 0:
                out.append(text[start:index])
                start = index + 1
            index += 1
        out.append(text[start:])
        return [a for a in out if a.strip()]

    @staticmethod
    def literal(text: str) -> float | str:
        """A call argument: a string literal, or a numeric expression."""
        raw = text.strip()
        if len(raw) >= 2 and raw[0] in "'\"" and raw[-1] == raw[0]:
            return JsLiterals.unescape(raw[1:-1])
        return Checksum.number(raw)

    @staticmethod
    def number(text: str) -> float:
        """A numeric expression with no calls -- `0x1a2` or `-0x32a+-0xe3*-0x19+0x1300`."""
        value = Checksum(text, calls=False).value(lambda fn, args: None)
        if math.isnan(value) or math.isinf(value):
            raise ValueError("not a finite number")
        return value

    @property
    def calls(self) -> list[tuple[str, tuple[float | str, ...]]]:
        return [value for kind, value in self.tokens if kind == "call"]  # type: ignore[misc]

    def value(self, lookup: Callable[[str, tuple[float | str, ...]], str | None]) -> float:
        self._at = 0
        self._lookup = lookup
        result = self._sum()
        if self._at != len(self.tokens):
            raise ValueError("trailing tokens")
        return result

    def _peek(self) -> tuple[str, Any] | None:
        return self.tokens[self._at] if self._at < len(self.tokens) else None

    def _sum(self) -> float:
        total = self._product()
        while (token := self._peek()) and token[0] == "op" and token[1] in "+-":
            self._at += 1
            right = self._product()
            total = total + right if token[1] == "+" else total - right
        return total

    def _product(self) -> float:
        total = self._unary()
        while (token := self._peek()) and token[0] == "op" and token[1] in "*/":
            self._at += 1
            right = self._unary()
            if token[1] == "*":
                total = total * right
            elif right == 0:
                total = (
                    math.nan
                    if total == 0 or math.isnan(total)
                    else math.copysign(math.inf, total) * math.copysign(1, right)
                )
            else:
                total = total / right
        return total

    def _unary(self) -> float:
        token = self._peek()
        if token and token[0] == "op" and token[1] in "+-":
            self._at += 1
            value = self._unary()
            return -value if token[1] == "-" else value
        return self._atom()

    def _atom(self) -> float:
        token = self._peek()
        if token is None:
            raise ValueError("unexpected end")
        self._at += 1
        kind, value = token
        if kind == "num":
            return cast(float, value)
        if kind == "call":
            fn, args = value
            return self.parse_int(self._lookup(fn, args) or "")
        if value == "(":
            inner = self._sum()
            closing = self._peek()
            if closing != ("op", ")"):
                raise ValueError("unbalanced")
            self._at += 1
            return inner
        raise ValueError("unexpected token")

    @staticmethod
    def parse_int(text: str) -> float:
        """`parseInt(text)` with no radix."""
        match = re.match(r"\s*([+-]?)(0[xX][0-9a-fA-F]+|\d+)", text)
        if match is None:
            return math.nan
        sign = -1.0 if match.group(1) == "-" else 1.0
        digits = match.group(2)
        return sign * float(int(digits, 16) if digits[:2].lower() == "0x" else int(digits))


class Resolver:
    """Calls of the decoder, through every wrapper and alias, resolved to the strings they return.

    A wrapper is a function whose body is one `return` of another call: `function W(a, b, c, d) {
    return D(c - -0x2b, a); }`. Its arguments are expressions over its parameters, evaluated with
    the caller's literal arguments substituted in."""

    MAX_DEPTH: ClassVar[int] = 12

    def __init__(
        self,
        decoder: str,
        offset: int,
        mode: str,
        values: list[str],
        wrappers: dict[str, tuple[list[str], str, list[str]]],
    ) -> None:
        self.decoder = decoder
        self.offset = offset
        self.mode = mode
        self.values = values
        self.wrappers = wrappers

    def names(self) -> set[str]:
        return {self.decoder, *self.wrappers}

    def resolve(self, fn: str, args: tuple[float | str, ...], depth: int = 0) -> str | None:
        if depth > self.MAX_DEPTH:
            return None
        if fn == self.decoder:
            if not args or isinstance(args[0], str):
                return None
            position = int(args[0]) - self.offset
            if not 0 <= position < len(self.values):
                return None
            key = args[1] if len(args) > 1 else None
            return ObfuscatorIo.decode(self.values[position], self.mode, key)
        wrapper = self.wrappers.get(fn)
        if wrapper is None:
            return None
        params, callee, expressions = wrapper
        if not params and not expressions:
            return self.resolve(callee, args, depth + 1)
        env = dict(zip(params, args, strict=False))
        forwarded: list[float | str] = []
        for expression in expressions:
            value = Resolver.evaluate(expression, env)
            if value is None:
                return None
            forwarded.append(value)
        return self.resolve(callee, tuple(forwarded), depth + 1)

    @staticmethod
    def evaluate(expression: str, env: dict[str, float | str]) -> float | str | None:
        raw = expression.strip()
        if raw in env:
            return env[raw]
        if len(raw) >= 2 and raw[0] in "'\"" and raw[-1] == raw[0]:
            return JsLiterals.unescape(raw[1:-1])

        def bound(match: re.Match[str]) -> str:
            value = env.get(match.group(0))
            if value is None or isinstance(value, str):
                raise ValueError("unbound or string")
            return f"({value!r})"

        try:
            numeric = re.sub(r"(?<![\w$])[A-Za-z_$][\w$]*", bound, raw)
            return Checksum.number(numeric.replace("inf", "Infinity"))
        except ValueError:
            return None


class ObfuscatorIo:
    """javascript-obfuscator's string array, reversed. See the module docstring."""

    _ARRAY_FUNCTION: ClassVar[re.Pattern[str]] = re.compile(
        r"function\s+(?P<name>[\w$]+)\s*\(\s*\)\s*\{\s*(?:const|var|let)\s+[\w$]+\s*=\s*\["
    )
    _DECODER: ClassVar[re.Pattern[str]] = re.compile(
        r"function\s+(?P<name>[\w$]+)\s*\(\s*(?P<index>[\w$]+)\s*,\s*[\w$]+\s*\)\s*\{"
    )
    _OFFSET: ClassVar[re.Pattern[str]] = re.compile(
        r"(?P<var>[\w$]{1,60})\s{0,4}=\s{0,4}(?P<again>[\w$]{1,60})\s{0,4}-\s{0,4}"
        r"(?P<offset>\(?[-+*/\s0-9a-fA-Fx]{1,200}?\)?)\s{0,4}[;,]"
    )
    _ROTATION: ClassVar[re.Pattern[str]] = re.compile(
        r"while\s*\(\s*!!\[\]\s*\)\s*\{\s*try\s*\{\s*(?:const|var|let)\s+[\w$]+\s*=\s*(?P<expr>[^;]{1,8000});"
        r"\s*if\s*\(\s*[\w$]+\s*===\s*[\w$]+\s*\)\s*break[\s\S]{0,400}?\}\s*\}\s*\}?\s*\(\s*(?P<array>[\w$]+)\s*,\s*(?P<target>[-+*/()\s0-9a-fA-Fx.]{1,400}?)\s*\)\s*\)?\s*[;,]"
    )
    _WRAPPER: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:function\s+(?P<fname>[\w$]+)|(?:const|var|let)\s+(?P<vname>[\w$]+)\s*=\s*function)\s*"
        r"\((?P<params>[\w$,\s]{0,200})\)\s*\{\s*return\s+(?P<callee>[\w$]+)\s*\("
    )
    _ALIAS: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:\b(?:const|var|let)\s+|,\s*)([\w$]+)\s*=\s*([\w$]+)\s*(?=[,;)])"
    )
    _CONSTANT_OBJECT: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:const|var|let)\s+([\w$]+)\s*=\s*\{"
    )
    _ENTRY: ClassVar[re.Pattern[str]] = re.compile(
        r"\s{0,8}(?:'(?P<q>[\w$]{1,80})'|\"(?P<d>[\w$]{1,80})\"|(?P<i>[\w$]{1,80}))\s{0,4}:\s{0,4}"
        r"(?P<v>'[^'\\\n]{0,2000}'|\"[^\"\\\n]{0,2000}\"|[-+*/()\s0-9a-fA-Fx]{1,120}?)\s{0,8}(?=[,}])"
    )

    @classmethod
    def applies(cls, text: str) -> bool:
        return "while(!![])" in text.replace(" ", "") and bool(cls._ARRAY_FUNCTION.search(text))

    @classmethod
    def recover(cls, text: str) -> Recovery | None:
        if len(text) > MAX_TEXT or not cls.applies(text):
            return None
        text = cls.fold_constant_objects(text)
        arrays: dict[str, list[str]] = {}
        for match in cls._ARRAY_FUNCTION.finditer(text):
            parsed = JsLiterals.array(text, match.end() - 1)
            if parsed is not None and parsed[0]:
                arrays[match.group("name")] = parsed[0]
        if not arrays:
            return None
        wrappers = cls.wrappers(text)
        for rotation in cls._ROTATION.finditer(text):
            array_name = rotation.group("array")
            if array_name not in arrays:
                continue
            try:
                target = Checksum.number(rotation.group("target").rstrip(") \t\n"))
                checksum = Checksum(rotation.group("expr"))
            except ValueError:
                continue
            for decoder_name, offset in cls._decoders_for(text, array_name)[:6]:
                solved = cls._solve(
                    arrays[array_name], decoder_name, offset, wrappers, checksum, target
                )
                if solved is not None:
                    return cls._substitute(text, solved)
        return None

    @classmethod
    def fold_constant_objects(cls, text: str) -> str:
        """`const o = {_0xa: 0x2a3, _0xb: 'k'}` ... `f(o._0xa)` becomes `f(0x2a3)`."""
        constants: dict[str, str] = {}
        for match in cls._CONSTANT_OBJECT.finditer(text):
            name = match.group(1)
            position = match.end()
            entries: dict[str, str] = {}
            while True:
                entry = cls._ENTRY.match(text, position)
                if entry is None:
                    break
                key = entry.group("q") or entry.group("d") or entry.group("i")
                entries[key] = entry.group("v").strip()
                position = entry.end()
                if text.startswith(",", position):
                    position += 1
                    continue
                break
            if entries and re.match(r"\s*\}", text[position:]):
                for key, value in entries.items():
                    constants[f"{name}.{key}"] = value
        if not constants:
            return text
        owners = {key.split(".", 1)[0] for key in constants}
        pattern = re.compile(
            r"(?<![\w$.])(" + "|".join(re.escape(o) for o in sorted(owners)) + r")"
            r"(?:\.([\w$]+)|\[\s*'([\w$]+)'\s*\])"
        )

        def one(match: re.Match[str]) -> str:
            key = f"{match.group(1)}.{match.group(2) or match.group(3)}"
            value = constants.get(key)
            return (
                f"({value})"
                if value is not None and not value.startswith(("'", '"'))
                else value or match.group(0)
            )

        return pattern.sub(one, text)

    @classmethod
    def wrappers(cls, text: str) -> dict[str, tuple[list[str], str, list[str]]]:
        found: dict[str, tuple[list[str], str, list[str]]] = {}
        for match in cls._WRAPPER.finditer(text):
            name = match.group("fname") or match.group("vname")
            opening = match.end() - 1
            close = Checksum.closing(text, opening)
            if close is None or not re.match(r"\s*;?\s*\}", text[close + 1 :]):
                continue
            params = [p.strip() for p in match.group("params").split(",") if p.strip()]
            found[name] = (
                params,
                match.group("callee"),
                Checksum.split_args(text[opening + 1 : close]),
            )
        for _ in range(8):
            grown = False
            for alias in cls._ALIAS.finditer(text):
                name, target = alias.group(1), alias.group(2)
                if name not in found and name != target:
                    # An alias forwards whatever it is given.
                    found[name] = ([], target, [])
                    grown = True
            if not grown:
                break
        return found

    @classmethod
    def _decoders_for(cls, text: str, array_name: str) -> list[tuple[str, int]]:
        """Every function that reads the array and subtracts an offset from an index: more than
        one can, and the checksum decides which is the decoder."""
        found: list[tuple[str, int]] = []
        for match in cls._DECODER.finditer(text):
            body = text[match.end() : match.end() + 6000]
            if not re.search(rf"(?<![\w$]){re.escape(array_name)}\s*\(\s*\)", body[:1500]):
                continue
            offset = next(
                (
                    m
                    for m in cls._OFFSET.finditer(body[:1500])
                    if m.group("var") == m.group("again")
                ),
                None,
            )
            if offset is None:
                continue
            try:
                found.append((match.group("name"), int(Checksum.number(offset.group("offset")))))
            except ValueError:
                continue
        return found

    @classmethod
    def _solve(
        cls,
        values: list[str],
        decoder: str,
        offset: int,
        wrappers: dict[str, tuple[list[str], str, list[str]]],
        checksum: Checksum,
        target: float,
    ) -> Resolver | None:
        if not checksum.calls:
            return None
        size = len(values)
        for mode in ("plain", "base64", "rc4"):
            for shift in range(size):
                resolver = Resolver(
                    decoder, offset, mode, values[shift:] + values[:shift], wrappers
                )
                try:
                    if checksum.value(resolver.resolve) == target:
                        return resolver
                except ValueError:
                    return None
        return None

    @staticmethod
    def _base64(raw: str) -> bytes | None:
        """obfuscator.io's base64: its own alphabet (lowercase first), padding ignored."""
        table = str.maketrans(OBFUSCATOR_IO_ALPHABET[:64], STANDARD_ALPHABET[:64])
        body = raw.translate(table).rstrip("=")
        try:
            return base64.b64decode(body + "=" * (-len(body) % 4))
        except (ValueError, binascii.Error):
            return None

    @classmethod
    def decode(cls, raw: str, mode: str, key: object) -> str | None:
        if mode == "plain":
            return raw
        data = cls._base64(raw)
        if data is None:
            return None
        if mode == "base64":
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return None
        # rc4: the base64 step ends in `decodeURIComponent`, and rc4 runs over the characters
        # that yields; the key is the call's second argument.
        if not isinstance(key, str) or not key:
            return None
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
        state = list(range(256))
        j = 0
        for i in range(256):
            j = (j + state[i] + ord(key[i % len(key)])) % 256
            state[i], state[j] = state[j], state[i]
        i = j = 0
        out = []
        for char in text:
            i = (i + 1) % 256
            j = (j + state[i]) % 256
            state[i], state[j] = state[j], state[i]
            out.append(chr(ord(char) ^ state[(state[i] + state[j]) % 256]))
        return "".join(out)

    _PROPERTY: ClassVar[re.Pattern[str]] = re.compile(r"\[\s*'([A-Za-z_$][\w$]*)'\s*\]")
    _CONCAT: ClassVar[re.Pattern[str]] = re.compile(
        r"'([^'\\\n]{0,4000})'\s{0,4}\+\s{0,4}'([^'\\\n]{0,4000})'"
    )

    @classmethod
    def _substitute(cls, text: str, resolver: Resolver) -> Recovery:
        names = resolver.names()
        head = re.compile(
            r"(?<![\w$.])("
            + "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
            + r")\s*\("
        )
        out: list[str] = []
        position = resolved = remaining = 0
        for match in head.finditer(text):
            if match.start() < position:
                continue
            close = Checksum.closing(text, match.end() - 1)
            if close is None:
                continue
            try:
                args = tuple(
                    Checksum.literal(a) for a in Checksum.split_args(text[match.end() : close])
                )
            except ValueError:
                remaining += 1
                continue
            value = resolver.resolve(match.group(1), args)
            if value is None:
                remaining += 1
                continue
            out.append(text[position : match.start()])
            out.append(JsLiterals.quote(value))
            position = close + 1
            resolved += 1
        out.append(text[position:])
        result = "".join(out)
        result = re.sub(r"\?\.\[\s*'([A-Za-z_$][\w$]*)'\s*\]", r"?.\1", result)
        result = cls._PROPERTY.sub(lambda m: "." + m.group(1), result)
        for _ in range(8):
            folded = cls._CONCAT.sub(lambda m: "'" + m.group(1) + m.group(2) + "'", result)
            if folded == result:
                break
            result = folded
        return Recovery(result, "obfuscator.io", resolved, remaining)


class Layers:
    """The layer under a layer: a program carried as data and decoded before it runs.

        invisible       a run of tag characters (U+E0000-E007F) or variation selectors
                        (U+FE00-FE0F, U+E0100-E01EF), one byte per character -- the way a payload
                        is written into a file so that nothing on screen shows it
        static decode   `atob('...')`, `Buffer.from('...', 'base64'|'hex')`,
                        `String.fromCharCode(n, ...)`, `'...'.split('').reverse().join('')`,
                        each with literal arguments only

    A decoded layer is kept only when it reads as text (printable, mostly), and is appended to
    what is read, marked, so the rules see the program the file carries. Nothing is run.
    """

    MAX_LAYERS: ClassVar[int] = 4
    MAX_LAYER: ClassVar[int] = 1 << 20

    _INVISIBLE_RUN: ClassVar[re.Pattern[str]] = re.compile(
        "[\U000e0000-\U000e007f\ufe00-\ufe0f\U000e0100-\U000e01ef]{16,}"
    )
    _ATOB: ClassVar[re.Pattern[str]] = re.compile(
        r"\batob\s{0,4}\(\s{0,4}['\"`](?P<b>[A-Za-z0-9+/=\s]{16,200000})['\"`]\s{0,4}\)"
    )
    _BUFFER: ClassVar[re.Pattern[str]] = re.compile(
        r"\bBuffer\s{0,4}\.\s{0,4}from\s{0,4}\(\s{0,4}['\"`](?P<b>[A-Za-z0-9+/=_\-\s]{16,200000})['\"`]"
        r"\s{0,4},\s{0,4}['\"](?P<enc>base64|base64url|hex)['\"]\s{0,4}\)"
    )
    _CHAR_CODES: ClassVar[re.Pattern[str]] = re.compile(
        r"\bString\s{0,4}\.\s{0,4}fromCharCode\s{0,4}\(\s{0,4}"
        r"(?P<n>[0-9a-fA-Fx]{1,8}\s{0,4},[0-9a-fA-Fx,\s]{13,200000})"
        r"\s{0,4}\)"
    )
    _REVERSED: ClassVar[re.Pattern[str]] = re.compile(
        r"['\"](?P<s>[^'\"\n]{16,200000})['\"]\s{0,4}\.\s{0,4}split\s{0,4}\(\s{0,4}['\"]['\"]\s{0,4}\)"
        r"\s{0,4}\.\s{0,4}reverse\s{0,4}\(\s{0,4}\)\s{0,4}\.\s{0,4}join\s{0,4}\(\s{0,4}['\"]['\"]\s{0,4}\)"
    )

    @staticmethod
    def _readable(text: str) -> bool:
        if len(text) < 8:
            return False
        printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
        return printable / len(text) > 0.9

    @classmethod
    def _invisible(cls, run: str) -> str:
        out = bytearray()
        for char in run:
            code = ord(char)
            if 0xE0000 <= code <= 0xE007F:
                out.append(code - 0xE0000)
            elif 0xFE00 <= code <= 0xFE0F:
                out.append(code - 0xFE00)
            elif 0xE0100 <= code <= 0xE01EF:
                out.append(code - 0xE0100 + 16)
        return out.decode("utf-8", "replace")

    @classmethod
    def decoded(cls, text: str) -> list[tuple[str, str]]:
        """(how, plaintext) for each layer this text carries, one level down."""
        found: list[tuple[str, str]] = []
        for match in cls._INVISIBLE_RUN.finditer(text):
            found.append(("invisible characters", cls._invisible(match.group(0))))
        for match in cls._ATOB.finditer(text):
            body = re.sub(r"\s", "", match.group("b"))
            try:
                found.append(
                    (
                        "atob",
                        base64.b64decode(body + "=" * (-len(body) % 4)).decode("utf-8", "replace"),
                    )
                )
            except ValueError:
                continue
        for match in cls._BUFFER.finditer(text):
            body = re.sub(r"\s", "", match.group("b"))
            try:
                if match.group("enc") == "hex":
                    data = bytes.fromhex(body)
                else:
                    data = base64.b64decode(
                        body.replace("-", "+").replace("_", "/") + "=" * (-len(body) % 4)
                    )
            except ValueError:
                continue
            found.append((f"Buffer.from {match.group('enc')}", data.decode("utf-8", "replace")))
        for match in cls._CHAR_CODES.finditer(text):
            try:
                found.append(
                    (
                        "fromCharCode",
                        "".join(
                            chr(IntegerLiteral.value(n))
                            for n in re.split(r"\s*,\s*", match.group("n"))
                        ),
                    )
                )
            except ValueError:
                continue
        for match in cls._REVERSED.finditer(text):
            found.append(("reversed string", match.group("s")[::-1]))
        return [(how, plain[: cls.MAX_LAYER]) for how, plain in found if cls._readable(plain)]

    @classmethod
    def peel(cls, text: str) -> tuple[str, int]:
        """The text with every layer under it appended, to `MAX_LAYERS` deep; and how many."""
        added: list[str] = []
        frontier = [text]
        seen: set[str] = set()
        for depth in range(cls.MAX_LAYERS):
            next_frontier: list[str] = []
            for body in frontier:
                for how, plain in cls.decoded(body):
                    if plain in seen:
                        continue
                    seen.add(plain)
                    added.append(
                        f"\n/* cordon: layer {depth + 2}, decoded from {how} */\n{plain}\n"
                    )
                    next_frontier.append(plain)
            if not next_frontier:
                break
            frontier = next_frontier
        return text + "".join(added), len(added)


class Deobfuscator:
    """Every reversal this module knows, tried in turn: the string array first, then the layers
    under it."""

    @staticmethod
    def recover(text: str, language: str | None) -> Recovery | None:
        if language not in ("javascript", "typescript"):
            return None
        recovery = ObfuscatorIo.recover(text)
        base = recovery.text if recovery is not None else text
        peeled, layers = Layers.peel(base)
        if recovery is None and not layers:
            return None
        if recovery is None:
            # Only what was decoded is new: the file itself is read as it is.
            return Recovery(peeled[len(base) :], "layers", layers, 0)
        return Recovery(peeled, recovery.technique, recovery.resolved + layers, recovery.remaining)
