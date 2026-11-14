"""Names and values built by a local decoder helper, folded to the strings they decode to (item 41).

A function whose whole body is one known decode of its parameter -- hex pairs,
`Buffer.from(_, 'hex'|'base64')`, `atob`, char codes, a reversed string -- is a decoder helper.
Each call over a literal is rewritten to the string it decodes to, so `require(g('6178696f73'))`
reads `require('axios')` and the existing flow rules judge the decoded names. The file's own code is
never run; the decode runs here, bounded (`DecoderHelpers.MAX_*`), and any bound hit or exception
leaves the file as it was (`recover` returns None).
"""

from __future__ import annotations

import base64
import binascii
import re
from bisect import bisect_right
from collections import Counter
from collections.abc import Callable
from typing import ClassVar

from cordon_scanner.analysis.shared.deobfuscation import (
    MAX_TEXT,
    Checksum,
    IntegerLiteral,
    JsLiterals,
    Recovery,
)


class DecoderHelpers:
    """A local function that is one known decode of its parameter, and its calls over literals.

    Recognised from tokens, never evaluated: the body must be exactly `return <decode of p>` (or
    `const s = <decode of p>; return s`), where the decode is one of `_FORMS`. Anything else is not
    a helper and its calls are left as they are, so what this adds is only what the code does.
    Composition (`g(k('...'))`) folds layer by layer, a layer per pass, to `MAX_PASSES`."""

    MAX_ARGUMENT: ClassVar[int] = 4096
    MAX_RESULT: ClassVar[int] = 4096
    MAX_FOLDS: ClassVar[int] = 4096
    MAX_DECODED: ClassVar[int] = 1 << 20
    MAX_PASSES: ClassVar[int] = 8
    MAX_HEADS: ClassVar[int] = 50_000
    MAX_BODY: ClassVar[int] = 600
    MAX_HELPERS: ClassVar[int] = 64
    _TOKENS: ClassVar[tuple[str, ...]] = ("fromCharCode", "Buffer", "atob", "reverse")
    """Without one of these no `_FORMS` decode can be in the file: most files pay four searches."""
    MAX_ARRAYS: ClassVar[int] = 256
    MAX_METHODS: ClassVar[int] = 10_000

    _P: ClassVar[str] = "\x00"
    _STRING: ClassVar[str] = r"""(?:'[^'\\\n]{0,4200}'|"[^"\\\n]{0,4200}")"""
    _QUOTE: ClassVar[str] = r"""['"]"""
    _KEYWORDS: ClassVar[frozenset[str]] = frozenset(
        {"if", "for", "while", "switch", "catch", "function", "return", "with", "typeof", "await"}
    )

    _FUNCTION: ClassVar[re.Pattern[str]] = re.compile(
        r"function\s+(?P<name>[\w$]+)\s*\(\s*(?P<param>[\w$]+)\s*\)\s*\{"
    )
    _FUNCTION_EXPRESSION: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:const|let|var)\s+(?P<name>[\w$]+)\s*=\s*function\b[\s\w$]{0,100}?"
        r"\(\s*(?P<param>[\w$]+)\s*\)\s*\{"
    )
    _ARROW: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:const|let|var)\s+(?P<name>[\w$]+)\s*=\s*(?:\(\s*(?P<p1>[\w$]+)\s*\)|(?P<p2>[\w$]+))\s*=>\s*"
    )
    _METHOD: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<=[{,])\s*(?P<name>[\w$]+)\s*\(\s*(?P<param>[\w$]+)\s*\)\s*\{"
    )
    _CONSTANT: ClassVar[re.Pattern[str]] = re.compile(
        rf"\bconst\s+(?P<name>[\w$]+)\s*=\s*(?P<value>{_STRING}|\[[-\w\s,]{{0,4200}}\])\s*(?=[;,\n])"
    )
    _LOCAL: ClassVar[re.Pattern[str]] = re.compile(r"(?:const|let|var) ([\w$]+)=")
    _CALL: ClassVar[re.Pattern[str]] = re.compile(r"(?<![\w$.])([\w$]+(?:\.[\w$]+)?)\s{0,8}\(")

    # (pattern over the normalised body expression with the parameter as \x00, decoder name)
    _FORMS: ClassVar[tuple[tuple[re.Pattern[str], str], ...]] = (
        (
            re.compile(
                r"^\x00\.replace\(/(?:\.\.|\[0-9a-fA-F\]\{2\}|\[0-9a-f\]\{2\})/g,"
                r"(?:\(?(?P<a>[\w$]+)\)?=>String\.fromCharCode\(parseInt\((?P=a),16\)\)"
                r"|function\((?P<b>[\w$]+)\)\{return String\.fromCharCode\(parseInt\((?P=b),16\)\);?\})\)$"
            ),
            "hex_pairs",
        ),
        (
            re.compile(
                r"^\x00\.match\(/(?:\.\.|\[0-9a-fA-F\]\{2\})/g\)\.map\(\(?(?P<a>[\w$]+)\)?"
                r"=>String\.fromCharCode\(parseInt\((?P=a),16\)\)\)\.join\("
                + _QUOTE
                + _QUOTE
                + r"\)$"
            ),
            "hex_pairs",
        ),
        (
            re.compile(
                r"^Buffer\.from\(\x00,(?P<q>['\"])(?P<enc>hex|base64|base64url)(?P=q)\)"
                r"\.toString\((?:['\"]utf-?8['\"])?\)$"
            ),
            "buffer",
        ),
        (re.compile(r"^atob\(\x00\)$"), "atob"),
        (re.compile(r"^String\.fromCharCode\(\.\.\.\x00\)$"), "char_codes"),
        (
            re.compile(
                r"^\x00\.map\(\(?(?P<a>[\w$]+)\)?=>String\.fromCharCode\((?P=a)\)\)\.join\("
                + _QUOTE
                + _QUOTE
                + r"\)$"
            ),
            "char_codes",
        ),
        (
            re.compile(
                r"^\x00\.split\("
                + _QUOTE
                + _QUOTE
                + r"\)\.reverse\(\)\.join\("
                + _QUOTE
                + _QUOTE
                + r"\)$"
            ),
            "reverse",
        ),
    )

    @classmethod
    def recover(cls, text: str) -> Recovery | None:
        if len(text) > MAX_TEXT:
            return None
        try:
            return cls._recover(text)
        except (ValueError, RecursionError, MemoryError):
            # S2: a fallback; the next reader (or SOURCE.UNPARSED for running files) reads it
            return None

    @classmethod
    def _recover(cls, text: str) -> Recovery | None:
        if not any(token in text for token in cls._TOKENS):
            return None
        helpers, spans = cls.helpers(text)
        if not helpers:
            return None
        constants = cls._constants(text)
        folds = decoded = remaining = 0
        current = text
        for _ in range(cls.MAX_PASSES):
            current, count, size, remaining = cls._pass(current, helpers, constants, spans)
            folds += count
            decoded += size
            if folds > cls.MAX_FOLDS or decoded > cls.MAX_DECODED:
                return None
            if count == 0 or remaining == 0:
                break
            helpers, spans = cls.helpers(current)
            constants = cls._constants(current)
        if folds == 0:
            return None
        return Recovery(cls._indexed(current), "decoder helper", folds, remaining)

    _ARRAY_CONSTANT: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:const)\s+(?P<name>[\w$]+)\s*=\s*\["
    )
    _KEY_ARRAY: ClassVar[re.Pattern[str]] = re.compile(r"\[\s*\[\s*('[^'\\\n]{0,4200}')\s*\]\s*\]")

    @classmethod
    def _indexed(cls, text: str) -> str:
        """`hl[1]` of a `const hl = ['a', 'b']` becomes `'b'`, and `[['b']]` becomes `['b']`.

        The folded names sit in an array and are read by index, as the sample does; the flow rules
        follow a literal, not a binding. Only a once-declared `const` array of string literals."""
        arrays: dict[str, list[str]] = {}
        for match in cls._ARRAY_CONSTANT.finditer(text):
            parsed = JsLiterals.array(text, match.end() - 1)
            if parsed is not None:
                arrays[match.group("name")] = parsed[0]
        declared = Counter(re.findall(r"\b(?:const|let|var)\s+([\w$]+)", text))
        arrays = {n: v for n, v in list(arrays.items())[: cls.MAX_ARRAYS] if declared[n] == 1}
        if arrays:
            pattern = re.compile(
                r"(?<![\w$.])("
                + "|".join(map(re.escape, arrays))
                + r")\s*\[\s*(\d{1,6}|0[xX][0-9a-fA-F]{1,5})\s*\](?!\s*=[^=])"
            )

            def one(match: re.Match[str]) -> str:
                values = arrays[match.group(1)]
                index = int(match.group(2), 0)
                return JsLiterals.quote(values[index]) if index < len(values) else match.group(0)

            text = pattern.sub(one, text)
        return cls._KEY_ARRAY.sub(lambda m: "[" + m.group(1) + "]", text)

    @staticmethod
    def _word(char: str) -> bool:
        return char.isalnum() or char in "_$"

    @classmethod
    def _normal(cls, body: str, param: str) -> str:
        """The body without space that carries no meaning, the parameter standing as `\\x00`."""
        words = body.strip()
        kept: list[str] = []
        for index, char in enumerate(words):
            if not char.isspace():
                kept.append(char)
            elif (
                kept
                and not kept[-1].isspace()
                and cls._word(kept[-1])
                and cls._word(words[index + 1 :].lstrip()[:1])
            ):
                kept.append(" ")
        squeezed = "".join(kept)
        return re.sub(
            rf"(?<![\w$])(?<![\w$]\.){re.escape(param)}(?![\w$])", DecoderHelpers._P, squeezed
        )

    @classmethod
    def _form(cls, body: str, param: str) -> str | None:
        if len(body) > cls.MAX_BODY:
            return None
        normal = cls._normal(body, param)
        if normal.startswith("return "):
            expression = normal[len("return ") :].removesuffix(";")
        else:
            declared = cls._LOCAL.match(normal)
            if declared is None:
                return None
            local = declared.group(1)
            expression, _, tail = normal[declared.end() :].rpartition(";return ")
            if tail.removesuffix(";") != local or re.search(
                rf"(?<![\w$]){re.escape(local)}(?![\w$])", expression
            ):
                return None
        for pattern, name in cls._FORMS:
            if pattern.match(expression):
                return name
        return None

    @staticmethod
    def _block(text: str, opening: int) -> int | None:
        """The index of the `}` closing the `{` at `opening`, skipping string literals."""
        depth = 0
        index = opening
        limit = min(len(text), opening + DecoderHelpers.MAX_BODY + 64)
        while index < limit:
            char = text[index]
            if char in "'\"`":
                end = index + 1
                while end < limit and text[end] != char:
                    end += 2 if text[end] == "\\" else 1
                index = end
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index
            index += 1
        return None

    @classmethod
    def helpers(cls, text: str) -> tuple[dict[str, tuple[str, bool]], list[tuple[int, int]]]:
        """name -> (decode form, is a method), and the spans of the definitions' own headers.

        A name defined twice is ambiguous and is dropped."""
        found: dict[str, tuple[str, bool]] = {}
        seen: dict[str, int] = {}
        expressions: set[str] = set()
        spans: list[tuple[int, int]] = []
        owners = [(m.start(), m.end(), m.group(1)) for m in cls._OWNER.finditer(text)]
        methods = 0

        def note(name: str, form: str | None, method: bool, expression: bool = False) -> None:
            seen[name] = seen.get(name, 0) + 1
            if expression:
                expressions.add(name)
            if form is not None:
                found[name] = (form, method)

        for pattern, method in (
            (cls._FUNCTION, False),
            (cls._FUNCTION_EXPRESSION, False),
            (cls._METHOD, True),
        ):
            for match in pattern.finditer(text):
                name = match.group("name")
                if name in cls._KEYWORDS:
                    continue
                if method:
                    methods += 1
                    if methods > cls.MAX_METHODS:
                        continue
                    owner = cls._owner(text, owners, match.start())
                    if owner is None:
                        continue
                    name = f"{owner}.{name}"
                opening = match.end() - 1
                spans.append((match.start(), match.end()))
                close = cls._block(text, opening)
                form = (
                    cls._form(text[opening + 1 : close], match.group("param"))
                    if close is not None
                    else None
                )
                note(name, form, method, pattern is cls._FUNCTION_EXPRESSION)
        for match in cls._ARROW.finditer(text):
            param = match.group("p1") or match.group("p2")
            spans.append((match.start(), match.end()))
            start = match.end()
            if text.startswith("{", start):
                close = cls._block(text, start)
                body = text[start + 1 : close] if close is not None else None
            else:
                end = text.find("\n", start, start + cls.MAX_BODY)
                stop = text.find(";", start, start + cls.MAX_BODY)
                ends = [e for e in (end, stop) if e != -1]
                body = "return " + text[start : min(ends) if ends else start + cls.MAX_BODY]
            form = cls._form(body, param) if body is not None else None
            note(match.group("name"), form, False, True)
        trusted: dict[str, tuple[str, bool]] = {}
        for name, value in found.items():
            if seen[name] != 1 or len(trusted) >= cls.MAX_HELPERS:
                continue
            if not value[1]:
                assigned = len(re.findall(rf"(?<![\w$.]){re.escape(name)}\s*=(?![=>])", text))
                if assigned > (1 if name in expressions else 0):
                    continue
            trusted[name] = value
        spans.sort()
        return trusted, spans

    _OWNER: ClassVar[re.Pattern[str]] = re.compile(r"(?:const|let|var)\s+([\w$]+)\s*=\s*\{")

    @classmethod
    def _owner(cls, text: str, owners: list[tuple[int, int, str]], position: int) -> str | None:
        """The object literal a method at `position` sits in: the last `const o = {` before it,
        within 3,000 characters, that is still open there. `owners` is read once per text."""
        at = bisect_right(owners, (position, 0, "")) - 1
        if at < 0 or position - owners[at][0] > 3000:
            return None
        _, end, name = owners[at]
        inside = text[end - 1 : position]
        return name if inside.count("{") > inside.count("}") else None

    @classmethod
    def _constants(cls, text: str) -> dict[str, str]:
        """`const H = '<literal>'` (or an array of numbers), once-declared names only."""
        found: dict[str, str] = {}
        seen: dict[str, int] = {}
        for match in cls._CONSTANT.finditer(text):
            name = match.group("name")
            seen[name] = seen.get(name, 0) + 1
            found[name] = match.group("value")
        return {n: v for n, v in found.items() if seen[n] == 1 and len(v) <= 4300}

    @classmethod
    def _argument(cls, raw: str, constants: dict[str, str]) -> str | list[int] | None:
        """The literal an argument is: a string, a bound constant, or an array of integers."""
        raw = raw.strip()
        if re.fullmatch(r"[\w$]+", raw) and raw in constants:
            raw = constants[raw]
        if len(raw) >= 2 and raw[0] in "'\"" and raw[-1] == raw[0]:
            return JsLiterals.unescape(raw[1:-1])
        if raw.startswith("[") and raw.endswith("]"):
            return [int(IntegerLiteral.value(i)) for i in Checksum.split_args(raw[1:-1])]
        return None

    @staticmethod
    def _printable(value: str) -> bool:
        return bool(value) and all(c.isprintable() or c in "\n\r\t" for c in value)

    @classmethod
    def decode(cls, form: str, argument: str | list[int], enc: str = "") -> str | None:
        if form == "char_codes":
            if not isinstance(argument, list) or not 0 < len(argument) <= cls.MAX_RESULT:
                return None
            if any(not 0 <= n <= 0x10FFFF for n in argument):
                return None
            return "".join(map(chr, argument))
        if not isinstance(argument, str) or len(argument) > cls.MAX_ARGUMENT:
            return None
        if form == "reverse":
            return argument[::-1]
        if form == "hex_pairs":
            if not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", argument):
                return None
            return "".join(chr(int(argument[i : i + 2], 16)) for i in range(0, len(argument), 2))
        if form == "atob":
            body = re.sub(r"\s", "", argument)
            if not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", body):
                return None
            try:
                return base64.b64decode(body + "=" * (-len(body) % 4)).decode("latin-1")
            except (ValueError, binascii.Error):
                return None
        return None

    @staticmethod
    def _base64_bytes(argument: str) -> bytes:
        if not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", argument):
            raise ValueError("not base64")
        return base64.b64decode(argument + "=" * (-len(argument) % 4))

    _BUFFER_DECODERS: ClassVar[dict[str, Callable[[str], bytes]]] = {
        "hex": bytes.fromhex,
        "base64": lambda argument: DecoderHelpers._base64_bytes(argument),
        "base64url": lambda argument: DecoderHelpers._base64_bytes(
            argument.replace("-", "+").replace("_", "/")
        ),
    }

    @classmethod
    def _buffer(cls, encoding: str, argument: object) -> str | None:
        decoder = cls._BUFFER_DECODERS.get(encoding)
        if decoder is None or not isinstance(argument, str) or len(argument) > cls.MAX_ARGUMENT:
            return None
        try:
            return decoder(argument).decode("utf-8")
        except (ValueError, binascii.Error):
            return None

    @classmethod
    def _pass(
        cls,
        text: str,
        helpers: dict[str, tuple[str, bool]],
        constants: dict[str, str],
        spans: list[tuple[int, int]],
    ) -> tuple[str, int, int, int]:
        starts = [start for start, _ in spans]
        encodings = cls._encodings(text, helpers)
        out: list[str] = []
        position = folds = size = remaining = examined = 0
        for match in cls._CALL.finditer(text):
            name = match.group(1)
            if name not in helpers:
                continue
            examined += 1
            if examined > cls.MAX_HEADS:
                raise ValueError("too many calls")
            if match.start() < position:
                continue
            at = bisect_right(starts, match.start()) - 1
            if at >= 0 and match.start() < spans[at][1]:
                continue
            form, _ = helpers[name]
            window = text[match.end() - 1 : match.end() + cls.MAX_ARGUMENT + 4300]
            close = Checksum.closing(window, 0)
            if close is None:
                remaining += 1
                continue
            inner = window[1:close].strip()
            args = (
                [inner]
                if inner.startswith("[") and inner.endswith("]") and inner.count("]") == 1
                else Checksum.split_args(inner)
            )
            argument = cls._argument(args[0], constants) if len(args) == 1 else None
            value = None
            if argument is not None:
                value = (
                    cls._buffer(encodings[name], argument)
                    if form == "buffer"
                    else cls.decode(form, argument)
                )
            if value is None or len(value) > cls.MAX_RESULT or not cls._printable(value):
                remaining += 1
                continue
            out.append(text[position : match.start()])
            out.append(JsLiterals.quote(value))
            position = match.end() - 1 + close + 1
            folds += 1
            size += len(value)
        out.append(text[position:])
        return "".join(out), folds, size, remaining

    @classmethod
    def _encodings(cls, text: str, helpers: dict[str, tuple[str, bool]]) -> dict[str, str]:
        """The encoding a Buffer helper names, read from its own definition."""
        found: dict[str, str] = {}
        for name, (form, _) in helpers.items():
            if form != "buffer":
                continue
            definition = re.search(
                rf"(?<![\w$]){re.escape(name.split('.')[-1])}\b[^;]{{0,200}}?Buffer\s*\.\s*from\s*\([^)]*?,\s*['\"]"
                r"(hex|base64url|base64)['\"]",
                text,
            )
            if definition is not None:
                found[name] = definition.group(1)
        return found
