"""JavaScript names and strings a file computes from constants, evaluated without running it.

Hiding a name is the disguise malware reaches for first: `require(_d("6f73"))` for `os`,
`global[d([112,114,111,99,101,115,115])]` for `process`, `"h".concat("os")` for a hostname call,
`[104,116,116,112,115].map(c=>String.fromCharCode(c)).join("")` for a URL. Every rule that looks
for `child_process`, `userInfo` or a host then reads nothing (review 98: dax-styles, a preinstall
helper loading modules from hex, sodexo's collection URL).

This module evaluates the *pure* part of those expressions -- string and array operations, character
codes, hex and base64 decoding, constants bound once, and small local decoder functions -- and writes
the result back into a view of the file, so the same rules read what the code will use. It is a
static reading, not execution: there is no I/O, no host object, no `require`, no loop it cannot
bound, and every step is counted. What it cannot evaluate stays as it was, or becomes a hole in a
string (`_`) so a partly known command still reads (`require('https').get('https://...' + user)`).

The view keeps every line where it was: a replacement that swallows newlines writes them back.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any, ClassVar, Final

from cordon_scanner.analysis.javascript.evaluation.expressions import _Evaluator
from cordon_scanner.analysis.javascript.evaluation.values import (
    BUILTIN_DECODER_LOOP,
    MAX_REGEX,
    MAX_STRING,
    MAX_TEMPLATE_DEPTH,
    MAX_TEXT,
    Tok,
)
from cordon_scanner.foundation.formats.scanned_json import ScannedJson

_PUNCT: Final = (
    "===",
    "!==",
    "...",
    ">>>",
    "=>",
    "==",
    "!=",
    "<=",
    ">=",
    "&&",
    "||",
    "+=",
    "-=",
    "++",
    "--",
    "<<",
    ">>",
)
#: `_PUNCT` by first character, each in its order: the scan tried all seventeen at every bracket
#: and operator, most of a minified bundle's characters.
_PUNCT_BY_FIRST: Final = {c: tuple(p for p in _PUNCT if p[0] == c) for c in {p[0] for p in _PUNCT}}
_NAME_START: Final = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_$")
_NAME_CHAR: Final = _NAME_START | frozenset("0123456789")
_NUMBER: Final = re.compile(r"0[xX][0-9a-fA-F]{1,16}|\d{1,20}(?:\.\d{1,20})?(?:[eE][-+]?\d{1,4})?")


class JsEval:
    """`resolve(text)`: the file with computed names and strings written out."""

    BUILTIN_DECODER_LOOP: ClassVar[re.Pattern[str]] = BUILTIN_DECODER_LOOP

    # -- tokens ----------------------------------------------------------------------------------

    #: The tokens of the large text read most recently, by identity -- each text held, so its
    #: identity cannot be reused: the flow analysis, the folding pass and the intent model each
    #: tokenized the same 10 MB bundle again (review 98: 87 passes over one package's files).
    _recent: ClassVar[dict[tuple[int, bool], tuple[str, list[Tok]]]] = {}
    #: One: a large text's tokens are hundreds of megabytes, and its passes come together.
    RECENT: ClassVar[int] = 1
    CACHED_FROM: ClassVar[int] = 256 * 1024

    @staticmethod
    def tokens(text: str, templates: bool = False, depth: int = 0) -> list[Tok]:
        """`_scan`, read once per large text: a caller is given its own list of the same tokens."""
        if depth or len(text) < JsEval.CACHED_FROM:
            return JsEval._scan(text, templates, depth)
        key = (id(text), templates)
        held = JsEval._recent.get(key)
        if held is None or held[0] is not text:
            if len(JsEval._recent) >= JsEval.RECENT:
                JsEval._recent.pop(next(iter(JsEval._recent)))
            held = JsEval._recent[key] = (text, JsEval._scan(text, templates, depth))
        return list(held[1])

    @staticmethod
    def _scan(text: str, templates: bool = False, depth: int = 0) -> list[Tok]:
        """`_run` over the whole text."""
        return JsEval._run(text, 0, len(text), templates, depth, {})

    @staticmethod
    def _run(
        text: str,
        pos: int,
        n: int,
        templates: bool,
        depth: int,
        memo: dict[int, tuple[int, int]],
        out: list[Tok] | None = None,
    ) -> list[Tok]:
        """Tokens by a linear scan: no pattern runs over a string's body, so no input can make the
        tokenizer backtrack.

        With `templates`, an interpolated template literal is given as the expression it is:
        `` `a${x}b` `` reads `( "a" + ( x ) + "b" )`, so its text stays a string and only what is
        inside `${}` is read as code. Without it, the whole literal is read as code (the
        evaluator's view). Templates nested deeper than `MAX_TEMPLATE_DEPTH` are read that way
        too, so no nesting can exhaust the stack.

        With `out`, the tokens are appended to it (a template's interpolation is read straight into
        the list that holds the template, not into one of its own to be copied up a level)."""
        out = [] if out is None else out
        while pos < n:
            c = text[pos]
            if c.isspace():
                pos += 1
                continue
            if c == "/" and text.startswith("//", pos, n):
                nl = text.find("\n", pos, n)
                pos = n if nl < 0 else nl
                continue
            if c == "/" and text.startswith("/*", pos, n):
                close = text.find("*/", pos + 2, n)
                pos = n if close < 0 else close + 2
                continue
            if c == "/" and JsEval._regex_allowed(out):
                end = JsEval._regex_end(text, pos, n)
                if end > 0:
                    out.append(Tok("regex", text[pos:end], pos, end))
                    pos = end
                    continue
            if c in "\"'`":
                pos = JsEval._string(text, pos, out, templates, depth, n, memo)
                continue
            if c in _NAME_START:
                j = pos + 1
                while j < n and text[j] in _NAME_CHAR:
                    j += 1
                out.append(Tok("name", text[pos:j], pos, j))
                pos = j
                continue
            if c.isdigit():
                m = _NUMBER.match(text, pos, n)
                if m:
                    raw = m.group(0)
                    value: Any = (
                        int(raw, 16)
                        if raw[:2].lower() == "0x"
                        else float(raw)
                        if "." in raw or "e" in raw.lower()
                        else int(raw)
                    )
                    out.append(Tok("num", value, pos, m.end()))
                    pos = m.end()
                    continue
            for p in _PUNCT_BY_FIRST.get(c, ()):
                if text.startswith(p, pos, n):
                    out.append(Tok("punct", p, pos, pos + len(p)))
                    pos += len(p)
                    break
            else:
                if c in "-+*/%^&|~!?:;,.(){}[]<>=":
                    out.append(Tok("punct", c, pos, pos + 1))
                pos += 1
        return out

    @staticmethod
    def _string(
        text: str,
        pos: int,
        out: list[Tok],
        templates: bool,
        depth: int,
        n: int,
        memo: dict[int, tuple[int, int]],
    ) -> int:
        """Read the string or template literal opening at `pos` into `out`; the position after it."""
        c = text[pos]
        # To the literal's real end however long it is: giving up at a length and resuming
        # one character later re-read the same string from every quote inside it, which on
        # a long escaped JSON string was quadratic (review 98).
        j = pos + 1
        while j < n and text[j] != c:
            if text[j] == "\\":
                j += 2
                continue
            if c != "`" and text[j] == "\n":
                break
            if c == "`" and text.startswith("${", j):
                break
            j += 1
        if j < n and text[j] == c:
            if j - pos <= MAX_STRING:
                out.append(Tok("str", JsEval._unquote(text[pos : j + 1]), pos, j + 1))
            else:
                out.append(Tok("longstr", "", pos, j + 1))  # too long to evaluate
            return j + 1
        if c == "`":
            end = (
                JsEval._template(text, pos, out, depth, n, memo)
                if templates and depth < MAX_TEMPLATE_DEPTH
                else -1
            )
            return end if end > 0 else pos + 1  # else: read what is inside as code
        return max(j, pos + 1)  # unterminated on its line: what it held is not code

    #: After these a `/` starts a regular expression, not a division.
    _REGEX_AFTER_NAME: ClassVar[frozenset[str]] = frozenset(
        [
            "return",
            "typeof",
            "case",
            "in",
            "of",
            "delete",
            "void",
            "throw",
            "new",
            "else",
            "do",
            "yield",
            "await",
            "instanceof",
        ]
    )

    @staticmethod
    def _regex_allowed(out: list[Tok]) -> bool:
        if not out:
            return True
        prev = out[-1]
        if prev.kind == "punct":
            return prev.value not in (")", "]", "}", "++", "--")
        return prev.kind == "name" and prev.value in JsEval._REGEX_AFTER_NAME

    @staticmethod
    def _regex_end(text: str, pos: int, n: int) -> int:
        """One past a regular expression literal starting at `pos` (flags included), or -1. A
        linear scan: escapes and character classes, never a newline, and short -- a real pattern is,
        and a `/` that only looks like one's start costs a bounded look on a minified line."""
        j, in_class = pos + 1, False
        while j < n and j - pos <= MAX_REGEX:
            c = text[j]
            if c == "\\":
                j += 2
                continue
            if c == "\n":
                return -1
            if c == "[":
                in_class = True
            elif c == "]":
                in_class = False
            elif c == "/" and not in_class:
                j += 1
                while j < n and (text[j].isalpha()):
                    j += 1
                return j
            j += 1
        return -1

    @staticmethod
    def _template(
        text: str, pos: int, out: list[Tok], depth: int, n: int, memo: dict[int, tuple[int, int]]
    ) -> int:
        """Tokens of the interpolated template opening at `pos` (see `tokens`), appended to `out`;
        one past its closing backtick, or -1 (nothing appended) if it does not close."""
        j, start = pos + 1, pos + 1
        mark = len(out)
        out.append(Tok("punct", "(", pos, pos + 1))
        while j < n:
            c = text[j]
            if c == "\\":
                j += 2
                continue
            if c == "`" or text.startswith("${", j):
                close = -1 if c == "`" else JsEval._interpolation_end(text, j + 2, depth, n, memo)
                if c != "`" and close < 0:
                    del out[mark:]
                    return -1
                if j > start:
                    if len(out) - mark > 1:
                        out.append(Tok("punct", "+", start, start))
                    out.append(Tok("str", JsEval._unquote("`" + text[start:j] + "`"), start, j))
                if c == "`":
                    out.append(Tok("punct", ")", j, j + 1))
                    return j + 1
                if len(out) - mark > 1:
                    out.append(Tok("punct", "+", j, j))
                out.append(Tok("punct", "(", j, j + 2))
                JsEval._run(text, j + 2, close, True, depth + 1, memo, out)
                out.append(Tok("punct", ")", close, close + 1))
                j = start = close + 1
                continue
            j += 1
        del out[mark:]
        return -1

    @staticmethod
    def _interpolation_end(
        text: str, pos: int, depth: int, n: int, memo: dict[int, tuple[int, int]]
    ) -> int:
        """The `}` closing the `${` whose body starts at `pos`, past strings and nested templates
        inside it; -1 if there is none, or if the body nests templates so deep that, started at `depth`,
        one would pass `MAX_TEMPLATE_DEPTH` (the same answer a nested read at each depth gave).

        One pass over the whole nesting, whatever its depth: `memo` holds, for every body found,
        where it closes and how many template levels it holds inside, so a body read again (the
        tokenizer reads an over-deep template as code, backtick by backtick) costs a lookup."""
        held = memo.get(pos)
        if held is None:
            JsEval._interpolation_scan(text, pos, n, memo)
            held = memo[pos]
        end, height = held
        return end if end >= 0 and depth + height <= MAX_TEMPLATE_DEPTH else -1

    @staticmethod
    def _interpolation_scan(text: str, pos: int, n: int, memo: dict[int, tuple[int, int]]) -> None:
        """Fill `memo` for the body at `pos` and every body nested in it: (closing `}` or -1, template
        levels inside). An explicit stack of bodies stands in for the recursion, so no nesting can
        exhaust the interpreter's stack and each character is read once. A frame is
        [start, cursor, braces, height, string cursor or -1, quote]."""
        stack: list[list[Any]] = [[pos, pos, 0, 0, -1, ""]]
        while stack:
            frame = stack[-1]
            start, j, braces, height, k, quote = frame
            if k >= 0:  # inside a quoted string of this body
                nested = False
                while k < n and text[k] != quote and (quote == "`" or text[k] != "\n"):
                    if text[k] == "\\":
                        k += 2
                    elif quote == "`" and text.startswith("${", k):
                        frame[4] = k + 2
                        stack.append([k + 2, k + 2, 0, 0, -1, ""])
                        nested = True
                        break
                    else:
                        k += 1
                if nested:
                    continue
                frame[1], frame[4] = k + 1, -1
                continue
            found = -1
            while j < n:
                c = text[j]
                if c in "\"'`":
                    frame[1], frame[2], frame[4], frame[5] = j, braces, j + 1, c
                    break
                if c == "{":
                    braces += 1
                elif c == "}":
                    if braces == 0:
                        found = j
                        break
                    braces -= 1
                j += 1
            else:  # the text ended inside this body: it, and every body around it, never closes
                for open_frame in stack:
                    memo[open_frame[0]] = (-1, 0)
                return
            if found < 0:
                continue  # a string opened: read it on the next turn
            memo[start] = (found, height)
            stack.pop()
            if stack:
                stack[-1][4] = found + 1
                stack[-1][3] = max(stack[-1][3], height + 1)

    @staticmethod
    def _unquote(raw: str) -> str:
        body = raw[1:-1]
        if "\\" not in body:
            return body
        try:
            decoded: str = ScannedJson.loads(
                '"' + body.replace('"', '\\"').replace("\\'", "'").replace("\\`", "`") + '"'
            )
            return decoded
        except (ValueError, json.JSONDecodeError):
            return re.sub(r"\\x([0-9a-fA-F]{2})", lambda x: chr(int(x.group(1), 16)), body)

    # -- the entry point -------------------------------------------------------------------------

    @classmethod
    def resolve(cls, text: str) -> str:
        return cls.resolve_with_decodes(text)[0]

    @classmethod
    def resolve_with_decodes(cls, text: str) -> tuple[str, list[int]]:
        """The view, and the 1-based lines on which a value was decoded (not only joined)."""
        if len(text) > MAX_TEXT:
            return text, []
        ev = _Evaluator(cls.tokens(text), text)
        ev.bind()
        view = cls.module_names(ev.rewrite())
        lines = sorted({text.count("\n", 0, offset) + 1 for offset in ev.decoded_offsets})
        return view, lines

    #: Node's own modules whose members the rules name: `vm.runInContext`, `child_process.exec`.
    _CORE_MODULE_BINDING: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?<![\w$.])(?:var|let|const)\s{1,8}([A-Za-z_$][\w$]{0,40})\s{0,4}=\s{0,4}require\s{0,4}\(\s{0,4}"""
        r"""['"`](?:node:)?(child_process|vm|https?|http2|net|tls|dgram|dns|fs|os|crypto|zlib|module|worker_threads)['"`]\s{0,4}\)"""
        r"""\s{0,4}(?=[;,\n])"""
    )

    @classmethod
    def module_names(cls, text: str) -> str:
        """`var mint_kiwi = require('vm'); mint_kiwi.runInContext(...)` read as `vm.runInContext`.

        A module bound to a name chosen to look like anything else keeps every rule written
        against the module's members from matching (review 98: an extension's payload ran a
        server's response through `vm` under a food word). Each name bound once, to one module,
        is written back as the module's name where it is used as an object (`name.member`); a name
        bound twice is a reused short name in a bundle, and is left alone. Lengths change, line
        breaks do not."""
        found: dict[str, str] = {}
        twice: set[str] = set()
        for m in cls._CORE_MODULE_BINDING.finditer(text):
            name, module = m.group(1), m.group(2)
            if name in found or name in twice:
                twice.add(name)
                found.pop(name, None)
            elif name != module.replace("_", "") and name != module:
                found[name] = module
        if not found:
            return text
        for name in list(found):
            # Bound again anywhere else (`name = ...`, a parameter, another declaration): not one value.
            if len(re.findall(rf"(?<![\w$.]){re.escape(name)}\s{{0,4}}=(?!=)", text)) > 1:
                found.pop(name)
        if not found:
            return text
        use = re.compile(
            r"(?<![\w$.])("
            + "|".join(re.escape(n) for n in found)
            + r")(?=\s{0,4}\.\s{0,4}[A-Za-z_$])"
        )
        return use.sub(lambda m: found[m.group(1)], text)


Evaluate = Callable[[str], str]
__all__ = ["JsEval"]
