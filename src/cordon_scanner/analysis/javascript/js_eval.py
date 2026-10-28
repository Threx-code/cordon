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

import base64
import binascii
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar, Final

from cordon_scanner.analysis.javascript.evaluation.values import (
    _HIDDEN_SIGNIFICANT,
    HOLE,
    MAX_DEPTH,
    MAX_REGEX,
    MAX_STEPS,
    MAX_STRING,
    MAX_TEMPLATE_DEPTH,
    MAX_TEXT,
    UNKNOWN,
    Buf,
    Fn,
    Holey,
    Tok,
    Unknown,
)

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

    BUILTIN_DECODER_LOOP: ClassVar[re.Pattern[str]] = re.compile(
        r"for\s*\([^)]{0,80}\)\s*\{?\s*[\w$]+\s*\+=\s*String\s*\.\s*fromCharCode\s*\(\s*([\w$]+)\s*\[\s*[\w$]+\s*\]\s*\)"
    )

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
        """Tokens by a linear scan: no pattern runs over a string's body, so no input can make the
        tokenizer backtrack.

        With `templates`, an interpolated template literal is given as the expression it is:
        `` `a${x}b` `` reads `( "a" + ( x ) + "b" )`, so its text stays a string and only what is
        inside `${}` is read as code. Without it, the whole literal is read as code (the
        evaluator's view). Templates nested deeper than `MAX_TEMPLATE_DEPTH` are read that way
        too, so no nesting can exhaust the stack."""
        out: list[Tok] = []
        pos, n = 0, len(text)
        while pos < n:
            c = text[pos]
            if c.isspace():
                pos += 1
                continue
            if c == "/" and text.startswith("//", pos):
                nl = text.find("\n", pos)
                pos = n if nl < 0 else nl
                continue
            if c == "/" and text.startswith("/*", pos):
                close = text.find("*/", pos + 2)
                pos = n if close < 0 else close + 2
                continue
            if c == "/" and JsEval._regex_allowed(out):
                end = JsEval._regex_end(text, pos)
                if end > 0:
                    out.append(Tok("regex", text[pos:end], pos, end))
                    pos = end
                    continue
            if c in "\"'`":
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
                    pos = j + 1
                elif c == "`":
                    end = (
                        JsEval._template(text, pos, out, depth)
                        if templates and depth < MAX_TEMPLATE_DEPTH
                        else -1
                    )
                    pos = end if end > 0 else pos + 1  # else: read what is inside as code
                else:
                    pos = max(j, pos + 1)  # unterminated on its line: what it held is not code
                continue
            if c in _NAME_START:
                j = pos + 1
                while j < n and text[j] in _NAME_CHAR:
                    j += 1
                out.append(Tok("name", text[pos:j], pos, j))
                pos = j
                continue
            if c.isdigit():
                m = _NUMBER.match(text, pos)
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
                if text.startswith(p, pos):
                    out.append(Tok("punct", p, pos, pos + len(p)))
                    pos += len(p)
                    break
            else:
                if c in "-+*/%^&|~!?:;,.(){}[]<>=":
                    out.append(Tok("punct", c, pos, pos + 1))
                pos += 1
        return out

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
    def _regex_end(text: str, pos: int) -> int:
        """One past a regular expression literal starting at `pos` (flags included), or -1. A
        linear scan: escapes and character classes, never a newline, and short -- a real pattern is,
        and a `/` that only looks like one's start costs a bounded look on a minified line."""
        j, n, in_class = pos + 1, len(text), False
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
    def _template(text: str, pos: int, out: list[Tok], depth: int) -> int:
        """Tokens of the interpolated template opening at `pos` (see `tokens`), appended to `out`;
        one past its closing backtick, or -1 (nothing appended) if it does not close."""
        n, j, start = len(text), pos + 1, pos + 1
        got: list[Tok] = [Tok("punct", "(", pos, pos + 1)]
        while j < n:
            c = text[j]
            if c == "\\":
                j += 2
                continue
            if c == "`" or text.startswith("${", j):
                if j > start:
                    if len(got) > 1:
                        got.append(Tok("punct", "+", start, start))
                    got.append(Tok("str", JsEval._unquote("`" + text[start:j] + "`"), start, j))
                if c == "`":
                    got.append(Tok("punct", ")", j, j + 1))
                    out.extend(got)
                    return j + 1
                close = JsEval._interpolation_end(text, j + 2, depth)
                if close < 0:
                    return -1
                if len(got) > 1:
                    got.append(Tok("punct", "+", j, j))
                got.append(Tok("punct", "(", j, j + 2))
                got.extend(
                    Tok(t.kind, t.value, t.start + j + 2, t.end + j + 2)
                    for t in JsEval.tokens(text[j + 2 : close], True, depth + 1)
                )
                got.append(Tok("punct", ")", close, close + 1))
                j = start = close + 1
                continue
            j += 1
        return -1

    @staticmethod
    def _interpolation_end(text: str, pos: int, depth: int) -> int:
        """The `}` closing the `${` whose body starts at `pos`, past strings and nested templates
        inside it; -1 if there is none."""
        braces, j, n = 0, pos, len(text)
        while j < n:
            c = text[j]
            if c in "\"'`":
                k = j + 1
                while k < n and text[k] != c and (c == "`" or text[k] != "\n"):
                    if text[k] == "\\":
                        k += 2
                    elif c == "`" and text.startswith("${", k):
                        if depth >= MAX_TEMPLATE_DEPTH:
                            return -1
                        inner = JsEval._interpolation_end(text, k + 2, depth + 1)
                        if inner < 0:
                            return -1
                        k = inner + 1
                    else:
                        k += 1
                j = k + 1
                continue
            if c == "{":
                braces += 1
            elif c == "}":
                if braces == 0:
                    return j
                braces -= 1
            j += 1
        return -1

    @staticmethod
    def _unquote(raw: str) -> str:
        body = raw[1:-1]
        if "\\" not in body:
            return body
        try:
            decoded: str = json.loads(
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


@dataclass
class _Evaluator:
    toks: list[Tok]
    text: str
    env: dict[str, Any] = field(default_factory=dict)
    fns: dict[str, Fn] = field(default_factory=dict)
    aliases: set[str] = field(default_factory=set)
    steps: int = 0
    _last_prelude: list[tuple[str, list[Any]]] = field(default_factory=list)
    decoded: bool = False
    """Whether the evaluation in progress decoded something: hex, base64, character codes."""
    decoded_offsets: list[int] = field(default_factory=list)
    """Where in the text a rewritten span's value was decoded rather than only joined."""

    # -- bindings ---------------------------------------------------------------------------------

    def bind(self) -> None:
        """Constants assigned once from evaluable expressions, decoders, and aliases of require."""
        toks = self.toks
        counts: dict[str, int] = {}
        for i, t in enumerate(toks):
            if (
                t.kind == "name"
                and i + 1 < len(toks)
                and toks[i + 1].value in ("=", "+=")
                and (i == 0 or toks[i - 1].value != ".")
            ):
                counts[t.value] = counts.get(t.value, 0) + 1
        done_accumulating: set[int] = set()
        for _ in range(3):
            for i, t in enumerate(toks):
                if t.kind != "name" or i in done_accumulating:
                    continue
                if t.value in ("function",) and i + 2 < len(toks) and toks[i + 1].kind == "name":
                    self._function_decl(i)
                    continue
                if i + 2 >= len(toks) or toks[i + 1].value != "=":
                    continue
                accumulates = (
                    counts.get(t.value, 0) > 1
                    and t.value in self.env
                    and toks[i + 2].kind == "name"
                    and toks[i + 2].value == t.value
                )
                if counts.get(t.value, 0) != 1 and not accumulates and t.value in self.env:
                    continue
                if i > 0 and toks[i - 1].value == ".":
                    continue
                name = t.value
                rhs = i + 2
                # `const _r = require;` and `module.constructor._load` style aliases.
                if (
                    toks[rhs].value == "require"
                    and rhs + 1 < len(toks)
                    and toks[rhs + 1].value in (";", ",", "\n")
                ):
                    self.aliases.add(name)
                    continue
                arrow = self._arrow_at(rhs)
                if arrow is not None:
                    self.fns[name] = arrow
                    continue
                if name in self.env and not accumulates:
                    continue
                if accumulates:
                    done_accumulating.add(i)
                self.steps = 0
                value, _ = self._expr(rhs, 0)
                if isinstance(value, (str, int, float, list, Buf, Holey)) and not (
                    isinstance(value, list) and len(value) > 5000
                ):
                    self.env[name] = value

    def _function_decl(self, i: int) -> None:
        toks = self.toks
        name = toks[i + 1].value
        j = i + 2
        if j >= len(toks) or toks[j].value != "(":
            return
        params, j = self._params(j)
        if params is None or j >= len(toks) or toks[j].value != "{":
            return
        body_end = self._match(j)
        if body_end is None:
            return
        body_text = self.text[toks[j].start : toks[body_end].end]
        loop = JsEval.BUILTIN_DECODER_LOOP.search(body_text)
        if loop and params and loop.group(1) == params[0]:
            self.fns[name] = Fn(params, [], "charcodes")
            return
        ret = self._single_return(j + 1, body_end)
        if ret is not None:
            self.fns[name] = Fn(params, ret, prelude=list(self._last_prelude))

    def _arrow_at(self, k: int) -> Fn | None:
        toks = self.toks
        if k >= len(toks):
            return None
        params: list[Any] | None
        if toks[k].kind == "name" and k + 1 < len(toks) and toks[k + 1].value == "=>":
            params, j = [toks[k].value], k + 2
        elif toks[k].value == "(":
            params, j = self._params(k)
            if params is None or j >= len(toks) or toks[j].value != "=>":
                return None
            j += 1
        else:
            return None
        if j < len(toks) and toks[j].value == "{":
            end = self._match(j)
            if end is None:
                return None
            body_text = self.text[toks[j].start : toks[end].end]
            loop = JsEval.BUILTIN_DECODER_LOOP.search(body_text)
            if loop and params and loop.group(1) == params[0]:
                return Fn(params, [], "charcodes")
            ret = self._single_return(j + 1, end)
            return Fn(params, ret, prelude=list(self._last_prelude)) if ret is not None else None
        end = self._expr_end(j)
        return Fn(params, self.toks[j:end])

    def _params(self, j: int) -> tuple[list[str] | None, int]:
        toks = self.toks
        params: list[str] = []
        j += 1
        while j < len(toks) and toks[j].value != ")":
            if toks[j].kind == "name":
                params.append(toks[j].value)
                # Defaults are skipped: `(u, j = true, f = _d("6970"))`.
                if j + 1 < len(toks) and toks[j + 1].value == "=":
                    j = self._expr_end(j + 2) - 1
            elif toks[j].value != ",":
                return None, j
            j += 1
        return params, j + 1

    def _single_return(self, start: int, end: int) -> list[Tok] | None:
        """The returned expression of a body that is only `const x = ...;` lines and a return;
        the declarations are kept in `self._last_prelude` for the caller."""
        toks = self.toks
        prelude: list[tuple[str, list[Any]]] = []
        j = start
        while j < end and toks[j].value in ("const", "let", "var") and j + 2 < end:
            if toks[j + 1].kind != "name" or toks[j + 2].value != "=":
                return None
            stop = self._expr_end(j + 3)
            prelude.append((toks[j + 1].value, toks[j + 3 : stop]))
            j = stop + 1 if stop < end and toks[stop].value == ";" else stop
            if len(prelude) > 8:
                return None
        self._last_prelude = prelude
        if j < end and toks[j].value == "return":
            stop = self._expr_end(j + 1)
            return toks[j + 1 : stop]
        return None

    def _match(self, j: int) -> int | None:
        pair = {"(": ")", "[": "]", "{": "}"}[self.toks[j].value]
        depth = 0
        for k in range(j, min(len(self.toks), j + 50_000)):
            v = self.toks[k].value
            if self.toks[k].kind != "punct":
                continue
            if v in "([{":
                depth += 1
            elif v in ")]}":
                depth -= 1
                if depth == 0:
                    return k if v == pair else None
        return None

    def _expr_end(self, j: int) -> int:
        depth = 0
        toks = self.toks
        while j < len(toks):
            t = toks[j]
            if t.kind == "punct":
                if t.value in "([{":
                    depth += 1
                elif t.value in ")]}":
                    if depth == 0:
                        return j
                    depth -= 1
                elif t.value in (";", ",") and depth == 0:
                    return j
            j += 1
        return j

    # -- evaluation -------------------------------------------------------------------------------

    def _tick(self) -> bool:
        self.steps += 1
        return self.steps <= MAX_STEPS

    def _expr(self, j: int, depth: int, local: dict[str, Any] | None = None) -> tuple[Any, int]:
        """Evaluate from token `j`; returns (value, index after). `+` and `^` only: the arithmetic a
        decoder uses."""
        if depth > MAX_DEPTH or not self._tick():
            return UNKNOWN, self._expr_end(j)
        left, j = self._unary(j, depth, local)
        while (
            j < len(self.toks)
            and self.toks[j].kind == "punct"
            and self.toks[j].value in ("+", "-", "^", "*", "%")
        ):
            op = self.toks[j].value
            right, j = self._unary(j + 1, depth + 1, local)
            left = self._binary(op, left, right)
        return left, j

    def _binary(self, op: str, a: Any, b: Any) -> Any:
        if op == "+":
            if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                return a + b
            sa, sb = self._as_str(a), self._as_str(b)
            if sa is None and sb is None:
                return UNKNOWN
            joined = (sa if sa is not None else HOLE) + (sb if sb is not None else HOLE)
            if len(joined) > MAX_STRING:
                return UNKNOWN
            return joined if sa is not None and sb is not None else Holey(joined)
        if isinstance(a, int) and isinstance(b, int):
            if op == "^":
                return a ^ b
            if op == "-":
                return a - b
            if op == "*":
                return a * b
            if op == "%" and b:
                return a % b
        return UNKNOWN

    @staticmethod
    def _as_str(v: Any) -> str | None:
        if isinstance(v, str):
            return v
        if isinstance(v, Holey):
            return v.text
        if isinstance(v, bool):
            return None
        if isinstance(v, int):
            return str(v)
        if isinstance(v, float):
            return str(int(v)) if v.is_integer() else str(v)
        return None

    def _unary(self, j: int, depth: int, local: dict[str, Any] | None) -> tuple[Any, int]:
        toks = self.toks
        if j >= len(toks):
            return UNKNOWN, j
        t = toks[j]
        if t.kind == "punct" and t.value == "-":
            v, j = self._unary(j + 1, depth + 1, local)
            return (-v if isinstance(v, (int, float)) else UNKNOWN), j
        return self._postfix(*self._primary(j, depth, local), depth, local)

    def _primary(self, j: int, depth: int, local: dict[str, Any] | None) -> tuple[Any, int]:
        toks = self.toks
        t = toks[j]
        if t.kind in ("str", "tmpl"):
            return t.value, j + 1
        if t.kind == "num":
            return t.value, j + 1
        if t.kind == "punct" and t.value == "(":
            v, k = self._expr(j + 1, depth + 1, local)
            return v, (k + 1 if k < len(toks) and toks[k].value == ")" else k)
        if t.kind == "punct" and t.value == "[":
            items: list[Any] = []
            k = j + 1
            while k < len(toks) and toks[k].value != "]":
                if toks[k].value == ",":
                    k += 1
                    continue
                v, k = self._expr(k, depth + 1, local)
                items.append(v)
                if len(items) > 20_000:
                    return UNKNOWN, self._expr_end(k)
            return items, k + 1
        if t.kind == "name":
            name = t.value
            if local is not None and name in local:
                return local[name], j + 1
            if name in self.env:
                return self.env[name], j + 1
            if name in ("String", "Buffer", "atob", "parseInt", "decodeURIComponent", "unescape"):
                return ("builtin", name), j + 1
            if name in self.fns:
                return ("fn", name), j + 1
            return UNKNOWN, j + 1
        return UNKNOWN, j + 1

    def _postfix(self, v: Any, j: int, depth: int, local: dict[str, Any] | None) -> tuple[Any, int]:
        toks = self.toks
        while j < len(toks) and toks[j].kind == "punct" and toks[j].value in (".", "[", "("):
            if not self._tick():
                return UNKNOWN, self._expr_end(j)
            if toks[j].value == ".":
                if j + 1 >= len(toks) or toks[j + 1].kind != "name":
                    return UNKNOWN, j + 1
                v, j = self._member(v, toks[j + 1].value), j + 2
            elif toks[j].value == "[":
                key, k = self._expr(j + 1, depth + 1, local)
                j = k + 1 if k < len(toks) and toks[k].value == "]" else k
                v = self._index(v, key)
            else:
                args, j = self._args(j, depth, local)
                v = self._call(v, args, depth)
        return v, j

    def _args(self, j: int, depth: int, local: dict[str, Any] | None) -> tuple[list[Any], int]:
        toks = self.toks
        args: list[Any] = []
        k = j + 1
        while k < len(toks) and toks[k].value != ")":
            if toks[k].value == ",":
                k += 1
                continue
            if toks[k].value == "...":
                before = k
                v, k = self._expr(k + 1, depth + 1, local)
                if k <= before + 1:
                    return [*args, UNKNOWN], len(toks)
                args.extend(v if isinstance(v, list) else [UNKNOWN])
                continue
            arrow = self._arrow_at(k)
            if arrow is not None:
                args.append(arrow)
                k = self._expr_end(k)
                continue
            before = k
            v, k = self._expr(k, depth + 1, local)
            if k <= before:
                # A stray closer (`]`, `}`) where an argument should be: the call is not one this
                # evaluator understands. Stop here rather than read the same token forever.
                return [*args, UNKNOWN], len(toks)
            args.append(v)
        return args, k + 1

    def _member(self, v: Any, name: str) -> Any:
        if isinstance(v, tuple) and v[:1] == ("builtin",):
            return ("builtin", f"{v[1]}.{name}")
        if isinstance(v, (str, list, Buf, Holey)):
            return ("method", v, name)
        if isinstance(v, (int, float)) and name == "toString":
            return ("method", v, name)
        return UNKNOWN

    def _index(self, v: Any, key: Any) -> Any:
        if isinstance(key, str) and not isinstance(v, Unknown):
            # `s["con" + "cat"]`: a member named by a computed string.
            return self._member(v, key)
        if isinstance(v, (list, str)) and isinstance(key, (int, float)) and float(key).is_integer():
            i = int(key)
            return v[i] if -len(v) <= i < len(v) else UNKNOWN
        return UNKNOWN

    def _call(self, f: Any, args: list[Any], depth: int) -> Any:
        if depth > MAX_DEPTH:
            return UNKNOWN
        if isinstance(f, tuple) and f[:1] == ("fn",):
            fn = self.fns[f[1]]
            if fn.kind == "charcodes":
                arg = args[0] if args else UNKNOWN
                return self._charcodes(arg)
            local = dict(zip(fn.params, args, strict=False))
            if not fn.body:
                return UNKNOWN
            for name, tokens in fn.prelude:
                pre = _Evaluator(tokens, self.text, self.env, self.fns, self.aliases, self.steps)
                local[name], _ = pre._expr(0, depth + 1, local)
                self.steps = pre.steps
            sub = _Evaluator(fn.body, self.text, self.env, self.fns, self.aliases, self.steps)
            value, _ = sub._expr(0, depth + 1, local)
            self.steps = sub.steps
            self.decoded = self.decoded or sub.decoded
            return value
        if isinstance(f, tuple) and f[:1] == ("builtin",):
            return self._builtin(f[1], args)
        if isinstance(f, tuple) and f[:1] == ("method",):
            return self._method(f[1], f[2], args, depth)
        return UNKNOWN

    def _charcodes(self, arg: Any) -> Any:
        self.decoded = True
        if isinstance(arg, list) and all(
            isinstance(c, (int, float)) and 0 <= c < 0x110000 for c in arg
        ):
            return "".join(chr(int(c)) for c in arg)[:MAX_STRING]
        if isinstance(arg, str):
            return arg
        return UNKNOWN

    def _builtin(self, name: str, args: list[Any]) -> Any:
        if name in ("String.fromCharCode", "atob") or (
            name == "Buffer.from" and len(args) > 1 and args[1] in ("hex", "base64", "base64url")
        ):
            self.decoded = True
        if name == "String.fromCharCode":
            if args and all(isinstance(c, (int, float)) and 0 <= c < 0x110000 for c in args):
                return "".join(chr(int(c)) for c in args)
            return UNKNOWN
        if name == "Buffer.from" and args:
            enc = args[1] if len(args) > 1 else "utf8"
            src = args[0]
            if isinstance(src, list) and all(isinstance(c, int) and 0 <= c < 256 for c in src):
                return Buf(bytes(src))
            if not isinstance(src, str) or not isinstance(enc, str):
                return UNKNOWN
            try:
                if enc == "hex":
                    return Buf(binascii.unhexlify(src[: len(src) // 2 * 2]))
                if enc in ("base64", "base64url"):
                    return Buf(
                        base64.b64decode(
                            src.replace("-", "+").replace("_", "/") + "=" * (-len(src) % 4)
                        )
                    )
                return Buf(src.encode("utf-8", "replace"))
            except (binascii.Error, ValueError):
                return UNKNOWN
        if name == "atob" and args and isinstance(args[0], str):
            try:
                return base64.b64decode(args[0] + "=" * (-len(args[0]) % 4)).decode("latin-1")
            except (binascii.Error, ValueError):
                return UNKNOWN
        if name == "parseInt" and args and isinstance(args[0], str):
            radix = int(args[1]) if len(args) > 1 and isinstance(args[1], (int, float)) else 10
            try:
                return int(args[0].strip(), radix)
            except ValueError:
                return UNKNOWN
        if name in ("decodeURIComponent", "unescape") and args and isinstance(args[0], str):
            from urllib.parse import unquote

            return unquote(args[0])
        return UNKNOWN

    def _method(self, obj: Any, name: str, args: list[Any], depth: int) -> Any:
        if isinstance(obj, Buf):
            if name == "toString":
                enc = args[0] if args else "utf8"
                if enc == "hex":
                    return obj.data.hex()
                if enc == "base64":
                    return base64.b64encode(obj.data).decode()
                return obj.data.decode("utf-8", "replace")[:MAX_STRING]
            return UNKNOWN
        if isinstance(obj, (int, float)) and name == "toString":
            radix = int(args[0]) if args and isinstance(args[0], (int, float)) else 10
            return format(int(obj), {2: "b", 8: "o", 16: "x"}.get(radix, "d"))
        if isinstance(obj, Holey):
            if name == "concat":
                pieces = [obj.text] + [self._as_str(a) or HOLE for a in args]
                return Holey("".join(pieces))
            return UNKNOWN
        if isinstance(obj, str):
            return self._string_method(obj, name, args)
        if isinstance(obj, list):
            return self._list_method(obj, name, args, depth)
        return UNKNOWN

    def _string_method(self, s: str, name: str, args: list[Any]) -> Any:
        a = args
        if name == "concat":
            parts = [self._as_str(x) for x in a]
            if any(p is None for p in parts):
                return Holey(s + "".join(p if p is not None else HOLE for p in parts))
            return s + "".join(parts)  # type: ignore[arg-type]
        if name == "split" and a and isinstance(a[0], str):
            return list(s) if a[0] == "" else s.split(a[0])
        if name == "charCodeAt":
            i = int(a[0]) if a and isinstance(a[0], (int, float)) else 0
            return ord(s[i]) if 0 <= i < len(s) else UNKNOWN
        if name in ("slice", "substring"):
            b = int(a[0]) if a and isinstance(a[0], (int, float)) else 0
            e = int(a[1]) if len(a) > 1 and isinstance(a[1], (int, float)) else None
            return s[b:e]
        if name == "substr":
            b = int(a[0]) if a and isinstance(a[0], (int, float)) else 0
            ln = int(a[1]) if len(a) > 1 and isinstance(a[1], (int, float)) else None
            return s[b : b + ln if ln is not None else None]
        if (
            name in ("replace", "replaceAll")
            and len(a) == 2
            and isinstance(a[0], str)
            and isinstance(a[1], str)
        ):
            return s.replace(a[0], a[1]) if name == "replaceAll" else s.replace(a[0], a[1], 1)
        if name in ("toString", "trim", "toLowerCase", "toUpperCase"):
            return {
                "toString": s,
                "trim": s.strip(),
                "toLowerCase": s.lower(),
                "toUpperCase": s.upper(),
            }[name]
        return UNKNOWN

    def _list_method(self, items: list[Any], name: str, args: list[Any], depth: int) -> Any:
        if name == "join":
            sep = args[0] if args and isinstance(args[0], str) else ","
            parts = [self._as_str(x) for x in items]
            if all(p is not None for p in parts):
                out = sep.join(parts)  # type: ignore[arg-type]
                return out if len(out) <= MAX_STRING else UNKNOWN
            return Holey(sep.join(p if p is not None else HOLE for p in parts))
        if name == "reverse":
            return list(reversed(items))
        if name == "map" and args and isinstance(args[0], Fn):
            fn = args[0]
            mapped = []
            for item in items[:20_000]:
                if not self._tick():
                    return UNKNOWN
                if fn.kind == "charcodes":
                    mapped.append(self._charcodes(item))
                    continue
                sub = _Evaluator(fn.body, self.text, self.env, self.fns, self.aliases, self.steps)
                v, _ = sub._expr(0, depth + 1, dict(zip(fn.params, [item], strict=False)))
                self.steps = sub.steps
                self.decoded = self.decoded or sub.decoded
                mapped.append(v)
            return mapped
        if name == "concat":
            return items + [x for a in args for x in (a if isinstance(a, list) else [a])]
        if name == "slice":
            b = int(args[0]) if args and isinstance(args[0], (int, float)) else 0
            e = int(args[1]) if len(args) > 1 and isinstance(args[1], (int, float)) else None
            return items[b:e]
        return UNKNOWN

    # -- the view ---------------------------------------------------------------------------------

    _STARTS: ClassVar[frozenset[str]] = frozenset(
        {"String", "Buffer", "atob", "decodeURIComponent", "unescape"}
    )

    def rewrite(self) -> str:
        """The text with every evaluable call or chain written as the string it produces, bracket
        lookups by a known name written as members, and aliases of require written as require."""
        toks = self.toks
        edits: list[tuple[int, int, str]] = []
        i = 0
        while i < len(toks):
            t = toks[i]
            start_here = (
                (t.kind == "name" and (t.value in self.fns or t.value in self._STARTS))
                or (
                    t.kind == "punct"
                    and t.value == "["
                    and i > 0
                    and toks[i - 1].kind == "punct"
                    and toks[i - 1].value in ("=", "(", ",", ":", "return")
                )
                or (
                    t.kind in ("str", "tmpl")
                    and i + 2 < len(toks)
                    and toks[i + 1].value in (".", "+")
                    and (toks[i + 2].kind != "str" or toks[i + 1].value == ".")
                )
            )
            if (
                t.kind == "name"
                and t.value in self.aliases
                and i + 1 < len(toks)
                and toks[i + 1].value == "("
            ) and (i == 0 or toks[i - 1].value != "."):
                edits.append((t.start, t.end, "require"))
            # `var cmd = get_ + tar_ + user + "');"`: an assignment from computed pieces is written
            # as the string it holds, so the code it assembles reads as code.
            if (
                t.kind == "name"
                and t.value in self.env
                and isinstance(self.env[t.value], (str, Holey))
                and i + 2 < len(toks)
                and toks[i + 1].value == "="
                and (i == 0 or toks[i - 1].value in ("var", "let", "const", ";", "{", "}"))
                and toks[i + 2].kind != "str"
            ):
                stop = self._expr_end(i + 2)
                value = self.env[t.value]
                literal = json.dumps(value if isinstance(value, str) else value.text)
                if stop > i + 2 and len(literal) <= MAX_STRING:
                    lo, hi = toks[i + 2].start, toks[stop - 1].end
                    edits.append((lo, hi, literal + "\n" * self.text[lo:hi].count("\n")))
                    i = stop
                    continue
            # A constant passed as an argument, written as the string it is: `dns.lookup(domain, cb)`
            # reads as `dns.lookup("host.example", cb)` to a rule that looks for a literal host.
            if (
                t.kind == "name"
                and isinstance(self.env.get(t.value), str)
                and 0 < len(self.env[t.value]) <= 2048
                and i > 0
                and i + 1 < len(toks)
                and toks[i - 1].value in ("(", ",")
                and toks[i + 1].value in (",", ")")
            ):
                edits.append((t.start, t.end, json.dumps(self.env[t.value])))
                i += 1
                continue
            if not start_here or (i > 0 and toks[i - 1].value in (".", "function")):
                i += 1
                continue
            self.steps = 0
            self.decoded = False
            value, end = self._expr(i, 0)
            if (
                self.decoded
                and end > i + 1
                and _HIDDEN_SIGNIFICANT.search(
                    value
                    if isinstance(value, str)
                    else value.text
                    if isinstance(value, Holey)
                    else ""
                )
            ):
                self.decoded_offsets.append(t.start)
            text_value = (
                value
                if isinstance(value, str)
                else value.text
                if isinstance(value, Holey)
                else None
            )
            end = min(end, len(toks))  # an evaluation that gave up reports the end of the tokens
            if text_value is not None and end > i + 1 and len(text_value) <= MAX_STRING:
                lo, hi = t.start, toks[end - 1].end
                original = self.text[lo:hi]
                literal = json.dumps(text_value)
                if literal != original:
                    edits.append((lo, hi, literal + "\n" * original.count("\n")))
                i = end
                continue
            i += 1
        # `obj["userInfo"]` -> `obj.userInfo`, once the key is a literal (in the file or written).
        text = self._apply(self.text, edits)
        text = re.sub(r"\bmodule\s*\.\s*constructor\s*\.\s*_load\s*\(", "require(", text)
        return re.sub(r'\[\s*"([A-Za-z_$][\w$]{0,40})"\s*\]', r".\1", text)

    @staticmethod
    def _apply(text: str, edits: list[tuple[int, int, str]]) -> str:
        out: list[str] = []
        pos = 0
        for lo, hi, rep in sorted(edits):
            if lo < pos:
                continue
            out.append(text[pos:lo])
            out.append(rep)
            pos = hi
        out.append(text[pos:])
        return "".join(out)


Evaluate = Callable[[str], str]
__all__ = ["JsEval"]
