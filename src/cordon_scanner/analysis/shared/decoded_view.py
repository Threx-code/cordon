"""One decoded reading of a source file, with a map back to the raw text (reviews/pypi-98/18-DECODED-VIEW.md).

A raw-text rule reads the file as written; the language reads it decoded. The view re-spells only what the
parser itself rewrites, never an expression:

- Python (from `tokenize`, so every line and comment stays): a string literal that holds an escape
  (`\\x`, `\\u`, `\\U`, `\\N{}`, octal) is written with its value; adjacent literals (implicit
  concatenation) are joined into one, the newlines between them kept after it so line numbers hold;
  f-strings are split by our own splitter, the same on every Python, their literal parts decoded and
  their `{...}` fields copied as written; names are NFKC-normalised (PEP 3131).
- JavaScript / TypeScript (a scan of the text): `\\uXXXX` and `\\u{X...}` in identifiers, strings and
  template literals, and `\\xXX` in strings and templates, are written as the characters. Other
  escapes (`\\n`, `\\t`, ...) stay as written, so no line moves. Comments and regex literals are left
  alone where the scan can tell.
- Go (a scan of the text): `\\xXX`, octal, `\\uXXXX` and `\\UXXXXXXXX` in interpreted strings and
  rune literals are written as what they spell; a run of them is read as UTF-8 together (`\\x` and
  octal are bytes), and left as written when it is not. Raw (backquoted) strings, comments and
  identifiers are exact in Go. A character that would break a line or is a control character stays
  as written, so no line moves.

`segments` lists every re-spelt piece as (view start, view end, raw start, raw end), in characters of the
text; everything between is the raw text unchanged. `to_raw` sends a view span to the raw span of every
piece it touches. A view that changes nothing has `differs` False and callers read the raw text alone.

The view is a reader like any other: past `MAX_TOKENS` tokens or `MAX_CHARS` characters it raises
`ViewOverBudget`, which the caller turns into the file's fail-closed gap; it never falls back to the raw
text in silence. A Python file `tokenize` stops on keeps the view of every token before the error and the
rest raw, marked `partial`.
"""

from __future__ import annotations

import ast
import bisect
import io
import re
import tokenize
import unicodedata
from dataclasses import dataclass, field
from typing import ClassVar


class ViewOverBudget(Exception):
    """The file is past what the view may read: the caller reports the file INCOMPLETE."""


@dataclass
class DecodedView:
    text: str
    raw: str
    segments: list[tuple[int, int, int, int]] = field(default_factory=list)
    partial: bool = False

    #: A view past these is refused (`ViewOverBudget`), not built in part.
    MAX_TOKENS: ClassVar[int] = 2_000_000
    MAX_CHARS: ClassVar[int] = 16_000_000

    @property
    def differs(self) -> bool:
        return bool(self.segments)

    # -- positions --------------------------------------------------------------------------------

    def to_raw(self, start: int, end: int) -> tuple[int, int]:
        """The raw span of a view span: an end inside a re-spelt piece takes the whole piece."""
        return self._raw_point(start, low=True), self._raw_point(max(start, end), low=False)

    def _raw_point(self, offset: int, *, low: bool) -> int:
        starts = [s[0] for s in self.segments]
        i = bisect.bisect_right(starts, offset) - 1
        if i >= 0:
            vs, ve, rs, re_ = self.segments[i]
            if vs <= offset < ve or (not low and vs < offset <= ve):
                return rs if low else re_
            if offset >= ve:
                return re_ + (offset - ve)
        return offset

    # -- building ---------------------------------------------------------------------------------

    @classmethod
    def of(cls, text: str, language: str | None) -> DecodedView:
        if len(text) > cls.MAX_CHARS:
            raise ViewOverBudget(f"{len(text)} characters")
        if language == "python":
            return _Python(text).view()
        if language in ("javascript", "typescript"):
            return _Script(text).view()
        if language == "go":
            return _Go(text).view()
        return cls(text=text, raw=text)


class _Builder:
    def __init__(self, raw: str) -> None:
        self.raw = raw
        self.out: list[str] = []
        self.segments: list[tuple[int, int, int, int]] = []
        self.cursor = 0
        self.length = 0

    def copy_to(self, raw_offset: int) -> None:
        if raw_offset > self.cursor:
            piece = self.raw[self.cursor : raw_offset]
            self.out.append(piece)
            self.length += len(piece)
            self.cursor = raw_offset

    def replace(self, raw_start: int, raw_end: int, text: str) -> None:
        self.copy_to(raw_start)
        if text == self.raw[raw_start:raw_end]:
            self.copy_to(raw_end)
            return
        self.out.append(text)
        self.segments.append((self.length, self.length + len(text), raw_start, raw_end))
        self.length += len(text)
        self.cursor = raw_end

    def view(self, *, partial: bool = False) -> DecodedView:
        self.copy_to(len(self.raw))
        return DecodedView(
            text="".join(self.out), raw=self.raw, segments=self.segments, partial=partial
        )


# -- Python ---------------------------------------------------------------------------------------

_PREFIX = re.compile(r"(?i)^([rbuf]{0,3})('''|\"\"\"|'|\")")


class _FString:
    """Our own split of an f-string's source, the same on every Python (up to 3.11 it is one STRING
    token; 3.12 tokenizes its parts): prefix, quote, literal parts and `{...}` fields in order."""

    @staticmethod
    def split(source: str) -> tuple[str, str, list[tuple[str, str]]] | None:
        m = _PREFIX.match(source)
        if m is None or "f" not in m.group(1).lower():
            return None
        prefix, quote = m.group(1), m.group(2)
        body = source[m.end() : len(source) - len(quote)]
        if not source.endswith(quote) or len(source) < m.end() + len(quote):
            return None
        parts: list[tuple[str, str]] = []  # ("lit", text) or ("field", text)
        i, n, lit = 0, len(body), []
        raw_prefix = "r" in prefix.lower()
        while i < n:
            c = body[i]
            if c == "\\" and not raw_prefix and i + 1 < n:
                lit.append(body[i : i + 2])
                i += 2
                continue
            if c in "{}" and i + 1 < n and body[i + 1] == c:
                lit.append(c)  # `{{` and `}}`: one brace
                i += 2
                continue
            if c == "{":
                if lit:
                    parts.append(("lit", "".join(lit)))
                    lit = []
                j = _FString._field_end(body, i)
                if j < 0:
                    return None
                parts.append(("field", body[i : j + 1]))
                i = j + 1
                continue
            lit.append(c)
            i += 1
        if lit:
            parts.append(("lit", "".join(lit)))
        return prefix, quote, parts

    @staticmethod
    def _field_end(body: str, start: int) -> int:
        depth, i, n, q = 0, start, len(body), ""
        while i < n:
            c = body[i]
            if q:
                if body.startswith(q, i):
                    i += len(q)
                    q = ""
                    continue
                if c == "\\":
                    i += 2
                    continue
            elif c in "'\"":
                q = body[i : i + 3] if body.startswith(c * 3, i) else c
                i += len(q)
                continue
            elif c in "{[(":
                depth += 1
            elif c in "}])":
                depth -= 1
                if depth == 0 and c == "}":
                    return i
            i += 1
        return -1

    @staticmethod
    def decoded(source: str) -> str | None:
        """The f-string written with its literal parts decoded, fields as written; None when it
        holds no escape (nothing to re-spell)."""
        split = _FString.split(source)
        if split is None:
            return None
        prefix, quote, parts = split
        plain = re.sub("(?i)f", "", prefix)
        if "\\" not in "".join(t for k, t in parts if k == "lit") or "r" in prefix.lower():
            return None
        out = []
        for kind, part in parts:
            if kind == "field":
                out.append(part)
                continue
            try:
                value = ast.literal_eval(f"{plain}{quote}{part}{quote}")
            except (ValueError, SyntaxError, MemoryError, RecursionError):
                return None
            if isinstance(value, bytes):
                value = value.decode("latin-1")
            out.append(_Python.body(value, quote).replace("{", "{{").replace("}", "}}"))
        return f"{prefix}{quote}{''.join(out)}{quote}"


class _Python:
    def __init__(self, raw: str) -> None:
        self.raw = raw
        self.lines = [0]
        for line in raw.splitlines(keepends=True):
            self.lines.append(self.lines[-1] + len(line))

    def at(self, position: tuple[int, int]) -> int:
        row, col = position
        return self.lines[row - 1] + col if row - 1 < len(self.lines) else len(self.raw)

    @staticmethod
    def body(value: str, quote: str) -> str:
        """`value` as a literal's body between `quote`s: the quote, backslashes, line breaks and
        unprintable characters escaped, every other character as itself."""
        out = []
        for ch in value:
            if ch == "\\":
                out.append("\\\\")
            elif ch == quote[0]:
                out.append("\\" + ch)
            elif ch == "\n" and len(quote) == 1:
                out.append("\\n")
            elif not ch.isprintable() and ch not in "\n\t":
                out.append(ch.encode("unicode_escape").decode("ascii"))
            else:
                out.append(ch)
        return "".join(out)

    def tokens(self) -> tuple[list[tokenize.TokenInfo], bool]:
        out: list[tokenize.TokenInfo] = []
        try:
            for tok in tokenize.generate_tokens(io.StringIO(self.raw).readline):
                out.append(tok)
                if len(out) > DecodedView.MAX_TOKENS:
                    raise ViewOverBudget(f"more than {DecodedView.MAX_TOKENS} tokens")
        except (tokenize.TokenError, SyntaxError):
            return out, True
        return out, False

    def view(self) -> DecodedView:
        toks, partial = self.tokens()
        b = _Builder(self.raw)
        i, n = 0, len(toks)
        fstart = getattr(tokenize, "FSTRING_START", None)
        fend = getattr(tokenize, "FSTRING_END", None)
        while i < n:
            tok = toks[i]
            if tok.type == tokenize.NAME:
                normal = unicodedata.normalize("NFKC", tok.string)
                if normal != tok.string:
                    b.replace(self.at(tok.start), self.at(tok.end), normal)
                i += 1
                continue
            if tok.type == tokenize.STRING or (fstart is not None and tok.type == fstart):
                run, i = self._run(toks, i, fstart, fend)
                self._literals(b, run)
                continue
            i += 1
        return b.view(partial=partial)

    def _string_span(
        self, toks: list[tokenize.TokenInfo], i: int, fstart: int | None, fend: int | None
    ) -> tuple[int, int, int]:
        """(raw start, raw end, next index) of the literal at `i`: one STRING token, or a whole
        f-string from FSTRING_START to its FSTRING_END (3.12), nested ones included."""
        tok = toks[i]
        if fstart is None or tok.type != fstart:
            return self.at(tok.start), self.at(tok.end), i + 1
        depth, j = 0, i
        while j < len(toks):
            if toks[j].type == fstart:
                depth += 1
            elif toks[j].type == fend:
                depth -= 1
                if depth == 0:
                    return self.at(tok.start), self.at(toks[j].end), j + 1
            j += 1
        return self.at(tok.start), len(self.raw), len(toks)

    def _run(
        self, toks: list[tokenize.TokenInfo], i: int, fstart: int | None, fend: int | None
    ) -> tuple[list[tuple[int, int]], int]:
        """Adjacent literals from `i` (implicit concatenation): spans, separated only by line breaks
        inside brackets and comments."""
        spans: list[tuple[int, int]] = []
        while i < len(toks):
            tok = toks[i]
            if tok.type == tokenize.STRING or (fstart is not None and tok.type == fstart):
                s, e, i = self._string_span(toks, i, fstart, fend)
                spans.append((s, e))
                continue
            if tok.type in (tokenize.NL, tokenize.COMMENT) and spans:
                j = i
                while j < len(toks) and toks[j].type in (tokenize.NL, tokenize.COMMENT):
                    j += 1
                if j < len(toks) and (
                    toks[j].type == tokenize.STRING
                    or (fstart is not None and toks[j].type == fstart)
                ):
                    i = j
                    continue
            break
        return spans, i

    @staticmethod
    def _is_f(source: str) -> bool:
        m = _PREFIX.match(source)
        return m is not None and "f" in m.group(1).lower()

    @staticmethod
    def _lines_kept(text: str, source: str) -> str:
        """`text` with the newlines `source` held and `text` lost (a joined run's breaks, a
        backslash-newline continuation): every later line keeps its number."""
        return text + "\n" * max(0, source.count("\n") - text.count("\n"))

    def _literals(self, b: _Builder, spans: list[tuple[int, int]]) -> None:
        sources = [self.raw[s:e] for s, e in spans]
        is_f = [self._is_f(src) for src in sources]
        if len(spans) > 1 and not any(is_f):
            values: list[str] = []
            for src in sources:
                try:
                    v = ast.literal_eval(src)
                except (ValueError, SyntaxError, MemoryError, RecursionError):
                    values = []
                    break
                values.append(v.decode("latin-1") if isinstance(v, bytes) else v)
            first = _PREFIX.match(sources[0])
            if values and first is not None:
                joined = "".join(values)
                quote = first.group(2)
                span = self.raw[spans[0][0] : spans[-1][1]]
                written = f"{quote}{self.body(joined, quote)}{quote}"
                b.replace(spans[0][0], spans[-1][1], self._lines_kept(written, span))
                return
        for (s, e), src, f in zip(spans, sources, is_f, strict=True):
            if f:
                decoded = _FString.decoded(src)
                if decoded is not None:
                    b.replace(s, e, self._lines_kept(decoded, src))
                continue
            m = _PREFIX.match(src)
            if m is None or "r" in m.group(1).lower() or "\\" not in src:
                continue
            try:
                v = ast.literal_eval(src)
            except (ValueError, SyntaxError, MemoryError, RecursionError):
                continue
            if isinstance(v, bytes):
                v = v.decode("latin-1")
            quote = m.group(2)
            b.replace(s, e, self._lines_kept(f"{quote}{self.body(v, quote)}{quote}", src))


# -- JavaScript / TypeScript ----------------------------------------------------------------------

_JS_ESCAPE = re.compile(r"\\u\{([0-9A-Fa-f]{1,6})\}|\\u([0-9A-Fa-f]{4})|\\x([0-9A-Fa-f]{2})")
_REGEX_BEFORE = frozenset("(,=:[!&|?{};+-*%<>~^")


class _Script:
    def __init__(self, raw: str) -> None:
        self.raw = raw

    def view(self) -> DecodedView:
        b = _Builder(self.raw)
        if "\\" not in self.raw:
            return b.view()
        raw, i, n = self.raw, 0, len(self.raw)
        stack: list[
            str
        ] = []  # "`" a template, "${" an expression inside one, "{" a brace inside that
        last = ""
        while i < n:
            c = raw[i]
            if c == "/" and raw.startswith("//", i):
                j = raw.find("\n", i)
                i = n if j < 0 else j
                continue
            if c == "/" and raw.startswith("/*", i):
                j = raw.find("*/", i + 2)
                i = n if j < 0 else j + 2
                continue
            if c == "/" and (last == "" or last in _REGEX_BEFORE):
                i = self._regex_end(i)
                last = "/"
                continue
            if c in "'\"":
                i = self._literal(b, i, c, x=True)
                last = c
                continue
            if c == "`":
                stack.append("`")
                i = self._template(b, i + 1, stack)
                last = "`"
                continue
            if c == "}" and stack and stack[-1] == "${":
                stack.pop()  # the expression ends: back into the template
                i = self._template(b, i + 1, stack)
                continue
            if c == "}" and stack and stack[-1] == "{":
                stack.pop()
            elif c == "{" and stack:
                stack.append("{")
            if c == "\\" and raw.startswith("\\u", i):
                m = _JS_ESCAPE.match(raw, i)
                if m is not None and m.group(3) is None:
                    b.replace(m.start(), m.end(), self._char(m))
                    i = m.end()
                    last = "a"
                    continue
            if not c.isspace():
                last = c
            i += 1
        return b.view()

    @staticmethod
    def _char(m: re.Match[str]) -> str:
        value = int(m.group(1) or m.group(2) or m.group(3), 16)
        return chr(value) if value <= 0x10FFFF else m.group(0)

    def _escapes(self, b: _Builder, start: int, end: int) -> None:
        for m in _JS_ESCAPE.finditer(self.raw, start, end):
            # `\\x41` is a backslash then x41: an escape only after an even run of backslashes
            k, run = m.start() - 1, 0
            while k >= start and self.raw[k] == "\\":
                run += 1
                k -= 1
            if run % 2 == 0:
                b.replace(m.start(), m.end(), self._char(m))

    def _literal(self, b: _Builder, i: int, quote: str, *, x: bool) -> int:
        raw, j, n = self.raw, i + 1, len(self.raw)
        while j < n and raw[j] != quote and raw[j] != "\n":
            j += 2 if raw[j] == "\\" else 1
        self._escapes(b, i + 1, min(j, n))
        return j + 1

    def _template(self, b: _Builder, i: int, stack: list[str]) -> int:
        raw, j, n = self.raw, i, len(self.raw)
        while j < n:
            if raw[j] == "\\":
                j += 2
                continue
            if raw[j] == "`":
                self._escapes(b, i, j)
                stack.pop()
                return j + 1
            if raw.startswith("${", j):
                self._escapes(b, i, j)
                stack.append("${")
                return j + 2
            j += 1
        self._escapes(b, i, n)
        return n

    def _regex_end(self, i: int) -> int:
        raw, j, n, in_class = self.raw, i + 1, len(self.raw), False
        while j < n and raw[j] != "\n":
            c = raw[j]
            if c == "\\":
                j += 2
                continue
            if c == "[":
                in_class = True
            elif c == "]":
                in_class = False
            elif c == "/" and not in_class:
                return j + 1
            j += 1
        return j


# -- Go -------------------------------------------------------------------------------------------

_GO_ESCAPE = re.compile(r"\\(?:x([0-9A-Fa-f]{2})|([0-7]{3})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8}))")


class _Go:
    """Go's interpreted strings and rune literals with their byte and code-point escapes decoded."""

    def __init__(self, raw: str) -> None:
        self.raw = raw

    def view(self) -> DecodedView:
        b = _Builder(self.raw)
        if "\\" not in self.raw:
            return b.view()
        raw, i, n = self.raw, 0, len(self.raw)
        while i < n:
            c = raw[i]
            if raw.startswith("//", i):
                j = raw.find("\n", i)
                i = n if j < 0 else j
            elif raw.startswith("/*", i):
                j = raw.find("*/", i + 2)
                i = n if j < 0 else j + 2
            elif c == "`":
                j = raw.find("`", i + 1)
                i = n if j < 0 else j + 1
            elif c in "\"'":
                i = self._literal(b, i, c)
            else:
                i += 1
        return b.view()

    def _literal(self, b: _Builder, i: int, quote: str) -> int:
        raw, j, n = self.raw, i + 1, len(self.raw)
        while j < n and raw[j] != quote and raw[j] != "\n":
            if raw[j] != "\\":
                j += 1
                continue
            run = []
            k = j
            while (m := _GO_ESCAPE.match(raw, k)) is not None:
                run.append(m)
                k = m.end()
            if not run:
                j += 2  # another escape (`\\n`, `\\\\`, `\\"`) stays as written
                continue
            self._run(b, run)
            j = k
        return j + 1

    @staticmethod
    def _run(b: _Builder, run: list[re.Match[str]]) -> None:
        data = bytearray()
        for m in run:
            byte, octal, short, long = m.groups()
            if byte is not None or octal is not None:
                data.append(int(byte, 16) if byte is not None else int(octal, 8) & 0xFF)
                continue
            point = int(short or long, 16)
            if point > 0x10FFFF or 0xD800 <= point <= 0xDFFF:
                return
            data += chr(point).encode("utf-8")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return
        if not all(_Lines.kept(ch) for ch in text):
            return
        b.replace(run[0].start(), run[-1].end(), text)


class _Lines:
    @staticmethod
    def kept(ch: str) -> bool:
        """Whether a decoded character may be written as itself: not one that breaks a line
        (`str.splitlines`) and not another control character, so the view's lines are the file's."""
        return not (unicodedata.category(ch) == "Cc" or ch in "\u2028\u2029")


__all__ = ["DecodedView", "ViewOverBudget"]
