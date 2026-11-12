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
import functools
import io
import re
import tokenize
import unicodedata
from array import array
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import ClassVar

from cordon_scanner.foundation.collector import ScanCaches


class ViewOverBudget(Exception):
    """The file is past what the view may read: the caller reports the file INCOMPLETE."""


class _Starts:
    """The view starts of a flat segment array, read in place by `bisect`."""

    def __init__(self, flat: array[int]) -> None:
        self.flat = flat

    def __len__(self) -> int:
        return len(self.flat) // 4

    def __getitem__(self, i: int) -> int:
        return self.flat[4 * i]


@dataclass
class DecodedView:
    text: str
    raw: str
    #: Every re-spelt piece as view start, view end, raw start, raw end, flat: four 8-byte ints a
    #: piece, so a file of a million escaped literals keeps a map of 32 MB, not of a million tuples.
    flat: array[int] = field(default_factory=lambda: array("q"))
    partial: bool = False

    #: A view past these is refused (`ViewOverBudget`), not built in part.
    MAX_TOKENS: ClassVar[int] = 2_000_000
    MAX_CHARS: ClassVar[int] = 16_000_000
    #: Adjacent literals joined into one: a run past this is refused, not held.
    MAX_RUN: ClassVar[int] = 100_000

    @property
    def differs(self) -> bool:
        return bool(self.flat)

    @property
    def segments(self) -> list[tuple[int, int, int, int]]:
        f = self.flat
        return [(f[i], f[i + 1], f[i + 2], f[i + 3]) for i in range(0, len(f), 4)]

    # -- positions --------------------------------------------------------------------------------

    def to_raw(self, start: int, end: int) -> tuple[int, int]:
        """The raw span of a view span: an end inside a re-spelt piece takes the whole piece."""
        return self._raw_point(start, low=True), self._raw_point(max(start, end), low=False)

    def _raw_point(self, offset: int, *, low: bool) -> int:
        i = bisect.bisect_right(_Starts(self.flat), offset) - 1
        if i >= 0:
            vs, ve, rs, re_ = self.flat[4 * i : 4 * i + 4]
            if vs <= offset < ve or (not low and vs < offset <= ve):
                return rs if low else re_
            if offset >= ve:
                return re_ + (offset - ve)
        return offset

    @staticmethod
    @ScanCaches.register  # holds files' texts: emptied after each scan (foundation/collector)
    @functools.lru_cache(maxsize=8)
    def readings(text: str, language: str | None) -> tuple[str, ...]:
        """The text, and the view's text where it differs: what an excuse granted on an absence must
        find nothing in (note 18 §6). Raises `ViewOverBudget` for a text past the budget."""
        view = DecodedView.of(text, language)
        return (text, view.text) if view.differs else (text,)

    # -- building ---------------------------------------------------------------------------------

    @classmethod
    def of(cls, text: str, language: str | None) -> DecodedView:
        if len(text) > cls.MAX_CHARS:
            raise ViewOverBudget(f"{len(text)} characters")
        reader = _READERS.get(language or "")
        return cls(text=text, raw=text) if reader is None else reader(text).view()


class _Builder:
    """The view written as it is read: the text into one buffer, the map into one flat array."""

    def __init__(self, raw: str) -> None:
        self.raw = raw
        self.out = io.StringIO()
        self.flat: array[int] = array("q")
        self.cursor = 0
        self.length = 0

    def copy_to(self, raw_offset: int) -> None:
        if raw_offset > self.cursor:
            self.length += self.out.write(self.raw[self.cursor : raw_offset])
            self.cursor = raw_offset

    def replace(self, raw_start: int, raw_end: int, text: str) -> None:
        self.copy_to(raw_start)
        if text == self.raw[raw_start:raw_end]:
            self.copy_to(raw_end)
            return
        self.out.write(text)
        self.flat.extend((self.length, self.length + len(text), raw_start, raw_end))
        self.length += len(text)
        self.cursor = raw_end

    def view(self, *, partial: bool = False) -> DecodedView:
        self.copy_to(len(self.raw))
        return DecodedView(text=self.out.getvalue(), raw=self.raw, flat=self.flat, partial=partial)


# -- Python ---------------------------------------------------------------------------------------

#: 3.12's f-string tokens; -1 (no token has it) before.
_FSTRING_START: int = getattr(tokenize, "FSTRING_START", -1)
_FSTRING_END: int = getattr(tokenize, "FSTRING_END", -1)

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
                # S2: a fallback; the f-string stays as written, which the raw reading reads
                return None
            if isinstance(value, bytes):
                value = value.decode("latin-1")
            out.append(_Python.body(value, quote).replace("{", "{{").replace("}", "}}"))
        return f"{prefix}{quote}{''.join(out)}{quote}"


class _Python:
    def __init__(self, raw: str) -> None:
        self.raw = raw
        self.partial = False
        #: Where each line starts, as `tokenize` counts them: it reads through `StringIO.readline`,
        #: which ends a line at "\n" only -- not at a form feed or U+2028, as `str.splitlines`
        #: does. Eight bytes a line, and no list of the lines.
        self.lines: array[int] = array("q", [0])
        self.lines.extend(m.end() for m in re.finditer("\n", raw))

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

    def tokens(self) -> Iterator[tokenize.TokenInfo]:
        """The file's tokens, one at a time: nothing but the current run of literals is held, so
        a file of millions of tokens is read in the memory of a few. Past `MAX_TOKENS` the file is
        refused; where `tokenize` stops, the view is `partial` and the rest stays raw."""
        count = 0
        try:
            for tok in tokenize.generate_tokens(io.StringIO(self.raw).readline):
                count += 1
                if count > DecodedView.MAX_TOKENS:
                    raise ViewOverBudget(f"more than {DecodedView.MAX_TOKENS} tokens")
                yield tok
        except (tokenize.TokenError, SyntaxError):
            # S2: recorded; the view stops where tokenize did, the rest is read raw, and the file
            # is counted partial (stats.view_files)
            self.partial = True

    def view(self) -> DecodedView:
        self.partial = False
        b = _Builder(self.raw)
        stream = self.tokens()
        tok = next(stream, None)
        run: list[tuple[int, int]] = []
        while tok is not None:
            if self._opens_literal(tok):
                run.append(self._span(tok, stream))
                # The run goes on past line breaks inside brackets and comments, to the next literal:
                # what is skipped re-spells nothing, so it is not kept.
                tok = next(stream, None)
                while tok is not None and tok.type in (tokenize.NL, tokenize.COMMENT):
                    tok = next(stream, None)
                if tok is not None and self._opens_literal(tok):
                    if len(run) >= DecodedView.MAX_RUN:
                        raise ViewOverBudget(f"a run of more than {DecodedView.MAX_RUN} literals")
                    continue
                self._literals(b, run)
                run = []
                continue
            if tok.type == tokenize.NAME:
                normal = unicodedata.normalize("NFKC", tok.string)
                if normal != tok.string:
                    b.replace(self.at(tok.start), self.at(tok.end), normal)
            tok = next(stream, None)
        if run:
            self._literals(b, run)
        return b.view(partial=self.partial)

    @staticmethod
    def _opens_literal(tok: tokenize.TokenInfo) -> bool:
        return tok.type == tokenize.STRING or tok.type == _FSTRING_START

    def _span(
        self, tok: tokenize.TokenInfo, stream: Iterator[tokenize.TokenInfo]
    ) -> tuple[int, int]:
        """The raw span of the literal `tok` opens: one STRING token, or a whole f-string from
        FSTRING_START to its FSTRING_END (3.12), nested ones included, read off the stream."""
        if tok.type != _FSTRING_START:
            return self.at(tok.start), self.at(tok.end)
        depth = 1
        for inner in stream:
            if inner.type == _FSTRING_START:
                depth += 1
            elif inner.type == _FSTRING_END:
                depth -= 1
                if depth == 0:
                    return self.at(tok.start), self.at(inner.end)
        return self.at(tok.start), len(self.raw)

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
                    # S2: a fallback; the run is read literal by literal below, as written if not
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
                # S2: a fallback; the literal stays as written, which the raw reading reads
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
        if value > 0x10FFFF or not _Lines.kept(chr(value)):
            return m.group(0)  # a line break or control character stays escaped: no line moves
        return chr(value)

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
            data, k = self._run(j)
            if k == j:
                j += 2  # another escape (`\\n`, `\\\\`, `\\"`) stays as written
                continue
            text = self._text(data)
            if text is not None:
                b.replace(j, k, text)
            j = k
        return j + 1

    def _run(self, j: int) -> tuple[bytearray | None, int]:
        """The bytes a run of escapes from `j` spells, and where the run ends; None for bytes
        when one is no character (a surrogate, past U+10FFFF). Read in place: only the bytes held."""
        raw, data, k = self.raw, bytearray(), j
        ok = True
        while (m := _GO_ESCAPE.match(raw, k)) is not None:
            k = m.end()
            byte, octal, short, long = m.groups()
            if byte is not None or octal is not None:
                data.append(int(byte, 16) if byte is not None else int(octal, 8) & 0xFF)
                continue
            point = int(short or long, 16)
            if point > 0x10FFFF or 0xD800 <= point <= 0xDFFF:
                ok = False
            elif ok:
                data += chr(point).encode("utf-8")
        return (data if ok else None), k

    @staticmethod
    def _text(data: bytearray | None) -> str | None:
        """What the run is written as: its UTF-8 text, or None (left as written) when it is not
        UTF-8 or holds a character that would break a line."""
        if data is None:
            return None
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return None if _Lines.BREAKS.search(text) else text


class _Lines:
    #: A character that breaks a line (`str.splitlines`) or is another control character: the
    #: Unicode category Cc (U+0000-001F, U+007F-009F) and the line and paragraph separators.
    BREAKS: ClassVar[re.Pattern[str]] = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029]")

    @classmethod
    def kept(cls, ch: str) -> bool:
        """Whether a decoded character may be written as itself, so the view's lines are the file's."""
        return cls.BREAKS.match(ch) is None


#: The reader of each language the view knows; every other language's file is its own view.
_READERS: dict[str, type[_Python] | type[_Script] | type[_Go]] = {
    "python": _Python,
    "javascript": _Script,
    "typescript": _Script,
    "go": _Go,
}

__all__ = ["DecodedView", "ViewOverBudget"]
