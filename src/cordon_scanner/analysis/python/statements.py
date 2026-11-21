"""Where a Python module's top-level statements start, so a module too large to parse at once can
be parsed a run of whole statements at a time.

A cut anywhere else leaves a statement half in each piece, and neither piece parses: the first ten
megabytes of a 45 MB generated module are not a module, so the syntax-tree tier read nothing of it
(review 98, D1). Cut between top-level statements, every piece is a module of its own.

```
  NEWLINE at depth 0, or the DEDENT back to it     -> the next token starts a statement
  except a decorator's line                        -> what it decorates is the same statement
  except else / elif / except / finally             -> they continue the statement before
```
"""

from __future__ import annotations

import io
import re
import tokenize
from typing import ClassVar

CONTINUATIONS = frozenset({"else", "elif", "except", "finally"})
"""Keywords at depth 0 that continue the compound statement before them."""


class PythonStatements:
    STRAY_BYTES: ClassVar[dict[int, str]] = dict.fromkeys(range(0xDC80, 0xDD00), "�")
    """The lone surrogates `surrogateescape` decodes the 128 bytes 0x80-0xFF to, as U+FFFD."""

    @staticmethod
    def starts(text: str) -> list[int]:
        """The character offsets where `text`'s top-level statements start, 0 first. A text that
        stops partway (a window's end) gives the starts found before the token stream broke."""
        line_starts = [0]
        line_starts.extend(i + 1 for i, ch in enumerate(text) if ch == "\n")
        # At a statement's start from the first token, so a decorator on the module's first statement
        # is a decorator and what it decorates is the same statement; that first statement's start
        # stays 0, after any header comment or shebang, so a one-statement module is never cut.
        out, depth, at_start, decorated, first = [0], 0, True, False, True
        try:
            for token in tokenize.generate_tokens(io.StringIO(text).readline):
                if token.type == tokenize.INDENT:
                    depth += 1
                    continue
                if token.type == tokenize.DEDENT:
                    depth -= 1
                    at_start = at_start or depth == 0
                    continue
                if token.type == tokenize.NEWLINE:
                    at_start = at_start or depth == 0
                    continue
                if token.type in (tokenize.NL, tokenize.COMMENT, tokenize.ENDMARKER):
                    continue
                if at_start and depth == 0 and token.string not in CONTINUATIONS:
                    if not decorated and not first:
                        out.append(line_starts[token.start[0] - 1])
                    first = False
                    decorated = token.string == "@"
                at_start = False
        except (tokenize.TokenError, IndentationError, SyntaxError):
            # S2: a fallback; the next reader (or SOURCE.UNPARSED for running files) reads it
            pass  # the text stops inside a statement: the starts before it stand
        return sorted(set(out))

    @staticmethod
    def last_cut(data: bytes) -> int:
        """The byte offset of the last top-level statement start in `data` past its first byte, or
        0 where `data` is one statement (it cannot be cut there)."""
        # Every byte kept as a character (a stray byte as a lone surrogate), so a character offset
        # maps back to the byte it came from. The tokenizer encodes its text as UTF-8, which a lone
        # surrogate cannot be (pkqer 1: an internal error, no report), so it reads each stray byte
        # as U+FFFD instead: one character for one, the offsets unchanged.
        try:
            text = seen = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("utf-8", "surrogateescape")
            seen = text.translate(PythonStatements.STRAY_BYTES)
        starts = [s for s in PythonStatements.starts(seen) if s > 0]
        if not starts:
            return 0
        return len(text[: starts[-1]].encode("utf-8", "surrogateescape"))

    @staticmethod
    def may_parse(text: str) -> bool:
        """Whether `text` may parse, read from its tokens alone: its token stream reaches its end
        without breaking. A piece of a file cut at a byte limit inside a string, a bracket or a line
        does not; one cut after a whole line may, and is then parsed as before -- so a piece is only
        ever kept from a reader when it cannot parse (`engine/window_pass.py`)."""
        try:
            for _ in tokenize.generate_tokens(io.StringIO(text).readline):
                pass
        except (tokenize.TokenError, IndentationError, SyntaxError):
            # S2: a fallback; the next reader (or SOURCE.UNPARSED for running files) reads it
            return False
        return True


class StatementScan:
    """Where a module's top-level statements start, read from its characters, with no tokens: what
    item 32's pass 1 cuts a module at. `PythonStatements.starts` asks the tokenizer, which holds a
    copy of the text and of each token: 95 MB for a 13.6 MB module that is one literal, more than
    parsing the whole module (41 MB). This holds the list of starts and nothing else.

    It tracks what decides a line's start: strings (prefixes, triple quotes, escapes, f-strings and
    their nested fields), comments, brackets and backslash continuations. It needs no more than that
    to be safe: a start is only ever a column-0 line, and a cut anywhere but between statements
    leaves a piece that does not parse (inside a string, a bracket, a continued line, before what a
    decorator decorates), which its caller takes as "parse the whole module" (`ModuleFacts.build`).
    A missed start only makes a piece longer. Returns [0] where the text cannot be scanned."""

    WORD_END: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z_]\w*")
    PREFIX: ClassVar[re.Pattern[str]] = re.compile(r"(?i)(?:rb|br|fr|rf|b|r|u|f)$")
    #: What a scan has to stop at inside code: a string's quote, a comment, a bracket, a backslash,
    #: a line's end.
    STOPS: ClassVar[re.Pattern[str]] = re.compile(r"""['"#()\[\]{}\\\n]""")
    #: Inside a string: an escape, a line's end, the quote, and in an f-string a field's `{`.
    STRING_STOPS: ClassVar[dict[tuple[str, bool], re.Pattern[str]]] = {
        (quote, formatted): re.compile("[\\\\\n" + quote + ("{" if formatted else "") + "]")
        for quote in "'\""
        for formatted in (False, True)
    }
    #: Inside an f-string's field: a nested string's quote, or a bracket.
    FIELD_STOPS: ClassVar[re.Pattern[str]] = re.compile(r"""['"(\[{)\]}]""")

    def __init__(self, text: str) -> None:
        self.text = text
        self.at = 0

    @staticmethod
    def starts(text: str) -> list[int]:
        scan = StatementScan(text)
        try:
            return scan.run()
        except ValueError:
            return [0]  # an unterminated string or bracket: one piece, the whole module

    def run(self) -> list[int]:
        text, out = self.text, [0]
        first, decorated = True, False
        line = 0
        while line < len(text):
            head = self.statement_head(line)
            if head is not None:
                word = self.WORD_END.match(text, head)
                keyword = word.group() if word else ""
                if keyword not in CONTINUATIONS:
                    if not first and not decorated:
                        out.append(line)
                    first = False
                    decorated = text.startswith("@", head)
            self.at = line
            line = self.logical_line_end()
        return out

    def statement_head(self, line: int) -> int | None:
        """Where a statement's first character is, if the line at `line` starts one at column 0."""
        if line >= len(self.text):
            return None
        char = self.text[line]
        if char in " \t\f\r\n#\\":
            return None
        return line

    def logical_line_end(self) -> int:
        """From `self.at`, the start of the next physical line that begins a new logical line:
        past strings, brackets and backslash continuations."""
        text, depth = self.text, 0
        while True:
            found = self.STOPS.search(text, self.at)
            if found is None:
                if depth:
                    raise ValueError("a bracket left open")
                return len(text)
            char, self.at = found.group(), found.end()
            if char == "\n":
                if depth == 0:
                    return self.at
            elif char == "#":
                end = text.find("\n", self.at)
                self.at = len(text) if end == -1 else end
            elif char == "\\":
                self.at += 1  # a backslash continues the line, or escapes what follows it
            elif char in "([{":
                depth += 1
            elif char in ")]}":
                depth = max(depth - 1, 0)
            else:
                self.string(found.start())

    def string(self, quote_at: int) -> None:
        """Past the string whose opening quote is at `quote_at`, `self.at` left after its end."""
        text = self.text
        prefix = self.PREFIX.search(text, max(0, quote_at - 2), quote_at)
        before = prefix.start() - 1 if prefix else quote_at - 1
        if prefix and before >= 0 and (text[before].isalnum() or text[before] == "_"):
            prefix = None  # `xr"..."`: the letters belong to a name, not a prefix
        formatted = prefix is not None and "f" in prefix.group().lower()
        quote = text[quote_at]
        triple = text.startswith(quote * 3, quote_at)
        closing = quote * 3 if triple else quote
        self.at = quote_at + len(closing)
        while True:
            found = self.STRING_STOPS[quote, formatted].search(text, self.at)
            if found is None:
                raise ValueError("a string left open")
            char, self.at = found.group(), found.end()
            if char == "\\":
                self.at += 1  # an escaped character, the quote and the line's end included
            elif char == "\n":
                if not triple:
                    raise ValueError("a string left open at its line's end")
            elif char == "{":
                if text.startswith("{", self.at):
                    self.at += 1  # `{{` is a brace, not a field
                else:
                    self.field()
            elif text.startswith(closing, found.start()):
                self.at = found.start() + len(closing)
                return

    def field(self) -> None:
        """Past an f-string's replacement field, whose `{` was just read: code, with its own strings
        and brackets, to the `}` that closes it (a format spec's nested fields balance)."""
        text, depth = self.text, 0
        while True:
            found = self.FIELD_STOPS.search(text, self.at)
            if found is None:
                raise ValueError("an f-string field left open")
            char, self.at = found.group(), found.end()
            if char in "([{":
                depth += 1
            elif char in ")]}":
                if depth == 0 and char == "}":
                    return
                depth = max(depth - 1, 0)
            else:
                self.string(found.start())


# Whether a file Python 3 will not parse fails on a construct only Python 2 accepts (item 27).
#
# A `setup.py` written for Python 2 cannot run on Python 3: pip on Python 3 fails on the same line,
# so its install hooks never run there, and reading it as "a manifest we could not read" blocked
# benign packages (10 of 4,609 PyPI units in item 27's count). It is said instead: not Python 3,
# naming the construct. Never from the SyntaxError alone, which is also what syntax newer than this
# interpreter gives (a template string scanned on 3.12 runs on 3.14): only a construct no Python 3
# accepts, found in the token stream on the very line the parse failed.
#
# ```
#   print "x"        exec "code"        exec code in ns
#   except A, e:     raise E, "msg"     `x`                a <> b
#   0777             ur"text"
# ```
STATEMENT_WORDS = {"print": "a print statement", "exec": "an exec statement"}
LEGACY_PREFIXES = frozenset({"ur", "UR", "Ur", "uR"})
# the tokenizer's own refusals that only Python 2 source produces
LEGACY_REFUSALS = {
    "leading zeros in decimal integer literals": "an octal literal written 0777",
    "`": "a backtick repr",
    # Python 3.14's tokenizer refuses the prefix pair itself, before any string token exists.
    "'u' and 'r' prefixes are incompatible": "a ur'' string",
}


class PythonTwo:
    @staticmethod
    def construct(text: str, line: int | None) -> str | None:
        """The Python 2 construct on `line` (1-based, the parse error's) that no Python 3 accepts,
        or None when there is none there."""
        if line is None:
            return None
        found: str | None = None
        try:
            tokens = tokenize.generate_tokens(io.StringIO(text).readline)
            at_start, depth, statement = True, 0, ""
            opener: tokenize.TokenInfo | None = None
            previous: tokenize.TokenInfo | None = None
            for token in tokens:
                if token.start[0] > line:
                    break
                if token.type in (tokenize.NL, tokenize.COMMENT, tokenize.INDENT, tokenize.DEDENT):
                    continue
                if token.type == tokenize.NEWLINE:
                    at_start, depth, statement, opener = True, 0, "", None
                    previous = token
                    continue
                on_line = token.start[0] == line
                if at_start:
                    opener = token
                    statement = token.string if token.type == tokenize.NAME else ""
                if token.type == tokenize.OP and token.string in "([{":
                    depth += 1
                elif token.type == tokenize.OP and token.string in ")]}":
                    depth -= 1
                if on_line and found is None:
                    found = PythonTwo._at(token, previous, previous is opener, depth, statement)
                at_start = False
                previous = token
        except (tokenize.TokenError, IndentationError, SyntaxError) as exc:
            # S2: a fallback; the next reader (or SOURCE.UNPARSED for running files) reads it
            where = getattr(exc, "lineno", None)
            if where is None and len(exc.args) > 1 and isinstance(exc.args[1], tuple):
                where = exc.args[1][0]  # a TokenError carries its (line, column) as an argument
            if found is None and where == line:
                text_of = str(exc)
                found = next(
                    (what for key, what in LEGACY_REFUSALS.items() if key in text_of), None
                )
        return found

    @staticmethod
    def _at(
        token: tokenize.TokenInfo,
        previous: tokenize.TokenInfo | None,
        after_opener: bool,
        depth: int,
        statement: str,
    ) -> str | None:
        if token.type == tokenize.OP and token.string == "<>":
            return "the <> operator"
        if (
            # Python 3.14 tokenizes `<>` as `<` then `>`, touching.
            token.type == tokenize.OP
            and token.string == ">"
            and previous is not None
            and previous.type == tokenize.OP
            and previous.string == "<"
            and previous.end == token.start
        ):
            return "the <> operator"
        if token.string == "`" and token.type in (tokenize.OP, tokenize.ERRORTOKEN):
            return "a backtick repr"
        if (
            token.type == tokenize.NUMBER
            and len(token.string) > 1
            and token.string[0] == "0"
            and token.string.isdigit()
            and token.string.strip("0")
        ):
            return "an octal literal written 0777"  # `00` is Python 3 too; `0777` is not
        if (
            # Python 3.11 tokenizes `0777` as `0` then `777`, touching, and does not refuse it.
            token.type == tokenize.NUMBER
            and token.string.isdigit()
            and previous is not None
            and previous.type == tokenize.NUMBER
            and previous.string == "0"
            and previous.end == token.start
        ):
            return "an octal literal written 0777"
        if (
            token.type == tokenize.STRING
            and previous is not None
            and previous.type == tokenize.NAME
            and previous.string in LEGACY_PREFIXES
            and previous.end == token.start
        ):
            return "a ur'' string"
        if (
            previous is not None
            and previous.type == tokenize.NAME
            and previous.string in STATEMENT_WORDS
            and after_opener  # the word opens the statement: `print "x"`, not `f(print)`
            and (
                token.type in (tokenize.STRING, tokenize.NAME, tokenize.NUMBER)
                or (token.type == tokenize.OP and token.string == ">>")
            )
        ):
            return STATEMENT_WORDS[previous.string]
        if token.type == tokenize.OP and token.string == "," and depth == 0:
            if statement == "except":
                return "except A, e"
            if statement == "raise":
                return "raise E, value"
        return None


__all__ = ["CONTINUATIONS", "PythonStatements", "PythonTwo", "StatementScan"]
