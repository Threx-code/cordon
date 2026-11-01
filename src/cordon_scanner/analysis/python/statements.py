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
        out, depth, at_start, decorated = [0], 0, False, False
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
                    if not decorated:
                        out.append(line_starts[token.start[0] - 1])
                    decorated = token.string == "@"
                at_start = False
        except (tokenize.TokenError, IndentationError, SyntaxError):
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
            return False
        return True


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
            where = getattr(exc, "lineno", None)
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


__all__ = ["CONTINUATIONS", "PythonStatements", "PythonTwo"]
