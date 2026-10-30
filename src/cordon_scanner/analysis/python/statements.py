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

CONTINUATIONS = frozenset({"else", "elif", "except", "finally"})
"""Keywords at depth 0 that continue the compound statement before them."""


class PythonStatements:
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
        # maps back to the byte it came from.
        text = data.decode("utf-8", "surrogateescape")
        starts = [s for s in PythonStatements.starts(text) if s > 0]
        if not starts:
            return 0
        return len(text[: starts[-1]].encode("utf-8", "surrogateescape"))


__all__ = ["CONTINUATIONS", "PythonStatements"]
