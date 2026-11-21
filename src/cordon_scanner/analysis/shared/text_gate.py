"""The one policy for a search of a file's raw text that decides whether a parsed reader runs.

A prefilter reads the text as written; the reader it guards reads what the language's parser makes
of it. The two differ where the language rewrites the text before it is a name:

- Python reads identifiers NFKC-normalised (PEP 3131): `subprocess.check_output(cmd)` written in
  fullwidth letters is that call, while the text holds none of its words.
- JavaScript reads `\\u0072equire` and `\\u{72}equire` in an identifier as `require`, and the same
  escapes, with `\\x72`, inside a string.

`TextGate.views` gives the readings a gate searches: the text itself, and, only where they can
differ, its NFKC normal form or a copy with the escapes decoded. A gate that finds its words in any
of them opens. Opening more often costs time and loses nothing, so a reading that differs from the
parser's in the other direction (an escape the decoder does not know, a normal form that merges two
names the language keeps apart) only opens a gate the parser would have kept shut. An ASCII Python
text and a JavaScript text without a backslash escape are searched once, as before.
"""

from __future__ import annotations

import functools
import re
import unicodedata
from typing import ClassVar

from cordon_scanner.foundation.collector import ScanCaches


class TextGate:
    #: The languages whose identifiers are NFKC-normalised by their parser.
    NFKC: ClassVar[frozenset[str]] = frozenset({"python"})
    #: The languages whose identifiers and strings take `\u` escapes (and strings `\x`).
    ESCAPED: ClassVar[frozenset[str]] = frozenset({"javascript", "typescript"})

    _ESCAPE: ClassVar[re.Pattern[str]] = re.compile(
        r"\\u\{([0-9A-Fa-f]{1,6})\}|\\u([0-9A-Fa-f]{4})|\\x([0-9A-Fa-f]{2})"
    )

    @staticmethod
    def views(text: str, language: str) -> tuple[str, ...]:
        """The text, and each reading of it the language's parser may make that differs. An ASCII
        Python text, or a script with no escape, is the text alone; the others are read once for
        all of a file's gates (`_read`)."""
        if text.isascii() and (language not in TextGate.ESCAPED or "\\" not in text):
            return (text,)
        return TextGate._read(text, language)

    @staticmethod
    @ScanCaches.register  # holds files' texts: emptied after each scan (foundation/collector)
    @functools.lru_cache(maxsize=8)
    def _read(text: str, language: str) -> tuple[str, ...]:
        cls = TextGate
        out = [text]
        if language in cls.NFKC and not text.isascii():
            normal = unicodedata.normalize("NFKC", text)
            if normal != text:
                out.append(normal)
        if language in cls.ESCAPED and "\\" in text and cls._ESCAPE.search(text):
            out.append(cls._ESCAPE.sub(cls._decoded, text))
        return tuple(out)

    @classmethod
    def may_hold(cls, words: re.Pattern[str] | None, text: str, language: str) -> bool:
        """Whether a reading of `text` holds one of `words` (no words: always)."""
        return words is None or any(words.search(view) for view in cls.views(text, language))

    @classmethod
    def name(cls, name: str, language: str) -> str:
        """A name as the language's parser reads it, for comparing a name taken from the raw text
        with one taken from a parse: the last reading `views` makes of it."""
        return cls.views(name, language)[-1]

    @staticmethod
    def _decoded(match: re.Match[str]) -> str:
        digits = match.group(1) or match.group(2) or match.group(3)
        value = int(digits, 16)
        return chr(value) if value <= 0x10FFFF else match.group(0)


__all__ = ["TextGate"]
