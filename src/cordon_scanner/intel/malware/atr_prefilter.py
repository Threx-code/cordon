"""Literal text a pattern's every match must contain: the prefilter in front of ATR's regexes.

ATR's rules run every pattern over every view of every agent-facing text, and a package with a few
thousand skill files spent most of a scan there (2.3 million scans, four minutes). Nearly every
pattern needs some plain word to match at all -- `ignore`, `previous instructions`, `system prompt`
-- and a text that holds none of those words cannot match, so the regex is skipped.

It must never skip a match. So it says only what it can show from the parsed pattern and gives up
otherwise: literals are taken from runs the pattern requires (not optional, not one side of an
alternation unless every side has one); a branch counts only when every alternative yields a literal;
and only ASCII literals are used. Every ATR pattern is case-insensitive, and Python's case-insensitive
matching pairs `i` with U+0131 and `s` with U+017F, which no lower-casing reproduces; so the text is
folded by `CaseFold`, built by asking the regex engine itself which characters it matches to each
ASCII letter, and a literal is looked for in that.
"""

from __future__ import annotations

import functools
import re
import string
from typing import Any, Final

MIN_LITERAL: Final = 3
"""Shorter literals filter nothing worth the check."""


class RequiredLiterals:
    """Module operations, grouped as one class (the class-based architecture rule)."""

    @staticmethod
    def of(pattern: str, flags: int) -> tuple[str, ...] | None:
        """Lower-cased ASCII strings at least one of which every match of `pattern` contains, or
        None when that cannot be shown -- and then the pattern always runs."""
        try:
            import re._constants as const  # type: ignore[import-not-found,import-untyped,unused-ignore]
            import re._parser as parser  # type: ignore[import-not-found,import-untyped,unused-ignore]
        except ImportError:  # pragma: no cover - CPython < 3.11 layout
            return None
        try:
            parsed = parser.parse(pattern, flags)
        except Exception:
            return None
        found = RequiredLiterals._sequence(list(parsed), const)
        return tuple(sorted(found)) if found else None

    @staticmethod
    def _better(a: frozenset[str] | None, b: frozenset[str] | None) -> frozenset[str] | None:
        """The more selective of two sufficient needle sets: the longer shortest literal, then fewer."""
        if not a:
            return b
        if not b:
            return a
        key_a = (min(len(s) for s in a), -len(a))
        key_b = (min(len(s) for s in b), -len(b))
        return a if key_a >= key_b else b

    @staticmethod
    def _sequence(items: list[tuple[Any, Any]], const: Any) -> frozenset[str] | None:
        best: frozenset[str] | None = None
        run: list[str] = []

        def close() -> None:
            nonlocal best, run
            if len(run) >= MIN_LITERAL:
                best = RequiredLiterals._better(best, frozenset({"".join(run)}))
            run = []

        for op, value in items:
            if op is const.LITERAL:
                char = chr(value)
                if char.isascii():
                    run.append(char.lower())
                    continue
                close()
                continue
            close()
            inner: frozenset[str] | None = None
            if op is const.SUBPATTERN:
                inner = RequiredLiterals._sequence(list(value[-1]), const)
            elif op in (
                const.MAX_REPEAT,
                const.MIN_REPEAT,
                getattr(const, "POSSESSIVE_REPEAT", None),
            ):
                low, _high, body = value
                if low >= 1:
                    inner = RequiredLiterals._sequence(list(body), const)
            elif op is const.BRANCH:
                alternatives = [RequiredLiterals._sequence(list(b), const) for b in value[1]]
                if alternatives and all(alternatives):
                    inner = frozenset().union(*alternatives)  # type: ignore[arg-type]
            elif op is getattr(const, "ATOMIC_GROUP", None):
                inner = RequiredLiterals._sequence(list(value), const)
            best = RequiredLiterals._better(best, inner)
        close()
        return best

    @staticmethod
    def may_match(needles: tuple[str, ...] | None, folded: str | None) -> bool:
        """False only when the text, folded by `CaseFold`, holds none of the needles."""
        if needles is None or folded is None:
            return True
        return any(needle in folded for needle in needles)


class CaseFold:
    """Text folded so that a case-insensitive ASCII letter is found wherever the regex would match it."""

    @staticmethod
    @functools.cache
    def _table() -> dict[int, str]:
        """Every non-ASCII character the regex engine matches to an ASCII letter under IGNORECASE,
        mapped to that letter. Asked of the engine over every code point, not listed from memory."""
        letters = re.compile(r"[a-z]", re.IGNORECASE)
        everything = "".join(chr(c) for c in range(0x80, 0x110000) if not 0xD800 <= c < 0xE000)
        table: dict[int, str] = {}
        for found in letters.finditer(everything):
            char = found.group()
            for letter in string.ascii_lowercase:
                if re.fullmatch(letter, char, re.IGNORECASE):
                    table[ord(char)] = letter
                    break
        return table

    @staticmethod
    def fold(text: str) -> str:
        """`text` with those characters replaced by their letter, then lower-cased. Lower-casing can
        add characters (U+0130 becomes two) but never removes an ASCII letter, so a literal the regex
        could match is always still there."""
        return text.translate(CaseFold._table()).lower()
