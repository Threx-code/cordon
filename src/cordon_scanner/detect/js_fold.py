"""JavaScript names split into string fragments, joined back: `'chi'+'ld_pro'+'cess'`.

Splitting a name into pieces is the cheapest disguise there is, and every pattern that looks for
`child_process`, `spawn` or `rundll32` misses it. The compromised `eslint-config-prettier` releases
(2025) launched a bundled DLL from `postinstall` as
`require('chi'+'ld_pro'+'cess')["sp"+"awn"]("rund"+"ll32", ...)` and nothing matched (review 98).
Python's analysis already folds constants; this is the same view for JavaScript.

Only fragments fold: two adjacent literals, each a run of name characters, at least one of them
short. That is the shape of a split word. Ordinary concatenation -- a URL built from a base and a
path, a message from sentences -- joins pieces that are long or carry spaces and punctuation, and
stays as it is, so a bundle full of it is read as it was.

The folded text keeps every line where it was: the newlines a join swallowed are written back after
it, so a line number found in the fold is the line in the file.
"""

from __future__ import annotations

import re
from typing import Final

_FRAGMENT: Final = r"[\w.$-]{1,40}"


def _literal(name: str) -> str:
    """A quoted fragment, either quote, captured as `<name>s` or `<name>d` (no backreference)."""
    return rf"""(?:'(?P<{name}s>{_FRAGMENT})'|"(?P<{name}d>{_FRAGMENT})")"""


_PAIR: Final = re.compile(_literal("a") + r"\s{0,8}\+\s{0,8}" + _literal("b"))
SHORT: Final = 8
"""A piece this long or shorter is a fragment of a word, not a word."""
MAX_PASSES: Final = 6
"""`'a'+'b'+'c'+'d'` folds pairwise, one join per pass."""


class JsFold:
    @staticmethod
    def _pieces(match: re.Match[str]) -> tuple[str, str]:
        return (
            match.group("as") or match.group("ad") or "",
            match.group("bs") or match.group("bd") or "",
        )

    @staticmethod
    def has_fragments(text: str) -> bool:
        return any(min(map(len, JsFold._pieces(m))) <= SHORT for m in _PAIR.finditer(text))

    @staticmethod
    def fold(text: str) -> str:
        """`text` with adjacent short-fragment literals joined, lines kept in place."""

        def join(match: re.Match[str]) -> str:
            left, right = JsFold._pieces(match)
            if min(len(left), len(right)) > SHORT:
                return match.group(0)
            quote = "'" if match.group("as") is not None else '"'
            return f"{quote}{left}{right}{quote}" + "\n" * match.group(0).count("\n")

        for _ in range(MAX_PASSES):
            folded = _PAIR.sub(join, text)
            if folded == text:
                break
            text = folded
        return text
