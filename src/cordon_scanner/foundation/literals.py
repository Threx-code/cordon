"""Whether any of a set of literals occurs in some bytes, with as few scans as the set allows.

A rule's prefilter asks one question of every file: is any of these literals in it? Asked as
`any(literal in data for literal in literals)`, that is one full scan of the file per literal until
one is found -- and since most files hold none, almost always one scan per literal. Across the
capability rules that came to 700 literal scans per file and cost more than the regexes the gates
exist to spare: 23.7 s of gates against 11.8 s of matching over ten thousand files of ordinary
packages.

Two reductions, both exact -- `present` answers what the `any(...)` above answers, always:

    containment   a literal containing another literal of the set is dropped: wherever it
                  occurs, the shorter one occurs too, so it can never be the only one present.
                  (`discordapp` with `discord`; `access_token` with `token`.)

    core          a few short strings, each literal containing one of them. No core string
                  present means no literal can be present, so the answer is False after a
                  handful of scans; only a file holding a core string pays for the full set.
                  (`\\t-rf`, `\\n-rf`, `\\r-rf` ... share `-rf`.) Kept only when it is at most half
                  the size of the set it guards.

         data ──► any core string? ──no──► False
                        │yes
                        ▼
                  any literal? ──► the answer
"""

from __future__ import annotations

from collections import Counter
from typing import ClassVar


class LiteralGate:
    """`any(literal in data for literal in literals)`, answered with fewer scans."""

    CORE_SHORTEST: ClassVar[int] = 3
    """Core strings shorter than this would be in nearly every file and stop nothing."""

    __slots__ = ("core", "literals")

    def __init__(self, literals: tuple[bytes, ...] | list[bytes] | set[bytes]) -> None:
        minimal: list[bytes] = []
        for literal in sorted(set(literals), key=len):
            if not any(kept in literal for kept in minimal):
                minimal.append(literal)
        self.literals: tuple[bytes, ...] = tuple(minimal)
        self.core: tuple[bytes, ...] | None = LiteralGate._core(minimal)

    @staticmethod
    def _core(minimal: list[bytes]) -> tuple[bytes, ...] | None:
        """Short strings each literal contains one of, chosen greedily; None if not worth it."""
        if len(minimal) <= 2 or min(map(len, minimal)) < LiteralGate.CORE_SHORTEST:
            return None
        uncovered = set(minimal)
        chosen: list[bytes] = []
        while uncovered:
            counts: Counter[bytes] = Counter()
            for literal in uncovered:
                counts.update(
                    {
                        literal[start:end]
                        for start in range(len(literal))
                        for end in range(start + LiteralGate.CORE_SHORTEST, len(literal) + 1)
                    }
                )
            best, covered = max(counts.items(), key=lambda item: (item[1], len(item[0]), item[0]))
            if covered == 1:
                chosen.extend(uncovered)
                break
            chosen.append(best)
            uncovered = {literal for literal in uncovered if best not in literal}
        core: list[bytes] = []
        for piece in sorted(set(chosen), key=len):
            if not any(kept in piece for kept in core):
                core.append(piece)
        if len(core) * 2 > len(minimal):
            return None
        return tuple(core)

    def present(self, data: bytes) -> bool:
        """Whether any of the literals occurs in `data`."""
        if self.core is not None and not any(piece in data for piece in self.core):
            return False
        return any(literal in data for literal in self.literals)


__all__ = ["LiteralGate"]
