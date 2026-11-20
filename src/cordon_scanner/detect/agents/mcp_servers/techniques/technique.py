"""One attack technique as a row: the shapes it takes in source text, what else must be there, what makes it
something else, and the inert fixtures that say what is and is not an instance."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from cordon_scanner.foundation.models import Confidence, Severity

#: A fixture: (file suffix, source text).
Fixture = tuple[str, str]


@dataclass(frozen=True, slots=True)
class Technique:
    rule_id: str
    family: str
    title: str
    message: str
    remediation: str
    patterns: tuple[str, ...]
    requires: tuple[str, ...] = ()
    unless: tuple[str, ...] = ()
    at_least: int = 1
    severity: Severity = Severity.HIGH
    confidence: Confidence = Confidence.MEDIUM
    positive: tuple[Fixture, ...] = ()
    negative: tuple[Fixture, ...] = ()
    #: Compiled once: the patterns, the required and the excluding shapes.
    _compiled: tuple[
        tuple[re.Pattern[str], ...], tuple[re.Pattern[str], ...], tuple[re.Pattern[str], ...]
    ] = field(default=((), (), ()), compare=False, repr=False)

    def __post_init__(self) -> None:
        flags = re.IGNORECASE
        object.__setattr__(
            self,
            "_compiled",
            (
                tuple(re.compile(p, flags) for p in self.patterns),
                tuple(re.compile(p, flags) for p in self.requires),
                tuple(re.compile(p, flags) for p in self.unless),
            ),
        )

    def find(self, text: str) -> tuple[int, int] | None:
        """The span of the first shape that matches, when the technique is in `text`, else None."""
        patterns, requires, unless = self._compiled
        first: re.Match[str] | None = None
        found = 0
        for pattern in patterns:
            match = pattern.search(text)
            if match is not None:
                found += 1
                first = first or match
        if first is None or found < self.at_least:
            return None
        if any(r.search(text) is None for r in requires) or any(u.search(text) for u in unless):
            return None
        return first.start(), first.end()


__all__ = ["Fixture", "Technique"]
