"""CVSS v3.x base scores, computed from the vector string.

OSV records carry a qualitative severity only where the source writes one (`database_specific`);
many carry just the CVSS vector -- `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` -- and some sources
(Go's database among them) neither. The score follows the FIRST specification exactly, including
its round-up, so a record rates the way NVD and GitHub rate it.
"""

from __future__ import annotations

import math
from typing import Final

_WEIGHTS: Final = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PRIVILEGES: Final = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}


class Cvss:
    """CVSS v3 base scores and their qualitative ratings."""

    @staticmethod
    def _round_up(value: float) -> float:
        """CVSS v3.1's Roundup: the smallest number, to one decimal, at or above the input."""
        integer = round(value * 100_000)
        if integer % 10_000 == 0:
            return integer / 100_000.0
        return (math.floor(integer / 10_000) + 1) / 10.0

    @staticmethod
    def base_score(vector: str) -> float | None:
        """The base score of a CVSS v3.0 or v3.1 vector, or None if it is not one."""
        if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
            return None
        metrics: dict[str, str] = {}
        for part in vector.split("/")[1:]:
            key, _, value = part.partition(":")
            metrics[key] = value
        try:
            scope = metrics["S"]
            av, ac, ui = (
                _WEIGHTS["AV"][metrics["AV"]],
                _WEIGHTS["AC"][metrics["AC"]],
                _WEIGHTS["UI"][metrics["UI"]],
            )
            pr = _PRIVILEGES[scope][metrics["PR"]]
            c, i, a = (_WEIGHTS[k][metrics[k]] for k in ("C", "I", "A"))
        except KeyError:
            return None
        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        if impact <= 0:
            return 0.0
        exploitability = 8.22 * av * ac * pr * ui
        total = impact + exploitability if scope == "U" else 1.08 * (impact + exploitability)
        return Cvss._round_up(min(total, 10.0))

    @staticmethod
    def rating(score: float) -> str:
        """The qualitative rating the specification gives a score."""
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low" if score > 0 else "none"


__all__ = ["Cvss"]
