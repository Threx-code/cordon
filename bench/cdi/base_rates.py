"""How common a behaviour class is among established legitimate packages, and what that lets it do.

A behaviour (a package that runs a command at install, reads an environment variable, opens a socket) is a class. A
class that many legitimate packages show is no evidence of malice on its own: labelling a package malicious for it would
block those legitimate packages too. So each class has a BASE RATE on established legitimate packages, with its 95%
interval, and a class whose base rate may be above its ceiling cannot make a malicious label alone: it can only add to
other evidence.

The ceiling is the benign upper bar the gate is held to (`benign_ub_bar`): a rule that alone fires on more legitimate
packages than that would break the gate. "May be above" is read on the interval's upper bound, so a class counted on too
few packages to be sure is held back too: nothing is allowed to label alone on a guess.
"""

from __future__ import annotations

from typing import Any, Final

from bench.cdi.gate import DEFAULT_POLICY, Gate

CEILING: Final[float] = DEFAULT_POLICY["benign_ub_bar"]
MIN_LEGIT: Final = DEFAULT_POLICY["min_benign_n_for_bar"]
"""The fewest established legitimate packages a class's base rate may be counted on to be believed."""


class BaseRates:
    @staticmethod
    def rate(k: int, n: int) -> dict[str, Any] | None:
        """`k` of `n` established legitimate packages show the class, with the interval; None when none were counted."""
        if n <= 0:
            return None
        low, high = Gate.wilson(k, n)
        return {"k": k, "n": n, "value": k / n, "low": low, "high": high}

    @classmethod
    def table(cls, counts: dict[str, tuple[int, int]]) -> dict[str, dict[str, Any]]:
        """`{class: (legit packages with it, established legit packages counted)}` -> each class's base rate and whether it
        may label alone."""
        out = {}
        for name, (k, n) in sorted(counts.items()):
            rate = cls.rate(k, n)
            out[name] = {"rate": rate, "may_label_alone": cls.may_label_alone(rate)}
        return out

    @staticmethod
    def may_label_alone(rate: dict[str, Any] | None, ceiling: float = CEILING) -> bool:
        """Whether a class is sure to be rarer among legitimate packages than the ceiling: counted on enough of them and
        with an upper bound at or under it."""
        return rate is not None and rate["n"] >= MIN_LEGIT and rate["high"] <= ceiling

    @classmethod
    def label(
        cls, classes: list[str], table: dict[str, dict[str, Any]], other_evidence: bool
    ) -> bool:
        """Whether a package showing `classes` may be labelled malicious: only if some class may label alone, or other,
        independent evidence stands beside them. A class missing from the table has no base rate, so it may not."""
        if other_evidence:
            return bool(classes)
        return any(table.get(name, {}).get("may_label_alone") for name in classes)
