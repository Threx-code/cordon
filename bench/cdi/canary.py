"""Canary units in every batch of a measurement run.

A batch of scans can go wrong without any single result looking wrong: a scanner started in a bad environment, a cache from
another run, a changed limit. So each batch carries a few canary units whose result is known beforehand (a unit that must be
blocked, a unit that must come back clear). After the batch:

    valid        every canary is present and gave the expected result
    invalid      a canary deviated, or one is missing, or the batch has fewer canaries than required

An invalid batch is thrown away whole: none of its rows count, and the run says which canaries deviated (by canary name, never by
what the unit was). Nothing here reads a package: a canary is a name and an expected outcome."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, Final

EXPECTED: Final = ("blocked", "clear")
MIN_CANARIES: Final = 2


class BadCanary(ValueError):
    """A canary is declared with an outcome that is neither blocked nor clear, or the set is too small to catch a drift."""


class Canaries:
    @staticmethod
    def declare(expected: Mapping[str, str], minimum: int = MIN_CANARIES) -> dict[str, str]:
        """The canaries of a run: name -> the result that is expected. At least one must be blocked and one clear."""
        for name, outcome in expected.items():
            if outcome not in EXPECTED:
                raise BadCanary(f"canary {name!r} expects {outcome!r}: blocked or clear")
        if len(expected) < minimum or set(expected.values()) != set(EXPECTED):
            raise BadCanary(f"a batch needs at least {minimum} canaries, one that must be blocked and one that must be clear")
        return dict(expected)

    @staticmethod
    def check(batch: Iterable[Mapping[str, Any]], expected: Mapping[str, str]) -> dict[str, Any]:
        """The verdict on one batch. A row is `{"unit": name, "outcome": "blocked" | "clear" | other}`."""
        seen: dict[str, str] = {}
        for row in batch:
            if row.get("unit") in expected:
                seen[str(row["unit"])] = str(row.get("outcome"))
        missing = sorted(name for name in expected if name not in seen)
        deviating = sorted(name for name, got in seen.items() if got != expected[name])
        return {
            "valid": not missing and not deviating,
            "deviating": deviating,
            "missing": missing,
            "canaries": len(expected),
        }

    @classmethod
    def keep(cls, batches: Iterable[list[dict[str, Any]]], expected: Mapping[str, str]) -> dict[str, Any]:
        """The rows of the valid batches (canaries left out) and a verdict for each batch, in order."""
        kept: list[dict[str, Any]] = []
        verdicts = []
        for batch in batches:
            verdict = cls.check(batch, expected)
            verdicts.append(verdict)
            if verdict["valid"]:
                kept.extend(row for row in batch if row.get("unit") not in expected)
        return {"rows": kept, "batches": verdicts, "invalidated": sum(1 for v in verdicts if not v["valid"])}
