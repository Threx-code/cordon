"""The automatic pre-test of a candidate rule before it ships, and the records it leaves.

`PreTest.decide` is the bar per ecosystem: the candidate must catch three or more families out of the family it was
learned from, fire on legitimate units at a rate whose Wilson upper bound is within 0.5%, and run within the time budget.
A candidate under the bar is dropped with a record that says which clause it failed; one over it proceeds, with the same
numbers recorded. `PreTest.phrase_family` turns a store of agent-text by family into one family pattern, or refuses.
`PreTest.phrase_record` is the record of a phrase rule: its legitimate-text rate on masked text and on unmasked text, and
the masking version both were measured under.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Collection, Mapping, Sequence
from typing import Any, ClassVar

from bench.cdi.factstore import FactStore
from bench.cdi.gate import Gate


class PreTest:
    MIN_FAMILIES: ClassVar[int] = 3
    LEGIT_UPPER: ClassVar[float] = 0.005
    PHRASE_WORDS: ClassVar[int] = 4

    @staticmethod
    def legit_bound(hits: int, units: int) -> float:
        """The upper end of the 95% Wilson interval of `hits` legitimate fires in `units` units."""
        return Gate.wilson(hits, units)[1]

    @classmethod
    def decide(
        cls,
        candidate: str,
        ecosystem: str,
        *,
        families_caught: Sequence[str],
        own_family: str,
        legit_hits: int,
        legit_units: int,
        milliseconds: float,
        budget_ms: float,
        store: FactStore | None = None,
        reads: Collection[str] = (),
        term_version: str = "",
    ) -> dict[str, Any]:
        """`{"decision": "proceed" | "drop" | "refused", "reasons": [...], numbers...}` for one candidate in one ecosystem.

        With the `store` the numbers were measured on, a candidate that reads a fact the store lacks, or terms of another
        version, is refused before any number is read: it stops here with the reason."""
        out_of_family = sorted(set(families_caught) - {own_family})
        if store is not None and (why := store.refuses(reads, term_version)) is not None:
            return {
                "candidate": candidate,
                "ecosystem": ecosystem,
                "decision": "refused",
                "reasons": [why],
                "families_out_of_family": out_of_family,
            }
        _, upper = Gate.wilson(legit_hits, legit_units)
        reasons = []
        if len(out_of_family) < cls.MIN_FAMILIES:
            reasons.append(
                f"{len(out_of_family)} families out of family, fewer than {cls.MIN_FAMILIES}"
            )
        if upper > cls.LEGIT_UPPER:
            reasons.append(
                f"legitimate rate {legit_hits}/{legit_units} has upper bound {upper:.4f}, over {cls.LEGIT_UPPER}"
            )
        if milliseconds > budget_ms:
            reasons.append(f"{milliseconds} ms is over the budget of {budget_ms} ms")
        return {
            "candidate": candidate,
            "ecosystem": ecosystem,
            "decision": "drop" if reasons else "proceed",
            "reasons": reasons,
            "families_out_of_family": out_of_family,
            "legit": {"k": legit_hits, "n": legit_units, "upper": round(upper, 6)},
            "milliseconds": milliseconds,
            "budget_ms": budget_ms,
        }

    @classmethod
    def phrase_family(
        cls, store: Mapping[str, Sequence[str]], legit: Sequence[str], legit_budget: int
    ) -> dict[str, Any]:
        """One pattern for the phrase that three or more families share, within `legit_budget` legitimate texts.

        Raises `ValueError` when no phrase is shared by `MIN_FAMILIES` families (a single-family phrase is a
        signature, not a family pattern) or when the pattern fires on more legitimate texts than the budget."""
        seen: dict[str, set[str]] = defaultdict(set)
        for family, texts in store.items():
            for text in texts:
                words = re.findall(r"[a-z0-9']+", text.lower())
                for i in range(len(words) - cls.PHRASE_WORDS + 1):
                    seen[" ".join(words[i : i + cls.PHRASE_WORDS])].add(family)
        shared = sorted(
            (p for p, f in seen.items() if len(f) >= cls.MIN_FAMILIES),
            key=lambda p: (-len(seen[p]), p),
        )
        if not shared:
            raise ValueError(
                f"no phrase is shared by {cls.MIN_FAMILIES} families: a single-family phrase is not a family pattern"
            )
        phrase = shared[0]
        pattern = r"\s+".join(re.escape(word) for word in phrase.split())
        hits = sum(1 for text in legit if re.search(pattern, text, re.IGNORECASE))
        if hits > legit_budget:
            raise ValueError(
                f"the pattern fires on {hits} legitimate texts, over the budget of {legit_budget}"
            )
        return {
            "pattern": pattern,
            "phrase": phrase,
            "families": sorted(seen[phrase]),
            "legit_hits": hits,
            "linear": cls.linear(pattern),
        }

    @staticmethod
    def linear(pattern: str) -> bool:
        """Whether the pattern has no quantified group and no alternation: a run of literals and `\\s+`, linear in the text."""
        stripped = pattern.replace(r"\s+", "")
        return not re.search(r"[(|)*+?{]", re.sub(r"\\.", "", stripped))

    @staticmethod
    def phrase_record(
        rule: str, masked: float, unmasked: float, masking_version: str
    ) -> dict[str, Any]:
        """The record of a phrase rule: both legitimate-text rates and the masking version they were measured under."""
        for name, value in (("masked", masked), ("unmasked", unmasked)):
            if not 0 <= value <= 1:
                raise ValueError(f"the {name} rate is a share between 0 and 1")
        if not masking_version:
            raise ValueError("a phrase rule's record names the masking version")
        return {
            "rule": rule,
            "legit_rate_masked": masked,
            "legit_rate_unmasked": unmasked,
            "masking_version": masking_version,
        }
