"""When an ecosystem may be claimed at all (sizes and diversity): a held-out split that is too small or too narrow is refused, with the minimum named.

Sizes. Zero misses on n malware units bounds the miss rate (95%, rule of three) at 3/n, so 185 units is the least that supports a claim, and a legitimate block rate of 0.3% needs about 3,000
units to be told from 0.4%. The plan's own sizes are larger: 500 to 1,000 malware, and at least 15,000 legitimate (the whole catalogue when it holds fewer than 100,000). The statistical floors REFUSE;
the plan sizes are reported as `short_of_plan` and never as a pass.

Diversity. A claim rests on many campaigns, not one: no campaign or family above 20% of the held-out malware split, at least 10 distinct campaigns or families, and a development split at least as
large as the held-out one (a model graded on a split larger than the one it was developed on has seen less than it is graded on).
"""

from __future__ import annotations

from collections import Counter
from typing import Final

MALWARE_FLOOR: Final = 185
LEGIT_FLOOR: Final = 3_000
MALWARE_PLAN: Final = 500
LEGIT_PLAN: Final = 15_000
CATALOGUE_WHOLE_BELOW: Final = 100_000
MAX_FAMILY_SHARE: Final = 0.20
MIN_FAMILIES: Final = 10


class ClaimRefused(ValueError):
    """A claim was made on a split that is too small or too narrow; `reasons` names each minimum."""

    def __init__(self, reasons: tuple[str, ...]) -> None:
        super().__init__("refused: " + "; ".join(reasons))
        self.reasons = reasons


class Claims:
    @staticmethod
    def sizes(malware_n: int, legit_n: int) -> tuple[str, ...]:
        """The statistical floors a split is refused below."""
        out = []
        if malware_n < MALWARE_FLOOR:
            out.append(f"malware held-out {malware_n} is below the minimum {MALWARE_FLOOR}")
        if legit_n < LEGIT_FLOOR:
            out.append(f"legitimate held-out {legit_n} is below the minimum {LEGIT_FLOOR}")
        return tuple(out)

    @staticmethod
    def short_of_plan(
        malware_n: int, legit_n: int, catalogue: int | None = None
    ) -> tuple[str, ...]:
        """Where a split passes the floors and is still under the plan's size. The legitimate plan is the whole catalogue when it holds fewer than 100,000 units."""
        out = []
        if malware_n < MALWARE_PLAN:
            out.append(f"malware held-out {malware_n} is short of the plan {MALWARE_PLAN}")
        plan = (
            catalogue if catalogue is not None and catalogue < CATALOGUE_WHOLE_BELOW else LEGIT_PLAN
        )
        if legit_n < plan:
            out.append(f"legitimate held-out {legit_n} is short of the plan {plan}")
        return tuple(out)

    @staticmethod
    def diversity(held_families: list[str], dev_malware_n: int) -> tuple[str, ...]:
        """One family per held-out malware unit, and the size of the development split. Empty when the split is diverse enough."""
        out = []
        counts = Counter(held_families)
        total = len(held_families)
        if len(counts) < MIN_FAMILIES:
            out.append(
                f"{len(counts)} distinct campaigns or families, the minimum is {MIN_FAMILIES}"
            )
        if total:
            top = max(counts.values())
            if top / total > MAX_FAMILY_SHARE:
                out.append(
                    f"one campaign or family holds {top} of {total} held-out units ({top / total:.0%}), the most allowed is {MAX_FAMILY_SHARE:.0%}"
                )
        if dev_malware_n < total:
            out.append(
                f"the development split ({dev_malware_n}) is smaller than the held-out one ({total})"
            )
        return tuple(out)

    @staticmethod
    def require(
        held_families: list[str],
        dev_malware_n: int,
        legit_n: int,
        catalogue: int | None = None,
    ) -> dict[str, tuple[str, ...]]:
        """Refuse a claim (`ClaimRefused`) on a split below a floor or lacking diversity; otherwise return what is short of the plan."""
        reasons = Claims.sizes(len(held_families), legit_n) + Claims.diversity(
            held_families, dev_malware_n
        )
        if reasons:
            raise ClaimRefused(reasons)
        return {"short_of_plan": Claims.short_of_plan(len(held_families), legit_n, catalogue)}
