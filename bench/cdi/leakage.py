"""The leakage gates (learning loop row LL-43; SI-Q8 and SI-Q9): what a generator or a retrain may read.

A release informs a generator only when its label tier is confirmed or corroborated AND its split is one a generator may use. Every
other release (silver labels, val, held, fresh, sealed, excluded) is refused, and the refusal names why, so a window's report can
say how many were kept out and for which reason instead of dropping them silently.

The split names are the dataset manifests' (`Schemas.FACTORY_SPLITS`: train, dev). The distiller carves its own `confirm` rows out of
the dev data to re-measure a chosen predicate, so a generator's list adds that one name (`GENERATOR_SPLITS`).

The tier gate is about labels of MALICIOUS releases: an established legit release has no tier to fail, but its split is checked the
same way, because a sealed legit set must not tune a legit rate either."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Any, Final

from bench.cdi.schemas import FACTORY_SPLITS, FACTORY_TIERS

if TYPE_CHECKING:
    from collections.abc import Iterable

#: The splits a generator may read: the factory's, plus the distiller's own confirm carve-out of the dev rows.
GENERATOR_SPLITS: Final = FACTORY_SPLITS | {"confirm"}


class LeakageRefused(ValueError):
    """A release that may not inform a generator was offered to one. `reasons` says why, in the report's own words."""

    def __init__(self, reasons: tuple[str, ...]) -> None:
        super().__init__("refused: " + ", ".join(reasons))
        self.reasons = reasons


class Leakage:
    @staticmethod
    def reasons(
        split: str,
        tier: str | None = None,
        splits: frozenset[str] = GENERATOR_SPLITS,
    ) -> tuple[str, ...]:
        """Why a release may not inform a generator (empty: it may). `tier` is None for a legit release."""
        out = []
        if tier is not None and tier not in FACTORY_TIERS:
            out.append(f"label_tier_{tier}")
        if split not in splits:
            out.append(f"split_{split}")
        return tuple(out)

    @staticmethod
    def require(
        split: str, tier: str | None = None, splits: frozenset[str] = GENERATOR_SPLITS
    ) -> None:
        """For a caller offered one release at a time: raise `LeakageRefused` rather than return."""
        reasons = Leakage.reasons(split, tier, splits)
        if reasons:
            raise LeakageRefused(reasons)

    @staticmethod
    def admit(
        units: Iterable[Any], splits: frozenset[str] = GENERATOR_SPLITS
    ) -> tuple[list[Any], Counter[str]]:
        """The units a generator may read, and the count of each reason for the rest. A unit has `split`, `label`
        (`mal` for a malicious release) and `label_tier`."""
        kept: list[Any] = []
        refused: Counter[str] = Counter()
        for unit in units:
            tier = unit.label_tier if unit.label == "mal" else None
            reasons = Leakage.reasons(unit.split, tier, splits)
            if reasons:
                refused.update(reasons)
            else:
                kept.append(unit)
        return kept, refused
