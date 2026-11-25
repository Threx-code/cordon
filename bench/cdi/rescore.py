"""The gate re-scores a candidate from the rows (learning loop row LL-52: generator bugs are caught by replay, not trusted).

A generator states what it found: how many families the predicate covers, its legit fire bound, on the train rows and again on the
confirm rows. A bug in the generator (a wrong mask, a split mixed up, a bound computed on the wrong rows) would state a number the
rows do not give. So the gate recomputes every stated number from the same labelled rows and the thresholds the candidate records
(`Distiller.params`, in its search record), and a candidate whose claim differs from the re-score is rejected, naming the field.

    check     recompute the stated numbers for the stated predicate; any difference is a `ClaimMismatch`
    replay    run the whole distillation again with the recorded thresholds; the same rows must give the same candidate

The rows go through the same leakage gates as the generator's (`bench/cdi/leakage.py`), so rows a generator may not read are not
scored either. Facts only: nothing here reads a package."""

from __future__ import annotations

import hashlib
from statistics import NormalDist
from typing import TYPE_CHECKING, Any

from bench.cdi.distill import Distillation, Distiller, Terms, _Space
from bench.cdi.leakage import Leakage

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from bench.cdi.distill import Unit


class ClaimMismatch(ValueError):
    """A candidate's stated numbers differ from the re-score. `fields` names which."""

    def __init__(self, fields: tuple[str, ...]) -> None:
        super().__init__("the candidate's claim differs from the re-score in: " + ", ".join(fields))
        self.fields = fields


class Rescore:
    @staticmethod
    def claims(
        candidate: dict[str, Any],
        search: dict[str, Any],
        units: Iterable[Unit],
        refused_families: frozenset[str] = frozenset(),
        terms_of: Callable[[dict[str, Any]], set[tuple[str, ...]]] | None = None,
    ) -> dict[str, Any]:
        """The numbers the rows give for the candidate's predicate, in the shape of the candidate's own."""
        params = Rescore.params(search, refused_families)
        allowed, _refused = Leakage.admit(units)
        kept = [u for u in allowed if not (u.label == "mal" and u.family in refused_families)]
        reader = terms_of or Terms.of
        predicate = tuple(tuple(str(t) for t in term) for term in candidate["predicate"])
        z = NormalDist().inv_cdf(1 - params["alpha"] / max(1, int(search["candidates"])))
        z_confirm = NormalDist().inv_cdf(1 - params["alpha"])
        train = _Space([u for u in kept if u.split == "train"], reader)
        confirm = _Space([u for u in kept if u.split == "confirm"], reader)
        train_upper, worst = train.legit_upper(predicate, z)
        confirm_upper, _w = confirm.legit_upper(predicate, z_confirm)
        return {
            "generator": params["generator"],
            "predicate_digest": Terms.digest(predicate),
            "size": len(predicate),
            "train": {
                "legit_units": train.legit_mask.bit_count(),
                "legit_hits": train.legit_fires(train.mask_of(predicate)),
                "families": train.families(train.mask_of(predicate)),
                "legit_upper": round(train_upper, 6),
                "worst_stratum_upper": worst,
            },
            "confirm": {
                "families": confirm.families(confirm.mask_of(predicate)),
                "legit_upper": round(confirm_upper, 6),
                "legit_fires": confirm.legit_fires(confirm.mask_of(predicate)),
                "legit_n": confirm.legit_mask.bit_count(),
            },
        }

    @staticmethod
    def check(
        candidate: dict[str, Any],
        search: dict[str, Any],
        units: Iterable[Unit],
        refused_families: frozenset[str] = frozenset(),
        terms_of: Callable[[dict[str, Any]], set[tuple[str, ...]]] | None = None,
    ) -> None:
        """Raise `ClaimMismatch` unless every stated number is the one the rows give."""
        recomputed = Rescore.claims(candidate, search, units, refused_families, terms_of)
        differing = []
        for name in ("generator", "predicate_digest", "size"):
            if candidate.get(name) != recomputed[name]:
                differing.append(name)
        for part in ("train", "confirm"):
            stated = candidate.get(part, {})
            for name, value in recomputed[part].items():
                if stated.get(name) != value:
                    differing.append(f"{part}.{name}")
        if differing:
            raise ClaimMismatch(tuple(differing))

    @staticmethod
    def replay(
        search: dict[str, Any],
        units: Iterable[Unit],
        refused_families: frozenset[str] = frozenset(),
        terms_of: Callable[[dict[str, Any]], set[tuple[str, ...]]] | None = None,
    ) -> Distillation:
        """The distillation run again with the thresholds the search record states."""
        params = Rescore.params(search, refused_families)
        return Distiller(
            min_families=params["min_families"],
            confirm_min_families=params["confirm_min_families"],
            budget=params["budget"],
            max_size=params["max_size"],
            max_terms=params["max_terms"],
            max_candidates=params["max_candidates"],
            alpha=params["alpha"],
            refused_families=refused_families,
            terms_of=terms_of,
            generator=params["generator"],
            lofo=params["lofo"],
            max_unscored_share=params.get("max_unscored_share", 0.02),
            min_legit_for_bar=params.get("min_legit_for_bar", 740),
        ).distill(list(units))

    @staticmethod
    def params(search: dict[str, Any], refused_families: frozenset[str]) -> dict[str, Any]:
        """The recorded thresholds, if the record has them and the refused families are the ones it was made with."""
        params = search.get("params")
        if not isinstance(params, dict):
            raise ValueError("this search record states no thresholds, so it cannot be replayed")
        digest = hashlib.sha256("\n".join(sorted(refused_families)).encode("utf-8")).hexdigest()
        if digest != params.get("refused_families_digest"):
            raise ValueError("the refused families are not the ones this candidate was made with")
        return params
