"""G5, structural siblings (learning loop row LL-22): a release shaped like a confirmed malicious family is flagged, and never labelled.

A family's CORE is the set of the scanner's own fact terms (`rules/fact_terms.py`) that all its members share (or that at least
`support` of them share): the shape the family keeps from release to release while its names, hosts and bytes change. A release is a
structural sibling of a family when its signature holds the whole core. That is a detection, a reason to look: the hit carries
`label: None` and no verdict, because a shape is not proof, and a label comes only from the teacher or a person.

A core is used only when it is distinctive:
    * at least `min_core` terms (a family of one boring file has no shape to match);
    * the share of established legit releases whose signature holds the whole core, bounded by Wilson at `z`, is within `budget`;
      a core that ordinary packages also hold would flag them, so it is refused and counted.

Only releases the leakage gates admit form a family (`bench/cdi/leakage.py`: confirmed or corroborated labels, train or dev
splits); the rest are counted by reason. Facts only: nothing here reads a package, and a hit carries a family id and a release key the
loop already holds, never a name, host or path."""

from __future__ import annotations

import math
from dataclasses import dataclass
from statistics import NormalDist
from typing import TYPE_CHECKING, Any, Final

from bench.cdi.census import Signature
from bench.cdi.distill import Wilson
from bench.cdi.leakage import Leakage

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from bench.cdi.distill import Unit

Term = tuple[str, ...]
KIND: Final = "structural_sibling"


@dataclass(frozen=True)
class FamilyCore:
    """What a family keeps: its shared terms, how many members showed them, and how many legit releases hold them all."""

    family: str
    core: frozenset[Term]
    members: frozenset[str]
    legit_fires: int
    legit_units: int


class Siblings:
    def __init__(
        self, *, support: float = 1.0, min_core: int = 3, budget: float = 0.005, alpha: float = 0.05
    ) -> None:
        if not 0.5 < support <= 1.0:
            raise ValueError(
                "a core is what most of a family shares: support is above one half and at most one"
            )
        self.support = support
        self.min_core = min_core
        self.budget = budget
        self.z = NormalDist().inv_cdf(1 - alpha)

    def families(self, units: Iterable[Unit]) -> tuple[list[FamilyCore], dict[str, int]]:
        """The usable family cores of the labelled units, and why every other family or unit was left out, as counts."""
        admitted, refused = Leakage.admit(units)
        counts = dict(refused)
        legit = [Signature.of(u.facts) for u in admitted if u.label == "legit"]
        by_family: dict[str, list[Unit]] = {}
        for unit in admitted:
            if unit.label == "mal" and unit.family:
                by_family.setdefault(unit.family, []).append(unit)
        cores: list[FamilyCore] = []
        for family in sorted(by_family):
            members = by_family[family]
            core = self.core_of([Signature.of(u.facts) for u in members])
            if len(core) < self.min_core:
                counts["core_too_small"] = counts.get("core_too_small", 0) + 1
                continue
            fires = sum(1 for signature in legit if core <= signature)
            if not legit or Wilson.upper(fires, len(legit), self.z) > self.budget:
                counts["over_legit_budget"] = counts.get("over_legit_budget", 0) + 1
                continue
            cores.append(
                FamilyCore(family, core, frozenset(u.key for u in members), fires, len(legit))
            )
        return cores, counts

    def core_of(self, signatures: list[frozenset[Term]]) -> frozenset[Term]:
        """The terms held by at least `support` of the members' signatures."""
        needed = math.ceil(self.support * len(signatures))
        seen: dict[Term, int] = {}
        for signature in signatures:
            for term in signature:
                seen[term] = seen.get(term, 0) + 1
        return frozenset(term for term, n in seen.items() if n >= needed)

    @staticmethod
    def find(
        cores: Iterable[FamilyCore], releases: Iterable[tuple[str, Mapping[str, Any]]]
    ) -> list[dict[str, Any]]:
        """The releases that hold a whole core, other than the family's own members: detections, each with no label."""
        usable = list(cores)
        hits: list[dict[str, Any]] = []
        for key, facts in releases:
            signature = Signature.of(facts)
            for family in usable:
                if key in family.members or not family.core <= signature:
                    continue
                hits.append(
                    {
                        "kind": KIND,
                        "release": key,
                        "family": family.family,
                        "core_terms": len(family.core),
                        "similarity": round(len(family.core) / len(signature), 6),
                        "label": None,
                    }
                )
        hits.sort(key=lambda h: (h["release"], h["family"]))
        return hits
