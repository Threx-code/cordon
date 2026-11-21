"""G2, the distiller (learning loop rows LL-16 to LL-19, LL-63, LL-66, LL-90, LL-101): the smallest general predicate
over `facts/v1` records that separates labelled malicious releases the scanner misses from legitimate ones.

The teacher (the isolated analysis service) says what a release DID; the distiller finds what the static facts of the
same releases have in common that legitimate releases do not, so the offline scanner can catch the next one without
running anything. It reads facts only (`cordon_scanner.report.facts`), never a package's bytes.

    terms        from each record: a file-level term is (where, capabilities) -- where is any, unreached or one place,
                 and the capabilities one or two that the same file has; a package-level term is a package rule or a
                 lifecycle hook kind. Names, hosts, ages and publishers are never terms (LL-19, LL-66).
    support      a term is kept only when missed malicious units of at least `min_families` families have it
                 (LL-18), from the train split only; a family with any member in a sealed, held-out or fresh-1 set
                 is refused whole before anything is counted (LL-63).
    search       conjunctions of up to `max_size` kept terms, in a fixed order, bounded by `max_candidates`; the
                 search size is recorded and the legit bound is corrected for it (LL-17, LL-90).
    legit        the fire rate per stratum (age x publisher history x ecosystem), and the WORST stratum's Wilson
                 upper bound must be within `budget` (LL-66).
    confirm      the chosen predicate is re-measured on the confirm split, rows never used to choose it (LL-90);
                 only a predicate that holds there is a candidate.
    output       the canonical predicate and its digest (the tombstone key of LL-74), the counts, the search record;
                 never a unit key or a family key.

Bitsets keep the search fast: every term holds the set of units that have it as one integer, so a conjunction is an
AND and a count is `int.bit_count`."""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import re
from dataclasses import dataclass, field
from statistics import NormalDist
from typing import TYPE_CHECKING, Any, Final

from bench.cdi.leakage import Leakage

from cordon_scanner.rules.fact_terms import FactTerms

if TYPE_CHECKING:
    from collections.abc import Callable

REFUSED_KINDS: Final = FactTerms.REFUSED
"""Term kinds the distiller never uses: identities belong to intel (G1), ages and publishers only stratify."""
METADATA_KINDS: Final = frozenset({"hook"})
"""Package metadata rather than behaviour: such a term needs support in at least two ecosystems (LL-101)."""


@dataclass(frozen=True)
class Unit:
    """One labelled release: its facts record and what is known about it. `family` is empty for legit units."""

    key: str
    label: str
    family: str
    ecosystem: str
    stratum: str
    split: str
    facts: dict[str, Any]
    missed: bool = True
    label_tier: str = "confirmed"
    """The label's tier (`Schemas`: confirmed, corroborated, silver ...); only a malicious unit is gated on it (`bench/cdi/leakage.py`)."""


@dataclass
class Distillation:
    """What a run decided: the candidate (or None) and why every other choice was refused, as counts."""

    candidate: dict[str, Any] | None
    refused: dict[str, int] = field(default_factory=dict)
    search: dict[str, Any] = field(default_factory=dict)


class Terms:
    """The terms of one facts record."""

    @staticmethod
    def of(facts: dict[str, Any]) -> set[tuple[str, ...]]:
        """The scanner's own reading of a facts record (`rules/fact_terms.py`): the terms learned here are
        exactly the terms a package-scope rule is evaluated on."""
        return FactTerms.of_facts(facts)

    @staticmethod
    def check(term: tuple[str, ...]) -> None:
        if term[0] in REFUSED_KINDS:
            raise ValueError(f"refused term kind: {term[0]}")

    @staticmethod
    def canonical(predicate: tuple[tuple[str, ...], ...]) -> str:
        return json.dumps(sorted(list(t) for t in predicate), separators=(",", ":"))

    @staticmethod
    def digest(predicate: tuple[tuple[str, ...], ...]) -> str:
        return hashlib.sha256(Terms.canonical(predicate).encode("utf-8")).hexdigest()


class Wilson:
    @staticmethod
    def upper(fires: int, n: int, z: float) -> float:
        if n == 0:
            return 1.0
        p = fires / n
        centre = p + z * z / (2 * n)
        spread = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
        return min(1.0, (centre + spread) / (1 + z * z / n))


class Distiller:
    """Run with `distill(units)`. Every threshold is a constructor argument, fixed before a run (LL-91)."""

    def __init__(
        self,
        *,
        min_families: int = 3,
        confirm_min_families: int = 1,
        budget: float = 0.005,
        max_size: int = 3,
        max_terms: int = 40,
        max_candidates: int = 20_000,
        alpha: float = 0.05,
        refused_families: frozenset[str] = frozenset(),
        terms_of: Callable[[dict[str, Any]], set[tuple[str, ...]]] | None = None,
        generator: str = "G2",
        metadata_kinds: frozenset[str] = METADATA_KINDS,
        lofo: bool = True,
    ) -> None:
        self.min_families = min_families
        self.confirm_min_families = confirm_min_families
        self.budget = budget
        self.max_size = max_size
        self.max_terms = max_terms
        self.max_candidates = max_candidates
        self.alpha = alpha
        self.refused_families = refused_families
        # What a unit's facts are read as: the scanner's own fact terms (G2), or the terms of a release pair (G6, `bench/cdi/pairs.py`).
        self.terms_of = terms_of or Terms.of
        self.generator = generator
        self.metadata_kinds = metadata_kinds
        # LL-51: leave each family out and see whether a predicate chosen without it still covers it. Off inside its own re-runs.
        self.lofo = lofo

    def distill(self, units: list[Unit]) -> Distillation:
        refused: dict[str, int] = {}
        # LL-43 (SI-Q8, SI-Q9): a held, fresh, sealed, val or excluded release, or a malicious one without a confirmed or corroborated
        # label, is refused with its reason before anything is counted; it is never dropped silently.
        allowed, leaked = Leakage.admit(units)
        refused.update(leaked)
        kept_units = []
        for u in allowed:
            if u.label == "mal" and u.family in self.refused_families:
                refused["unit_in_refused_family"] = refused.get("unit_in_refused_family", 0) + 1
                continue
            kept_units.append(u)
        versions = {str(u.facts.get("facts_version", "")) for u in kept_units}
        if len(versions) > 1:
            # A fact's meaning can change between versions (LL-104): one distillation reads one version.
            raise ValueError(
                f"facts of {len(versions)} versions in one distillation; rebuild the store at one head"
            )
        train = [u for u in kept_units if u.split == "train"]
        confirm = [u for u in kept_units if u.split == "confirm"]
        space = _Space(train, self.terms_of)
        terms = self._kept_terms(space, refused)
        candidates, searched = self._search(space, terms)
        z = NormalDist().inv_cdf(1 - self.alpha / max(1, searched))
        passing = []
        for predicate, mask in candidates:
            families = space.families(mask)
            if families < self.min_families:
                refused["under_min_families"] = refused.get("under_min_families", 0) + 1
                continue
            upper, worst = space.legit_upper(predicate, z)
            if upper > self.budget:
                refused["over_legit_budget"] = refused.get("over_legit_budget", 0) + 1
                continue
            passing.append(
                (len(predicate), -families, upper, Terms.canonical(predicate), predicate, worst)
            )
        passing.sort(key=lambda p: p[:4])
        search = {
            "terms": len(terms),
            "candidates": searched,
            "max_size": self.max_size,
            "max_terms": self.max_terms,
            "z": round(z, 4),
            "train_units": len(train),
            "confirm_units": len(confirm),
            "facts_version": next(iter(versions), ""),
            "params": self.params(),
        }
        confirm_space = _Space(confirm, self.terms_of)
        z_confirm = NormalDist().inv_cdf(1 - self.alpha)
        for size, neg_families, upper, _canon, predicate, worst in passing:
            mask = confirm_space.mask_of(predicate)
            confirm_families = confirm_space.families(mask)
            confirm_upper, _w = confirm_space.legit_upper(predicate, z_confirm)
            if confirm_families < self.confirm_min_families or confirm_upper > self.budget:
                refused["failed_confirm"] = refused.get("failed_confirm", 0) + 1
                continue
            candidate = {
                "generator": self.generator,
                "predicate": json.loads(Terms.canonical(predicate)),
                "predicate_digest": Terms.digest(predicate),
                "size": size,
                "train": {
                    "families": -neg_families,
                    "legit_upper": round(upper, 6),
                    "worst_stratum_upper": worst,
                },
                "confirm": {"families": confirm_families, "legit_upper": round(confirm_upper, 6)},
            }
            if self.lofo:
                candidate["out_of_family"] = self._out_of_family(kept_units, space)
            return Distillation(candidate=candidate, refused=refused, search=search)
        return Distillation(candidate=None, refused=refused, search=search)

    def _out_of_family(self, units: list[Unit], space: _Space) -> dict[str, Any]:
        """Leave-one-family-out (LL-51, the dev-overfit loophole): for each family the predicate was chosen from, choose again
        WITHOUT it, under the same thresholds, and ask whether that predicate fires on at least half of the family's own units. The
        share of families it covers is the number a rule chosen on dev has to show before it is believed on a family it has not
        seen. With too few families to leave one out and still meet `min_families`, nothing is claimed (recall none)."""
        families = sorted(space.family_masks)
        if len(families) - 1 < self.min_families:
            return {"families": len(families), "covered": 0, "recall": None}
        inner = Distiller(
            min_families=self.min_families,
            confirm_min_families=self.confirm_min_families,
            budget=self.budget,
            max_size=self.max_size,
            max_terms=self.max_terms,
            max_candidates=self.max_candidates,
            alpha=self.alpha,
            refused_families=self.refused_families,
            terms_of=self.terms_of,
            generator=self.generator,
            metadata_kinds=self.metadata_kinds,
            lofo=False,
        )
        covered = 0
        for family in families:
            own = [u for u in units if u.label == "mal" and u.family == family]
            rest = [u for u in units if not (u.label == "mal" and u.family == family)]
            chosen = inner.distill(rest).candidate
            if chosen is None:
                continue
            predicate = {tuple(term) for term in chosen["predicate"]}
            fires = sum(1 for u in own if predicate <= self.terms_of(u.facts))
            covered += 2 * fires >= len(own)
        return {
            "families": len(families),
            "covered": covered,
            "recall": round(covered / len(families), 6),
        }

    def params(self) -> dict[str, Any]:
        """Every threshold of this run, recorded with the candidate so the gate can replay it (LL-52). The refused families are
        counted and digested, never listed."""
        names = "\n".join(sorted(self.refused_families)).encode("utf-8")
        return {
            "generator": self.generator,
            "min_families": self.min_families,
            "confirm_min_families": self.confirm_min_families,
            "budget": self.budget,
            "alpha": self.alpha,
            "max_size": self.max_size,
            "max_terms": self.max_terms,
            "max_candidates": self.max_candidates,
            "lofo": self.lofo,
            "refused_families": len(self.refused_families),
            "refused_families_digest": hashlib.sha256(names).hexdigest(),
        }

    def _kept_terms(self, space: _Space, refused: dict[str, int]) -> list[tuple[str, ...]]:
        kept = []
        for term, mask in space.term_masks.items():
            if term[0] in REFUSED_KINDS:
                refused["refused_kind"] = refused.get("refused_kind", 0) + 1
                continue
            if space.families(mask) < self.min_families:
                refused["single_or_few_families"] = refused.get("single_or_few_families", 0) + 1
                continue
            if term[0] in self.metadata_kinds and space.ecosystems(mask) < 2:
                refused["metadata_one_ecosystem"] = refused.get("metadata_one_ecosystem", 0) + 1
                continue
            kept.append(term)
        # Most families first, then the rarest among legit, then the term itself: a fixed order (LL-17).
        kept.sort(
            key=lambda t: (
                -space.families(space.term_masks[t]),
                space.legit_fires(space.term_masks[t]),
                t,
            )
        )
        return kept[: self.max_terms]

    def _search(
        self, space: _Space, terms: list[tuple[str, ...]]
    ) -> tuple[list[tuple[tuple[tuple[str, ...], ...], int]], int]:
        out: list[tuple[tuple[tuple[str, ...], ...], int]] = []
        searched = 0
        for size in range(1, self.max_size + 1):
            for predicate in itertools.combinations(terms, size):
                if searched >= self.max_candidates:
                    return out, searched
                searched += 1
                mask = space.mask_of(predicate)
                if mask & space.missed_mask:
                    out.append((predicate, mask))
        return out, searched


class _Space:
    """The units of one split as bit positions, and each term as the integer of the units that have it."""

    def __init__(
        self, units: list[Unit], terms_of: Callable[[dict[str, Any]], set[tuple[str, ...]]]
    ) -> None:
        self.term_masks: dict[tuple[str, ...], int] = {}
        self.family_masks: dict[str, int] = {}
        self.ecosystem_masks: dict[str, int] = {}
        self.strata: dict[str, int] = {}
        self.missed_mask = 0
        self.legit_mask = 0
        for i, u in enumerate(sorted(units, key=lambda u: u.key)):
            bit = 1 << i
            for term in terms_of(u.facts):
                self.term_masks[term] = self.term_masks.get(term, 0) | bit
            if u.label == "mal" and u.missed:
                self.missed_mask |= bit
                self.family_masks[u.family] = self.family_masks.get(u.family, 0) | bit
                self.ecosystem_masks[u.ecosystem] = self.ecosystem_masks.get(u.ecosystem, 0) | bit
            elif u.label == "legit":
                self.legit_mask |= bit
                self.strata[u.stratum] = self.strata.get(u.stratum, 0) | bit

    def mask_of(self, predicate: tuple[tuple[str, ...], ...]) -> int:
        mask = -1
        for term in predicate:
            mask &= self.term_masks.get(term, 0)
        return mask if mask != -1 else 0

    def families(self, mask: int) -> int:
        return sum(1 for fm in self.family_masks.values() if mask & fm)

    def ecosystems(self, mask: int) -> int:
        return sum(1 for em in self.ecosystem_masks.values() if mask & em)

    def legit_fires(self, mask: int) -> int:
        return (mask & self.legit_mask).bit_count()

    def legit_upper(self, predicate: tuple[tuple[str, ...], ...], z: float) -> tuple[float, str]:
        """The worst stratum's Wilson upper bound of the predicate's legit fire rate, and that stratum's name. With
        no legit unit at all the bound is 1: no evidence is never a pass."""
        mask = self.mask_of(predicate)
        if not self.strata:
            return 1.0, ""
        return max(
            (
                (Wilson.upper((mask & sm).bit_count(), sm.bit_count(), z), name)
                for name, sm in self.strata.items()
            ),
            key=lambda x: (x[0], x[1]),
        )


class PackRenderer:
    """A distilled candidate as a rule pack the scanner loads (LL-16b): one package-scope composite whose terms are
    the predicate's, in the `LEARNED.<AREA>.<NNN>` namespace (LL-4). The pack carries no sample and no text from any
    package: its terms are the scanner's own vocabulary, and its evidence is the counts the distiller measured."""

    RULE_ID: Final = re.compile(r"LEARNED\.[A-Z][A-Z0-9_]{0,23}\.[0-9]{3}")

    @staticmethod
    def spec(term: list[str]) -> str:
        Terms.check(tuple(term))
        if term[0] == "file":
            caps = ", ".join(term[2:])
            return f"{{file: {{where: {term[1]}, capabilities: [{caps}]}}}}"
        return f"{{{term[0]}: {term[1]}}}"

    @staticmethod
    def render(
        candidate: dict[str, Any],
        rule_id: str,
        *,
        severity: str = "high",
        confidence: str = "medium",
    ) -> str:
        if not PackRenderer.RULE_ID.fullmatch(rule_id):
            raise ValueError(f"a learned rule id is LEARNED.<AREA>.<NNN>, not {rule_id!r}")
        train, confirm = candidate["train"], candidate["confirm"]
        said = "; ".join(" ".join(t) for t in candidate["predicate"])
        message = (
            f"Machine-made detector (learning loop, distiller G2): this package has the shape {said}. Learned from "
            f"{train['families']} families; legitimate upper bound {train['legit_upper']:.4%} on the training store "
            f"and {confirm['legit_upper']:.4%} on rows never used to choose it."
        )
        terms = "\n".join(f"        - {PackRenderer.spec(t)}" for t in candidate["predicate"])
        digest = candidate["predicate_digest"]
        return (
            f"pack: {{id: learned.{digest[:12]}, version: 1.0.0, license: Apache-2.0, source: cordon-learning-loop}}\n"
            "rules:\n"
            f"  - id: {rule_id}\n"
            "    category: suspicious\n"
            f"    severity: {severity}\n"
            f"    confidence: {confidence}\n"
            f"    title: '{PackRenderer.quoted('Machine-made: ' + said)}'\n"
            f"    message: '{PackRenderer.quoted(message)}'\n"
            "    remediation: 'Read what the named file does and why nothing in the package starts it; report a false "
            "positive from the finding.'\n"
            "    match:\n"
            "      kind: composite\n"
            "      scope: package\n"
            "      all:\n"
            f"{terms}\n"
        )

    @staticmethod
    def quoted(text: str) -> str:
        return text.replace("'", "''")


__all__ = [
    "METADATA_KINDS",
    "REFUSED_KINDS",
    "Distillation",
    "Distiller",
    "PackRenderer",
    "Terms",
    "Unit",
    "Wilson",
]
