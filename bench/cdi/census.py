"""The miss census (learning loop row LL-12, SI-Q7, SI-Q8, SI-Q9): every confirmed malicious release of a window that the
release head does not block gets one class and one route, from its `facts/v2` record and its label alone.

    READING GAP          the scan was incomplete, or a file kind or form was not read (a file with an unread state,
                         a package gap): a reader item opens (`bench/cdi/reader_items.py`, LL-13), by gap rule and file form
    NO SEPARATING FACT   no gap, and every term of the release's facts signature is also held by one established legit
                         release (nearest-legit distance zero on the scanner's own fact terms): no conjunction of terms
                         can fire on it without firing on that release, so it goes to the teacher (LL-14)
    FACTS EXIST          no gap, and the release has a term no legit release holds: it goes to the generators

A reading gap comes first: a release the scanner did not read has no signature to compare. The rule is the design's
(`reviews/self-improving/10-LEARNING-LOOP.md` section 6), read literally; the refinement LL-97 asks for (a candidate term
set's own legit rate) is a later row.

Leakage (SI-Q8, SI-Q9): a miss is routed (to the reader, the teacher or a generator) only when its label tier is confirmed
or corroborated AND its split is train or dev (`Schemas.eligible_for_factory`). Every other miss (silver labels, val, held,
fresh, sealed, excluded) is counted in its class, with the reason it was held, and routed nowhere. A record of another facts version is counted and never classified (LL-104:
a fact is not read against a different version).

Facts only: nothing here reads a package, and a report carries counts, never a unit or family name."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

from bench.cdi.leakage import Leakage
from bench.cdi.schemas import FACTORY_SPLITS, Schemas

from cordon_scanner.report.facts import FACTS_VERSION
from cordon_scanner.rules.fact_terms import FactTerms

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

READING_GAP: Final = "READING_GAP"
NO_SEPARATING_FACT: Final = "NO_SEPARATING_FACT"
FACTS_EXIST: Final = "FACTS_EXIST"
CLASSES: Final = (READING_GAP, NO_SEPARATING_FACT, FACTS_EXIST)

#: Where a classified miss goes. `counted_only` is every miss the leakage gates keep from learning.
ROUTES: Final = {
    READING_GAP: "reader",
    NO_SEPARATING_FACT: "teacher",
    FACTS_EXIST: "generators",
}
COUNTED_ONLY: Final = "counted_only"
#: The form of a gap no file carries (a timeout, a package-wide limit).
PACKAGE_FORM: Final = "package"
#: A package that is not content-complete with no rule recorded: still a gap, named so.
UNRECORDED: Final = "UNRECORDED"

Term = tuple[str, ...]
Gap = tuple[str, str]


@dataclass(frozen=True)
class MissRow:
    """One confirmed malicious release the release head does not block. `family` and `key` stay in the loop's own
    store; a report never repeats them."""

    key: str
    family: str
    ecosystem: str
    split: str
    label_tier: str
    facts: Mapping[str, Any]


@dataclass(frozen=True)
class Verdict:
    """What the census decided about one miss."""

    key: str
    family: str
    klass: str
    gaps: tuple[Gap, ...]
    distance: int | None
    eligible: bool
    held: tuple[str, ...]
    route: str


@dataclass
class Report:
    """A window's census: the verdicts, and the counts a stage reports."""

    window: str
    verdicts: list[Verdict] = field(default_factory=list)
    stale: int = 0

    def for_generators(self) -> list[Verdict]:
        """The only misses a generator may read: FACTS EXIST and eligible. The factory refuses everything else."""
        return [v for v in self.verdicts if v.route == ROUTES[FACTS_EXIST]]

    def counts(self) -> dict[str, int]:
        counted = Counter(v.klass for v in self.verdicts)
        held = Counter(reason for v in self.verdicts for reason in v.held)
        out = {"misses": len(self.verdicts), "stale_facts_version": self.stale}
        out.update({klass.lower(): counted.get(klass, 0) for klass in CLASSES})
        out["fed_to_generators"] = len(self.for_generators())
        out["held"] = sum(1 for v in self.verdicts if v.held)
        out.update({f"held_{reason}": n for reason, n in sorted(held.items())})
        return out


class ReadingGaps:
    """What the scan did not read, from a facts record: (the gap's rule id, the form of the file it was) pairs."""

    @staticmethod
    def of(facts: Mapping[str, Any]) -> tuple[Gap, ...]:
        found: set[Gap] = set()
        in_files: set[str] = set()
        for entry in facts.get("files", ()):
            for rule in entry.get("unread", ()):
                found.add((str(rule), str(entry.get("ext", "OTHER"))))
                in_files.add(str(rule))
        for rule in facts.get("gaps", {}):
            if str(rule) not in in_files:
                found.add((str(rule), PACKAGE_FORM))
        incomplete = facts.get("content_complete") is False or facts.get("complete") is False
        if incomplete and not found:
            found.add((UNRECORDED, PACKAGE_FORM))
        return tuple(sorted(found))


class Signature:
    """A release's facts as the scanner's own terms, without the kinds a rule may never use."""

    @staticmethod
    def of(facts: Mapping[str, Any]) -> frozenset[Term]:
        return frozenset(t for t in FactTerms.of_facts(facts) if t[0] not in FactTerms.REFUSED)

    @staticmethod
    def distance(signature: frozenset[Term], legit: Iterable[frozenset[Term]]) -> int:
        """The fewest terms of the signature that an established legit release lacks (0: one holds them all)."""
        return min((len(signature - other) for other in legit), default=len(signature))


class Census:
    @staticmethod
    def eligibility(row: MissRow) -> tuple[bool, tuple[str, ...]]:
        """Whether the miss may inform a generator, and if not, why (the label tier, the split, or both)."""
        reasons = Leakage.reasons(row.split, row.label_tier, FACTORY_SPLITS)
        eligible = Schemas.eligible_for_factory(row.label_tier, row.split)
        return eligible, reasons

    @staticmethod
    def run(
        window: str,
        misses: Iterable[MissRow],
        legit: Iterable[Mapping[str, Any]],
        facts_version: str = FACTS_VERSION,
    ) -> Report:
        """Classify and route every miss of a window against the established legit releases' facts (same version)."""
        legit_signatures = [
            Signature.of(f) for f in legit if f.get("facts_version") == facts_version
        ]
        report = Report(window)
        for row in misses:
            if row.facts.get("facts_version") != facts_version:
                report.stale += 1
                continue
            report.verdicts.append(Census.one(row, legit_signatures))
        report.verdicts.sort(key=lambda v: v.key)
        return report

    @staticmethod
    def one(row: MissRow, legit: list[frozenset[Term]]) -> Verdict:
        eligible, held = Census.eligibility(row)
        gaps = ReadingGaps.of(row.facts)
        distance: int | None = None
        if gaps:
            klass = READING_GAP
        else:
            distance = Signature.distance(Signature.of(row.facts), legit)
            klass = NO_SEPARATING_FACT if distance == 0 else FACTS_EXIST
        # Held, fresh, sealed, excluded and silver-labelled misses are counted in their class, with the reason, and go nowhere
        # (a reader built from a held unit's shape is as much a leak as a rule built from it).
        route = ROUTES[klass] if eligible else COUNTED_ONLY
        return Verdict(row.key, row.family, klass, gaps, distance, eligible, held, route)
