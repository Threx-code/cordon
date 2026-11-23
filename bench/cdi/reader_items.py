"""The reading-gap tracker (learning loop row LL-13): the reader items the census opens, by gap kind and file form.

An item is a (kind, form) pair: the gap's rule id (`OPERATIONAL.FILE.TRUNCATED`, a timeout ...) and the form of the file it was (an
extension class of the facts record, or `package` for a gap no file carries). Each window's census (`bench/cdi/census.py`) updates the
items, and an item:

    opens     when a miss the leakage gates let through (route `reader`) shows the gap
    stays open  while any later window's census still shows it, in a routed miss or in a held one (a held miss never opens an item or
              names a family; it can only keep one open: closing on the strength of a window that hid the gap in its held units would
              be wrong)
    closes    only in a window AFTER the one it was last seen in, whose census no longer shows it, and only once an acceptance test
              (the reader reads a benign fixture of that form) is attached; with none attached it stays open and says it is waiting
    reopens   when a closed item's gap shows again

Windows are applied in order (a window not after the last one is refused): the same census twice is not a second window. The state is
plain JSON (sorted, no timestamps), so the same windows give the same bytes. It holds counts, and the families of routed misses only."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, Final

from bench.cdi.census import READING_GAP, ROUTES

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from bench.cdi.census import Gap, Verdict

OPEN: Final = "open"
CLOSED: Final = "closed"

#: What closing an item needs (`ClosureEvidence`): at least this many units of the form seen in the window, the heavy-tail time ratio
#: within this bound, and a time that grows with the input no faster than this share over the input's growth.
MIN_UNITS_SEEN: Final = 20
MAX_TIME_RATIO: Final = 1.10
LINEARITY_SLACK: Final = 1.25
SCALE_POINTS: Final = ("mib10_cpu_seconds", "tokens1m_cpu_seconds")
TAIL_FIELDS: Final = (
    "sum_base",
    "sum_candidate",
    "p50_base",
    "p50_candidate",
    "p99_base",
    "p99_candidate",
    "timeouts_base",
    "timeouts_candidate",
)


class EvidenceRefused(ValueError):
    """The evidence offered for closing an item does not meet the closure rule. `problems` says which part failed."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


class ClosureEvidence:
    @staticmethod
    def problems(evidence: Mapping[str, Any]) -> list[str]:
        """What is missing or failing in the evidence for closing a reader item. Empty when it may close.

        scale          the form at 10 MiB and at a million tokens, each within a CPU bound
        linearity      the hostile-input check: a larger input of the same form takes no more than its growth (with a little slack)
        heavy tail     the ratio of the sums of scan times, candidate over base, within 1.10, with p50, p99 and the units at
                       the timeout stated for both sides
        legit          the share of legit releases that scan incomplete is not up
        units seen     at least 20 units of the form seen in the window"""
        found: list[str] = []
        scale = evidence.get("scale") or {}
        bound = scale.get("bound_cpu_seconds")
        for point in SCALE_POINTS:
            value = scale.get(point)
            if not isinstance(bound, (int, float)) or not isinstance(value, (int, float)):
                found.append(f"scale: {point} or the bound is missing")
            elif value > bound:
                found.append(f"scale: {point} is {value} CPU seconds, over the bound of {bound}")
        line = evidence.get("linearity") or {}
        try:
            if line["large_seconds"] / line["small_seconds"] > line["size_ratio"] * LINEARITY_SLACK:
                found.append("linearity: the time grows faster than the input")
        except (KeyError, TypeError, ZeroDivisionError):
            found.append("linearity: the small time, the large time or the size ratio is missing")
        tail = evidence.get("heavy_tail") or {}
        if any(not isinstance(tail.get(k), (int, float)) for k in TAIL_FIELDS):
            found.append("heavy tail: the ratio of sums, p50, p99 and the units at the timeout must all be stated")
        elif tail["sum_base"] <= 0 or tail["sum_candidate"] / tail["sum_base"] > MAX_TIME_RATIO:
            found.append(f"heavy tail: the ratio of sums is over {MAX_TIME_RATIO}")
        legit = evidence.get("legit_incomplete") or {}
        if not all(isinstance(legit.get(k), (int, float)) for k in ("before", "after")):
            found.append("legit incomplete: the rate before and after must be stated")
        elif legit["after"] > legit["before"]:
            found.append("legit incomplete: the rate went up")
        seen = evidence.get("units_seen")
        if not isinstance(seen, int) or seen < MIN_UNITS_SEEN:
            found.append(f"units seen: fewer than {MIN_UNITS_SEEN} units of the form were seen in the window")
        return found

    @staticmethod
    def reference(evidence: Mapping[str, Any]) -> str:
        return "evidence:" + hashlib.sha256(json.dumps(evidence, sort_keys=True).encode("utf-8")).hexdigest()[:16]


@dataclass
class ReaderItem:
    kind: str
    form: str
    status: str
    opened_window: str
    last_seen_window: str
    units: int
    held_units: int
    closed_window: str | None = None
    families: list[str] = field(default_factory=list)
    windows_seen: int = 1
    reopened: int = 0
    acceptance: str | None = None

    @property
    def waiting_for_acceptance(self) -> bool:
        """Open, absent from the latest window, and only the missing acceptance test keeps it open."""
        return (
            self.status == OPEN
            and self.units == 0
            and self.held_units == 0
            and self.acceptance is None
        )


class ReaderTracker:
    def __init__(self, items: Iterable[ReaderItem] = (), last_window: str = "") -> None:
        self.items: dict[Gap, ReaderItem] = {(i.kind, i.form): i for i in items}
        self.last_window = last_window

    def attach_acceptance(self, kind: str, form: str, reference: str) -> None:
        """Record the test that has the reader read a benign fixture of this form (a test reference, not text)."""
        item = self.items.get((kind, form))
        if item is None:
            raise KeyError("no such reader item")
        item.acceptance = reference

    def attach_evidence(self, kind: str, form: str, evidence: Mapping[str, Any]) -> str:
        """Attach the closure evidence of an item as its acceptance: the item may close only when every part of the rule holds.
        Raises `EvidenceRefused` naming each part that does not, and leaves the item as it was."""
        item = self.items.get((kind, form))
        if item is None:
            raise KeyError("no such reader item")
        problems = ClosureEvidence.problems(evidence)
        if problems:
            raise EvidenceRefused(problems)
        item.acceptance = ClosureEvidence.reference(evidence)
        return item.acceptance

    def apply(self, window: str, verdicts: Iterable[Verdict]) -> None:
        """Take a window's census: open, keep, reopen or close the items."""
        if window <= self.last_window:
            raise ValueError("a window is applied once, after the last one")
        routed: dict[Gap, list[Verdict]] = {}
        held: dict[Gap, int] = {}
        for verdict in verdicts:
            if verdict.klass != READING_GAP:
                continue
            for gap in verdict.gaps:
                if verdict.route == ROUTES[READING_GAP]:
                    routed.setdefault(gap, []).append(verdict)
                else:
                    held[gap] = held.get(gap, 0) + 1
        for gap in sorted(set(routed) | set(held)):
            self._show(gap, window, routed.get(gap, []), held.get(gap, 0))
        for gap, item in sorted(self.items.items()):
            if gap not in routed and gap not in held:
                self._absent(item, window)
        self.last_window = window

    def _show(self, gap: Gap, window: str, routed: list[Verdict], held: int) -> None:
        families = sorted({v.family for v in routed if v.family})
        item = self.items.get(gap)
        if item is None:
            if not routed:
                return  # held units alone never open an item
            self.items[gap] = ReaderItem(
                gap[0],
                gap[1],
                OPEN,
                window,
                window,
                units=len(routed),
                held_units=held,
                families=families,
            )
            return
        if item.status == CLOSED:
            # The reader was accepted and the gap came back: the acceptance test did not cover it, so a new one is needed.
            item.status, item.closed_window, item.acceptance = OPEN, None, None
            item.reopened += 1
        item.last_seen_window = window
        item.windows_seen += 1
        item.units, item.held_units = len(routed), held
        item.families = families

    @staticmethod
    def _absent(item: ReaderItem, window: str) -> None:
        item.units = item.held_units = 0
        if item.status == OPEN and item.acceptance is not None:
            item.status, item.closed_window = CLOSED, window

    def counts(self) -> dict[str, int]:
        items = list(self.items.values())
        return {
            "open": sum(1 for i in items if i.status == OPEN),
            "closed": sum(1 for i in items if i.status == CLOSED),
            "waiting_for_acceptance": sum(1 for i in items if i.waiting_for_acceptance),
        }

    def state(self) -> str:
        """The canonical JSON of the tracker: the same windows give the same text."""
        record: dict[str, Any] = {
            "last_window": self.last_window,
            "items": [asdict(self.items[gap]) for gap in sorted(self.items)],
        }
        return json.dumps(record, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def of_state(text: str) -> ReaderTracker:
        record = json.loads(text)
        return ReaderTracker((ReaderItem(**i) for i in record["items"]), record["last_window"])
