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

import json
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, Final

from bench.cdi.census import READING_GAP, ROUTES

if TYPE_CHECKING:
    from collections.abc import Iterable

    from bench.cdi.census import Gap, Verdict

OPEN: Final = "open"
CLOSED: Final = "closed"


@dataclass
class ReaderItem:
    kind: str
    form: str
    status: str
    opened_window: str
    last_seen_window: str
    closed_window: str | None = None
    units: int = 0
    held_units: int = 0
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
