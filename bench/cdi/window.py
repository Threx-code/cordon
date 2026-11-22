"""The report of one fresh window: what was captured in it, and how much of it the scanner's content caught.

    unit   one release captured in the window: how it was labelled, and what caught it (or nothing did)

Three rules shape the numbers, and none of them is optional:

* The recall denominator is the units labelled by upstream evidence (an advisory) or by two readers. A unit only the
  teacher (the isolated analysis service) labelled is counted apart and is never in the denominator: a label a machine
  wrote about its own work cannot be the yardstick for it. A teacher confirmation of a release the scanner's static
  facts already block is not new learning either; only one the scanner missed is.
* The headline recall is content only: what the scanner's own rules and learned detectors caught from the package. Units
  caught only because an advisory already named them are reported on their own line and never count toward it, nor as
  learning.
* The machine share is the share of content catches made by machine-learned detectors. Advisory matches (the intel
  identities) are not content catches, so they are in neither side of it.
* A unit with no label is UNKNOWN: it is in no denominator and is never read as benign. The attack classes are reported
  one by one, and a class the training set lacks is flagged, since its recall is the recall on something never taught.
* A window is frozen with the head and facts version that scored it, and scoring it again with another is refused.
"""

from __future__ import annotations

import hashlib
import json
import statistics
from dataclasses import dataclass
from typing import Any, ClassVar

from bench.cdi.gate import Gate

UPSTREAM = "upstream"
READERS = "readers"
TEACHER = "teacher"
CONFIRMING = frozenset({UPSTREAM, READERS})
"""The label sources that make a unit part of the recall denominator."""

CONTENT_HUMAN = "content_human"
CONTENT_LEARNED = "content_learned"
ADVISORY = "advisory"
NONE = "none"
CAUGHT_BY = frozenset({CONTENT_HUMAN, CONTENT_LEARNED, ADVISORY, NONE})


@dataclass(frozen=True)
class WindowUnit:
    unit: str
    labelled_by: frozenset[str]
    caught_by: str
    attack_class: str = ""
    """The attack class the unit's label names, or "" when it names none."""
    first_of_family: bool | None = None
    """Whether it is the first release of its family captured (True), a sibling of one already captured (False), or not
    known (None)."""
    label_delay_days: float | None = None
    """Days from capture to its label, when it has one."""

    def __post_init__(self) -> None:
        if self.caught_by not in CAUGHT_BY:
            raise ValueError(f"caught_by is one of {sorted(CAUGHT_BY)}, not {self.caught_by!r}")
        if not self.labelled_by <= CONFIRMING | {TEACHER}:
            raise ValueError(f"unknown label source in {sorted(self.labelled_by)}")

    @property
    def confirmed(self) -> bool:
        return bool(self.labelled_by & CONFIRMING)

    @property
    def content_caught(self) -> bool:
        return self.caught_by in (CONTENT_HUMAN, CONTENT_LEARNED)


class RescoreRefused(ValueError):
    """A frozen window was offered a scan result made by another head or another facts version."""


class FrozenWindow:
    """A window's scan results as they were at capture, with the head commit and the facts version that made them.

    The numbers of a window are only comparable with each other while they come from the same scanner and the same facts.
    Re-scoring a window with a later head would quietly turn "what the scanner caught then" into "what it catches now", so
    it is refused: a later head scores the next window."""

    @staticmethod
    def freeze(units: list[WindowUnit], head: str, facts_version: str) -> dict[str, Any]:
        body = [
            [u.unit, sorted(u.labelled_by), u.caught_by]
            for u in sorted(units, key=lambda u: u.unit)
        ]
        digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()
        return {"head": head, "facts_version": facts_version, "units": len(units), "digest": digest}

    @staticmethod
    def rescore(frozen: dict[str, Any], head: str, facts_version: str) -> None:
        """Returns when the window may be scored again by this head and facts version, else raises `RescoreRefused`."""
        if head != frozen["head"]:
            raise RescoreRefused(
                f"the window was captured at {frozen['head']}: a later head ({head}) scores the next one"
            )
        if facts_version != frozen["facts_version"]:
            raise RescoreRefused(
                f"the window was captured with facts version {frozen['facts_version']}, not {facts_version}"
            )


class WindowReport:
    FAMILY_RULE: ClassVar[str] = "family-rule/1"

    @staticmethod
    def figure(k: int, n: int) -> dict[str, Any] | None:
        """`k` of `n` with its 95% interval, or None when nothing was counted: a figure that does not exist is not zero."""
        if n <= 0:
            return None
        low, high = Gate.wilson(k, n)
        return {"k": k, "n": n, "value": k / n, "low": low, "high": high}

    @classmethod
    def by_class(
        cls, confirmed: list[WindowUnit], train_classes: frozenset[str] | None
    ) -> dict[str, dict[str, Any]]:
        """Content recall for each attack class of the window's confirmed units. A class the training set has none of is
        flagged: its recall measures what the scanner was never taught, which is the point of a new class. With no
        training classes given, nothing is flagged and `absent_from_train` is None: not known."""
        out: dict[str, dict[str, Any]] = {}
        for name in sorted({u.attack_class for u in confirmed if u.attack_class}):
            members = [u for u in confirmed if u.attack_class == name]
            out[name] = {
                "recall": cls.figure(sum(1 for u in members if u.content_caught), len(members)),
                "absent_from_train": None if train_classes is None else name not in train_classes,
            }
        return out

    @classmethod
    def of(
        cls,
        units: list[WindowUnit],
        starts_on: str,
        ends_on: str,
        *,
        never_captured: int = 0,
        train_classes: frozenset[str] | None = None,
    ) -> dict[str, Any]:
        confirmed = [u for u in units if u.confirmed]
        teacher_only = [u for u in units if not u.confirmed and TEACHER in u.labelled_by]
        content = [u for u in confirmed if u.content_caught]
        advisory = [u for u in confirmed if u.caught_by == ADVISORY]
        learned = [u for u in content if u.caught_by == CONTENT_LEARNED]
        firsts = [u for u in confirmed if u.first_of_family is True]
        siblings = [u for u in confirmed if u.first_of_family is False]
        delays = [u.label_delay_days for u in units if u.label_delay_days is not None]
        by_class = cls.by_class(confirmed, train_classes)
        return {
            "starts_on": starts_on,
            "ends_on": ends_on,
            "denominator": len(confirmed),
            "content_recall": cls.figure(len(content), len(confirmed)),
            "advisory_catches": cls.figure(len(advisory), len(confirmed)),
            "advisory_counts_as_learning": False,
            "machine_share": cls.figure(len(learned), len(content)),
            "teacher_only": {
                "excluded": len(teacher_only),
                "already_blocked": sum(1 for u in teacher_only if u.caught_by != NONE),
                "new_learning": sum(1 for u in teacher_only if u.caught_by == NONE),
            },
            "first_of_family_recall": cls.figure(
                sum(1 for u in firsts if u.content_caught), len(firsts)
            ),
            "sibling_recall": cls.figure(
                sum(1 for u in siblings if u.content_caught), len(siblings)
            ),
            "family_position_unknown": sum(1 for u in confirmed if u.first_of_family is None),
            "unlabelled_unknown": sum(1 for u in units if not u.labelled_by),
            "never_captured": never_captured,
            "never_captured_share": cls.share(never_captured, len(units) + never_captured),
            "label_delay_days": {"median": statistics.median(delays), "n": len(delays)}
            if delays
            else None,
            "by_class": by_class,
            "new_classes": sorted(
                name for name, row in by_class.items() if row["absent_from_train"] is True
            ),
            "family_rule": cls.FAMILY_RULE,
        }

    @staticmethod
    def share(part: int, whole: int) -> float | None:
        return part / whole if whole > 0 else None
