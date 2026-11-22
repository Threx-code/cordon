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
"""

from __future__ import annotations

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
    def of(cls, units: list[WindowUnit], starts_on: str, ends_on: str) -> dict[str, Any]:
        confirmed = [u for u in units if u.confirmed]
        teacher_only = [u for u in units if not u.confirmed and TEACHER in u.labelled_by]
        content = [u for u in confirmed if u.content_caught]
        advisory = [u for u in confirmed if u.caught_by == ADVISORY]
        learned = [u for u in content if u.caught_by == CONTENT_LEARNED]
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
            "family_rule": cls.FAMILY_RULE,
        }
