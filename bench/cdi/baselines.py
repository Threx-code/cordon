"""Which earlier version a release is compared with, and how the recall on a package's malicious versions is told.

A release-pair measures what changed between a version and a version known to be fine. The immediate predecessor is
often not that: after a takeover it is the first malicious version, and comparing the second malicious version with the
first measures nothing. So the baseline of a version is the LAST version before it that is labelled established-clean:
clean by the label store, and by a publisher history long enough to trust. A malicious, an unlabelled or a clean-but-new
version is passed over. A version with no such baseline has no pair, and is counted as having none.

Recall on malicious versions is told in two numbers: the first malicious version of a package (the takeover itself) and
every later one, which a detector may catch only because it saw the first.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from bench.cdi.gate import Gate

CLEAN: Final = "clean"
MALICIOUS: Final = "malicious"
UNLABELLED: Final = "unlabelled"
LABELS: Final = frozenset({CLEAN, MALICIOUS, UNLABELLED})


@dataclass(frozen=True)
class Release:
    package: str
    version: str
    order: int
    """The version's place in the package's publication order, oldest first."""
    label: str
    established: bool = False
    """Whether the label is established: the publisher's history is long enough that a clean label can be trusted."""
    caught: bool = False

    def __post_init__(self) -> None:
        if self.label not in LABELS:
            raise ValueError(f"a label is one of {sorted(LABELS)}, not {self.label!r}")

    @property
    def established_clean(self) -> bool:
        return self.label == CLEAN and self.established


class PairBaseline:
    @staticmethod
    def baseline(releases: list[Release], target: Release) -> Release | None:
        """The last established-clean version of the target's package published before it, or None."""
        before = [
            r
            for r in releases
            if r.package == target.package and r.order < target.order and r.established_clean
        ]
        return max(before, key=lambda r: r.order) if before else None

    @classmethod
    def pairs(cls, releases: list[Release]) -> list[tuple[Release, Release | None]]:
        """Each malicious version with its baseline (None when the package has no established-clean version before it)."""
        return [
            (r, cls.baseline(releases, r))
            for r in sorted(releases, key=lambda r: (r.package, r.order))
            if r.label == MALICIOUS
        ]

    @classmethod
    def recall(cls, releases: list[Release]) -> dict[str, Any]:
        """Recall on the first malicious version of each package and on the later ones, apart, over versions that have a
        baseline; the versions with none are counted on their own line and are in neither."""
        first: list[Release] = []
        later: list[Release] = []
        without = 0
        seen: set[str] = set()
        for target, base in cls.pairs(releases):
            is_first = target.package not in seen
            seen.add(target.package)
            if base is None:
                without += 1
            else:
                (first if is_first else later).append(target)
        return {
            "first_malicious": cls.figure(first),
            "later_malicious": cls.figure(later),
            "without_baseline": without,
        }

    @staticmethod
    def figure(targets: list[Release]) -> dict[str, Any] | None:
        if not targets:
            return None
        k = sum(1 for t in targets if t.caught)
        low, high = Gate.wilson(k, len(targets))
        return {"k": k, "n": len(targets), "value": k / len(targets), "low": low, "high": high}
