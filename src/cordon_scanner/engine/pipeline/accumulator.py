"""The mutable state of one scan: the findings so far, whether coverage stayed complete, whether every
dependency met an advisory source, and the counters the result reports.

Local to a single run. The engine itself holds no per-scan state, which is what makes one Scanner
instance reusable and safe to share; each phase that adds to a scan is handed this.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cordon_scanner.engine.pipeline.constants import INCOMPLETE_WHEN_REPORTED
from cordon_scanner.foundation.models import Finding

if TYPE_CHECKING:
    from collections.abc import Iterable


@dataclass
class Accumulator:
    """Mutable state for one scan.

    Deliberately local to a single run. The engine itself holds no per-scan
    state, which is what makes one Scanner instance reusable and safe to share.
    """

    findings: list[Finding] = field(default_factory=list)
    complete: bool = True
    """Every file's content was read: nothing refused, truncated, pruned or timed out."""
    advisory_complete: bool = True
    """Every dependency was checked against an advisory or registry source, and the threat intel
    was current. A missing feed is reported and never blocks a package for malware purposes
    (review 98, REC-5): the two halves are kept apart so the gate can tell them apart."""
    rejected_archives: set[str] = field(default_factory=set)
    """Archives already reported as read in part (`OPERATIONAL.ARCHIVE.REJECTED`), which the
    truncation notice would only repeat."""
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    rules_evaluated: int = 0

    finding_cap: int = 0
    """Ceiling on retained findings, from `limits.max_findings`.

    Zero disables it. The limit was declared and documented -- "a hostile
    repository can otherwise turn a scan into an out-of-memory failure by
    arranging for every line to match. Reaching this cap is itself reported" --
    and never checked anywhere.
    """

    capped: bool = False

    def append(self, finding: Finding) -> bool:
        """Retain one finding if the cap allows it.

        Enforced here rather than at render time, which is where
        `ReportOptions.max_findings` applies -- by then everything is already in
        memory and the limit has prevented nothing.
        """
        if finding.rule_id in INCOMPLETE_WHEN_REPORTED:
            self.complete = False
        if self.finding_cap and len(self.findings) >= self.finding_cap:
            self.capped = True
            self.complete = False
            return False
        self.findings.append(finding)
        return True

    def add(self, produced: Iterable[Finding]) -> None:
        """Retain a batch, stopping at the cap."""
        for finding in produced:
            if not self.append(finding):
                return


__all__ = []
