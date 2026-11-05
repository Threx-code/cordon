"""The mutable state of one scan: the findings so far, whether coverage stayed complete, whether every
dependency met an advisory source, and the counters the result reports.

Local to a single run. The engine itself holds no per-scan state, which is what makes one Scanner
instance reusable and safe to share; each phase that adds to a scan is handed this.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from cordon_scanner.engine.pipeline.constants import INCOMPLETE_WHEN_REPORTED
from cordon_scanner.foundation.models import Finding, Severity
from cordon_scanner.foundation.results import NOT_CONTENT_GAPS, Dependency, OperationalFinding
from cordon_scanner.foundation.taxonomy import AttackCategory

if TYPE_CHECKING:
    from collections.abc import Iterable


NOTICES = ("OPERATIONAL.INTEL.", "OPERATIONAL.ADVISORY.")
"""Operational findings about the advisory side, which `advisory_complete` reports: none of them
says that a file's content went unexamined."""


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

    facts: dict[str, dict[str, list[Any]]] = field(default_factory=dict)
    """Per-file facts the workers sent back (item 56, `engine/isolation/facts.py`), by path: plain data
    the parent joins across files without parsing any of them."""
    facts_bytes: int = 0
    """The bytes those facts took, against the scan's bound."""
    facts_content: int = 0
    """The bytes of content detection read, which the bound grows with (`Facts.budget`)."""
    verdict_facts: dict[str, float] | None = None
    """The facts the package verdict reads, when the rule file's deferred pass gathered them
    already (`engine/pipeline/facts`): the verdict reuses them instead of computing twice."""
    labels: dict[str, Any] = field(default_factory=dict)
    """The capability labels computed with those facts, which the intent observation reuses."""

    finding_cap: int = 0
    """Ceiling on retained findings, from `limits.max_findings`.

    Zero disables it. The limit was declared and documented -- "a hostile
    repository can otherwise turn a scan into an out-of-memory failure by
    arranging for every line to match. Reaching this cap is itself reported" --
    and never checked anywhere.
    """

    capped: bool = False

    content_gaps: list[tuple[str, str]] = field(default_factory=list)
    """(rule, path) of each coverage finding whose cause is the scanned content (every cause but `NOT_CONTENT_GAPS`),
    recorded where the scan stopped being complete: the gate blocks on these (item 27)."""
    _gap_keys: set[tuple[str, str]] = field(default_factory=set, repr=False)

    ledger_tree: list[str] = field(default_factory=list)
    """Every file the walk presented and every archive member listed, by path, in order: what the
    coverage ledger (item 38, `CoverageLedger`) accounts for."""
    ledger_read: set[str] = field(default_factory=set)
    """Paths whose unit was inspected: by a worker, or answered from the cache."""
    ledger_unstarted: set[str] = field(default_factory=set)
    """Paths of units the pool never started because the scan's budget ran out (GAPPED by path)."""

    not_installed: list[Dependency] = field(default_factory=list)
    """Dependency records only a file outside the inventory's scope declares (`DependencyScope`):
    reported with `installed=False`, never read by an install-set check or the verdict."""

    not_installed_findings: list[Finding] = field(default_factory=list)
    """Findings a member detector made about a file outside the inventory's scope, held out of the
    verdict at their info twins (`NotInstalledFiles`) and added after it."""

    late: bool = False
    """Whether `out_of_time` has reported the spent budget."""

    def incomplete(self, finding: Finding) -> bool:
        """The one way a scan stops being complete: `finding` says what went unread and why, and
        its rule is the cause the gate reads (every cause but `NOT_CONTENT_GAPS`, item 27). Retained as `append`."""
        self.complete = False
        self._gap(finding.rule_id, finding.location.path)
        return self.append(finding)

    def gap(self, finding: Finding) -> Finding:
        """`incomplete` for a finding the caller keeps itself (a list of a file's findings added
        later): the scan stops being complete and the cause is recorded, here; `finding` is
        returned to be kept where the caller keeps the rest."""
        self.complete = False
        self._gap(finding.rule_id, finding.location.path)
        return finding

    def out_of_time(self, ctx: Any, where: str, step: str) -> bool:
        """Whether the scan's budget is spent (`ScanContext.out_of_time`), checked before work after
        detection: then `step` does not run, and the scan says so, once, as a blocking gap (item 64:
        past the deadline the release checks loaded the whole advisory index, tens of seconds under
        load, while the scan was already over its budget)."""
        if ctx is None or not ctx.out_of_time():
            return False
        if not self.late:
            self.late = True
            self.incomplete(
                OperationalFinding.build(
                    path=where,
                    rule_id="OPERATIONAL.SCAN.TIMEOUT",
                    message=f"The scan's budget was spent before {step}, which did not run, nor did "
                    "any later step after detection.",
                    remediation="Rescan with more time (--timeout), or on a less loaded machine.",
                    severity=Severity.MEDIUM,
                )
            )
        return True

    def ended_late(self, ctx: Any, where: str) -> None:
        """A scan that ends past its deadline is never complete, whatever it finished (item 64: one ran
        nine times past its budget and exited 0, called complete)."""
        if ctx is not None and ctx.out_of_time() and self.complete:
            self.out_of_time(ctx, where, "the end of the scan")

    def coverage(self) -> dict[str, Any]:
        """The result's coverage fields, as `ScanResult` takes them."""
        return {
            "complete": self.complete and self.advisory_complete,
            "content_complete": self.complete,
            "content_gaps": tuple(self.content_gaps),
            "advisory_complete": self.advisory_complete,
        }

    def named_elsewhere(self, rule: str, path: str) -> None:
        """`incomplete` where the finding that names the cause is made by another step (a
        lockfile's OPERATIONAL.LOCKFILE.UNPARSED by its detector, the walk's limit by the walk's
        own notes): the scan stops being complete and the cause is recorded, with no second
        finding saying it again."""
        self.complete = False
        self._gap(rule, path)

    def absorb(self, complete: bool, gaps: tuple[tuple[str, str], ...]) -> None:
        """A worker's verdict on one unit, as this accumulator's own (item 28): the worker inspected
        the unit through `Detection.run` into an accumulator of its own, and its completeness and
        gaps cross back as data. One implementation, so the two processes cannot disagree."""
        if not complete:
            self.complete = False
        for rule, path in gaps:
            self._gap(rule, path)

    def _gap(self, rule: str, path: str) -> None:
        # Once per (rule, path): a finding both reported-incomplete and passed to `incomplete` is
        # one gap, not two.
        if rule not in NOT_CONTENT_GAPS and (rule, path) not in self._gap_keys:
            self._gap_keys.add((rule, path))
            self.content_gaps.append((rule, path))

    def append(self, finding: Finding) -> bool:
        """Retain one finding if the cap allows it.

        Enforced here rather than at render time, which is where
        `ReportOptions.max_findings` applies -- by then everything is already in
        memory and the limit has prevented nothing.
        """
        if finding.rule_id in INCOMPLETE_WHEN_REPORTED:
            self.complete = False
            self._gap(finding.rule_id, finding.location.path)
        if self.finding_cap and len(self.findings) >= self.finding_cap:
            if not self.capped:
                self._gap("OPERATIONAL.SCAN.FINDING_LIMIT", ".")  # a flood the content chose
            self.capped = True
            self.complete = False
            return False
        self.findings.append(finding)
        return True

    def explain_incomplete(self) -> None:
        """An incomplete scan says why: when no coverage finding names what went unexamined, a
        backstop does (`OPERATIONAL.SCAN.INCOMPLETE`). Every path that leaves a scan incomplete
        reports its own reason, so the backstop is a guarantee, never the expected path: two
        zuppa wheels ended incomplete with only a detection finding to show for it (review 98).

        A coverage finding is what the taxonomy says it is (`AttackCategory.COVERAGE`): every
        `OPERATIONAL.` finding and `POLICY.COVERAGE.PRUNED` among them. The pruned-directory note
        already says what went unread at its own, low severity; a second, medium note beside it
        would block a default scan it was written to leave quiet."""
        if self.complete or any(
            f.attack_category is AttackCategory.COVERAGE and not f.rule_id.startswith(NOTICES)
            for f in self.findings
        ):
            return
        self._gap("OPERATIONAL.SCAN.INCOMPLETE", ".")
        self.findings.append(
            OperationalFinding.build(
                path=".",
                rule_id="OPERATIONAL.SCAN.INCOMPLETE",
                message=(
                    "Part of this scan's input was not examined, and no specific reason was "
                    "recorded."
                ),
                remediation="Treat the unexamined part as unexamined, not as clean.",
                severity=Severity.MEDIUM,
            )
        )

    def add(self, produced: Iterable[Finding]) -> None:
        """Retain a batch, stopping at the cap."""
        for finding in produced:
            if not self.append(finding):
                return


__all__ = []
