"""GitLab Code Quality, which is the only report GitLab renders inline.

GitLab's security dashboards read its own report schemas, and those are a
licensed feature. The Code Quality report is not: it is available on every plan,
it renders in the merge request as a list of findings against the lines they
touch, and it is the one place a GitLab reviewer sees a scanner's output without
opening a job log.

The format is Code Climate's, which predates GitLab's use of it and carries no
severity vocabulary of its own beyond five words. The mapping is stated here
rather than inferred at the call site:

    critical -> blocker      high -> critical      medium -> major
    low      -> minor        info -> info

`fingerprint` is what GitLab uses to tell one finding from the next across
commits, so an unstable one makes every finding look new on every run. Cordon
already computes a stable one per finding; it is reused rather than rederived,
which is also what keeps a report comparable with the SARIF of the same scan.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from cordon_scanner.core.models import Category, Severity
from cordon_scanner.report.base import BaseReporter

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.core.models import Finding, ScanResult
    from cordon_scanner.report.base import ReportOptions

#: Code Climate's five words, which are all GitLab renders.
SEVERITY = {
    Severity.CRITICAL: "blocker",
    Severity.HIGH: "critical",
    Severity.MEDIUM: "major",
    Severity.LOW: "minor",
    Severity.INFO: "info",
}


class CodeClimateReporter(BaseReporter):
    """Code Quality JSON, for `artifacts: reports: codequality`."""

    id = "codeclimate"
    media_type = "application/json"
    file_extension = ".json"

    def render(self, result: ScanResult, opts: ReportOptions) -> Iterator[bytes]:
        findings = [f for f in result.findings if f.category is not Category.OPERATIONAL]
        if not opts.show_suppressed:
            findings = [f for f in findings if not f.is_suppressed]
        payload = [self._entry(finding) for finding in findings]
        yield json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        yield b"\n"

    @staticmethod
    def _entry(finding: Finding) -> dict[str, object]:
        # A finding about a whole file still has to name a line: GitLab drops
        # an entry with no position rather than showing it at the top of the
        # file.
        location = {
            "path": finding.location.path,
            "lines": {"begin": finding.location.line or 1},
        }
        # `check_name` is the rule, `description` is what happened. GitLab
        # shows the description and groups by the check, which is the division
        # the text reporter already makes between a rule id and a message.
        entry: dict[str, object] = {
            "type": "issue",
            "check_name": finding.rule_id,
            "description": finding.message,
            "categories": ["Security"],
            "severity": SEVERITY.get(finding.severity, "info"),
            "fingerprint": finding.fingerprint,
            "location": location,
        }
        if finding.remediation:
            entry["content"] = {"body": finding.remediation}
        return entry


__all__ = ["SEVERITY", "CodeClimateReporter"]
