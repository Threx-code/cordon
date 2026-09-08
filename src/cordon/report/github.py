"""GitHub Actions workflow commands.

Emits annotations that appear inline on the diff, which is the only place a
reviewer reliably sees them.

Two constraints come from the platform rather than from taste. Annotations are
capped at ten per level per step, so emitting more is wasted output that
displaces useful lines. And any newline in a message must be encoded, or the
remainder is printed as ordinary log text and the annotation is silently
truncated.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon.core.models import Category, Severity
from cordon.report.base import BaseReporter, ReportOptions

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon.core.models import ScanResult

LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "notice",
    Severity.INFO: "notice",
}

MAX_PER_LEVEL = 10


class GithubReporter(BaseReporter):
    @staticmethod
    def _escape_data(text: str) -> str:
        """Encode a workflow-command message body.

        A raw newline ends the command, so the rest of the message becomes ordinary
        log text and the annotation is silently truncated.
        """
        return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

    @staticmethod
    def _escape_property(text: str) -> str:
        return GithubReporter._escape_data(text).replace(":", "%3A").replace(",", "%2C")

    id = "github"
    media_type = "text/plain"
    file_extension = ".txt"

    def render(self, result: ScanResult, opts: ReportOptions) -> Iterator[bytes]:
        emitted: dict[str, int] = {"error": 0, "warning": 0, "notice": 0}

        for finding in result.findings:
            if finding.is_suppressed or finding.category is Category.OPERATIONAL:
                continue

            level = LEVEL[finding.severity]
            if emitted[level] >= MAX_PER_LEVEL:
                continue
            emitted[level] += 1

            location = finding.location
            parts = [f"file={GithubReporter._escape_property(location.path)}"]
            if location.line:
                parts.append(f"line={location.line}")
            if location.column:
                parts.append(f"col={location.column}")
            parts.append(f"title={GithubReporter._escape_property(finding.rule_id)}")

            message = GithubReporter._escape_data(
                f"{finding.message} "
                f"[{finding.severity}/{finding.confidence}, "
                f"risk {finding.risk.value}/100] {finding.remediation}"
            )
            yield f"::{level} {','.join(parts)}::{message}\n".encode()

        total = sum(1 for f in result.active if f.category is not Category.OPERATIONAL)
        shown = sum(emitted.values())
        if total > shown:
            yield (
                f"::notice::{total - shown} further finding(s) were not annotated; "
                f"GitHub limits annotations to {MAX_PER_LEVEL} per level. "
                f"See the full report in the job summary or in code scanning.\n"
            ).encode()

        if not result.complete:
            yield (
                b"::warning::The scan did not complete, so results are partial. "
                b"Treat this as reduced coverage rather than a clean result.\n"
            )


__all__ = ["GithubReporter"]
