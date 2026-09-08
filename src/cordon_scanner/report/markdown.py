"""Markdown, for pull-request comments and job summaries.

A pull-request comment is the most public destination a finding reaches: it is
visible to everyone with read access, it is emailed, and it persists after the
branch is gone. So evidence is masked here regardless of configuration, and the
comment is written to be skimmed rather than read.

Length is capped hard. A comment listing forty findings is a comment that gets
collapsed, and a collapsed comment protects nobody.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon_scanner.core.models import Category, Severity
from cordon_scanner.report.base import BaseReporter, Escape, ReportOptions

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.core.models import Finding, ScanResult

MAX_DETAILED = 10

SEVERITY_LABEL = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "info",
}


class MarkdownReporter(BaseReporter):
    id = "markdown"
    media_type = "text/markdown"
    file_extension = ".md"

    def render(self, result: ScanResult, opts: ReportOptions) -> Iterator[bytes]:
        findings = [
            f
            for f in result.findings
            if f.category is not Category.OPERATIONAL and not f.is_suppressed
        ]

        yield b"## Cordon supply-chain scan\n\n"

        if not findings:
            yield b"No findings.\n\n"
            yield self._footer(result)
            return

        counts = result.by_severity()
        header = " | ".join(
            f"{counts.get(s, 0)} {SEVERITY_LABEL[s]}"
            for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        )
        yield f"{header}\n\n".encode()

        yield b"| Severity | Rule | Location | Risk |\n"
        yield b"|---|---|---|---|\n"
        for finding in findings[:30]:
            yield (
                f"| {SEVERITY_LABEL[finding.severity]} "
                f"| `{Escape.code(finding.rule_id)}` "
                f"| `{Escape.code(str(finding.location))}` "
                f"| {finding.risk.value}/100 |\n"
            ).encode()

        if len(findings) > 30:
            yield f"\n_{len(findings) - 30} further finding(s) not listed._\n".encode()

        yield b"\n"
        for finding in findings[:MAX_DETAILED]:
            yield from self._detail(finding)

        yield self._footer(result)

    def _detail(self, f: Finding) -> Iterator[bytes]:
        yield (
            f"<details>\n<summary><b>{Escape.code(f.rule_id)}</b> at "
            f"<code>{Escape.code(str(f.location))}</code></summary>\n\n"
        ).encode()
        yield f"{Escape.markdown(f.message)}\n\n".encode()

        if f.explanation.escalations:
            yield b"**Why this severity**\n\n"
            for line in f.explanation.escalations:
                yield f"- {Escape.markdown(line)}\n".encode()
            yield b"\n"

        if f.remediation:
            yield f"**Remediation.** {Escape.markdown(f.remediation)}\n\n".encode()

        # Never the snippet. A comment is more public than a log, so only the
        # hash is published, which is still enough to correlate with a full
        # report elsewhere.
        yield f"`{Escape.code(f.evidence.match_hash)}`\n\n".encode()
        yield b"</details>\n\n"

    @staticmethod
    def _footer(result: ScanResult) -> bytes:
        state = "complete" if result.complete else "INCOMPLETE (results are partial)"
        return (
            f"---\n"
            f"{result.stats.files_scanned} files, "
            f"{result.stats.dependencies} dependencies, "
            f"{result.stats.duration_ms}ms, scan {state}. "
            f"Rules `{result.rulepack_version}` (`{result.rulepack_hash}`).\n"
        ).encode()


__all__ = ["MarkdownReporter"]
