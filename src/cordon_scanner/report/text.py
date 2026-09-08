"""Human-readable terminal output.

Written for somebody who did not author the rule, reading it under time
pressure, deciding whether to act. That reader needs four things in order: how
bad is it, where is it, why does the tool believe this, and what do I do.

Anything that does not serve one of those questions is noise, and noise is not
neutral here. A report that is tiring to read is a report that gets skimmed, and
a tool whose output gets skimmed stops being a control.

The ``why`` block renders the risk score's own derivation. That is the
explainability requirement made concrete: a reader can check the arithmetic. A
score nobody can reconstruct is a score nobody trusts, and a score nobody trusts
gets configured away.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon_scanner.core.models import Category, Severity
from cordon_scanner.report.base import BaseReporter, ReportOptions
from cordon_scanner.version import __version__

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.core.models import Finding, ScanResult

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}

WIDTH = 76


class TextReporter(BaseReporter):
    @staticmethod
    def _wrap(text: str, width: int, indent: str) -> list[str]:
        """Wrap prose to a width, preserving the indent."""
        words = text.split()
        if not words:
            return []
        lines: list[str] = []
        current = indent
        for word in words:
            if len(current) + len(word) + 1 > width and current.strip():
                lines.append(current)
                current = indent + word
            else:
                current = f"{current} {word}" if current.strip() else indent + word
        if current.strip():
            lines.append(current)
        return lines

    id = "text"
    media_type = "text/plain"
    file_extension = ".txt"

    def render(self, result: ScanResult, opts: ReportOptions) -> Iterator[bytes]:
        color = opts.color

        yield self._line(
            f"{DIM}cordon {__version__} · rulepack {result.rulepack_version} "
            f"({result.rulepack_hash}){RESET}",
            color,
        )
        yield b"\n"

        shown = [f for f in result.findings if opts.show_suppressed or not f.is_suppressed]
        reportable = [f for f in shown if f.category is not Category.OPERATIONAL]
        operational = [f for f in shown if f.category is Category.OPERATIONAL]

        if opts.max_findings and len(reportable) > opts.max_findings:
            hidden = len(reportable) - opts.max_findings
            reportable = reportable[: opts.max_findings]
        else:
            hidden = 0

        for finding in reportable:
            yield from self._finding(finding, color, opts.verbose)

        # Operational findings are grouped at the end rather than interleaved.
        # They describe the scan rather than the code, and mixing the two makes
        # a reader work to tell "your code is fine" from "I could not look".
        if operational:
            yield from self._operational_block(operational, color)

        yield from self._summary(result, color, hidden)

    # -- Findings --------------------------------------------------------

    def _finding(self, f: Finding, color: bool, verbose: bool) -> Iterator[bytes]:
        tint = SEVERITY_COLOR.get(f.severity, "")
        header = f"{tint}{str(f.severity).upper():<9}{RESET}{BOLD}{f.rule_id}{RESET}"
        suffix = f"{DIM}risk {f.risk.value}/100{RESET}"
        yield self._line(f"{header}  {suffix}", color)

        yield self._line(f"  {f.location}", color)
        meta = f"  {DIM}{f.category} · confidence {f.confidence} · detector {f.detector}{RESET}"
        yield self._line(meta, color)

        if f.is_suppressed and f.suppressed:
            yield self._line(
                f"  {DIM}suppressed until {f.suppressed.expires}"
                f"{' by ' + f.suppressed.approved_by if f.suppressed.approved_by else ''}"
                f"{RESET}",
                color,
            )

        yield b"\n"
        for line in TextReporter._wrap(f.message, WIDTH, "  "):
            yield self._line(line, color)

        if f.evidence.snippet:
            yield b"\n"
            yield self._line(f"  {DIM}evidence{RESET}  {f.evidence.snippet}", color)
        elif f.evidence.match_hash:
            yield b"\n"
            yield self._line(
                f"  {DIM}evidence{RESET}  {DIM}withheld; match "
                f"{f.evidence.match_hash[:23]}...{RESET}",
                color,
            )

        # The score, rendered as its own derivation. The reader can check it.
        yield b"\n"
        first = True
        for line in f.risk.explain():
            label = "why     " if first else "        "
            yield self._line(f"  {DIM}{label}{RESET}  {line}", color)
            first = False

        # Escalations get their own labelled block. Printed under the `why`
        # indent they read as further arithmetic, which is misleading: they are
        # the reason the severity changed, not a term in the sum.
        if f.explanation.escalations:
            yield b"\n"
            for index, escalation in enumerate(f.explanation.escalations):
                label = "context " if index == 0 else "        "
                for line_index, line in enumerate(TextReporter._wrap(escalation, WIDTH - 12, "")):
                    prefix = label if line_index == 0 else "        "
                    yield self._line(f"  {DIM}{prefix}{RESET}  {line.strip()}", color)

        if verbose and f.explanation.contributing:
            contributors = ", ".join(f.explanation.contributing)
            yield self._line(f"  {DIM}        {RESET}  from: {contributors}", color)

        if f.remediation:
            yield b"\n"
            wrapped = TextReporter._wrap(f.remediation, WIDTH - 12, "")
            for index, line in enumerate(wrapped):
                label = "fix     " if index == 0 else "        "
                yield self._line(f"  {DIM}{label}{RESET}  {line.strip()}", color)

        if f.references:
            yield b"\n"
            for index, ref in enumerate(f.references):
                label = "refs    " if index == 0 else "        "
                yield self._line(f"  {DIM}{label}{RESET}  {ref}", color)

        yield b"\n"

    def _operational_block(self, findings: list[Finding], color: bool) -> Iterator[bytes]:
        yield self._line(f"{DIM}{'-' * WIDTH}{RESET}", color)
        yield self._line(
            f"{DIM}scan coverage{RESET}  {len(findings)} note(s) about the scan itself",
            color,
        )
        for f in findings[:10]:
            yield self._line(f"  {DIM}{f.location.path}{RESET}  {f.message}", color)
        if len(findings) > 10:
            yield self._line(f"  {DIM}... and {len(findings) - 10} more{RESET}", color)
        yield b"\n"

    # -- Summary ---------------------------------------------------------

    def _summary(self, result: ScanResult, color: bool, hidden: int) -> Iterator[bytes]:
        counts = result.by_severity()
        yield self._line(f"{DIM}{'-' * WIDTH}{RESET}", color)

        parts = []
        for severity in (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ):
            count = counts.get(severity, 0)
            tint = SEVERITY_COLOR.get(severity, "") if count else DIM
            parts.append(f"{tint}{count} {severity}{RESET}")

        suppressed = len(result.suppressed)
        if suppressed:
            parts.append(f"{DIM}{suppressed} suppressed{RESET}")

        yield self._line(" · ".join(parts), color)

        stats = result.stats
        detail = (
            f"{DIM}{stats.files_scanned} files · {stats.duration_ms}ms"
            f"{f' · {stats.files_skipped} skipped' if stats.files_skipped else ''}"
            f"{RESET}"
        )
        yield self._line(detail, color)

        # Completeness is stated on every scan, not only when it fails. A reader
        # should never have to infer whether the tool actually looked.
        if result.complete:
            yield self._line(f"{DIM}scan complete{RESET}", color)
        else:
            yield self._line(
                f"{SEVERITY_COLOR[Severity.MEDIUM]}scan INCOMPLETE{RESET} "
                f"{DIM}- results are partial; see the coverage notes above{RESET}",
                color,
            )

        if hidden:
            yield self._line(f"{DIM}{hidden} further finding(s) not shown{RESET}", color)

    # -- Helpers ---------------------------------------------------------

    @staticmethod
    def _line(text: str, color: bool) -> bytes:
        if not color:
            for code in (RESET, BOLD, DIM, *SEVERITY_COLOR.values()):
                text = text.replace(code, "")
        return (text + "\n").encode("utf-8")


__all__ = ["TextReporter"]
