"""JUnit XML.

Not a natural fit for security findings, and shipped anyway because it is the
one format every CI system already knows how to display. A team that has to
click into a build log to read results will stop reading them; a team whose
existing test tab shows the findings will not.

The mapping treats each rule as a test case and each finding as a failure of it.
That is a deliberate distortion of the format, and the alternative -- one test
case per finding -- is worse, because it makes the test count change on every
run and the history unreadable.
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING
from xml.sax.saxutils import escape, quoteattr

from cordon_scanner.core.models import Category
from cordon_scanner.report.base import BaseReporter, Escape, ReportOptions

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.core.models import Finding, ScanResult


class JunitReporter(BaseReporter):
    id = "junit"
    media_type = "application/xml"
    file_extension = ".xml"

    def render(self, result: ScanResult, opts: ReportOptions) -> Iterator[bytes]:
        findings = [f for f in result.findings if f.category is not Category.OPERATIONAL]
        if not opts.show_suppressed:
            findings = [f for f in findings if not f.is_suppressed]

        by_rule: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            by_rule[finding.rule_id].append(finding)

        failures = sum(1 for f in findings if not f.is_suppressed)
        skipped = sum(1 for f in findings if f.is_suppressed)

        yield b'<?xml version="1.0" encoding="UTF-8"?>\n'
        yield (
            f'<testsuites name="cordon" tests="{len(by_rule)}" '
            f'failures="{failures}" skipped="{skipped}" '
            f'time="{result.stats.duration_ms / 1000:.3f}">\n'
        ).encode()
        yield (
            f'  <testsuite name="cordon" tests="{len(by_rule)}" '
            f'failures="{failures}" skipped="{skipped}">\n'
        ).encode()

        for rule_id in sorted(by_rule):
            for finding in sorted(by_rule[rule_id], key=lambda f: str(f.location)):
                yield from self._case(finding)

        # A degraded scan must be visible in the test tab too, or a partial run
        # is indistinguishable from a clean one in the place people actually
        # look.
        if not result.complete:
            yield (
                b'    <testcase name="scan.completeness" classname="cordon">\n'
                b'      <failure message="the scan did not complete">'
                b"Results are partial. Coverage was reduced by a limit or a timeout."
                b"</failure>\n    </testcase>\n"
            )

        yield b"  </testsuite>\n</testsuites>\n"

    @staticmethod
    def _attr(text: str) -> str:
        """Quote an attribute, with control characters removed first.

        `quoteattr` handles `&<>"` and not C0 control characters, which XML 1.0
        forbids outright. A filename may legally contain one on POSIX, so a path
        holding `\x01` produced a document every conforming parser rejects --
        and a CI test tab that shows nothing at all rather than the finding.
        """
        return quoteattr(Escape.control_characters(text))

    @staticmethod
    def _text(text: str) -> str:
        """Escape element text, with control characters removed first."""
        return escape(Escape.control_characters(text))

    def _case(self, finding: Finding) -> Iterator[bytes]:
        name = self._attr(f"{finding.rule_id} {finding.location}")
        classname = self._attr(finding.detector)

        yield f"    <testcase name={name} classname={classname}>\n".encode()

        if finding.is_suppressed and finding.suppressed:
            reason = self._attr(finding.suppressed.justification[:200])
            yield f"      <skipped message={reason}/>\n".encode()
        else:
            summary = self._attr(f"{finding.severity}: {finding.explanation.summary}"[:200])
            body = self._text(
                f"{finding.message}\n\n"
                f"Location:   {finding.location}\n"
                f"Severity:   {finding.severity}\n"
                f"Confidence: {finding.confidence}\n"
                f"Risk:       {finding.risk.value}/100\n\n"
                f"Remediation: {finding.remediation}"
            )
            yield f"      <failure message={summary}>{body}</failure>\n".encode()

        yield b"    </testcase>\n"


__all__ = ["JunitReporter"]
