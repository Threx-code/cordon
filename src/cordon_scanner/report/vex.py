"""CycloneDX VEX: which of the vulnerabilities in the SBOM actually apply.

An SBOM says what is in the artefact. A scanner says which of those have
advisories. Neither answers the question a consumer downstream actually has --
*does this one affect you* -- and that gap is why vulnerability reports arrive
in inboxes as spreadsheets to be triaged by hand, repeatedly, by people who
cannot see the code.

VEX is the answer written down. Each statement names a vulnerability, the
component it is about, and an analysis: exploitable, or not affected with a
reason. It is machine-readable, so a consumer's own tooling can drop what the
producer has already ruled out instead of re-raising it.

Cordon has exactly one thing to say here, and says only that. With
`--reachability`, a transitive dependency that first-party code does not import
is recorded as `not_affected` with the justification `code_not_reachable` and
the detail that this is an import-level check rather than a call-graph proof.
Everything else is `exploitable`, which is the honest default: not "we looked
and it is exploitable", but "nothing here rules it out".

The document is a CycloneDX 1.5 BOM carrying only `vulnerabilities`, which is
the shape the specification calls an independent VEX -- it references the
components by purl rather than restating the SBOM, so the two can be published
together and stay consistent.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from cordon_scanner.core.models import Category, Severity
from cordon_scanner.report.base import BaseReporter
from cordon_scanner.version import __version__

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.core.models import Finding, ScanResult
    from cordon_scanner.report.base import ReportOptions

#: CycloneDX's severity vocabulary, which is not Cordon's.
SEVERITY = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "info",
}

VULNERABILITY_RULES = frozenset({"VULNERABLE.DEPENDENCY.KNOWN.001", "MALWARE.DEPENDENCY.KNOWN.001"})
"""The findings that name a vulnerability rather than describe a behaviour.

A VEX statement is about a known vulnerability in a component. A finding that a
build script pipes a download into a shell is neither, and putting it here would
produce a document whose statements cannot be acted on by the tooling that reads
them."""


class VexReporter(BaseReporter):
    """`--format vex`, alongside the SBOM of the same scan."""

    id = "vex"
    media_type = "application/vnd.cyclonedx+json"
    file_extension = ".vex.json"

    def render(self, result: ScanResult, opts: ReportOptions) -> Iterator[bytes]:
        findings = [
            finding
            for finding in result.findings
            if finding.rule_id in VULNERABILITY_RULES
            and finding.category is not Category.OPERATIONAL
        ]
        if not opts.show_suppressed:
            findings = [f for f in findings if not f.is_suppressed]

        document = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "tools": [{"vendor": "cordon", "name": "cordon-scanner", "version": __version__}]
            },
            "vulnerabilities": [self._statement(f) for f in findings],
        }
        yield json.dumps(document, indent=2, sort_keys=True).encode("utf-8")
        yield b"\n"

    @staticmethod
    def _statement(finding: Finding) -> dict[str, object]:
        metadata = dict(finding.evidence.metadata)
        reachability = metadata.get("reachability", "")

        if reachability == "not_imported":
            analysis: dict[str, object] = {
                "state": "not_affected",
                "justification": "code_not_reachable",
                "detail": (
                    "First-party code in this repository does not import this "
                    "transitive dependency. This is an import-level check, not a "
                    "call-graph proof: it rules out the ordinary path to the "
                    "vulnerable code, not a dynamic load."
                ),
            }
        else:
            # Not a claim that it is exploitable. A statement has to say
            # something, and "nothing here rules it out" is what `exploitable`
            # means when the producer has not analysed further. What was
            # actually looked at is recorded, because a consumer reading this
            # deserves to know whether an analysis ran at all.
            looked = {
                "imported": (
                    "First-party code imports this package, so the ordinary path "
                    "to the vulnerable code exists."
                ),
                "unknown": (
                    "Reachability could not be determined: a direct dependency not "
                    "seen imported may be loaded dynamically or under another name."
                ),
            }.get(
                str(reachability),
                "Reported against the resolved version. No reachability analysis "
                "ran; pass --reachability for the import-level check.",
            )
            analysis = {"state": "exploitable", "detail": looked}

        statement: dict[str, object] = {
            "id": VexReporter._identifier(finding),
            "source": {"name": "OSV"},
            "analysis": analysis,
            "description": finding.message,
            "ratings": [{"severity": SEVERITY.get(finding.severity, "unknown"), "method": "other"}],
        }
        if finding.location.package:
            statement["affects"] = [{"ref": finding.location.package}]
        if finding.remediation:
            statement["recommendation"] = finding.remediation
        if finding.references:
            statement["advisories"] = [{"url": url} for url in finding.references]
        return statement

    @staticmethod
    def _identifier(finding: Finding) -> str:
        """The advisory identifier, or the fingerprint when there is none.

        A VEX statement without an id cannot be correlated with anything, which
        is the whole purpose of the document, so one is always emitted.
        """
        explanation = finding.explanation
        for token in (explanation.summary if explanation else "").split():
            cleaned = token.strip(".,()")
            if cleaned.startswith(("GHSA-", "CVE-", "MAL-", "RUSTSEC-", "PYSEC-", "GO-")):
                return cleaned
        for token in finding.message.split():
            cleaned = token.strip(".,()")
            if cleaned.startswith(("GHSA-", "CVE-", "MAL-", "RUSTSEC-", "PYSEC-", "GO-")):
                return cleaned
        return f"cordon-{finding.fingerprint}"


__all__ = ["SEVERITY", "VULNERABILITY_RULES", "VexReporter"]
