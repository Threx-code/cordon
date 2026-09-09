"""SARIF 2.1.0 output.

SARIF is how findings reach code-scanning platforms, and it is easy to produce a
technically-valid file that is useless in practice. Three properties decide
whether it works, and all three are frequently missed:

**``security-severity``.** This is what platforms sort, filter and threshold on.
A SARIF file without it renders every finding as equally important, discarding
the entire ranking the risk scorer exists to produce. It is a string on the rule,
on a 0-10 scale.

**``partialFingerprints``.** This is how a platform tracks an alert across
commits. Without it, reformatting a file re-raises every alert in it as new,
users get an alert storm caused by a whitespace change, and they learn to dismiss
findings in bulk. Cordon's fingerprints deliberately exclude line and column for
exactly this reason.

**``tool.driver.rules``.** The full rule catalogue, not only the rules that
fired. Platforms render rule help pages from this, so omitting it means a
developer clicking through from an alert lands on nothing.

Suppressed findings are emitted with a ``suppressions`` entry rather than
dropped, so a reviewer can see what was silenced and why without reading the
repository's configuration.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from cordon_scanner.core.models import Category, Severity
from cordon_scanner.core.scoring import RiskScorer
from cordon_scanner.report.base import BaseReporter, ReportOptions
from cordon_scanner.version import __version__

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.core.models import Finding, ScanResult

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

# SARIF has three levels. The mapping compresses five severities into them, so
# the precise ranking has to survive elsewhere -- which is what
# `security-severity` is for.
LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


class SarifReporter(BaseReporter):
    @staticmethod
    def _pascal(rule_id: str) -> str:
        """Turn a dotted rule id into a SARIF ``name``.

        The spec asks for an opaque identifier; platforms display it, so it should
        read as a name rather than as punctuation.
        """
        return "".join(part.capitalize() for part in rule_id.replace(".", " ").split())

    id = "sarif"
    media_type = "application/sarif+json"
    file_extension = ".sarif"

    def render(self, result: ScanResult, opts: ReportOptions) -> Iterator[bytes]:
        findings = [f for f in result.findings if f.category is not Category.OPERATIONAL]
        if not opts.show_suppressed:
            findings = [f for f in findings if not f.is_suppressed]

        rules, rule_index = self._rules(findings)

        run: dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": "Cordon",
                    "version": __version__,
                    "informationUri": "https://github.com/Threx-code/cordon",
                    "semanticVersion": __version__,
                    "rules": rules,
                }
            },
            "results": [self._result(f, rule_index) for f in findings],
            "invocations": [
                {
                    # A degraded scan says so in the SARIF itself, so a platform
                    # showing zero alerts is distinguishable from a scan that
                    # could not finish.
                    "executionSuccessful": result.complete,
                    "toolExecutionNotifications": [
                        self._notification(f)
                        for f in result.findings
                        if f.category is Category.OPERATIONAL
                    ],
                }
            ],
            "automationDetails": {"id": f"cordon/{result.config_hash}"},
            "properties": {
                "rulepack": result.rulepack_version,
                "rulepackHash": result.rulepack_hash,
                "configHash": result.config_hash,
                "complete": result.complete,
            },
        }

        if opts.repository_uri:
            run["versionControlProvenance"] = [
                {
                    "repositoryUri": opts.repository_uri,
                    **({"revisionId": opts.revision} if opts.revision else {}),
                }
            ]

        document = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [run],
        }

        # Encoded in chunks rather than as one string. `base.py` says `render`
        # streams "so a result with fifty thousand findings streams to disk
        # instead of being assembled in memory. On a hostile repository the
        # finding count is attacker-influenced, which makes streaming a
        # resource-safety property" -- and this reporter built the whole
        # document and called `json.dumps` on it, holding the encoded form and
        # the object graph at once, at the `max_findings` ceiling of fifty
        # thousand.
        #
        # `JSONEncoder.iterencode` produces the identical bytes without ever
        # materialising them, so the property the base class documents is true
        # of the format most likely to be large.
        encoder = json.JSONEncoder(indent=2, sort_keys=True, ensure_ascii=False)
        for piece in encoder.iterencode(document):
            yield piece.encode("utf-8")
        yield b"\n"

    # -- Rule catalogue --------------------------------------------------

    def _rules(self, findings: list[Finding]) -> tuple[list[dict[str, Any]], dict[str, int]]:
        """Build the rule catalogue and an id-to-index map.

        Deduplicated by rule id and ordered deterministically, because SARIF
        results reference rules by index and an unstable order would make two
        runs of the same scan produce different documents.
        """
        seen: dict[str, Finding] = {}
        for finding in findings:
            seen.setdefault(finding.rule_id, finding)

        rules: list[dict[str, Any]] = []
        index: dict[str, int] = {}

        for position, (rule_id, example) in enumerate(sorted(seen.items())):
            index[rule_id] = position
            rules.append(
                {
                    "id": rule_id,
                    "name": SarifReporter._pascal(rule_id),
                    "shortDescription": {"text": example.explanation.summary or rule_id},
                    "fullDescription": {"text": example.message},
                    "help": {
                        "text": f"{example.message}\n\n{example.remediation}",
                        "markdown": self._help_markdown(example),
                    },
                    "defaultConfiguration": {"level": LEVEL[example.severity]},
                    "properties": {
                        # The property platforms actually sort on.
                        "security-severity": RiskScorer.security_severity(example.risk),
                        "tags": self._tags(example),
                        "category": str(example.category),
                        "confidence": str(example.confidence),
                    },
                    **({"helpUri": example.references[0]} if example.references else {}),
                }
            )

        return rules, index

    @staticmethod
    def _tags(finding: Finding) -> list[str]:
        """Tags for a rule.

        ``security`` is required for a platform to treat the alert as a security
        alert rather than a quality one, which changes where it appears and who
        is notified.
        """
        tags = ["security", str(finding.category)]
        tags.extend(str(c) for c in finding.capabilities)
        return sorted(set(tags))

    @staticmethod
    def _help_markdown(finding: Finding) -> str:
        parts = [f"## {finding.explanation.summary}", "", finding.message]
        if finding.remediation:
            parts += ["", "### Remediation", "", finding.remediation]
        if finding.explanation.escalations:
            parts += ["", "### Why this was escalated", ""]
            parts += [f"- {e}" for e in finding.explanation.escalations]
        if finding.references:
            parts += ["", "### References", ""]
            parts += [f"- {r}" for r in finding.references]
        return "\n".join(parts)

    # -- Results ---------------------------------------------------------

    def _result(self, f: Finding, rule_index: dict[str, int]) -> dict[str, Any]:
        region: dict[str, Any] = {}
        if f.location.line is not None:
            region["startLine"] = f.location.line
        if f.location.column is not None:
            region["startColumn"] = f.location.column
        if f.location.end_line is not None:
            region["endLine"] = f.location.end_line
        if f.location.byte_start is not None:
            region["byteOffset"] = f.location.byte_start
            if f.location.byte_end is not None:
                region["byteLength"] = f.location.byte_end - f.location.byte_start

        entry: dict[str, Any] = {
            "ruleId": f.rule_id,
            "ruleIndex": rule_index.get(f.rule_id, 0),
            "level": LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.location.path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        **({"region": region} if region else {}),
                    }
                }
            ],
            # Without this a reformat re-raises every alert in the file as new,
            # and users learn to dismiss findings in bulk.
            "partialFingerprints": {"cordonFingerprint/v1": f.fingerprint},
            "properties": {
                "risk": f.risk.value,
                "confidence": str(f.confidence),
                "category": str(f.category),
                "detector": f.detector,
                "riskFactors": [
                    {"name": x.name, "points": x.points, "reason": x.reason} for x in f.risk.factors
                ],
            },
        }

        if f.evidence.match_hash:
            entry["properties"]["matchHash"] = f.evidence.match_hash

        if f.is_suppressed and f.suppressed:
            entry["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": f.suppressed.justification,
                    "properties": {
                        "expires": f.suppressed.expires,
                        "approvedBy": f.suppressed.approved_by or "",
                    },
                }
            ]

        return entry

    @staticmethod
    def _notification(f: Finding) -> dict[str, Any]:
        return {
            "level": "warning",
            "message": {"text": f.message},
            "descriptor": {"id": f.rule_id},
        }


__all__ = ["SarifReporter"]
