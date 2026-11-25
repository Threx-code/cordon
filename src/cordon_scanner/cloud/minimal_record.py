"""What the execution plane may send the control plane: ids, digests, findings, decisions, nothing of the customer's content
(invariants I6, row BP-1-4).

`MinimalRecord.of` projects a scan result onto the `scan/v1` contract (`contracts/schemas/scan-v1.json`) by an allowlist: for each
finding its rule id, severity, confidence, category, detector, fingerprint, the path and line it was found at and the hash of what
matched (for a secret the keyed hash `hmac-sha256:<hex>`, its hex); for the scan whether it completed, the rule ids of any part of the content it could not read, and the scanner and rule
versions. Everything else a finding carries stays on the machine: its message and remediation (they quote what the rule matched,
an install command or a path on disk), its evidence snippet and metadata, its explanation and risk factors, the dependency list,
the repository's remote and branch. An allowlist, so a field added to the report later does not leave by default.

`MinimalRecord.problems` is the check an ingest contract test, or the sender itself before sending, runs over any document that
claims to be one: the schema errors, and every key at any level that the allowlist does not name.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.contracts.schema_check import SchemaChecker
from cordon_scanner.contracts.schemas import ContractSchemas
from cordon_scanner.version import __version__

if TYPE_CHECKING:
    from cordon_scanner.foundation.results import ScanResult

_HASH = re.compile(r"^[0-9a-f]{16,64}$")


class MinimalRecord:
    TOP: ClassVar[frozenset[str]] = frozenset({"findings", "completeness", "versions"})
    FINDING: ClassVar[frozenset[str]] = frozenset(
        {
            "rule_id",
            "severity",
            "confidence",
            "category",
            "location",
            "evidence_hash",
            "detector",
            "fingerprint",
        }
    )
    LOCATION: ClassVar[frozenset[str]] = frozenset({"path", "line"})
    COMPLETENESS: ClassVar[frozenset[str]] = frozenset({"complete", "gaps"})
    VERSIONS: ClassVar[frozenset[str]] = frozenset({"scanner", "rules"})

    @classmethod
    def of(cls, result: ScanResult) -> dict[str, Any]:
        """The `scan/v1` record of `result`: unsuppressed findings only (a suppression is the tenant's policy, not a finding)."""
        findings: list[dict[str, Any]] = []
        for finding in result.findings:
            if finding.is_suppressed:
                continue
            location: dict[str, Any] = {"path": finding.location.path}
            if finding.location.line is not None and finding.location.line >= 0:
                location["line"] = finding.location.line
            item: dict[str, Any] = {
                "rule_id": finding.rule_id,
                "severity": finding.severity.name.lower(),
                "confidence": finding.confidence.name.lower(),
                "category": finding.category.name.lower(),
                "location": location,
                "detector": finding.detector,
                "fingerprint": finding.fingerprint,
            }
            matched = (
                str(finding.evidence.match_hash)
                .removeprefix("hmac-sha256:")
                .removeprefix("sha256:")
            )
            if _HASH.fullmatch(matched):
                item["evidence_hash"] = matched
            findings.append(item)
        return {
            "findings": findings,
            "completeness": {
                "complete": bool(result.complete),
                "gaps": sorted({rule for rule, _path in result.content_gaps}),
            },
            "versions": {
                "scanner": __version__,
                "rules": result.rulepack_hash or result.rulepack_version,
            },
        }

    @classmethod
    def problems(cls, document: Any) -> list[str]:
        """What is wrong with a document that claims to be a minimal record: schema errors and any key outside the allowlist."""
        if not isinstance(document, dict):
            return ["a minimal record is an object"]
        found = [
            str(error) for error in SchemaChecker.errors(ContractSchemas.load("scan-v1"), document)
        ]
        found += cls._extra("record", document, cls.TOP)
        for name, allowed in (("completeness", cls.COMPLETENESS), ("versions", cls.VERSIONS)):
            part = document.get(name)
            if isinstance(part, dict):
                found += cls._extra(name, part, allowed)
        findings = document.get("findings")
        for index, item in enumerate(findings if isinstance(findings, list) else []):
            if isinstance(item, dict):
                found += cls._extra(f"findings[{index}]", item, cls.FINDING)
                place = item.get("location")
                if isinstance(place, dict):
                    found += cls._extra(f"findings[{index}].location", place, cls.LOCATION)
        return found

    @staticmethod
    def _extra(where: str, part: dict[str, Any], allowed: frozenset[str]) -> list[str]:
        return [
            f"{where}: {key!r} is not part of a minimal record"
            for key in sorted(set(part) - allowed)
        ]


__all__ = ["MinimalRecord"]
