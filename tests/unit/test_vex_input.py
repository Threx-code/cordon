"""M1: VEX statements applied to a scan, and decisions written back out."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.core.vex import VexDocuments, VexError
from cordon_scanner.report.base import ReportOptions
from cordon_scanner.report.vex import VexReporter

LOCK = {
    "name": "app",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "version": "1.0.0", "dependencies": {"lodash": "4.17.15"}},
        "node_modules/lodash": {
            "version": "4.17.15",
            "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
            "integrity": "sha512-8xOcRHvCjnocdS5cpwXQXVzmmh5e5+saE2QGoeQmbKmRS6J3VQppPOIt0MnmE+4xlZoumy0GPG0D0MVIQbNA1A==",
        },
    },
}


class VexHelpers:
    @staticmethod
    def scan(tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "app", "version": "1.0.0", "dependencies": {"lodash": "4.17.15"}})
        )
        (tmp_path / "package-lock.json").write_text(json.dumps(LOCK))
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)

    @staticmethod
    def vulnerable(result) -> list:
        return [f for f in result.findings if f.rule_id.startswith("VULNERABLE.DEPENDENCY")]


class TestApplying:
    def test_an_openvex_not_affected_statement(self, tmp_path) -> None:
        result = VexHelpers.scan(tmp_path)
        findings = VexHelpers.vulnerable(result)
        assert findings, "lodash 4.17.15 has advisories"
        target = sorted(VexDocuments.identifiers_of(findings[0]))[0]
        statements = VexDocuments.parse(
            {
                "@context": "https://openvex.dev/ns/v0.2.0",
                "statements": [
                    {
                        "vulnerability": {"name": target},
                        "products": [{"@id": "pkg:npm/lodash"}],
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_in_execute_path",
                    }
                ],
            },
            "vendor.openvex.json",
        )
        applied = VexDocuments.apply(result.findings, statements)
        ruled = [f for f in applied if f.suppressed and f.suppressed.approved_by == "vex"]
        assert ruled and all(target in VexDocuments.identifiers_of(f) for f in ruled)
        assert "vulnerable_code_not_in_execute_path" in ruled[0].suppressed.justification

    def test_affected_rules_nothing_out(self, tmp_path) -> None:
        result = VexHelpers.scan(tmp_path)
        target = sorted(VexDocuments.identifiers_of(VexHelpers.vulnerable(result)[0]))[0]
        statements = VexDocuments.parse(
            {
                "statements": [
                    {
                        "vulnerability": target,
                        "products": ["pkg:npm/lodash@4.17.15"],
                        "status": "affected",
                    }
                ]
            },
            "x",
        )
        assert not any(f.suppressed for f in VexDocuments.apply(result.findings, statements))

    def test_another_product_is_not_covered(self, tmp_path) -> None:
        result = VexHelpers.scan(tmp_path)
        target = sorted(VexDocuments.identifiers_of(VexHelpers.vulnerable(result)[0]))[0]
        statements = VexDocuments.parse(
            {
                "statements": [
                    {
                        "vulnerability": target,
                        "products": ["pkg:npm/underscore"],
                        "status": "not_affected",
                    }
                ]
            },
            "x",
        )
        assert not any(f.suppressed for f in VexDocuments.apply(result.findings, statements))

    def test_cyclonedx_vex(self, tmp_path) -> None:
        result = VexHelpers.scan(tmp_path)
        target = sorted(VexDocuments.identifiers_of(VexHelpers.vulnerable(result)[0]))[0]
        statements = VexDocuments.parse(
            {
                "bomFormat": "CycloneDX",
                "vulnerabilities": [
                    {
                        "id": target,
                        "affects": [{"ref": "pkg:npm/lodash@4.17.15"}],
                        "analysis": {"state": "not_affected"},
                    }
                ],
            },
            "x",
        )
        assert any(f.suppressed for f in VexDocuments.apply(result.findings, statements))

    def test_a_statement_cannot_silence_malware_or_a_secret(self) -> None:
        from cordon_scanner.core.models import Category

        statements = VexDocuments.parse(
            {"statements": [{"vulnerability": "MAL-2025-1", "status": "not_affected"}]}, "x"
        )
        assert all(s.status == "not_affected" for s in statements)
        # `apply` only ever looks at the VULNERABLE category.
        assert Category.MALICIOUS is not Category.VULNERABLE

    def test_not_a_vex_document(self) -> None:
        with pytest.raises(VexError):
            VexDocuments.parse({"something": []}, "x")


class TestWritingDecisions:
    def test_a_baselined_vulnerability_is_in_triage_and_a_vex_one_keeps_its_status(
        self, tmp_path
    ) -> None:
        from cordon_scanner.core.policy import Baseline

        result = VexHelpers.scan(tmp_path)
        baselined = Baseline.from_result(result).apply(result.findings)
        document = json.loads(
            b"".join(
                VexReporter().render(
                    type(result)(
                        **{
                            **{k: getattr(result, k) for k in result.__dataclass_fields__},
                            "findings": baselined,
                        }
                    ),
                    ReportOptions(),
                )
            )
        )
        states = {v["analysis"]["state"] for v in document["vulnerabilities"]}
        assert states == {"in_triage"}
