"""The domain model.

These types are the contract every other component depends on, so the tests here
are about invariants rather than behaviour: immutability, deterministic ordering,
fingerprint stability, and round-trip fidelity.

Fingerprint stability gets the most attention. Four separate features rest on it
-- deduplication, baselines, suppression matching and alert tracking in code
scanning platforms -- and a change to how it is computed silently invalidates
every baseline and re-raises every alert in every repository using the tool.
"""

from __future__ import annotations

import dataclasses

import pytest

from cordon.core.models import (
    Capability,
    Category,
    Confidence,
    Dependency,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Hook,
    LanguageStat,
    Location,
    Project,
    RedactionMode,
    Repository,
    RiskFactor,
    RiskScore,
    ScanResult,
    ScanStats,
    Scope,
    Severity,
    Suppression,
)


def finding(**kw) -> Finding:
    defaults = {
        "rule_id": "TEST.RULE.001",
        "category": Category.SUSPICIOUS,
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "message": "something",
        "location": Location(path="a.py", line=1),
        "evidence": Evidence(
            kind=EvidenceKind.SNIPPET,
            match_hash=Evidence.hash_bytes(b"x"),
            redaction=RedactionMode.MASKED,
            snippet="payload",
        ),
        "remediation": "fix",
        "explanation": Explanation(summary="s", matched_rule="TEST.RULE.001"),
        "risk": RiskScore(value=50, base=70, confidence_multiplier=0.75),
        "detector": "test",
    }
    defaults.update(kw)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestSeverity:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("critical", Severity.CRITICAL),
            ("HIGH", Severity.HIGH),
            ("  medium  ", Severity.MEDIUM),
            ("low", Severity.LOW),
            ("info", Severity.INFO),
        ],
    )
    def test_parsing(self, text: str, expected: Severity) -> None:
        assert Severity.parse(text) is expected

    def test_parsing_is_idempotent(self) -> None:
        assert Severity.parse(Severity.HIGH) is Severity.HIGH

    def test_parses_from_an_integer(self) -> None:
        assert Severity.parse(4) is Severity.CRITICAL

    def test_unknown_value_lists_the_valid_ones(self) -> None:
        with pytest.raises(ValueError, match="info, low, medium, high, critical"):
            Severity.parse("extreme")

    def test_ordering_is_comparable(self) -> None:
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW
        assert max(Severity.LOW, Severity.CRITICAL) is Severity.CRITICAL

    def test_string_form_is_lowercase(self) -> None:
        assert str(Severity.CRITICAL) == "critical"


class TestConfidence:
    def test_parsing_and_ordering(self) -> None:
        assert Confidence.parse("confirmed") > Confidence.parse("high")
        assert Confidence.parse("LOW") is Confidence.LOW

    def test_unknown_value_is_refused(self) -> None:
        with pytest.raises(ValueError, match="unknown confidence"):
            Confidence.parse("certain")

    def test_confirmed_is_the_ceiling(self) -> None:
        """Reserved for cryptographic identity. No heuristic reaches it."""
        assert max(Confidence) is Confidence.CONFIRMED


class TestCategoryAndCapability:
    def test_five_categories(self) -> None:
        assert {str(c) for c in Category} == {
            "malicious", "suspicious", "vulnerable", "policy", "operational"
        }

    def test_six_capabilities(self) -> None:
        """The set is small on purpose: they are forced by the attacker's
        objective, not chosen, which is why they generalise across languages."""
        assert {str(c) for c in Capability} == {
            "decode", "execute", "spawn", "credential", "egress", "persist"
        }


# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------


class TestFingerprint:
    def test_is_computed_automatically(self) -> None:
        assert finding().fingerprint

    def test_is_stable_for_identical_findings(self) -> None:
        assert finding().fingerprint == finding().fingerprint

    def test_survives_a_line_move(self) -> None:
        """The property that stops a reformat re-raising every alert in a file
        as new, which is what teaches people to dismiss findings in bulk."""
        a = finding(location=Location(path="a.py", line=1))
        b = finding(location=Location(path="a.py", line=847))
        assert a.fingerprint == b.fingerprint

    def test_survives_a_column_change(self) -> None:
        a = finding(location=Location(path="a.py", line=1, column=1))
        b = finding(location=Location(path="a.py", line=1, column=40))
        assert a.fingerprint == b.fingerprint

    def test_differs_across_paths(self) -> None:
        a = finding(location=Location(path="a.py"))
        b = finding(location=Location(path="b.py"))
        assert a.fingerprint != b.fingerprint

    def test_differs_across_rules(self) -> None:
        assert finding(rule_id="A.001").fingerprint != finding(rule_id="B.001").fingerprint

    def test_differs_when_the_matched_text_differs(self) -> None:
        a = finding()
        b = finding(
            evidence=Evidence(
                kind=EvidenceKind.SNIPPET,
                match_hash=Evidence.hash_bytes(b"y"),
                redaction=RedactionMode.MASKED,
                snippet="different",
            )
        )
        assert a.fingerprint != b.fingerprint

    def test_whitespace_changes_do_not_alter_it(self) -> None:
        """Reformatting a line must not create a new alert."""
        a = finding(
            evidence=Evidence(
                kind=EvidenceKind.SNIPPET,
                match_hash=Evidence.hash_bytes(b"x"),
                redaction=RedactionMode.MASKED,
                snippet="eval(  payload )",
            )
        )
        b = finding(
            evidence=Evidence(
                kind=EvidenceKind.SNIPPET,
                match_hash=Evidence.hash_bytes(b"x"),
                redaction=RedactionMode.MASKED,
                snippet="eval( payload )",
            )
        )
        assert a.fingerprint == b.fingerprint

    def test_symbol_distinguishes_two_matches_in_one_file(self) -> None:
        a = finding(location=Location(path="a.py", symbol="alpha"))
        b = finding(location=Location(path="a.py", symbol="beta"))
        assert a.fingerprint != b.fingerprint

    def test_hash_only_evidence_still_yields_a_fingerprint(self) -> None:
        f = finding(
            evidence=Evidence(
                kind=EvidenceKind.HASH,
                match_hash=Evidence.hash_bytes(b"secret"),
                redaction=RedactionMode.HASH_ONLY,
            )
        )
        assert f.fingerprint

    def test_a_package_finding_keys_on_the_package(self) -> None:
        a = finding(location=Location(path="", package="pkg:npm/a@1"))
        b = finding(location=Location(path="", package="pkg:npm/b@1"))
        assert a.fingerprint != b.fingerprint


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    @pytest.mark.parametrize(
        "instance",
        [
            finding(),
            Location(path="a.py"),
            Evidence(
                kind=EvidenceKind.HASH,
                match_hash="sha256:x",
                redaction=RedactionMode.MASKED,
            ),
            RiskScore(value=1, base=1, confidence_multiplier=1.0),
            Suppression(rule="A", path="b", justification="x" * 40, expires="2099-01-01"),
            Dependency(purl="pkg:npm/a@1", ecosystem="npm", name="a"),
            ScanResult(),
        ],
        ids=lambda x: type(x).__name__,
    )
    def test_domain_objects_are_frozen(self, instance) -> None:
        """A caller must not be able to mutate a result and re-serialise it as
        though a scan produced it."""
        field = next(iter(dataclasses.fields(instance))).name
        with pytest.raises((AttributeError, dataclasses.FrozenInstanceError, TypeError)):
            setattr(instance, field, "mutated")

    def test_with_suppression_returns_a_new_object(self) -> None:
        original = finding()
        suppressed = original.with_suppression(
            Suppression(rule="A", path="a.py", justification="x" * 40, expires="2099-01-01")
        )
        assert original.suppressed is None
        assert suppressed.suppressed is not None
        assert suppressed is not original


# ---------------------------------------------------------------------------
# Ordering
# ---------------------------------------------------------------------------


class TestOrdering:
    def test_sorts_by_severity_then_risk(self) -> None:
        result = ScanResult(
            findings=(
                finding(rule_id="A", severity=Severity.LOW),
                finding(rule_id="B", severity=Severity.CRITICAL),
                finding(rule_id="C", severity=Severity.HIGH),
            )
        ).sorted()
        assert [f.rule_id for f in result.findings] == ["B", "C", "A"]

    def test_risk_breaks_a_severity_tie(self) -> None:
        result = ScanResult(
            findings=(
                finding(
                    rule_id="LOWRISK",
                    risk=RiskScore(value=10, base=70, confidence_multiplier=1.0),
                ),
                finding(
                    rule_id="HIGHRISK",
                    risk=RiskScore(value=90, base=70, confidence_multiplier=1.0),
                ),
            )
        ).sorted()
        assert [f.rule_id for f in result.findings] == ["HIGHRISK", "LOWRISK"]

    def test_ordering_is_total_and_stable(self) -> None:
        """Never completion order, which varies with worker scheduling."""
        findings = tuple(
            finding(rule_id=f"R.{i:03d}", location=Location(path=f"f{i}.py"))
            for i in range(30)
        )
        first = ScanResult(findings=findings).sorted()
        second = ScanResult(findings=tuple(reversed(findings))).sorted()
        assert [f.fingerprint for f in first.findings] == [
            f.fingerprint for f in second.findings
        ]


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------


class TestScanResult:
    def test_active_excludes_suppressed(self) -> None:
        suppression = Suppression(
            rule="A", path="a.py", justification="x" * 40, expires="2099-01-01"
        )
        result = ScanResult(
            findings=(finding(rule_id="A"), finding(rule_id="B").with_suppression(suppression))
        )
        assert len(result.findings) == 2
        assert len(result.active) == 1
        assert len(result.suppressed) == 1

    def test_counts_by_severity(self) -> None:
        result = ScanResult(
            findings=(
                finding(severity=Severity.CRITICAL),
                finding(rule_id="B", severity=Severity.CRITICAL),
                finding(rule_id="C", severity=Severity.LOW),
            )
        )
        counts = result.by_severity()
        assert counts[Severity.CRITICAL] == 2
        assert counts[Severity.LOW] == 1

    def test_counts_by_category(self) -> None:
        result = ScanResult(
            findings=(
                finding(category=Category.MALICIOUS),
                finding(rule_id="B", category=Category.POLICY),
            )
        )
        assert result.by_category()[Category.MALICIOUS] == 1

    def test_filtering(self) -> None:
        result = ScanResult(
            findings=(
                finding(rule_id="A", severity=Severity.CRITICAL),
                finding(rule_id="B", severity=Severity.LOW),
            )
        )
        assert len(result.filter(min_severity=Severity.HIGH).findings) == 1
        assert len(result.filter(categories=[Category.MALICIOUS]).findings) == 0

    def test_serialises_completely(self) -> None:
        result = ScanResult(
            findings=(finding(),),
            repository=Repository(
                root="/r",
                languages=(LanguageStat("python", 1, 10, 1.0, ("*.py",)),),
                projects=(Project(path="", ecosystem="pypi"),),
                hooks=(Hook(kind="build", path="setup.py", name="setup.py"),),
            ),
            dependencies=(Dependency(purl="pkg:npm/a@1", ecosystem="npm", name="a"),),
            stats=ScanStats(files_scanned=1),
        )
        payload = result.to_dict()
        assert payload["findings"][0]["rule_id"] == "TEST.RULE.001"
        assert payload["repository"]["languages"][0]["language"] == "python"
        assert payload["dependencies"][0]["purl"] == "pkg:npm/a@1"

    def test_empty_result_serialises(self) -> None:
        assert ScanResult().to_dict()["findings"] == []

    def test_completeness_defaults_to_true(self) -> None:
        assert ScanResult().complete is True


# ---------------------------------------------------------------------------
# Supporting types
# ---------------------------------------------------------------------------


class TestSupportingTypes:
    def test_location_renders_readably(self) -> None:
        assert str(Location(path="a.py")) == "a.py"
        assert str(Location(path="a.py", line=4)) == "a.py:4"
        assert str(Location(path="a.py", line=4, column=2)) == "a.py:4:2"

    def test_a_package_location_prefers_the_package(self) -> None:
        assert str(Location(path="", package="pkg:npm/a@1")) == "pkg:npm/a@1"

    def test_location_omits_absent_fields_when_serialised(self) -> None:
        assert Location(path="a.py").to_dict() == {"path": "a.py"}

    def test_evidence_hashing_is_content_addressed(self) -> None:
        assert Evidence.hash_bytes(b"a") == Evidence.hash_bytes(b"a")
        assert Evidence.hash_bytes(b"a") != Evidence.hash_bytes(b"b")
        assert Evidence.hash_bytes(b"a").startswith("sha256:")

    def test_risk_explanation_sums_to_the_value(self) -> None:
        """The explainability requirement, asserted arithmetically."""
        score = RiskScore(
            value=87,
            base=70,
            confidence_multiplier=1.0,
            factors=(
                RiskFactor("install_time", 15, "runs at install"),
                RiskFactor("egress", 2, "network"),
            ),
        )
        lines = list(score.explain())
        assert "base 70" in lines[0]
        assert any("install_time" in line for line in lines)
        derived = int(score.base * score.confidence_multiplier) + sum(
            f.points for f in score.factors
        )
        assert derived == score.value

    def test_dependency_scope_defaults_to_runtime(self) -> None:
        assert Dependency(purl="p", ecosystem="npm", name="a").scope is Scope.RUNTIME

    def test_suppression_serialises_its_justification(self) -> None:
        s = Suppression(
            rule="A", path="a.py", justification="x" * 40, expires="2099-01-01",
            approved_by="security",
        )
        payload = s.to_dict()
        assert payload["approved_by"] == "security"
        assert payload["justification"]
