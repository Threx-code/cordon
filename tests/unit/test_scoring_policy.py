"""Risk scoring and policy evaluation.

The scoring tests assert *orderings* rather than exact numbers wherever the
ordering is the thing that matters. A test pinned to a magic constant breaks
every time a weight is tuned and teaches people to update the expected value
without thinking; a test pinned to "a confirmed malware finding outranks a
doubtful one" fails only when something is genuinely wrong.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import date

import pytest

from cordon.core.config import Config, Policy, _load_yaml_subset
from cordon.core.errors import ExitCode
from cordon.core.models import (
    Capability,
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    RiskScore,
    ScanResult,
    Scope,
    Severity,
    Suppression,
)
from cordon.core.policy import (
    Baseline,
    SuppressionMatcher,
    evaluate,
    filter_for_reporting,
)
from cordon.core.scoring import (
    RiskScorer,
    ScoringContext,
    apply_category_floor,
    security_severity,
)


def make_finding(
    rule_id: str = "TEST.RULE.001",
    *,
    category: Category = Category.SUSPICIOUS,
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    path: str = "src/app.py",
    snippet: str | None = "payload",
    risk: int = 50,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        confidence=confidence,
        message="test finding",
        location=Location(path=path, line=1),
        evidence=Evidence(
            kind=EvidenceKind.SNIPPET,
            match_hash=Evidence.hash_bytes(b"payload"),
            redaction=RedactionMode.MASKED,
            snippet=snippet,
        ),
        remediation="fix it",
        explanation=Explanation(summary="because", matched_rule=rule_id),
        risk=RiskScore(value=risk, base=70, confidence_multiplier=1.0),
        detector="test",
    )


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


class TestRiskScoring:
    def setup_method(self) -> None:
        self.scorer = RiskScorer()

    def test_score_is_bounded(self) -> None:
        for severity in Severity:
            for confidence in Confidence:
                score = self.scorer.score(
                    severity,
                    confidence,
                    ScoringContext(
                        in_install_hook=True,
                        capabilities=frozenset(Capability),
                        is_obfuscated=True,
                        has_binary_payload=True,
                        is_reachable=True,
                        is_direct_dependency=True,
                        fix_available=False,
                    ),
                )
                assert 0 <= score.value <= 100

    def test_is_deterministic(self) -> None:
        """Baselines, caching and reproducible gates all depend on this."""
        ctx = ScoringContext(in_install_hook=True, capabilities={Capability.EGRESS})
        first = self.scorer.score(Severity.HIGH, Confidence.MEDIUM, ctx)
        second = self.scorer.score(Severity.HIGH, Confidence.MEDIUM, ctx)
        assert first == second
        assert first.value == second.value

    def test_confidence_scales_rather_than_adds(self) -> None:
        """A critical finding that is probably wrong must rank below a medium
        finding that is certainly right. Only a multiplicative weight produces
        that ordering; an additive term preserves severity order regardless."""
        doubtful_critical = self.scorer.score(Severity.CRITICAL, Confidence.LOW)
        certain_medium = self.scorer.score(Severity.MEDIUM, Confidence.CONFIRMED)
        assert certain_medium.value > doubtful_critical.value

    def test_confirmed_outranks_heuristic_at_equal_severity(self) -> None:
        confirmed = self.scorer.score(Severity.HIGH, Confidence.CONFIRMED)
        heuristic = self.scorer.score(Severity.HIGH, Confidence.HIGH)
        assert confirmed.value > heuristic.value

    def test_install_context_is_the_largest_positive_factor(self) -> None:
        """Install-time code runs as the developer before any other control, so
        the same capability pair means something different there."""
        in_app = self.scorer.score(
            Severity.MEDIUM,
            Confidence.MEDIUM,
            ScoringContext(capabilities={Capability.CREDENTIAL, Capability.EGRESS}),
        )
        in_hook = self.scorer.score(
            Severity.MEDIUM,
            Confidence.MEDIUM,
            ScoringContext(
                capabilities={Capability.CREDENTIAL, Capability.EGRESS},
                in_install_hook=True,
            ),
        )
        assert in_hook.value > in_app.value

    def test_dev_scope_reduces_but_does_not_eliminate(self) -> None:
        """A build-time dependency still runs on developer machines and CI
        runners, which is precisely where the credentials are."""
        runtime = self.scorer.score(Severity.HIGH, Confidence.HIGH)
        dev = self.scorer.score(Severity.HIGH, Confidence.HIGH, ScoringContext(scope=Scope.DEV))
        assert dev.value < runtime.value
        assert dev.value > 0

    def test_transitive_penalty_has_a_floor(self) -> None:
        """Depth must not bury a genuine finding: a malicious package eight
        levels down executes with the same privileges as one at the top."""
        shallow = self.scorer.score(
            Severity.HIGH, Confidence.HIGH, ScoringContext(dependency_depth=1)
        )
        deep = self.scorer.score(
            Severity.HIGH, Confidence.HIGH, ScoringContext(dependency_depth=40)
        )
        assert deep.value < shallow.value
        assert shallow.value - deep.value <= 6

    def test_unanalysed_reachability_is_not_scored_as_unreachable(self) -> None:
        neutral = self.scorer.score(Severity.HIGH, Confidence.HIGH, ScoringContext())
        explicit_false = self.scorer.score(
            Severity.HIGH, Confidence.HIGH, ScoringContext(is_reachable=False)
        )
        assert neutral.value == explicit_false.value

    def test_every_factor_carries_a_reason(self) -> None:
        score = self.scorer.score(
            Severity.CRITICAL,
            Confidence.HIGH,
            ScoringContext(
                in_install_hook=True,
                capabilities={Capability.CREDENTIAL, Capability.EGRESS},
            ),
        )
        assert score.factors
        for factor in score.factors:
            assert factor.reason, f"{factor.name} has no reason"
            assert factor.points != 0

    def test_explanation_reconstructs_the_score(self) -> None:
        """The design constraint: a score nobody can derive by hand is a score
        nobody trusts."""
        score = self.scorer.score(
            Severity.CRITICAL,
            Confidence.HIGH,
            ScoringContext(in_install_hook=True, capabilities={Capability.EGRESS}),
        )
        lines = list(score.explain())
        assert "base 90" in lines[0]
        assert any("install_time" in line for line in lines)
        assert str(score.value) in lines[-1]

        derived = int(score.base * score.confidence_multiplier) + sum(
            f.points for f in score.factors
        )
        assert derived == score.value


class TestSecuritySeverity:
    @pytest.mark.parametrize(
        ("value", "expected"), [(0, "0.0"), (50, "5.0"), (92, "9.2"), (100, "10.0")]
    )
    def test_maps_to_the_sarif_scale(self, value: int, expected: str) -> None:
        """Code scanning platforms sort and threshold on this property. A SARIF
        file without it renders every finding as equally important."""
        score = RiskScore(value=value, base=0, confidence_multiplier=1.0)
        assert security_severity(score) == expected


class TestCategoryFloor:
    def test_malicious_cannot_be_filed_below_high(self) -> None:
        """A rule author can be wrong about severity. The assertion 'this is
        evidence of intent to harm' is not something a threshold should hide."""
        assert apply_category_floor(Category.MALICIOUS, Severity.LOW) is Severity.HIGH
        assert apply_category_floor(Category.MALICIOUS, Severity.CRITICAL) is Severity.CRITICAL

    def test_other_categories_are_untouched(self) -> None:
        assert apply_category_floor(Category.POLICY, Severity.LOW) is Severity.LOW


# ---------------------------------------------------------------------------
# Policy evaluation
# ---------------------------------------------------------------------------


class TestPolicyEvaluation:
    def test_clean_result_passes(self) -> None:
        verdict = evaluate(ScanResult(), Policy.default())
        assert verdict.exit_code is ExitCode.CLEAN
        assert verdict.passed

    def test_high_severity_fails_by_default(self) -> None:
        result = ScanResult(findings=(make_finding(severity=Severity.HIGH),))
        assert evaluate(result, Policy.default()).exit_code is ExitCode.FINDINGS

    def test_below_threshold_passes(self) -> None:
        result = ScanResult(findings=(make_finding(severity=Severity.LOW),))
        assert evaluate(result, Policy.default()).exit_code is ExitCode.CLEAN

    def test_malicious_fails_at_any_severity(self) -> None:
        result = ScanResult(
            findings=(make_finding(category=Category.MALICIOUS, severity=Severity.INFO),)
        )
        assert evaluate(result, Policy.default()).exit_code is ExitCode.FINDINGS

    def test_malicious_bypasses_the_confidence_floor(self) -> None:
        """If a rule asserts intent to harm, 'we were only moderately sure' is a
        reason to look, not a reason to let the build through."""
        result = ScanResult(
            findings=(
                make_finding(
                    category=Category.MALICIOUS,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.LOW,
                ),
            )
        )
        assert evaluate(result, Policy.default()).exit_code is ExitCode.FINDINGS

    def test_low_confidence_does_not_gate_on_severity_alone(self) -> None:
        """Without this floor the noisiest rule in the pack sets the gate."""
        result = ScanResult(
            findings=(
                make_finding(
                    category=Category.SUSPICIOUS,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.LOW,
                ),
            )
        )
        assert evaluate(result, Policy.default()).exit_code is ExitCode.CLEAN

    def test_suppressed_findings_do_not_gate(self) -> None:
        finding = make_finding(severity=Severity.CRITICAL)
        suppressed = finding.with_suppression(
            Suppression(
                rule=finding.rule_id,
                path=finding.location.path,
                justification="x" * 40,
                expires="2099-01-01",
            )
        )
        result = ScanResult(findings=(suppressed,))
        assert evaluate(result, Policy.default()).exit_code is ExitCode.CLEAN

    def test_incomplete_scan_reports_but_does_not_fail_by_default(self) -> None:
        """Failing by default would break pipelines on the first large
        repository and teach people to append `|| true`."""
        result = ScanResult(complete=False)
        verdict = evaluate(result, Policy.default())
        assert verdict.exit_code is ExitCode.CLEAN
        assert "incomplete" in verdict.reason

    def test_incomplete_scan_fails_when_required(self) -> None:
        result = ScanResult(complete=False)
        policy = replace(Policy.default(), fail_on_incomplete=True)
        assert evaluate(result, policy).exit_code is ExitCode.INCOMPLETE

    def test_incompleteness_is_checked_before_findings(self) -> None:
        """A scan that did not finish cannot support a claim about what is not
        there, so the incomplete verdict must win."""
        result = ScanResult(findings=(make_finding(severity=Severity.CRITICAL),), complete=False)
        policy = replace(Policy.default(), fail_on_incomplete=True)
        assert evaluate(result, policy).exit_code is ExitCode.INCOMPLETE

    def test_verdict_names_the_triggering_findings(self) -> None:
        result = ScanResult(
            findings=(
                make_finding("A.001", severity=Severity.CRITICAL),
                make_finding("B.001", severity=Severity.LOW),
            )
        )
        verdict = evaluate(result, Policy.default())
        assert len(verdict.triggering) == 1
        assert verdict.triggering[0].rule_id == "A.001"


# ---------------------------------------------------------------------------
# Suppression
# ---------------------------------------------------------------------------


def config_with_suppression(rule: str, path: str, expires: str = "2099-01-01") -> Config:
    text = (
        "suppressions:\n"
        f"  - rule: {rule}\n"
        f"    path: {path}\n"
        f"    justification: {'x' * 40}\n"
        f"    expires: {expires}\n"
    )
    return Config.from_dict(_load_yaml_subset(text, source="t"), source="t")


class TestSuppressionMatcher:
    def test_matching_rule_and_path_suppresses(self) -> None:
        cfg = config_with_suppression("TEST.RULE.001", "src/app.py")
        (result,) = SuppressionMatcher(cfg).apply([make_finding()])
        assert result.is_suppressed

    def test_rule_must_match(self) -> None:
        """A suppression for one rule must not exempt the file from others."""
        cfg = config_with_suppression("OTHER.RULE.001", "src/app.py")
        (result,) = SuppressionMatcher(cfg).apply([make_finding()])
        assert not result.is_suppressed

    def test_path_must_match(self) -> None:
        """A suppression for one file must not exempt every file."""
        cfg = config_with_suppression("TEST.RULE.001", "src/other.py")
        (result,) = SuppressionMatcher(cfg).apply([make_finding()])
        assert not result.is_suppressed

    def test_directory_prefix_matches(self) -> None:
        cfg = config_with_suppression("TEST.RULE.001", "src/")
        (result,) = SuppressionMatcher(cfg).apply([make_finding(path="src/deep/app.py")])
        assert result.is_suppressed

    def test_glob_matches(self) -> None:
        cfg = config_with_suppression("TEST.RULE.001", "src/*.py")
        (result,) = SuppressionMatcher(cfg).apply([make_finding(path="src/app.py")])
        assert result.is_suppressed

    def test_malicious_cannot_be_suppressed_by_repo_config(self) -> None:
        """A repository able to silence a malware finding about itself is not
        being scanned."""
        cfg = config_with_suppression("TEST.RULE.001", "src/app.py")
        (result,) = SuppressionMatcher(cfg).apply([make_finding(category=Category.MALICIOUS)])
        assert not result.is_suppressed

    def test_expired_suppression_does_not_suppress(self) -> None:
        cfg = config_with_suppression("TEST.RULE.001", "src/app.py", expires="2020-01-01")
        (result,) = SuppressionMatcher(cfg, today=date(2026, 1, 1)).apply([make_finding()])
        assert not result.is_suppressed

    def test_expired_suppression_produces_a_policy_finding(self) -> None:
        """Expiry must be loud. A silently lapsed suppression produces a sudden
        unexplained finding in an unrelated pull request, which reads as a false
        positive and gets suppressed again without re-examination."""
        cfg = config_with_suppression("TEST.RULE.001", "src/app.py", expires="2020-01-01")
        findings = SuppressionMatcher(cfg, today=date(2026, 1, 1)).expiry_findings()
        assert len(findings) == 1
        assert findings[0].rule_id == "POLICY.SUPPRESSION.EXPIRED"
        assert findings[0].category is Category.POLICY

    def test_suppressed_findings_stay_in_the_result(self) -> None:
        """An auditor's first question is what the tool was told to ignore."""
        cfg = config_with_suppression("TEST.RULE.001", "src/app.py")
        findings = SuppressionMatcher(cfg).apply([make_finding()])
        result = ScanResult(findings=findings)
        assert len(result.findings) == 1
        assert len(result.active) == 0
        assert len(result.suppressed) == 1
        assert result.suppressed[0].suppressed is not None
        assert result.suppressed[0].suppressed.justification


# ---------------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------------


class TestBaseline:
    def test_known_findings_are_suppressed(self) -> None:
        finding = make_finding()
        baseline = Baseline.from_result(ScanResult(findings=(finding,)))
        (result,) = baseline.apply([finding])
        assert result.is_suppressed

    def test_new_findings_are_not_suppressed(self) -> None:
        baseline = Baseline.from_result(ScanResult(findings=(make_finding("OLD.001"),)))
        (result,) = baseline.apply([make_finding("NEW.001")])
        assert not result.is_suppressed

    def test_malicious_is_never_baselined(self) -> None:
        """A baseline records 'we have not fixed this yet', which is not a
        coherent position to hold about evidence of intent to harm."""
        finding = make_finding(category=Category.MALICIOUS)
        baseline = Baseline.from_result(ScanResult(findings=(finding,)))
        (result,) = baseline.apply([finding])
        assert not result.is_suppressed

    def test_survives_a_line_move(self) -> None:
        """Keyed on fingerprint, not position: reformatting must not empty the
        baseline and re-raise everything it contained."""
        original = make_finding()
        moved = replace(original, location=Location(path="src/app.py", line=847))
        baseline = Baseline.from_result(ScanResult(findings=(original,)))
        (result,) = baseline.apply([moved])
        assert result.is_suppressed

    def test_baselined_findings_are_visible_as_baselined(self) -> None:
        finding = make_finding()
        baseline = Baseline.from_result(ScanResult(findings=(finding,)))
        (result,) = baseline.apply([finding])
        assert result.suppressed is not None
        assert result.suppressed.approved_by == "baseline"


# ---------------------------------------------------------------------------
# Reporting filter
# ---------------------------------------------------------------------------


class TestReportingFilter:
    def test_below_threshold_is_hidden(self) -> None:
        cfg = Config.from_dict(
            _load_yaml_subset("scan:\n  severity_threshold: high\n", source="t"), source="t"
        )
        result = ScanResult(
            findings=(
                make_finding("HIGH.001", severity=Severity.HIGH),
                make_finding("LOW.001", severity=Severity.LOW),
            )
        )
        filtered = filter_for_reporting(result, cfg)
        assert [f.rule_id for f in filtered.findings] == ["HIGH.001"]

    def test_operational_findings_bypass_the_threshold(self) -> None:
        """Hiding these behind a threshold is how a scan that examined almost
        nothing comes to look like a clean one."""
        cfg = Config.from_dict(
            _load_yaml_subset("scan:\n  severity_threshold: critical\n", source="t"), source="t"
        )
        result = ScanResult(
            findings=(
                make_finding("OP.001", category=Category.OPERATIONAL, severity=Severity.INFO),
            )
        )
        assert len(filter_for_reporting(result, cfg).findings) == 1
