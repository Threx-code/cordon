"""Package composites: a block that is the combination of findings the rules already made.

```
  SELF_PUBLISH + DECODE_EXEC + REMOTE_CODE dropper, each at MEDIUM or stronger ──► MALWARE.WORM.SELF_PROPAGATION.001
  any two of the three, or a part a ceiling lowered below MEDIUM                  ──► nothing
```
Inert fixtures: findings built by the engine's own builder, with made-up paths; no code.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from cordon_scanner.decide.composites import PackageComposites
from cordon_scanner.foundation.models import Category, Confidence, Finding, Location, Severity
from cordon_scanner.foundation.results import OperationalFinding

PARTS = PackageComposites.WORM_PARTS


class Findings:
    @staticmethod
    def of(rule: str, severity: Severity = Severity.MEDIUM, path: str = "pkg/a.py") -> Finding:
        return OperationalFinding.build(
            path=path,
            rule_id=rule,
            message="m",
            remediation="r",
            category=Category.SUSPICIOUS,
            severity=severity,
        )

    @staticmethod
    def parts(severity: Severity = Severity.MEDIUM) -> list[Finding]:
        return [Findings.of(rule, severity, f"pkg/{i}.js") for i, rule in enumerate(PARTS)]


class TestTheWormComposite:
    def test_all_three_parts_in_one_package_make_it(self) -> None:
        worm = PackageComposites.worm(Findings.parts())
        assert worm is not None
        assert worm.rule_id == "MALWARE.WORM.SELF_PROPAGATION.001"
        assert worm.category is Category.MALICIOUS
        assert worm.severity is Severity.CRITICAL
        assert worm.related == PARTS

    @pytest.mark.parametrize("missing", PARTS)
    def test_two_of_the_three_make_nothing(self, missing: str) -> None:
        kept = [f for f in Findings.parts() if f.rule_id != missing]
        assert len(kept) == 2
        assert PackageComposites.worm(kept) is None

    @pytest.mark.parametrize("severity", [Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])
    def test_a_part_at_medium_or_stronger_counts(self, severity: Severity) -> None:
        assert PackageComposites.worm(Findings.parts(severity)) is not None

    @pytest.mark.parametrize("lowered", PARTS)
    @pytest.mark.parametrize("severity", [Severity.INFO, Severity.LOW])
    def test_a_part_a_ceiling_lowered_below_medium_does_not_count(
        self, lowered: str, severity: Severity
    ) -> None:
        findings = [
            Findings.of(f.rule_id, severity if f.rule_id == lowered else f.severity)
            for f in Findings.parts()
        ]
        assert PackageComposites.worm(findings) is None

    def test_the_parts_may_sit_in_three_different_files(self) -> None:
        findings = [
            Findings.of(PARTS[0], path="a/one.js"),
            Findings.of(PARTS[1], path="b/two.py"),
            Findings.of(PARTS[2], path="c/three.sh"),
        ]
        assert PackageComposites.worm(findings) is not None

    def test_other_findings_do_not_stand_in_for_a_part(self) -> None:
        findings = [
            Findings.of(PARTS[0]),
            Findings.of(PARTS[1]),
            Findings.of("SUSPECT.DROPPER.001"),
            Findings.of("SUSPECT.INSTALL.SCRIPT.001", Severity.HIGH),
        ]
        assert PackageComposites.worm(findings) is None

    def test_a_part_twice_is_still_one_part(self) -> None:
        findings = [*Findings.parts()[:2], Findings.of(PARTS[0], path="pkg/other.js")]
        assert PackageComposites.worm(findings) is None

    def test_the_composite_is_not_a_part_of_itself(self) -> None:
        worm = PackageComposites.worm(Findings.parts())
        assert worm is not None
        assert PackageComposites.worm([*Findings.parts()[:2], worm]) is None

    def test_nothing_in_nothing_out(self) -> None:
        assert PackageComposites.worm([]) is None


class TestItIsAddedAfterTheVerdict:
    def test_the_package_pipeline_adds_it_to_what_the_rules_left(self) -> None:
        from cordon_scanner.engine.pipeline.ceilings import Ceilings

        graded, _verdict = Ceilings.verdict(Findings.parts(), [])
        assert "MALWARE.WORM.SELF_PROPAGATION.001" in {f.rule_id for f in graded}

    def test_the_pipeline_adds_nothing_for_two_parts(self) -> None:
        from cordon_scanner.engine.pipeline.ceilings import Ceilings

        graded, _verdict = Ceilings.verdict(Findings.parts()[:2], [])
        assert "MALWARE.WORM.SELF_PROPAGATION.001" not in {f.rule_id for f in graded}

    def test_it_is_never_the_verdicts_own_evidence(self) -> None:
        """Added after the verdict is decided, so the rules and the feature record the verdict
        weighed are the three parts and not the composite. `VerdictFeatures.LATER_RULES` is part of
        the feature version, so it is left alone: a change to it moves the fold every shipped
        model is stamped with."""
        from cordon_scanner.engine.pipeline.ceilings import Ceilings

        graded, verdict = Ceilings.verdict(Findings.parts(), [])
        assert "MALWARE.WORM.SELF_PROPAGATION.001" in {f.rule_id for f in graded}
        assert set(PARTS) <= set(verdict["rules"])
        assert "MALWARE.WORM.SELF_PROPAGATION.001" not in verdict["rules"]


class TestTheCorroboratedInjectionComposite:
    """An injection phrase the agent-threat rules grade MEDIUM at LOW confidence, and the learned reading of the
    skill's instructions, in one package: two independent weak readers agreeing (reviews/mcp-98/21, lever A(1):
    on the skills dev half, out of fold by family, 49 caught for 11 legitimate units)."""

    PHRASE = PackageComposites.INJECTION_PHRASE
    READING = PackageComposites.SKILL_READING

    @staticmethod
    def of(
        rule: str,
        severity: Severity = Severity.MEDIUM,
        confidence: Confidence = Confidence.LOW,
        path: str = "skill/SKILL.md",
    ) -> Finding:
        return replace(Findings.of(rule, severity, path), confidence=confidence)

    def both(self) -> list[Finding]:
        return [self.of(self.PHRASE), self.of(self.READING, Severity.MEDIUM, Confidence.MEDIUM)]

    def test_the_phrase_and_the_reading_together_make_it(self) -> None:
        found = PackageComposites.corroborated_injection(self.both())
        assert found is not None
        assert found.rule_id == "SUSPECT.AGENT.INJECTION_CORROBORATED.001"
        assert found.category is Category.SUSPICIOUS
        assert (found.severity, found.confidence) == (Severity.HIGH, Confidence.MEDIUM)
        assert found.related == (self.PHRASE, self.READING)
        assert found.location.path == "skill/SKILL.md"

    def test_it_records_the_line_of_the_phrase_and_where_the_reading_was(self) -> None:
        phrase = replace(
            self.of(self.PHRASE), location=Location(path="skill/SKILL.md", line=42, column=3)
        )
        reading = self.of(self.READING, Severity.MEDIUM, Confidence.MEDIUM, path="skill/other.md")
        found = PackageComposites.corroborated_injection([phrase, reading])
        assert found is not None
        assert (found.location.path, found.location.line, found.location.column) == (
            "skill/SKILL.md",
            42,
            3,
        )
        assert dict(found.evidence.metadata)["reading_at"] == "skill/other.md"

    def test_a_phrase_with_no_line_leaves_the_finding_without_one(self) -> None:
        found = PackageComposites.corroborated_injection(self.both())
        assert found is not None
        assert found.location.line is None
        assert dict(found.evidence.metadata)["reading_at"] == "skill/SKILL.md"

    def test_it_trips_the_default_gate_where_its_parts_do_not(self) -> None:
        from cordon_scanner.decide.policy import PolicyGate
        from cordon_scanner.foundation.config.policy import Policy
        from cordon_scanner.foundation.errors import ExitCode
        from cordon_scanner.foundation.results import ScanResult

        parts = self.both()
        found = PackageComposites.corroborated_injection(parts)
        assert found is not None
        policy = Policy.default()
        assert (
            PolicyGate.evaluate(ScanResult(findings=tuple(parts)), policy).exit_code
            is ExitCode.CLEAN
        )
        assert (
            PolicyGate.evaluate(ScanResult(findings=(*parts, found)), policy).exit_code
            is ExitCode.FINDINGS
        )

    def test_either_part_alone_makes_nothing(self) -> None:
        assert PackageComposites.corroborated_injection(self.both()[:1]) is None
        assert PackageComposites.corroborated_injection(self.both()[1:]) is None

    @pytest.mark.parametrize(
        ("severity", "confidence"),
        [
            (Severity.LOW, Confidence.LOW),
            (Severity.MEDIUM, Confidence.MEDIUM),
            (Severity.HIGH, Confidence.LOW),
            (Severity.MEDIUM, Confidence.HIGH),
        ],
    )
    def test_only_the_grade_measured_counts_as_the_phrase(
        self, severity: Severity, confidence: Confidence
    ) -> None:
        """Measured at medium/low: the same rule at another grade is another reading, graded as it is."""
        findings = [self.of(self.PHRASE, severity, confidence), self.both()[1]]
        assert PackageComposites.corroborated_injection(findings) is None

    def test_the_reading_counts_at_any_grade(self) -> None:
        for severity, confidence in (
            (Severity.LOW, Confidence.LOW),
            (Severity.HIGH, Confidence.HIGH),
        ):
            findings = [self.both()[0], self.of(self.READING, severity, confidence)]
            assert PackageComposites.corroborated_injection(findings) is not None

    def test_a_suppressed_part_does_not_count(self) -> None:
        from cordon_scanner.foundation.models import Suppression

        suppressed = replace(
            self.both()[0],
            suppressed=Suppression(
                rule=self.PHRASE,
                path="skill/SKILL.md",
                justification="reviewed by the owner",
                expires="2999-01-01",
                approved_by="security@example.org",
            ),
        )
        assert PackageComposites.corroborated_injection([suppressed, self.both()[1]]) is None

    def test_the_parts_may_sit_in_different_files(self) -> None:
        findings = [
            self.of(self.PHRASE, path="a/SKILL.md"),
            self.of(self.READING, path="b/README.md"),
        ]
        assert PackageComposites.corroborated_injection(findings) is not None

    def test_the_composite_is_not_a_part_of_itself(self) -> None:
        found = PackageComposites.corroborated_injection(self.both())
        assert found is not None
        assert PackageComposites.corroborated_injection([found]) is None

    def test_the_package_pipeline_adds_it_after_the_verdict_and_never_as_its_evidence(self) -> None:
        from cordon_scanner.engine.pipeline.ceilings import Ceilings

        graded, verdict = Ceilings.verdict(self.both(), [])
        assert "SUSPECT.AGENT.INJECTION_CORROBORATED.001" in {f.rule_id for f in graded}
        assert "SUSPECT.AGENT.INJECTION_CORROBORATED.001" not in verdict["rules"]

    def test_the_pipeline_adds_nothing_for_one_part(self) -> None:
        from cordon_scanner.engine.pipeline.ceilings import Ceilings

        graded, _verdict = Ceilings.verdict(self.both()[:1], [])
        assert "SUSPECT.AGENT.INJECTION_CORROBORATED.001" not in {f.rule_id for f in graded}
