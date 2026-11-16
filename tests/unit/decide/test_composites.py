"""Package composites: a block that is the combination of findings the rules already made.

```
  SELF_PUBLISH + DECODE_EXEC + REMOTE_CODE dropper, each at MEDIUM or stronger ──► MALWARE.WORM.SELF_PROPAGATION.001
  any two of the three, or a part a ceiling lowered below MEDIUM                  ──► nothing
```
Inert fixtures: findings built by the engine's own builder, with made-up paths; no code.
"""

from __future__ import annotations

import pytest

from cordon_scanner.decide.composites import PackageComposites
from cordon_scanner.foundation.models import Category, Finding, Severity
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
