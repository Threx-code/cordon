"""Every finding lands in the taxonomy.

The table in `core/taxonomy.py` is derivation by rule-id prefix, which is only
safe if it is complete. A rule that falls through it produces findings marked
`unspecified`, which no filter matches and no coverage matrix counts -- a hole
that looks like an absence of findings rather than an absence of
classification. These tests are what make the table a checked artefact rather
than a best effort.
"""

from __future__ import annotations

import pytest

from cordon_scanner.core.registry import Registry
from cordon_scanner.core.taxonomy import AttackCategory, ThreatDomain, category_of, domain_of
from cordon_scanner.detect.catalogue import RuleCatalogue
from cordon_scanner.rules.loader import RuleLoader


def declared_rule_ids() -> list[str]:
    """Every rule the tool can emit: detector-declared and pack-declared.

    Both sources matter. A pack rule missing from the table is as unclassified
    as a detector one."""
    ids = {rule.id for rule in RuleCatalogue.from_detectors(Registry().detectors())}
    ids |= {rule.id for pack in RuleLoader.load_builtin() for rule in pack.rules}
    return sorted(ids)


class TestCompleteness:
    def test_the_catalogue_is_not_empty(self) -> None:
        """Guards the two tests below from passing vacuously."""
        assert len(declared_rule_ids()) > 20

    @pytest.mark.parametrize("rule_id", declared_rule_ids())
    def test_every_declared_rule_has_a_domain(self, rule_id: str) -> None:
        assert domain_of(rule_id) is not ThreatDomain.UNSPECIFIED, (
            f"{rule_id} falls through the domain table. Add a prefix for it, "
            f"or its findings are unclassified everywhere they are read."
        )

    @pytest.mark.parametrize("rule_id", declared_rule_ids())
    def test_every_declared_rule_has_a_category(self, rule_id: str) -> None:
        if rule_id.startswith(("CAP.", "AST.")):
            # Capability labels are inputs to composites rather than findings
            # in their own right; the composite carries the attack.
            pytest.skip("capability primitive, not a reported attack")
        assert category_of(rule_id) is not AttackCategory.UNSPECIFIED, (
            f"{rule_id} falls through the attack-category table."
        )


class TestOrdering:
    """The table is matched in order, so a broad prefix placed before a narrow
    one silently swallows it."""

    def test_a_specific_prefix_beats_the_general_one(self) -> None:
        assert domain_of("MALWARE.CI.SECRET_EXFIL.001") is ThreatDomain.CICD
        assert domain_of("MALWARE.EXFIL.001") is ThreatDomain.EXFILTRATION
        assert domain_of("MALWARE.SOMETHING.NEW.001") is ThreatDomain.MALWARE

    def test_dependency_confusion_is_not_swallowed_by_dependency(self) -> None:
        assert category_of("SUSPECT.DEPENDENCY.CONFUSION.001") is (
            AttackCategory.DEPENDENCY_CONFUSION
        )


class TestTheDistinctionsItExistsToMake:
    def test_a_vulnerability_is_not_an_attack(self) -> None:
        """A CVE in a dependency is a liability, not somebody attacking you.
        Reporting both as 'critical' with no way to tell them apart is what
        makes a report unusable for triage."""
        assert category_of("VULNERABLE.DEPENDENCY.KNOWN.001") is (AttackCategory.VULNERABILITY)
        assert category_of("MALWARE.EXFIL.001") is AttackCategory.EXFILTRATION

    def test_a_misconfiguration_is_not_an_attack(self) -> None:
        assert category_of("SUSPECT.IAC.PUBLIC_INGRESS.001") is AttackCategory.MISCONFIGURATION

    def test_coverage_findings_are_about_the_scan(self) -> None:
        assert domain_of("OPERATIONAL.FILE.TRUNCATED") is ThreatDomain.SCANNER
        assert category_of("OPERATIONAL.FILE.TRUNCATED") is AttackCategory.COVERAGE


class TestOnFindings:
    def test_a_finding_classifies_itself(self) -> None:
        from tests.support import a_finding

        finding = a_finding(rule_id="SECRET.AWS.ACCESS_KEY.001")
        assert finding.threat_domain is ThreatDomain.CREDENTIAL
        assert finding.attack_category is AttackCategory.SECRET_EXPOSURE

    def test_an_explicit_classification_is_kept(self) -> None:
        """Derivation is the default, not a straitjacket. A detector with
        better information than the rule id carries may say so."""
        from tests.support import a_finding

        finding = a_finding(
            rule_id="SECRET.AWS.ACCESS_KEY.001",
            threat_domain=ThreatDomain.CICD,
        )
        assert finding.threat_domain is ThreatDomain.CICD
