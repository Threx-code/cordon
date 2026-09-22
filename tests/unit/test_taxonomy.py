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
from cordon_scanner.core.taxonomy import (
    _CATEGORY_BY_PREFIX,
    _DOMAIN_BY_PREFIX,
    AttackCategory,
    ThreatDomain,
    category_of,
    domain_of,
)
from cordon_scanner.detect.catalogue import RuleCatalogue
from cordon_scanner.rules.loader import RuleLoader
from support import a_finding


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


def _matching_prefix(rule_id: str, table: tuple[tuple[str, object], ...]) -> str:
    """The entry that actually classifies this rule, matched the way the table is."""
    for prefix, _ in table:
        if rule_id.startswith(prefix):
            return prefix
    return ""


#: Rules a verb-only prefix classifies correctly, because they have no subject.
#:
#: `SUSPECT.DECODE_CHAIN.001` is about decoding, not about a part of the supply
#: chain, and `malware` is the right domain for it. Frozen as a list rather than
#: derived, so that a NEW family resting on the catch-all is a failure somebody
#: has to look at rather than a silent default.
CLASSIFIED_BY_VERB_ALONE = frozenset(
    {
        "MALWARE.ANTI_ANALYSIS.001",
        "MALWARE.REVERSE_SHELL.001",
        "SUSPECT.DECODE_CHAIN.001",
        "SUSPECT.REGISTRY.SELF_PUBLISH.001",
    }
)

#: The entries at the bottom of the domain table, which classify by the verb a
#: rule id starts with. A verb says what a rule claims, never what it is about.
VERB_PREFIXES = ("MALWARE.", "SUSPECT.", "POLICY.")


def _matching_prefix(rule_id: str, table: tuple[tuple[str, object], ...]) -> str:
    """The entry that classifies this rule, matched the way the table is."""
    for prefix, _ in table:
        if rule_id.startswith(prefix):
            return prefix
    return ""


class TestNothingRestsOnTheCatchAll:
    """The completeness tests above cannot fail while the catch-alls exist.

    `("SUSPECT.", MALWARE)` and `("POLICY.", SCANNER)` sit at the bottom of the
    table, so nothing is ever `UNSPECIFIED` and "has a domain" is true of every
    rule whose id begins with a word. A family added without an entry does not
    land nowhere -- it lands somewhere wrong, quietly.

    `SUSPECT.AZURE.` and `POLICY.AZURE.` did exactly that: sixteen rules, some
    five hundred findings against real infrastructure, reported as threat domain
    `malware` and `scanner`. The domain is not decoration -- `Policy._fails`
    reads `advisory_domains` by it -- so `sourceAddressPrefix: '*'` in a Bicep
    file failed a build while the identical finding in Terraform did not, and
    the README's own table promises posture is reported rather than blocking.
    `SUSPECT.DOCKERFILE.` and `POLICY.DOCKERFILE.` were the same.
    """

    @pytest.mark.parametrize("rule_id", declared_rule_ids())
    def test_a_rule_is_classified_by_its_subject(self, rule_id: str) -> None:
        prefix = _matching_prefix(rule_id, _DOMAIN_BY_PREFIX)
        if prefix not in VERB_PREFIXES:
            return
        assert rule_id in CLASSIFIED_BY_VERB_ALONE, (
            f"{rule_id} takes its threat domain from {prefix!r}, which says what "
            f"the rule claims and nothing about what it is about. Add a prefix "
            f"for its family -- a domain outside `advisory_domains` decides "
            f"whether the finding fails a build -- or add it to "
            f"CLASSIFIED_BY_VERB_ALONE with a reason."
        )

    def test_the_exemptions_are_all_still_shipped(self) -> None:
        """A frozen list rots into a lie unless something checks it."""
        declared = set(declared_rule_ids())
        assert declared >= CLASSIFIED_BY_VERB_ALONE, (
            f"exempted rules that no longer exist: {sorted(CLASSIFIED_BY_VERB_ALONE - declared)}"
        )


class TestOrdering:
    """The table is matched in order, so a broad prefix placed before a narrow
    one silently swallows it."""

    def test_a_specific_prefix_beats_the_general_one(self) -> None:
        assert domain_of("MALWARE.CI.SECRET_EXFIL.001") is ThreatDomain.CICD

    @pytest.mark.parametrize(
        ("name", "table"),
        [("domain", _DOMAIN_BY_PREFIX), ("category", _CATEGORY_BY_PREFIX)],
    )
    def test_no_entry_is_unreachable(self, name: str, table) -> None:
        """An entry below a prefix of itself can never match.

        Written down, never reached, and it reads as the classification the
        table gives. `POLICY.COMPOSE.` and `POLICY.CFN.` sat beneath `POLICY.`
        and said `misconfiguration` while reporting `policy`; `SUSPECT.BINARY.`,
        `POLICY.BINARY.` and `SUSPECT.SUBMODULE.` were each listed twice.
        """
        shadowed = [
            (prefix, earlier)
            for index, (prefix, _) in enumerate(table)
            for earlier, _ in table[:index]
            if prefix.startswith(earlier)
        ]
        assert not shadowed, f"the {name} table has entries that can never match: " + ", ".join(
            f"{p!r} is shadowed by {e!r}" for p, e in shadowed
        )
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
        finding = a_finding(rule_id="SECRET.AWS.ACCESS_KEY.001")
        assert finding.threat_domain is ThreatDomain.CREDENTIAL
        assert finding.attack_category is AttackCategory.SECRET_EXPOSURE

    def test_an_explicit_classification_is_kept(self) -> None:
        """Derivation is the default, not a straitjacket. A detector with
        better information than the rule id carries may say so."""
        finding = a_finding(
            rule_id="SECRET.AWS.ACCESS_KEY.001",
            threat_domain=ThreatDomain.CICD,
        )
        assert finding.threat_domain is ThreatDomain.CICD
