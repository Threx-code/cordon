"""Today's `PolicyGate` and `Decider.decide` over a compiled legacy policy agree, over a grid of policies x scans.

The grid is the one the 50,000-pair harness uses (`bench/tools/legacy_equivalence.py`): `fail_on_severity` (none and
the five) x `min_confidence_to_fail` (4) x `fail_on_categories` (4 subsets) x `advisory_domains` (the default and
none) x `fail_on_incomplete` (2) x accepted content gaps (none, one unexpired, one expired) = 1,152 policies. The scans here
are synthetic and cover each way a scan can fail the gate; the harness runs recorded rows.
"""

from __future__ import annotations

from datetime import date

import pytest

from cordon_scanner.decide.decision.legacy import LegacyBridge
from cordon_scanner.foundation.config.policy import DEFAULT_ADVISORY_DOMAINS, Policy
from cordon_scanner.foundation.models import Category, Confidence, Location, Severity
from cordon_scanner.foundation.results import ScanResult
from cordon_scanner.foundation.taxonomy import ThreatDomain
from support import Support

TODAY = date(2026, 11, 17)


class Scans:
    @staticmethod
    def finding(
        rule: str,
        category: Category,
        severity: Severity,
        confidence: Confidence,
        path: str = "a/x.py",
        line: int = 1,
    ):
        return Support.a_finding(
            rule_id=rule,
            category=category,
            severity=severity,
            confidence=confidence,
            location=Location(path=path, line=line),
        )

    @classmethod
    def all(cls) -> dict[str, ScanResult]:
        f = cls.finding
        mixed = (
            f("MALWARE.A.001", Category.MALICIOUS, Severity.HIGH, Confidence.LOW),
            f(
                "SUSPECT.B.001",
                Category.SUSPICIOUS,
                Severity.CRITICAL,
                Confidence.CONFIRMED,
                "b.js",
                9,
            ),
            f("SUSPECT.C.001", Category.SUSPICIOUS, Severity.MEDIUM, Confidence.HIGH, "c.js", 2),
            f("VULN.D.001", Category.VULNERABLE, Severity.HIGH, Confidence.MEDIUM, "d.json", 5),
        )
        infra = f(
            "SUSPECT.CI.FETCH_EXEC.001",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.HIGH,
            ".github/workflows/x.yml",
            4,
        )
        infra_malicious = f(
            "MALWARE.CI.SECRET_EXFIL.001",
            Category.MALICIOUS,
            Severity.HIGH,
            Confidence.HIGH,
            ".github/workflows/y.yml",
            8,
        )
        gaps = (("OPERATIONAL.SOURCE.UNPARSED", "a/broken.py"),)
        return {
            "empty": ScanResult(),
            "empty-incomplete": ScanResult(complete=False),
            "mixed": ScanResult(findings=mixed),
            "mixed-incomplete": ScanResult(findings=mixed, complete=False),
            "infra": ScanResult(findings=(infra,)),
            "infra-malicious": ScanResult(findings=(infra, infra_malicious)),
            "gap": ScanResult(content_gaps=gaps),
            "gap-and-finding": ScanResult(findings=mixed, content_gaps=gaps),
            "other-gap": ScanResult(content_gaps=(("OPERATIONAL.ARCHIVE.REJECTED", "z.zip"),)),
        }


POLICIES = LegacyBridge.policy_grid()
SCANS = Scans.all()


class TestTheLegacyPolicyAndTheDecisionAgree:
    def test_the_grid_is_wide_and_covers_every_domain_the_taxonomy_has(self) -> None:
        assert len(POLICIES) == 1152
        assert len(ThreatDomain) > len(DEFAULT_ADVISORY_DOMAINS)

    @pytest.mark.parametrize("name", sorted(SCANS))
    def test_every_policy_of_the_grid_agrees_on_this_scan(self, name: str) -> None:
        disagreements = [
            (index, problems)
            for index, policy in enumerate(POLICIES)
            if (problems := LegacyBridge.differences(SCANS[name], policy, TODAY))
        ]
        assert disagreements == []

    def test_the_grid_has_every_outcome_so_agreement_means_something(self) -> None:
        from collections import Counter

        from cordon_scanner.decide.policy import PolicyGate

        seen = Counter(
            PolicyGate.evaluate(scan, policy).exit_code.name
            for scan in SCANS.values()
            for policy in POLICIES
        )
        assert set(seen) == {"CLEAN", "FINDINGS", "INCOMPLETE"}
        assert all(count > 1000 for count in seen.values())

    def test_the_default_policy_blocks_malware_and_lets_infrastructure_choices_pass(self) -> None:
        policy = Policy()
        assert LegacyBridge.differences(SCANS["infra"], policy, TODAY) == []
        assert LegacyBridge.differences(SCANS["infra-malicious"], policy, TODAY) == []
