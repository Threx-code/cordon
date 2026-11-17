"""Today's failure policy as a policy v2, and the check that the two agree (design spec M1, 20).

`LegacyBridge.compiled(policy)` writes `foundation.config.policy.Policy` (what `PolicyGate` reads) as a
compiled v2 table; `LegacyBridge.evidence(result, policy, today)` writes a `ScanResult` as an `EvidenceSet`;
`LegacyBridge.differences` runs the real `PolicyGate` and `Decider.decide` on one (result, policy) pair and
lists where they disagree. The harness over 50,000 pairs calls only that.

```
  fail_on_categories           a deny rule on the category (a category match bypasses the confidence floor)
  fail_on_severity + floor     a deny rule on severity and confidence, in every domain that is not advisory
  advisory_domains             the severity rule's domain list leaves them out (the category rule still fires)
  fail_on_incomplete           defaults.on_incomplete: block (else warn)
  content gaps no acceptance covers   evidence.gaps, which `defaults.on_gaps` (block) turns into R204
```
The CLI keeps `PolicyGate` until M4 and M5 move the entry points onto `decide()`.
"""

from __future__ import annotations

import itertools
from datetime import UTC, date, datetime
from typing import ClassVar

from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.decider import Decider
from cordon_scanner.decide.decision.evidence import (
    ArtifactRef,
    Context,
    EvidenceSet,
    FindingFact,
    GapFact,
)
from cordon_scanner.decide.decision.policy_source import PolicySource
from cordon_scanner.decide.decision.table import CompiledPolicy
from cordon_scanner.decide.policy import PolicyGate, SuppressionMatcher
from cordon_scanner.foundation.config.policy import DEFAULT_ADVISORY_DOMAINS, Policy
from cordon_scanner.foundation.errors import ExitCode
from cordon_scanner.foundation.models import Category, Confidence, Finding, Severity, Suppression
from cordon_scanner.foundation.results import ScanResult
from cordon_scanner.foundation.taxonomy import ThreatDomain


class LegacyBridge:
    RULE_CODES = ("R400", "R401", "R404")
    #: The category sets of the policy grid.
    CATEGORY_SETS: ClassVar[tuple[frozenset[Category], ...]] = (
        frozenset(),
        frozenset({Category.MALICIOUS}),
        frozenset({Category.MALICIOUS, Category.SUSPICIOUS}),
        frozenset({Category.VULNERABLE, Category.POLICY}),
    )

    @classmethod
    def policy_grid(cls) -> list[Policy]:
        """The deterministic grid of failure policies the equivalence check runs: `fail_on_severity` (none and the
        five) x `min_confidence_to_fail` (4) x `fail_on_categories` (4 sets) x `advisory_domains` (the default and
        none) x `fail_on_incomplete` (2) x accepted content gaps (none, one unexpired, one expired) = 1,152."""
        gap = {"rule": "OPERATIONAL.SOURCE.UNPARSED", "path": "*.py", "justification": "accepted"}
        accepted = (
            None,
            (Suppression(expires="2999-01-01", **gap),),
            (Suppression(expires="2000-01-01", **gap),),
        )
        return [
            Policy(
                fail_on_severity=severity,
                min_confidence_to_fail=confidence,
                fail_on_categories=categories,
                advisory_domains=advisory,
                fail_on_incomplete=incomplete,
                accepted_gaps=gaps,
            )
            for severity, confidence, categories, advisory, incomplete, gaps in itertools.product(
                (None, *Severity),
                tuple(Confidence),
                cls.CATEGORY_SETS,
                (DEFAULT_ADVISORY_DOMAINS, frozenset()),
                (False, True),
                accepted,
            )
        ]

    @classmethod
    def source(cls, policy: Policy) -> PolicySource:
        """`policy` as a v2 source: the rules PolicyGate's `_fails` is, in the order it tests them."""
        rules: list[dict[str, object]] = []
        if policy.fail_on_categories:
            rules.append(
                {
                    "id": "legacy-categories",
                    "tier": "deny",
                    "then": "block",
                    "when": {
                        "finding.category": {
                            "in": sorted(str(c) for c in policy.fail_on_categories)
                        }
                    },
                }
            )
        failing = sorted(
            domain.value for domain in ThreatDomain if domain not in policy.advisory_domains
        )
        if policy.fail_on_severity is not None and failing:
            rules.append(
                {
                    "id": "legacy-severity",
                    "tier": "deny",
                    "then": "block",
                    "when": {
                        "finding.severity": f">={policy.fail_on_severity}",
                        "finding.confidence": f">={policy.min_confidence_to_fail}",
                        "finding.domain": {"in": failing},
                    },
                }
            )
        return PolicySource.from_json(
            {
                "policy_schema": 2,
                "id": "legacy",
                "version": 1,
                "rules": rules,
                "defaults": {
                    "on_incomplete": "block" if policy.fail_on_incomplete else "warn",
                    "on_gaps": "block",
                    "default": "allow",
                },
            }
        )

    @classmethod
    def compiled(cls, policy: Policy) -> CompiledPolicy:
        return PolicyCompiler.compile(cls.source(policy))

    @staticmethod
    def fact(finding: Finding) -> FindingFact:
        """One finding as a policy sees it."""
        stamp = finding.fingerprint
        hashed = len(stamp) in range(16, 65) and all(char in "0123456789abcdef" for char in stamp)
        return FindingFact(
            rule_id=finding.rule_id,
            severity=str(finding.severity),
            confidence=str(finding.confidence),
            category=str(finding.category),
            domain=str(finding.threat_domain.value if finding.threat_domain else "unspecified"),
            path=finding.location.path,
            line=finding.location.line,
            evidence_hash=stamp if hashed else None,
        )

    @classmethod
    def evidence(cls, result: ScanResult, policy: Policy, today: date) -> EvidenceSet:
        """The evidence of a scan: its active findings, whether it completed, and the content gaps no unexpired
        acceptance covers (acceptance is judged at `today`, as `PolicyGate` judges it at today's date)."""
        accepted = [
            gap for gap in policy.accepted_gaps or () if date.fromisoformat(gap.expires) >= today
        ]
        gaps = tuple(
            GapFact(rule, path)
            for rule, path in result.content_gaps
            if not any(SuppressionMatcher.covers(rule, path, gap) for gap in accepted)
        )
        return EvidenceSet(
            findings=tuple(cls.fact(item) for item in result.active),
            gaps=gaps,
            complete=result.complete,
        )

    @classmethod
    def differences(
        cls, result: ScanResult, policy: Policy, today: date | None = None
    ) -> list[str]:
        """Where `PolicyGate` and `Decider.decide` disagree on this pair; empty when they agree.

        Agreement means: BLOCK exactly when the gate's exit code is not CLEAN; for FINDINGS, the findings
        behind the content reasons are the gate's triggering findings; for INCOMPLETE, an R204 reason; for
        CLEAN, no content reason."""
        today = today or date.today()
        verdict = PolicyGate.evaluate(result, policy)
        decision = Decider.decide(
            ArtifactRef("package", "pkg:npm/legacy"),
            Context("cli", "dev"),
            cls.compiled(policy),
            cls.evidence(result, policy, today),
            datetime(today.year, today.month, today.day, 12, tzinfo=UTC),
        )
        found: list[str] = []
        failed = verdict.exit_code is not ExitCode.CLEAN
        if decision.blocked != failed:
            found.append(f"state: gate {verdict.exit_code.name}, decision {decision.state}")
        content = {
            (item.rule_id, item.path or None, item.line)
            for item in decision.explanation.reasons
            if item.code in cls.RULE_CODES
        }
        if verdict.exit_code is ExitCode.FINDINGS:
            triggering = {
                (f.rule_id, f.location.path or None, f.location.line) for f in verdict.triggering
            }
            if content != triggering:
                found.append("triggering findings differ")
        elif verdict.exit_code is ExitCode.INCOMPLETE:
            if "R204" not in decision.reason_codes:
                found.append("incomplete without R204")
        elif content:
            found.append("a content reason where the gate passed")
        return found


__all__ = ["LegacyBridge"]
