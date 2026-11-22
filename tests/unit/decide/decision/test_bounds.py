"""BP-0-10 (invariant I6): the library bounds the text it says, so a receiver can cap it one notch above.

A decision's text is fixed templates with ids, plus inputs echoed back (a gap's path, an approval's conditions). These tests give the decider hostile inputs (a path of thousands of characters with
control characters in it, thousands of findings, conditions of tens of thousands of characters) and check what it says: the summary and every reason at most 320 characters, at most 101 reasons, no control
character, and `reason_codes` still naming every code of the reasons that were not listed.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime

import pytest

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.decision.bounds import Bounds
from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.decider import Decider
from cordon_scanner.decide.decision.evidence import (
    Approval,
    ArtifactRef,
    Context,
    EvidenceSet,
    FindingFact,
    GapFact,
)
from cordon_scanner.decide.decision.outcome import Reason
from cordon_scanner.decide.decision.policy_source import PolicySource

CLOCK = datetime(2026, 11, 19, 8, 0, 30, tzinfo=UTC)
DIGEST = ArtifactDigests.of_bytes(b"the artifact")
DENY_ANY = [
    {"id": "deny-any", "tier": "deny", "then": "block", "when": {"finding.severity": ">=info"}}
]
TYPICAL = [
    {
        "id": "deny-malicious",
        "tier": "deny",
        "then": "block",
        "when": {"finding.category": "malicious", "finding.confidence": ">=medium"},
    },
    {
        "id": "deny-high",
        "tier": "deny",
        "then": "review",
        "when": {"finding.severity": ">=high", "finding.confidence": ">=medium"},
    },
]
ARTIFACT = ArtifactRef(
    kind="package",
    subject_id="pkg:npm/left-pad",
    digest=DIGEST,
    ecosystem="npm",
    released_at="2026-06-01T00:00:00Z",
)


class Kit:
    """The policy, the decision and the findings the tests below build."""

    @staticmethod
    def policy(rules):
        return PolicyCompiler.compile(
            PolicySource.from_json(
                {
                    "policy_schema": 2,
                    "id": "acme/production",
                    "version": 14,
                    "scope": ["acme"],
                    "rules": rules,
                    "defaults": {"warn_until_measured": ["pypi"]},
                }
            )
        )

    @staticmethod
    def decide(evidence, rules=DENY_ANY, environment="production"):
        return Decider.decide(
            ARTIFACT,
            Context(point="ci_gate", environment=environment, scope_path=("acme",)),
            Kit.policy(rules),
            evidence,
            CLOCK,
        )

    @staticmethod
    def finding(n, path="a.js", **kw):
        base = {
            "rule_id": f"SUSPECT.TEST.RULE_{n % 40}.001",
            "severity": "high",
            "confidence": "high",
            "category": "suspicious",
            "path": path,
            "line": n,
        }
        base.update(kw)
        return FindingFact(**base)

    @staticmethod
    def within_bounds(decision) -> None:
        explanation = decision.explanation
        assert len(explanation.summary) <= Bounds.TEXT
        assert len(explanation.reasons) <= Bounds.REASONS + 1
        for item in (*explanation.reasons,):
            assert len(item.text) <= Bounds.TEXT
        for text in (explanation.summary, *(r.text for r in explanation.reasons)):
            assert all(ord(c) >= 32 and ord(c) != 127 for c in text)


class TestTheBoundsThemselves:
    def test_a_control_character_becomes_a_question_mark_and_newlines_too(self) -> None:
        assert Bounds.clean("a\nb\x00c\x7fd\te") == "a?b?c?d?e"

    def test_a_text_is_cut_with_an_ellipsis_only_when_it_is_too_long(self) -> None:
        assert Bounds.cut("x" * 320, 320) == "x" * 320
        cut = Bounds.cut("x" * 321, 320)
        assert len(cut) == 320 and cut.endswith("…")

    def test_a_path_keeps_its_first_two_hundred_characters_and_an_ellipsis(self) -> None:
        assert Bounds.path("p" * 200) == "p" * 200
        assert Bounds.path("p" * 201) == "p" * 200 + "…"

    def test_conditions_are_joined_and_cut_at_five_hundred(self) -> None:
        assert Bounds.conditions(("a", "b")) == "a; b"
        assert len(Bounds.conditions(("c" * 400, "d" * 400))) == 500

    def test_more_than_a_hundred_reasons_become_a_hundred_and_one_that_counts_the_rest(
        self,
    ) -> None:
        reasons = (*(Reason("R600", f"reason {n}") for n in range(130)), Reason("R204", "late"))
        bounded = Bounds.reasons(reasons)
        assert (
            len(bounded) == 101
            and bounded[-1].text == "and 31 more reasons, not listed"
            and bounded[-1].code == "R600"
        )
        assert Bounds.reasons(reasons[:100]) == reasons[:100]


class TestTheDeciderNeverSaysMoreThanItsBounds:
    def test_a_gap_with_a_path_of_five_thousand_characters_and_a_newline_in_it(self) -> None:
        gap = GapFact(
            rule_id="OPERATIONAL.ARCHIVE.REJECTED", path="dir/" + "x" * 2500 + "\n" + "y" * 2500
        )
        decision = Kit.decide(EvidenceSet(gaps=(gap,), complete=False))
        Kit.within_bounds(decision)
        text = next(r.text for r in decision.explanation.reasons if "not examined" in r.text)
        assert "…" in text and "\n" not in text

    def test_three_thousand_findings_give_a_hundred_reasons_and_one_that_counts_the_rest(
        self,
    ) -> None:
        decision = Kit.decide(
            EvidenceSet(
                findings=tuple(Kit.finding(n, path="f" * 3000 + f"/{n}.js") for n in range(3000))
            )
        )
        Kit.within_bounds(decision)
        reasons = decision.explanation.reasons
        assert len(reasons) == 101 and reasons[-1].text == "and 2900 more reasons, not listed"

    def test_the_codes_a_decision_carries_still_name_every_reason_not_listed(self) -> None:
        findings = tuple(Kit.finding(n) for n in range(150))
        gap = GapFact(rule_id="OPERATIONAL.ARCHIVE.REJECTED", path="late.tgz")
        decision = Kit.decide(EvidenceSet(findings=findings, gaps=(gap,), complete=False))
        listed = {r.code for r in decision.explanation.reasons}
        assert "R204" in decision.reason_codes and len(decision.explanation.reasons) == 101
        assert listed <= set(decision.reason_codes)

    def test_approval_conditions_of_fifty_thousand_characters(self) -> None:
        blocked = EvidenceSet(findings=(Kit.finding(1, category="malicious"),))
        approval = Approval(
            "a1",
            "approve_with_conditions",
            "2027-01-01T00:00:00Z",
            digests=(DIGEST,),
            scope_path=("acme",),
            conditions=("c" * 50_000, "d\ne"),
        )
        decision = Kit.decide(
            EvidenceSet(findings=blocked.findings, approvals=(approval,)), rules=TYPICAL
        )
        Kit.within_bounds(decision)
        assert any(r.code == "R703" for r in decision.explanation.reasons)

    def test_the_structured_fields_of_a_reason_are_data_and_stay_whole(self) -> None:
        long_path = "z" * 900
        decision = Kit.decide(EvidenceSet(findings=(Kit.finding(1, path=long_path),)))
        assert any(r.path == long_path for r in decision.explanation.reasons)

    def test_the_decision_in_json_is_the_bounded_one(self) -> None:
        decision = Kit.decide(
            EvidenceSet(
                gaps=(GapFact(rule_id="OPERATIONAL.SOURCE.UNPARSED", path="q" * 1000),),
                complete=False,
            )
        )
        document = decision.to_json()
        assert len(document["explanation"]["summary"]) <= Bounds.TEXT
        assert all(len(item["text"]) <= Bounds.TEXT for item in document["explanation"]["reasons"])

    @pytest.mark.parametrize("seed", range(8))
    def test_random_evidence_under_two_policies_never_exceeds_the_bounds(self, seed: int) -> None:
        rng = random.Random(f"bounds-{seed}")  # noqa: S311 - a fixed-seed test input, not a secret
        for _ in range(25):
            chars = "abcdef/._-" + "".join(map(chr, (10, 9, 0, 0x202E, 0x200B)))
            findings = tuple(
                Kit.finding(
                    n,
                    path="".join(
                        rng.choice(chars) for _ in range(rng.choice((0, 5, 120, 900, 2500)))
                    ),
                    rule_id="SUSPECT." + "R" * rng.choice((1, 20, 60, 90)) + ".001",
                )
                for n in range(rng.choice((0, 1, 5, 60, 150, 400)))
            )
            gaps = tuple(
                GapFact(
                    rule_id="OPERATIONAL.ARCHIVE.REJECTED",
                    path="".join(rng.choice(chars) for _ in range(rng.choice((0, 50, 3000)))),
                )
                for _ in range(rng.choice((0, 1, 4)))
            )
            evidence = EvidenceSet(findings=findings, gaps=gaps, complete=not gaps)
            for rules in (DENY_ANY, TYPICAL):
                Kit.within_bounds(
                    Kit.decide(
                        evidence,
                        rules=rules,
                        environment=rng.choice(("production", "ci", "eng-prod-eu-west-1")),
                    )
                )
