"""Rows BP-5-19, BP-5-20 and BP-5-21: where the provenance (R5xx), AI component (R6xx) and workflow (R7xx, R9xx) codes come from.

* R502, R504 and R505 come from three facts the evidence now carries (publisher first seen, a lookalike name, the registry host);
  each is read by its own predicate field, so a policy rule on it gets the code without naming it. One fixture per code, asked at the
  firewall and at the CLI.
* R600, R601, R602 and R604 are the code a finding of the AI-component scanner rules has of its own (`ReasonMap`): the MCP tool
  rug pull (`SUSPECT.MCP.TOOLS_CHANGED.001`) is R604 at the first session start that sees it.
* R701 says why an approval that would have lifted a rule does not (it ran out), and changes nothing else; R902 is the code of an allow
  rule over one of the policy's lists.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.contracts.reason_codes import ReasonCodes
from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.evidence import (
    Approval,
    ArtifactRef,
    EvidenceSet,
    FindingFact,
    Provenance,
)
from cordon_scanner.decide.decision.policy_source import PolicySource
from cordon_scanner.decide.decision.reason_map import ReasonMap
from cordon_scanner.decide.decision.records import DecisionError
from cordon_scanner.decide.points import PointRuntime

CLOCK = datetime(2026, 11, 19, 10, 0, tzinfo=UTC)
DIGEST = ArtifactDigests.of_bytes(b"artifact")
OTHER = ArtifactDigests.of_bytes(b"another artifact")


class Make:
    @staticmethod
    def policy(rules: list[dict[str, Any]], lists: dict[str, Any] | None = None):
        source: dict[str, Any] = {
            "policy_schema": 2,
            "id": "acme/policy",
            "version": 1,
            "scope": ["acme"],
            "rules": rules,
            "defaults": {},
        }
        if lists is not None:
            source["lists"] = lists
        return PolicyCompiler.compile(PolicySource.from_json(source))

    @staticmethod
    def artifact(**more: Any) -> ArtifactRef:
        return ArtifactRef(
            kind="package",
            subject_id="pkg:npm/left-pad",
            digest=DIGEST,
            ecosystem="npm",
            released_at="2026-06-01T00:00:00Z",
            **more,
        )

    @staticmethod
    def ask(
        policy, evidence: EvidenceSet, artifact: ArtifactRef | None = None, point: str = "ci_gate"
    ):
        return PointRuntime.ask(
            point,
            artifact or Make.artifact(),
            evidence,
            policy,
            CLOCK,
            environment="production",
            scope_path=("acme",),
        )

    @staticmethod
    def finding(rule_id: str, category: str = "suspicious") -> FindingFact:
        return FindingFact(
            rule_id=rule_id,
            severity="high",
            confidence="high",
            category=category,
            domain="agent",
            path="mcp.json",
            line=1,
        )

    @staticmethod
    def deny(category: str = "suspicious", **more: Any) -> dict[str, Any]:
        return {
            "id": "deny",
            "tier": "deny",
            "then": "block",
            "when": {"finding.category": category},
            **more,
        }


class TestProvenanceAndSourceCodes:
    """BP-5-19: one fixture per code at the firewall and the CLI."""

    POINTS = ("firewall", "cli")

    @pytest.mark.parametrize("point", POINTS)
    def test_a_publisher_first_seen_days_ago_is_r502(self, point: str) -> None:
        policy = Make.policy(
            [
                {
                    "id": "new",
                    "tier": "require",
                    "then": "review",
                    "when": {"publisher.age_days": "<30d"},
                }
            ]
        )
        recent = Provenance(slsa_level=2, publisher_first_seen="2026-11-14T00:00:00Z")
        old = Provenance(slsa_level=2, publisher_first_seen="2025-01-01T00:00:00Z")
        flagged = Make.ask(policy, EvidenceSet(provenance=recent), point=point)
        assert flagged.state == "REVIEW" and flagged.reason_codes == ("R502",)
        assert "R502" not in Make.ask(policy, EvidenceSet(provenance=old), point=point).reason_codes

    def test_a_publisher_date_that_is_not_verified_is_not_read(self) -> None:
        policy = Make.policy(
            [
                {
                    "id": "new",
                    "tier": "require",
                    "then": "review",
                    "when": {"publisher.age_days": "<30d"},
                }
            ]
        )
        unverified = Provenance(verified=False, publisher_first_seen="2026-11-14T00:00:00Z")
        assert "R502" not in Make.ask(policy, EvidenceSet(provenance=unverified)).reason_codes
        assert "R502" not in Make.ask(policy, EvidenceSet()).reason_codes

    @pytest.mark.parametrize("point", POINTS)
    def test_a_name_that_imitates_another_is_r504(self, point: str) -> None:
        policy = Make.policy(
            [
                {
                    "id": "twin",
                    "tier": "require",
                    "then": "block",
                    "when": {"name.lookalike": "present"},
                }
            ]
        )
        found = Make.ask(policy, EvidenceSet(lookalike_of="left-pad"), point=point)
        assert found.state == "BLOCK" and found.reason_codes == ("R504",)
        assert "R504" not in Make.ask(policy, EvidenceSet(), point=point).reason_codes

    @pytest.mark.parametrize("point", POINTS)
    def test_a_registry_that_is_not_allowed_is_r505(self, point: str) -> None:
        policy = Make.policy(
            [
                {
                    "id": "registries",
                    "tier": "require",
                    "then": "block",
                    "require": {"registry.host": {"in": ["registry.npmjs.org"]}},
                }
            ]
        )
        served = Make.artifact(registry="npm.mirror.example")
        allowed = Make.artifact(registry="registry.npmjs.org")
        blocked = Make.ask(policy, EvidenceSet(), served, point)
        assert blocked.state == "BLOCK" and blocked.reason_codes == ("R505",)
        assert Make.ask(policy, EvidenceSet(), allowed, point).state == "ALLOW"

    def test_the_new_fields_are_absent_from_evidence_and_artifacts_that_do_not_set_them(
        self,
    ) -> None:
        assert "lookalike_of" not in EvidenceSet().to_json()
        assert "publisher_first_seen" not in Provenance().to_json()
        assert "registry" not in Make.artifact().to_json()

    def test_a_publisher_date_must_be_a_time(self) -> None:
        with pytest.raises(DecisionError):
            Provenance(publisher_first_seen="last week")


class TestAiComponentCodes:
    """BP-5-20: R600 to R602 and R604 from the findings of the AI-component scanner rules."""

    @pytest.mark.parametrize(
        ("rule_id", "code"),
        [
            ("SUSPECT.MCP.TOOL_DESCRIPTION.001", "R600"),
            ("SUSPECT.MCP.LIVE_TOOL_DESCRIPTION.001", "R600"),
            ("SUSPECT.AGENT.SKILL_INSTRUCTIONS.001", "R601"),
            ("SUSPECT.AGENT.SKILL_JAILBREAK_TEXT.001", "R601"),
            ("SUSPECT.MCP.HANDLER_SHELL.001", "R602"),
            ("POLICY.AGENT.WILDCARD_PERMISSION.001", "R602"),
            ("SUSPECT.MCP.TOOLS_CHANGED.001", "R604"),
        ],
    )
    def test_a_finding_of_the_rule_gives_the_code_without_the_policy_naming_it(
        self, rule_id: str, code: str
    ) -> None:
        found = Make.ask(Make.policy([Make.deny()]), EvidenceSet(findings=(Make.finding(rule_id),)))
        assert found.state == "BLOCK" and found.reason_codes == (code,)

    def test_the_mcp_rug_pull_is_r604_at_the_first_session_start_that_sees_it(self) -> None:
        rug_pull = Make.finding("SUSPECT.MCP.TOOLS_CHANGED.001")
        policy = Make.policy(
            [
                {
                    "id": "tools-changed",
                    "tier": "deny",
                    "then": "review",
                    "when": {"finding.rule_id": "SUSPECT.MCP.TOOLS_CHANGED.001"},
                }
            ]
        )
        server = ArtifactRef(
            kind="mcp_server",
            subject_id="mcp:remote/mcp.example.com/sse",
            digest=ArtifactDigests.of_tool_list([{"name": "a", "description": "d"}]),
        )
        found = Make.ask(policy, EvidenceSet(findings=(rug_pull,)), server, point="agent_hook")
        assert found.state == "REVIEW" and found.reason_codes == ("R604",)

    def test_a_rule_that_names_its_own_code_keeps_it(self) -> None:
        policy = Make.policy([Make.deny(reason="R401")])
        found = Make.ask(
            policy, EvidenceSet(findings=(Make.finding("SUSPECT.MCP.TOOL_DESCRIPTION.001"),))
        )
        assert found.reason_codes == ("R401",)

    def test_two_findings_of_one_rule_firing_each_give_their_own_code(self) -> None:
        evidence = EvidenceSet(
            findings=(
                Make.finding("SUSPECT.MCP.TOOL_DESCRIPTION.001"),
                Make.finding("SUSPECT.AGENT.SKILL_INSTRUCTIONS.001"),
                Make.finding("SUSPECT.PACKAGE.OTHER.001"),
            )
        )
        found = Make.ask(Make.policy([Make.deny()]), evidence)
        assert found.reason_codes == ("R401", "R600", "R601")

    def test_a_finding_no_one_has_placed_keeps_the_code_of_its_category(self) -> None:
        found = Make.ask(
            Make.policy([Make.deny()]),
            EvidenceSet(findings=(Make.finding("SUSPECT.NEW.RULE.001"),)),
        )
        assert found.reason_codes == ("R401",)

    def test_every_rule_in_the_table_is_a_rule_of_the_scanner_and_a_code_of_the_registry(
        self,
    ) -> None:
        from kits.matrix import CoverageMatrix

        known = set(CoverageMatrix.shipped_rules())
        unknown = sorted(set(ReasonMap.TABLE) - known)
        assert not unknown, unknown
        assert all(ReasonCodes.is_registered(code) for code in ReasonMap.TABLE.values())


class TestWorkflowAndAllowCodes:
    """BP-5-21: R701 and R902 beside the R700, R702, R703, R900 and R901 the library already emitted."""

    @staticmethod
    def approval(
        kind: str = "approve", expires: str = "2026-11-01T00:00:00Z", **more: Any
    ) -> Approval:
        fields: dict[str, Any] = {
            "id": "APR-1",
            "kind": kind,
            "expires_at": expires,
            "digests": (DIGEST,),
            "scope_path": ("acme",),
        }
        return Approval(**{**fields, **more})

    def test_an_approval_that_ran_out_is_r701_beside_the_rule_it_no_longer_lifts(self) -> None:
        evidence = EvidenceSet(
            findings=(Make.finding("SUSPECT.PACKAGE.OTHER.001"),), approvals=(self.approval(),)
        )
        found = Make.ask(Make.policy([Make.deny()]), evidence)
        assert found.state == "BLOCK" and found.reason_codes == ("R401", "R701")

    @pytest.mark.parametrize(
        ("approval", "why"),
        [
            (approval(expires="2026-12-31T00:00:00Z"), "still active: R901, no R701"),
            (approval(revoked=True), "revoked, not expired"),
            (approval(digests=(OTHER,)), "another digest"),
            (approval(scope_path=("other",)), "another scope"),
            (approval(kind="exception"), "an exception is not an approval"),
        ],
    )
    def test_r701_is_only_for_a_lapsed_approval_of_this_digest_and_scope(
        self, approval: Approval, why: str
    ) -> None:
        evidence = EvidenceSet(
            findings=(Make.finding("SUSPECT.PACKAGE.OTHER.001"),), approvals=(approval,)
        )
        assert "R701" not in Make.ask(Make.policy([Make.deny()]), evidence).reason_codes, why

    def test_no_r701_when_no_rule_asks_for_more(self) -> None:
        found = Make.ask(Make.policy([]), EvidenceSet(approvals=(self.approval(),)))
        assert found.state == "ALLOW" and "R701" not in found.reason_codes

    def test_an_allow_rule_over_a_policy_list_is_r902_and_over_a_literal_is_r900(self) -> None:
        listed = Make.policy(
            [
                {
                    "id": "allow-list",
                    "tier": "allow",
                    "then": "allow",
                    "when": {"subject.id": {"in": "allowed"}},
                }
            ],
            lists={"allowed": ["pkg:npm/left-pad"]},
        )
        inline = Make.policy(
            [
                {
                    "id": "allow-one",
                    "tier": "allow",
                    "then": "allow",
                    "when": {"subject.id": "pkg:npm/left-pad"},
                }
            ]
        )
        wrapped = Make.policy(
            [
                {
                    "id": "allow-list",
                    "tier": "allow",
                    "then": "allow",
                    "when": {"artifact.digest": {"in": "digests"}},
                }
            ],
            lists={"digests": [DIGEST]},
        )
        assert Make.ask(listed, EvidenceSet()).reason_codes == ("R902",)
        assert Make.ask(inline, EvidenceSet()).reason_codes == ("R900",)
        assert Make.ask(wrapped, EvidenceSet()).reason_codes == ("R902",)

    def test_an_allow_rule_over_a_list_that_does_not_name_this_subject_does_not_fire(self) -> None:
        policy = Make.policy(
            [
                {
                    "id": "allow-list",
                    "tier": "allow",
                    "then": "allow",
                    "when": {"subject.id": {"in": "allowed"}},
                }
            ],
            lists={"allowed": ["pkg:npm/someone-else"]},
        )
        assert Make.ask(policy, EvidenceSet()).reason_codes == ("R903",)
