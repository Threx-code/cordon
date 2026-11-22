"""Row BP-V-31: the agent permission surface beyond hooks is a closed vocabulary of eight declared capabilities a policy can restrict.

`agent.capabilities` is a policy field read from what an agent declares. A policy that forbids one blocks an agent that declares it, names the
rule, and leaves an agent that does not declare it alone.
"""

from __future__ import annotations

import pytest
from test_decider import F  # type: ignore[import-not-found]

from cordon_scanner.decide.decision.capabilities import AgentCapabilities
from cordon_scanner.decide.decision.records import DecisionError, PolicyError

EIGHT = (
    "documents",
    "code_execution",
    "package_installs",
    "apis",
    "repository_changes",
    "databases",
    "financial_or_operational_workflows",
    "delegation",
)


class Rules:
    @staticmethod
    def forbid(name: str) -> dict[str, object]:
        return {
            "id": f"no-{name}",
            "tier": "deny",
            "then": "block",
            "when": {"agent.capabilities": name},
        }

    @staticmethod
    def agent(*declared: str):
        return F.artifact(kind="agent", subject_id="agent:acme/builder", capabilities=declared)


class TestTheVocabulary:
    def test_it_has_exactly_the_eight_entries_in_the_plans_order(self) -> None:
        assert AgentCapabilities.NAMES == EIGHT

    def test_an_unknown_name_is_found(self) -> None:
        assert AgentCapabilities.unknown(("delegation", "teleport")) == ("teleport",)

    def test_an_agent_cannot_declare_what_is_not_in_it(self) -> None:
        with pytest.raises(DecisionError, match="teleport"):
            Rules.agent("teleport")


class TestAPolicyForbiddingACapability:
    @pytest.mark.parametrize("name", EIGHT)
    def test_blocks_an_agent_that_declares_it_naming_the_rule(self, name: str) -> None:
        decision = F.decide(
            policy=F.policy(rules=[Rules.forbid(name)]), artifact=Rules.agent("documents", name)
        )
        assert decision.state == "BLOCK"
        assert f"no-{name}" in str(decision.to_json())

    @pytest.mark.parametrize("name", EIGHT)
    def test_leaves_an_agent_that_does_not_declare_it(self, name: str) -> None:
        others = tuple(other for other in EIGHT if other != name)
        assert (
            F.decide(
                policy=F.policy(rules=[Rules.forbid(name)]), artifact=Rules.agent(*others)
            ).state
            != "BLOCK"
        )

    def test_delegation_blocks_an_agent_that_declares_it_and_not_one_that_declares_nothing(
        self,
    ) -> None:
        policy = F.policy(rules=[Rules.forbid("delegation")])
        assert F.decide(policy=policy, artifact=Rules.agent("delegation")).state == "BLOCK"
        assert F.decide(policy=policy, artifact=Rules.agent()).state != "BLOCK"

    def test_a_list_of_capabilities_forbids_each_member(self) -> None:
        rule = {
            "id": "no-risky",
            "tier": "deny",
            "then": "block",
            "when": {"agent.capabilities": {"in": ["databases", "delegation"]}},
        }
        policy = F.policy(rules=[rule])
        assert F.decide(policy=policy, artifact=Rules.agent("databases")).state == "BLOCK"
        assert F.decide(policy=policy, artifact=Rules.agent("documents")).state != "BLOCK"

    def test_a_policy_naming_a_capability_that_is_not_in_the_vocabulary_is_refused(self) -> None:
        with pytest.raises(PolicyError, match="teleport"):
            F.policy(rules=[Rules.forbid("teleport")])

    def test_a_glob_over_the_vocabulary_is_allowed(self) -> None:
        rule = {
            "id": "no-package-things",
            "tier": "deny",
            "then": "block",
            "when": {"agent.capabilities": {"glob": "package_*"}},
        }
        assert (
            F.decide(policy=F.policy(rules=[rule]), artifact=Rules.agent("package_installs")).state
            == "BLOCK"
        )
