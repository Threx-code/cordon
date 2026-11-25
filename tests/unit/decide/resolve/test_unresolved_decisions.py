"""Row BP-3-15: a resolver that cannot reach its source yields UNRESOLVED, which `decide()` treats under I4 (fail closed, `R203`).

End to end at the firewall point: the registry or SCM API is down, the resolver says `unresolved`, its evidence goes to the point
runtime, and the decision is `R203` at the level the policy sets for unresolved names (`block` unless the tenant relaxed it, and then
the relaxation is on the record). A name that did resolve is decided as before, with no `R203`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.policy_source import PolicySource
from cordon_scanner.decide.decision.table import CompiledPolicy
from cordon_scanner.decide.points import PointRuntime
from cordon_scanner.decide.resolve.action import ActionResolver
from cordon_scanner.decide.resolve.mcp import McpResolver, RegistryArchive
from cordon_scanner.decide.resolve.resolution import Resolution, SourceUnavailable
from cordon_scanner.decide.resolve.skill import SkillResolver

CLOCK = datetime(2026, 11, 19, 9, 0, tzinfo=UTC)
COMMIT = "0123456789abcdef0123456789abcdef01234567"


class Sources:
    """A registry and an SCM API that are either up or down."""

    def __init__(self, up: bool) -> None:
        self.up = up

    def commit_of(self, owner: str, repo: str, ref: str) -> str:
        if not self.up:
            raise SourceUnavailable("no network")
        return COMMIT

    def archive(
        self, ecosystem: str, name: str, selector: str | None, index: str | None
    ) -> RegistryArchive:
        if not self.up:
            raise SourceUnavailable("no network")
        return RegistryArchive("1.0.0", b"archive", "registry.npmjs.org")


class Kit:
    @staticmethod
    def policy(unresolved: str | None = None) -> CompiledPolicy:
        defaults: dict[str, Any] = {"default": "allow"}
        if unresolved is not None:
            defaults["unresolved"] = unresolved
        return PolicyCompiler.compile(
            PolicySource.from_json(
                {
                    "policy_schema": 2,
                    "id": "acme/policy",
                    "version": 1,
                    "scope": ["acme"],
                    "rules": [],
                    "defaults": defaults,
                }
            )
        )

    @staticmethod
    def folder(root: Path, *, broken: bool) -> Path:
        folder = root / "skill"
        folder.mkdir()
        (folder / "SKILL.md").write_bytes(b"# skill\n")
        if broken:
            (folder / "link").symlink_to(root / "elsewhere")
        return folder

    @classmethod
    def resolutions(cls, root: Path, up: bool, *, broken_skill: bool) -> dict[str, Resolution]:
        sources = Sources(up)
        return {
            "ci_action": ActionResolver.resolve("actions/checkout@v4", sources),
            "mcp_server": McpResolver.resolve({"command": "npx", "args": ["-y", "tool"]}, sources),
            "agent_skill": SkillResolver.resolve(cls.folder(root, broken=broken_skill)),
        }

    @staticmethod
    def ask(found: Resolution, policy: CompiledPolicy, point: str = "firewall"):
        return PointRuntime.ask(
            point,
            found.artifact(),
            found.evidence(),
            policy,
            CLOCK,
            environment="production",
            scope_path=("acme",),
        )


class TestAnUnresolvedNameIsBlockedAtTheFirewall:
    def test_the_action_the_server_and_the_skill_each_give_r203_and_block(
        self, tmp_path: Path
    ) -> None:
        found = Kit.resolutions(tmp_path, up=False, broken_skill=True)
        assert {name: item.resolved for name, item in found.items()} == {
            "ci_action": False,
            "mcp_server": False,
            "agent_skill": False,
        }
        for name, item in found.items():
            decision = Kit.ask(item, Kit.policy())
            assert decision.state == "BLOCK", name
            assert "R203" in decision.reason_codes, name

    @pytest.mark.parametrize(
        "point",
        ["cli", "ide", "agent_hook", "firewall", "ci_gate", "deploy_admission", "inventory_sweep"],
    )
    def test_at_every_point_the_same(self, tmp_path: Path, point: str) -> None:
        found = Kit.resolutions(tmp_path, up=False, broken_skill=False)["ci_action"]
        decision = Kit.ask(found, Kit.policy(), point)
        assert decision.state == "BLOCK" and "R203" in decision.reason_codes

    def test_a_tenant_that_relaxed_it_gets_the_allow_and_the_relaxation_on_the_record(
        self, tmp_path: Path
    ) -> None:
        found = Kit.resolutions(tmp_path, up=False, broken_skill=False)["mcp_server"]
        decision = Kit.ask(found, Kit.policy(unresolved="warn"))
        assert decision.state == "ALLOW" and "R203" in decision.reason_codes
        assert decision.relaxations is not None
        assert any(item.code == "R203" for item in decision.relaxations)


class TestAResolvedNameIsDecidedAsBefore:
    def test_no_r203_when_the_source_answered(self, tmp_path: Path) -> None:
        found = Kit.resolutions(tmp_path, up=True, broken_skill=False)
        for name, item in found.items():
            assert item.resolved, name
            decision = Kit.ask(item, Kit.policy())
            assert "R203" not in decision.reason_codes, name
            assert decision.state == "ALLOW", name

    def test_a_source_that_comes_back_turns_the_block_into_the_allow(self, tmp_path: Path) -> None:
        sources = Sources(up=False)
        first = ActionResolver.resolve("actions/checkout@v4", sources)
        assert Kit.ask(first, Kit.policy()).state == "BLOCK"
        sources.up = True
        second = ActionResolver.resolve("actions/checkout@v4", sources)
        assert Kit.ask(second, Kit.policy()).state == "ALLOW"
