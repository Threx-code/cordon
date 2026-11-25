"""`agent hook` reads an agent's PreToolUse input and answers in the agent's form; it fails closed."""

from __future__ import annotations

import argparse
import io
import json
from datetime import timedelta
from pathlib import Path
from typing import Any, ClassVar

from cordon_scanner.cli.commands.decision.agent_hook import AgentHookCommand
from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.intel.base import PackageArchive
from kits.bundle_kit import T0, Kit, Platform
from unit.cli.test_policy_pull import Pull, Site
from unit.contracts.test_agent_hook import DENY, Scan, World


class Run:
    @staticmethod
    def hook(
        text: str,
        tmp_path: Path | None = None,
        category: str | None = None,
        store_dir: Path | None = None,
        minutes: int = 5,
        archive: Any = None,
    ) -> tuple[int, dict[str, Any], str]:
        out, err = io.StringIO(), io.StringIO()
        runtime = None
        if tmp_path is not None:
            scan = Scan()
            if category is not None:
                scan.category = category
            runtime = World.build(tmp_path, scan, DENY)
        code = AgentHookCommand.run(
            argparse.Namespace(),
            io.StringIO(text),
            out,
            err,
            runtime=runtime,
            clock=T0 + timedelta(minutes=minutes),
            store_dir=store_dir,
            archive=archive,
        )
        return code, json.loads(out.getvalue()), err.getvalue()

    @staticmethod
    def permission(answer: dict[str, Any]) -> str:
        return str(answer["hookSpecificOutput"]["permissionDecision"])


class TestTheHookAnswersInTheAgentsForm:
    def test_a_call_that_is_not_gated_is_allowed_without_a_runtime(self) -> None:
        text = json.dumps(World.hook("Read", file_path="README.md"))
        code, answer, _ = Run.hook(text)
        assert code == 0 and Run.permission(answer) == "allow", answer

    def test_a_gated_call_on_a_device_with_no_runtime_is_denied_with_the_way_out(
        self, tmp_path: Path
    ) -> None:
        text = json.dumps(World.hook("Bash", command="npm install left-pad@1.3.0"))
        code, answer, _ = Run.hook(text, store_dir=tmp_path / "never-pulled")
        assert code == 0 and Run.permission(answer) == "deny"
        assert "policy pull" in answer["hookSpecificOutput"]["permissionDecisionReason"]

    def test_a_gated_call_the_policy_blocks_is_denied_with_its_reason(self, tmp_path: Path) -> None:
        text = json.dumps(World.hook("Bash", command="npm install left-pad@1.3.0"))
        code, answer, _ = Run.hook(text, tmp_path, category="suspicious")
        assert code == 0 and Run.permission(answer) == "deny"
        assert (
            "Cordon denied this install" in answer["hookSpecificOutput"]["permissionDecisionReason"]
        )

    def test_a_gated_call_the_policy_allows_is_allowed(self, tmp_path: Path) -> None:
        text = json.dumps(World.hook("Bash", command="npm install left-pad@1.3.0"))
        code, answer, _ = Run.hook(text, tmp_path)
        assert code == 0 and Run.permission(answer) == "allow", answer


class TestItFailsClosed:
    def test_input_that_is_not_json_is_refused_with_exit_two(self) -> None:
        code, answer, err = Run.hook("not json")
        assert code == 2 and Run.permission(answer) == "deny" and "unreadable" in err

    def test_input_that_is_not_an_object_is_refused(self) -> None:
        code, answer, _ = Run.hook("[1, 2]")
        assert code == 2 and Run.permission(answer) == "deny"

    def test_empty_input_is_refused(self) -> None:
        assert Run.hook("")[0] == 2


class Registry:
    """The registry as the hook's package resolver sees it: a stand-in that records what was asked and never touches a network."""

    asked: ClassVar[list[tuple[str, str, str | None]]] = []

    @classmethod
    def online(cls, ecosystem: str, name: str, version: str | None) -> PackageArchive:
        cls.asked.append((ecosystem, name, version))
        return PackageArchive(
            ecosystem, name, version or "9.9.9", "x.tgz", b"bytes of " + name.encode()
        )

    @staticmethod
    def offline(ecosystem: str, name: str, version: str | None) -> PackageArchive:
        raise OSError("no route to the registry")


class TestAPulledStoreAnswersThroughTheHook:
    """`policy pull` leaves a store the hook opens: the pinned root, the delegation, the tenant and the verified bundle."""

    @staticmethod
    def pulled(tmp_path: Path, deny_digest: str | None = None) -> Path:
        platform = Platform()
        rules: list[dict[str, Any]] = [
            {
                "id": "no-commands",
                "tier": "deny",
                "then": "block",
                "reason": "R401",
                "when": {"subject.kind": "agent"},
            }
        ]
        if deny_digest is not None:
            rules.append(
                {
                    "id": "known-bad",
                    "tier": "deny",
                    "then": "block",
                    "reason": "R401",
                    "when": {"artifact.digest": deny_digest},
                }
            )
        policy = Kit.compiled(
            1, T0 + timedelta(days=2), default="allow", on_incomplete={"*": "warn"}, rules=rules
        )
        envelope = platform.publish(policy, issued=T0, expires=T0 + timedelta(days=2))
        assert Pull.run(tmp_path, platform, Site([envelope])) == 0
        return tmp_path / "store"

    def test_a_call_that_is_not_gated_is_allowed_on_a_pulled_store(self, tmp_path: Path) -> None:
        store = self.pulled(tmp_path)
        text = json.dumps(World.hook("Read", file_path="README.md"))
        code, answer, _ = Run.hook(text, store_dir=store, minutes=70)
        assert code == 0 and Run.permission(answer) == "allow"

    def test_an_install_whose_name_cannot_be_resolved_is_refused_by_the_decision_function(
        self, tmp_path: Path
    ) -> None:
        """Offline the registry cannot be asked, and the decision function refuses a subject it cannot resolve (R203)."""
        store = self.pulled(tmp_path)
        text = json.dumps(World.hook("Bash", command="npm install left-pad@1.3.0"))
        code, answer, _ = Run.hook(text, store_dir=store, minutes=70, archive=Registry.offline)
        reason = answer["hookSpecificOutput"]["permissionDecisionReason"]
        assert code == 0 and Run.permission(answer) == "deny" and "R203" in reason

    def test_an_install_the_registry_resolves_is_decided_on_its_digest_and_allowed(
        self, tmp_path: Path
    ) -> None:
        store = self.pulled(tmp_path)
        text = json.dumps(World.hook("Bash", command="npm install left-pad@1.3.0"))
        code, answer, _ = Run.hook(text, store_dir=store, minutes=70, archive=Registry.online)
        assert code == 0 and Run.permission(answer) == "allow"
        assert Registry.asked == [("npm", "left-pad", "1.3.0")]

    def test_a_digest_the_policy_denies_is_denied_once_the_name_resolves(
        self, tmp_path: Path
    ) -> None:
        store = self.pulled(tmp_path, deny_digest=ArtifactDigests.of_bytes(b"bytes of evil-pkg"))
        text = json.dumps(World.hook("Bash", command="pip install evil-pkg==2.0"))
        code, answer, _ = Run.hook(text, store_dir=store, minutes=70, archive=Registry.online)
        assert code == 0 and Run.permission(answer) == "deny"
        assert Registry.asked[-1] == ("pypi", "evil-pkg", "2.0")

    def test_a_command_is_denied_on_a_pulled_store(self, tmp_path: Path) -> None:
        store = self.pulled(tmp_path)
        text = json.dumps(World.hook("Bash", command="rm -rf build"))
        code, answer, _ = Run.hook(text, store_dir=store, minutes=70)
        assert code == 0 and Run.permission(answer) == "deny"

    def test_a_store_that_holds_a_bundle_but_no_pin_has_no_runtime(self, tmp_path: Path) -> None:
        text = json.dumps(World.hook("Bash", command="npm install left-pad@1.3.0"))
        _, answer, _ = Run.hook(text, store_dir=tmp_path)
        assert Run.permission(answer) == "deny"
