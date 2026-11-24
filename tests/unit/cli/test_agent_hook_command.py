"""`agent hook` reads an agent's PreToolUse input and answers in the agent's form; it fails closed."""

from __future__ import annotations

import argparse
import io
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

from cordon_scanner.cli.commands.decision.agent_hook import AgentHookCommand
from kits.bundle_kit import T0
from unit.contracts.test_agent_hook import DENY, Scan, World


class Run:
    @staticmethod
    def hook(
        text: str, tmp_path: Path | None = None, category: str | None = None
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
            clock=T0 + timedelta(minutes=5),
        )
        return code, json.loads(out.getvalue()), err.getvalue()

    @staticmethod
    def permission(answer: dict[str, Any]) -> str:
        return str(answer["hookSpecificOutput"]["permissionDecision"])


class TestTheHookAnswersInTheAgentsForm:
    def test_a_call_that_is_not_gated_is_allowed_without_a_runtime(self) -> None:
        text = json.dumps(World.hook("Read", file_path="README.md"))
        code, answer, _ = Run.hook(text)
        assert code == 0 and Run.permission(answer) == "allow"

    def test_a_gated_call_on_a_device_with_no_runtime_is_denied_with_the_way_out(self) -> None:
        text = json.dumps(World.hook("Bash", command="npm install left-pad@1.3.0"))
        code, answer, _ = Run.hook(text)
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
        assert code == 0 and Run.permission(answer) == "allow"


class TestItFailsClosed:
    def test_input_that_is_not_json_is_refused_with_exit_two(self) -> None:
        code, answer, err = Run.hook("not json")
        assert code == 2 and Run.permission(answer) == "deny" and "unreadable" in err

    def test_input_that_is_not_an_object_is_refused(self) -> None:
        code, answer, _ = Run.hook("[1, 2]")
        assert code == 2 and Run.permission(answer) == "deny"

    def test_empty_input_is_refused(self) -> None:
        assert Run.hook("")[0] == 2
