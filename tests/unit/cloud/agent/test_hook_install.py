"""The device inventory says, per agent product, whether Cordon's hook is installed: only when the agent's own hook configuration runs it."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cordon_scanner.cloud.agent.hook_install import HookInstall
from cordon_scanner.cloud.device import DeviceInventory


class Home:
    @staticmethod
    def settings(command: str, event: str = "PreToolUse") -> dict[str, Any]:
        return {
            "hooks": {
                event: [{"matcher": "Bash", "hooks": [{"type": "command", "command": command}]}]
            }
        }

    @staticmethod
    def write(home: Path, relative: str, document: dict[str, Any]) -> None:
        path = home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document), encoding="utf-8")

    @staticmethod
    def hooks(home: Path) -> dict[str, bool]:
        hooks: dict[str, bool] = DeviceInventory.collect(home)["inventory"]["hooks"]
        return hooks


class TestTheHookIsInstalledOnlyWhenTheAgentRunsIt:
    def test_a_claude_code_hook_that_runs_cordons_hook_is_installed(self, tmp_path: Path) -> None:
        Home.write(
            tmp_path,
            ".claude/settings.json",
            Home.settings("cordon-scanner agent hook --point agent_hook"),
        )
        assert Home.hooks(tmp_path) == {"claude-code": True}

    def test_an_agent_with_no_hook_configured_is_absent_not_missing(self, tmp_path: Path) -> None:
        Home.write(tmp_path, ".claude/settings.json", {"permissions": {}})
        Home.write(tmp_path, ".cursor/mcp.json", {"mcpServers": {}})
        assert Home.hooks(tmp_path) == {"claude-code": False, "cursor": False}

    def test_another_tools_hook_does_not_count(self, tmp_path: Path) -> None:
        Home.write(
            tmp_path, ".claude/settings.json", Home.settings("/usr/local/bin/other-guard --hook")
        )
        assert Home.hooks(tmp_path) == {"claude-code": False}

    def test_a_command_that_only_mentions_cordon_does_not_count(self, tmp_path: Path) -> None:
        Home.write(tmp_path, ".claude/settings.json", Home.settings("echo cordon-scanner hook"))
        assert Home.hooks(tmp_path) == {"claude-code": False}

    def test_the_hook_of_another_agent_is_told_apart(self, tmp_path: Path) -> None:
        Home.write(
            tmp_path,
            ".gemini/settings.json",
            Home.settings("/opt/bin/cordon-scanner hook", "BeforeTool"),
        )
        Home.write(tmp_path, ".claude/settings.json", {})
        assert Home.hooks(tmp_path) == {"claude-code": False, "gemini-cli": True}

    def test_products_that_are_not_agents_have_no_entry(self, tmp_path: Path) -> None:
        Home.write(tmp_path, ".claude/settings.json", Home.settings("cordon hook"))
        (tmp_path / ".npmrc").write_text("registry=https://registry.npmjs.org/\n", encoding="utf-8")
        assert set(Home.hooks(tmp_path)) == {"claude-code"}


class TestTheCommandReader:
    def test_the_program_and_its_hook_argument(self) -> None:
        assert HookInstall.runs_cordon("cordon-scanner agent hook")
        assert not HookInstall.runs_cordon("cordon-scanner scan .")
        assert not HookInstall.runs_cordon("")
        assert not HookInstall.runs_cordon(None)
        assert not HookInstall.runs_cordon("cordon-scanner 'unterminated")
