"""`agent inventory | report | mcp-approve | hook`: what is printed, sent and recorded, and which exit code
a refused report or an unreadable server gives (`cli/commands/agent.py`)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.cli.commands.agent import AgentCommand
from cordon_scanner.cloud import CloudError, device
from cordon_scanner.cloud.agent.report_queue import ReportQueue
from cordon_scanner.cloud.device_attestation import DeviceAttestation
from cordon_scanner.foundation.errors import CordonError, ExitCode
from cordon_scanner.intel.store.live_mcp import LiveMcp, LiveMcpError, ServedTool

PAYLOAD: dict[str, Any] = {
    "inventory": {
        "tools": [{"name": "claude"}, {"name": "cursor"}],
        "mcp_servers": [{"name": "x"}],
    },
    "findings": [{"rule_id": "R1"}],
}


class _Base:
    @staticmethod
    def run(action: str | None, **over: Any) -> int:
        base: dict[str, Any] = {"agent_command": action, "url": None, "signed": False}
        return AgentCommand.run(argparse.Namespace(**{**base, **over}))

    @pytest.fixture(autouse=True)
    def _device(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("CORDON_CONFIG_DIR", str(tmp_path / "config"))
        monkeypatch.setattr(
            device.DeviceInventory,
            "collect",
            staticmethod(lambda collection=None, verify_extensions=False: PAYLOAD),
        )


run = _Base.run


class TestInventoryAndReport(_Base):
    def test_a_missing_or_unknown_action_is_a_config_error(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert run(None) == int(ExitCode.CONFIG_ERROR)
        assert run("destroy") == int(ExitCode.CONFIG_ERROR)
        assert "agent needs inventory, report or mcp-approve" in capsys.readouterr().err

    def test_the_inventory_is_printed_exactly_as_it_would_be_sent(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert run("inventory") == int(ExitCode.CLEAN)
        assert json.loads(capsys.readouterr().out) == PAYLOAD

    def test_a_signed_inventory_prints_the_envelope_or_says_why_there_is_none(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(
            DeviceAttestation,
            "signed",
            staticmethod(lambda payload, url: {"signed": True, "url": url}),
        )
        assert run("inventory", signed=True, url="https://cloud.example.invalid") == int(
            ExitCode.CLEAN
        )
        assert json.loads(capsys.readouterr().out) == {
            "signed": True,
            "url": "https://cloud.example.invalid",
        }

        def refuse(payload: Any, url: Any) -> Any:
            raise CloudError("no device key")

        monkeypatch.setattr(DeviceAttestation, "signed", staticmethod(refuse))
        assert run("inventory", signed=True) == int(ExitCode.CONFIG_ERROR)
        captured = capsys.readouterr()
        assert captured.out == "" and "no device key" in captured.err

    def test_a_sent_report_says_how_much_was_sent_and_the_receipt(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(
            device.DeviceInventory, "report", staticmethod(lambda payload, url, store: "r-42")
        )
        assert run("report") == int(ExitCode.CLEAN)
        assert (
            capsys.readouterr().out
            == "sent: 2 tool(s), 1 MCP server(s), 1 finding(s) (receipt r-42)\n"
        )
        monkeypatch.setattr(
            device.DeviceInventory, "report", staticmethod(lambda payload, url, store: "")
        )
        run("report")
        assert capsys.readouterr().out == "sent: 2 tool(s), 1 MCP server(s), 1 finding(s)\n"

    def test_a_report_the_cloud_could_not_take_is_queued_for_the_next_run(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(
            device.DeviceInventory,
            "report",
            staticmethod(lambda payload, url, store: ReportQueue.QUEUED),
        )
        assert run("report") == int(ExitCode.CLEAN)
        assert "the report is queued and goes first next run" in capsys.readouterr().out

    def test_a_refused_report_is_a_config_error_with_the_clouds_words(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        def refuse(payload: Any, url: Any, store: Any) -> str:
            raise CloudError("device token missing")

        monkeypatch.setattr(device.DeviceInventory, "report", staticmethod(refuse))
        assert run("report") == int(ExitCode.CONFIG_ERROR)
        assert "device token missing" in capsys.readouterr().err

    def test_the_hook_action_goes_to_the_agent_hook_command(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.cli.commands.decision.agent_hook import AgentHookCommand

        monkeypatch.setattr(AgentHookCommand, "run", classmethod(lambda cls, args: 31))
        assert run("hook") == 31


class TestApproveMcp(_Base):
    @staticmethod
    def _repo(tmp_path: Path, servers: dict[str, Any]) -> Path:
        (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
        return tmp_path

    @staticmethod
    def _tools(monkeypatch: pytest.MonkeyPatch, answers: dict[str, Any]) -> list[str]:
        asked: list[str] = []

        def tools(url: str) -> Any:
            asked.append(url)
            answer = answers[url]
            if isinstance(answer, Exception):
                raise answer
            return answer

        monkeypatch.setattr(LiveMcp, "tools", staticmethod(tools))
        return asked

    def test_each_remote_servers_tools_are_recorded_once_and_written_for_review(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = self._repo(
            tmp_path,
            {
                "docs": {"url": "https://docs.example.invalid/mcp"},
                "local": {"command": "node", "args": ["server.js"]},
            },
        )
        (root / "README.md").write_text("see https://x.example.invalid/mcp", encoding="utf-8")
        tool = ServedTool.of({"name": "search", "description": "find pages"})
        asked = self._tools(monkeypatch, {"https://docs.example.invalid/mcp": [tool]})
        assert run("mcp-approve", target=str(root)) == int(ExitCode.CLEAN)
        assert asked == ["https://docs.example.invalid/mcp"], "a local server is never contacted"
        out = capsys.readouterr().out
        assert "docs: 1 tool(s) recorded from https://docs.example.invalid/mcp" in out
        assert "commit it, so a reviewer sees what was approved" in out
        written = json.loads((root / ".cordon" / "mcp-tools.json").read_text(encoding="utf-8"))
        assert list(written["servers"]) == ["docs"]
        assert written["servers"]["docs"]["tools"]["search"]["fingerprint"] == tool.fingerprint

    def test_a_server_that_cannot_be_read_fails_the_run_but_the_others_are_recorded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = self._repo(
            tmp_path,
            {
                "a": {"url": "https://a.example.invalid/mcp"},
                "b": {"url": "https://b.example.invalid/mcp"},
            },
        )
        self._tools(
            monkeypatch,
            {
                "https://a.example.invalid/mcp": LiveMcpError("401 unauthorised"),
                "https://b.example.invalid/mcp": [ServedTool.of({"name": "t"})],
            },
        )
        assert run("mcp-approve", target=str(root)) == int(ExitCode.SCANNER_ERROR)
        captured = capsys.readouterr()
        assert "a (https://a.example.invalid/mcp) not read: 401 unauthorised" in captured.err
        assert "b: 1 tool(s) recorded" in captured.out
        written = json.loads((root / ".cordon" / "mcp-tools.json").read_text(encoding="utf-8"))
        assert list(written["servers"]) == ["b"]

    def test_with_nothing_remote_nothing_is_recorded_and_no_file_is_written(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = self._repo(tmp_path, {"local": {"command": "node"}})
        self._tools(monkeypatch, {})
        assert run("mcp-approve", target=str(root)) == int(ExitCode.CLEAN)
        assert "no remote MCP server was read; nothing recorded" in capsys.readouterr().err
        assert not (root / ".cordon").exists()

    def test_when_every_remote_server_fails_the_exit_code_says_so(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = self._repo(tmp_path, {"a": {"url": "https://a.example.invalid/mcp"}})
        self._tools(monkeypatch, {"https://a.example.invalid/mcp": LiveMcpError("down")})
        assert run("mcp-approve", target=str(root)) == int(ExitCode.SCANNER_ERROR)

    def test_a_config_that_cannot_be_read_is_skipped_and_a_non_directory_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / ".mcp.json").write_bytes(b"\xff\xfe not utf-8")
        self._tools(monkeypatch, {})
        assert run("mcp-approve", target=str(tmp_path)) == int(ExitCode.CLEAN)
        with pytest.raises(CordonError, match="needs a repository directory"):
            run("mcp-approve", target=str(tmp_path / "missing"))

    def test_the_same_server_name_in_two_files_is_asked_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = self._repo(tmp_path, {"docs": {"url": "https://docs.example.invalid/mcp"}})
        (root / ".cursor").mkdir()
        (root / ".cursor" / "mcp.json").write_text(
            json.dumps({"mcpServers": {"docs": {"url": "https://other.example.invalid/mcp"}}}),
            encoding="utf-8",
        )
        asked = self._tools(
            monkeypatch,
            {"https://docs.example.invalid/mcp": [], "https://other.example.invalid/mcp": []},
        )
        run("mcp-approve", target=str(root))
        assert len(asked) == 1
