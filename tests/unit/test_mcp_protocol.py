"""The MCP server's protocol layer (`mcp/server`): both eras, errors, cancellation, rate limits."""

from __future__ import annotations

import base64
import io
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.mcp.runner import Cancelled, CancelToken, Runner, TimedOut
from cordon_scanner.mcp.server import LEGACY, MODERN, Server
from cordon_scanner.mcp.tools import TOOLS, Args, Outcome, Settings, Tool, ToolError
from cordon_scanner.mcp.workspace import Workspace

MODERN_META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"},
}


class Wire:
    """A server with its stdout captured, fed one message at a time."""

    def __init__(self, tmp_path: Path, **kwargs: Any) -> None:
        self.out = io.StringIO()
        settings = Settings(
            workspace=Workspace((tmp_path.resolve(),)),
            runner=Runner(offline=True),
            version="9.9.9",
            allow_online=kwargs.pop("allow_online", False),
            allow_machine=kwargs.pop("allow_machine", False),
        )
        self.server = Server(
            settings,
            workers=kwargs.pop("workers", 2),
            rate=kwargs.pop("rate", 1000),
            burst=kwargs.pop("burst", 100),
            audit=kwargs.pop("audit", None),
            out=self.out,
        )

    def send(self, message: Any) -> None:
        self.server.receive(json.dumps(message))

    def replies(self) -> list[dict[str, Any]]:
        self.server.pool.shutdown(wait=True)
        return [json.loads(line) for line in self.out.getvalue().splitlines()]

    def ask(self, message: dict[str, Any]) -> dict[str, Any]:
        before = len(self.out.getvalue().splitlines())
        self.send(message)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            lines = self.out.getvalue().splitlines()
            if len(lines) > before:
                return json.loads(lines[before])
            time.sleep(0.01)
        raise AssertionError("no reply")

    def initialize(self, version: str = "2025-11-25") -> dict[str, Any]:
        reply = self.ask(
            {
                "jsonrpc": "2.0",
                "id": "init",
                "method": "initialize",
                "params": {
                    "protocolVersion": version,
                    "capabilities": {},
                    "clientInfo": {"name": "t", "version": "1"},
                },
            }
        )
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return reply


class TestModernEra:
    def test_discover_lists_every_supported_version_and_identity(self, tmp_path: Path) -> None:
        reply = Wire(tmp_path).ask(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "server/discover",
                "params": {"_meta": MODERN_META},
            }
        )
        result = reply["result"]
        assert result["resultType"] == "complete"
        assert result["supportedVersions"] == [*MODERN, *LEGACY]
        assert result["capabilities"] == {"tools": {"listChanged": False}}
        assert result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "cordon-scanner"
        assert "instructions" in result

    def test_an_unsupported_version_is_error_32022_listing_supported(self, tmp_path: Path) -> None:
        meta = {**MODERN_META, "io.modelcontextprotocol/protocolVersion": "1900-01-01"}
        reply = Wire(tmp_path).ask(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": meta}}
        )
        assert reply["error"]["code"] == -32022
        assert reply["error"]["data"] == {
            "supported": [*MODERN, *LEGACY],
            "requested": "1900-01-01",
        }

    def test_missing_client_capabilities_is_invalid_params(self, tmp_path: Path) -> None:
        meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
        reply = Wire(tmp_path).ask(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": meta}}
        )
        assert reply["error"]["code"] == -32602

    def test_modern_requests_need_no_handshake_and_carry_result_type(self, tmp_path: Path) -> None:
        reply = Wire(tmp_path).ask(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": MODERN_META}}
        )
        result = reply["result"]
        assert result["resultType"] == "complete"
        tool = next(t for t in result["tools"] if t["name"] == "check_package")
        assert tool["title"] and tool["outputSchema"]["required"]
        assert tool["annotations"]["readOnlyHint"] is True
        assert tool["annotations"]["destructiveHint"] is False


class TestLegacyEra:
    @pytest.mark.parametrize("version", LEGACY)
    def test_initialize_echoes_a_supported_version(self, tmp_path: Path, version: str) -> None:
        result = Wire(tmp_path).initialize(version)["result"]
        assert result["protocolVersion"] == version
        assert result["capabilities"] == {"tools": {"listChanged": False}}
        assert result["serverInfo"]["name"] == "cordon-scanner"

    def test_an_unknown_version_is_answered_with_the_latest_legacy_one(
        self, tmp_path: Path
    ) -> None:
        assert Wire(tmp_path).initialize("2099-01-01")["result"]["protocolVersion"] == LEGACY[0]

    def test_requests_before_initialize_are_refused_but_ping_answers(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path)
        assert (
            wire.ask({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["error"]["code"] == -32600
        )
        assert wire.ask({"jsonrpc": "2.0", "id": 2, "method": "ping"})["result"] == {}

    def test_2024_11_05_tools_carry_no_fields_that_version_lacks(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path)
        wire.initialize("2024-11-05")
        tools = wire.ask({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
        assert all(set(t) == {"name", "description", "inputSchema"} for t in tools)

    def test_2025_03_26_adds_annotations_but_not_output_schemas(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path)
        wire.initialize("2025-03-26")
        tool = wire.ask({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"][0]
        assert "annotations" in tool and "outputSchema" not in tool and "title" not in tool

    def test_structured_content_only_from_2025_06_18(self, tmp_path: Path) -> None:
        for version, expected in (("2025-03-26", False), ("2025-06-18", True)):
            wire = Wire(tmp_path)
            wire.initialize(version)
            reply = wire.ask(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "explain_rule",
                        "arguments": {"rule_id": "SUSPECT.DEPENDENCY.TYPOSQUAT.001"},
                    },
                }
            )
            assert ("structuredContent" in reply["result"]) is expected
            assert reply["result"]["content"][0]["type"] == "text"
            assert "resultType" not in reply["result"]


class TestJsonRpc:
    def test_malformed_json_is_a_parse_error(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path)
        wire.server.receive("{not json")
        assert wire.replies()[0]["error"]["code"] == -32700

    def test_unknown_method_is_32601(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path)
        wire.initialize()
        assert (
            wire.ask({"jsonrpc": "2.0", "id": 9, "method": "resources/list"})["error"]["code"]
            == -32601
        )

    def test_a_null_or_boolean_id_is_refused(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path)
        assert wire.ask({"jsonrpc": "2.0", "id": None, "method": "ping"})["error"]["code"] == -32600
        assert wire.ask({"jsonrpc": "2.0", "id": True, "method": "ping"})["error"]["code"] == -32600

    def test_notifications_get_no_answer(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path)
        wire.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        wire.send(
            {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 77}}
        )
        assert wire.replies() == []

    def test_a_batch_is_answered_element_by_element(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path)
        wire.server.receive(
            json.dumps(
                [
                    {"jsonrpc": "2.0", "id": 1, "method": "ping"},
                    {"jsonrpc": "2.0", "id": 2, "method": "ping"},
                ]
            )
        )
        assert sorted(r["id"] for r in wire.replies()) == [1, 2]

    def test_unknown_tool_is_a_protocol_error(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path)
        wire.initialize()
        reply = wire.ask(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "rm_rf", "arguments": {}},
            }
        )
        assert reply["error"]["code"] == -32602

    def test_bad_arguments_are_a_tool_error_the_model_can_correct(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path)
        wire.initialize()
        reply = wire.ask(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "check_package",
                    "arguments": {"ecosystem": "cobol", "name": "x"},
                },
            }
        )
        assert reply["result"]["isError"] is True
        assert "unsupported ecosystem" in reply["result"]["content"][0]["text"]

    def test_every_line_written_is_one_json_message(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path)
        wire.initialize()
        wire.ask({"jsonrpc": "2.0", "id": 4, "method": "tools/list"})
        for line in wire.out.getvalue().splitlines():
            assert json.loads(line)["jsonrpc"] == "2.0"


class Slow:
    """A tool that waits until cancelled, to test cancellation."""

    started = threading.Event()

    @classmethod
    def handler(cls, settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        cls.started.set()
        while not token.cancelled:
            time.sleep(0.01)
        raise Cancelled


class TestConcurrency:
    def test_a_cancelled_call_sends_nothing_and_others_still_answer(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path)
        wire.initialize()
        wire.server.registry.tools["slow"] = Tool(
            "slow", "Slow", "waits", {"type": "object"}, Slow.handler
        )
        wire.send(
            {
                "jsonrpc": "2.0",
                "id": "long",
                "method": "tools/call",
                "params": {"name": "slow", "arguments": {}},
            }
        )
        assert Slow.started.wait(10)
        assert wire.ask({"jsonrpc": "2.0", "id": "quick", "method": "ping"})["result"] == {}
        wire.send(
            {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": "long"}}
        )
        ids = [r.get("id") for r in wire.replies()]
        assert "long" not in ids and "quick" in ids

    def test_tool_calls_past_the_rate_are_tool_errors(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path, rate=1, burst=1)
        wire.initialize()
        call = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "search_rules", "arguments": {"limit": 1}},
        }
        first = wire.ask({**call, "id": 1})
        second = wire.ask({**call, "id": 2})
        assert first["result"]["isError"] is False
        assert (
            second["result"]["isError"] is True
            and "retry in" in second["result"]["content"][0]["text"]
        )


class TestToolCatalogue:
    def test_names_follow_the_specification_and_are_unique(self) -> None:
        names = [t.name for t in TOOLS]
        assert len(names) == len(set(names))
        for name in names:
            assert 1 <= len(name) <= 128 and all(c.isalnum() or c in "_-." for c in name)

    def test_every_tool_is_read_only_with_an_object_input_schema(self) -> None:
        for tool in TOOLS:
            definition = tool.definition("2025-11-25")
            assert definition["inputSchema"]["type"] == "object"
            assert definition["annotations"]["readOnlyHint"] is True
            assert definition["annotations"]["destructiveHint"] is False
            assert len(tool.description) >= 60, tool.name

    def test_flagged_tools_are_hidden_until_the_server_allows_them(self, tmp_path: Path) -> None:
        off = {t.name for t in Wire(tmp_path).server.registry.tools.values()}
        on = {
            t.name
            for t in Wire(
                tmp_path, allow_online=True, allow_machine=True
            ).server.registry.tools.values()
        }
        assert {"scan_container_image", "list_local_agents", "scan_machine"} <= on - off
        assert on == {t.name for t in TOOLS}

    def test_the_audit_log_records_tool_and_verdict_never_arguments(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        wire = Wire(tmp_path, audit=log)
        wire.initialize()
        wire.ask(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "check_agent_file",
                    "arguments": {"path": "AGENTS.md", "content": "secret-marker-7731"},
                },
            }
        )
        entry = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
        assert entry["tool"] == "check_agent_file" and set(entry) == {
            "time",
            "tool",
            "error",
            "verdict",
            "seconds",
        }
        assert "secret-marker-7731" not in log.read_text(encoding="utf-8")


class TestHostileClients:
    def test_json_nested_past_the_parser_is_answered_not_fatal(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path)
        wire.server.receive("[" * 100_000 + "]" * 100_000)
        assert wire.replies()[0]["error"]["code"] == -32700

    def test_a_running_id_cannot_be_reused(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path)
        wire.initialize()
        wire.server.registry.tools["slow"] = Tool(
            "slow", "Slow", "waits", {"type": "object"}, Slow.handler
        )
        Slow.started.clear()
        call = {
            "jsonrpc": "2.0",
            "id": "same",
            "method": "tools/call",
            "params": {"name": "slow", "arguments": {}},
        }
        wire.send(call)
        assert Slow.started.wait(10)
        reply = wire.ask(call)
        assert reply["error"]["code"] == -32600
        wire.send(
            {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": "same"}}
        )
        wire.replies()

    def test_calls_past_the_queue_bound_are_answered_busy(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path, workers=1)
        wire.initialize()
        wire.server.registry.tools["slow"] = Tool(
            "slow", "Slow", "waits", {"type": "object"}, Slow.handler
        )
        for index in range(wire.server.max_pending):
            wire.send(
                {
                    "jsonrpc": "2.0",
                    "id": index,
                    "method": "tools/call",
                    "params": {"name": "slow", "arguments": {}},
                }
            )
        reply = wire.ask(
            {
                "jsonrpc": "2.0",
                "id": "extra",
                "method": "tools/call",
                "params": {"name": "slow", "arguments": {}},
            }
        )
        assert (
            reply["result"]["isError"] is True and "retry" in reply["result"]["content"][0]["text"]
        )
        for index in range(wire.server.max_pending):
            wire.send(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {"requestId": index},
                }
            )
        wire.replies()


class TestContentPaths:
    @pytest.mark.parametrize(
        "path",
        ["C:/Windows/x", "a:b", "NUL", "con.txt", "dir/COM1.log", "trailing.", "space ", "../x",
         "/etc/passwd", "a\\b", "~/x", "a//b", "tab\there", "x?y"],
    )  # fmt: skip
    def test_unusable_paths_are_refused(self, path: str) -> None:
        with pytest.raises(ToolError):
            Args.relative(path)

    @pytest.mark.parametrize(
        "path", ["AGENTS.md", ".github/workflows/ci.yml", ".claude/skills/x/SKILL.md", "console.js"]
    )
    def test_ordinary_paths_pass(self, path: str) -> None:
        assert str(Args.relative(path)) == path


class Tree:
    """A child that starts a grandchild, both sleeping: what a scan's worker processes look like."""

    @staticmethod
    def ended(pid: int) -> bool:
        """Gone, or a zombie: ended, and waiting only to be reaped by whoever adopted it (in a
        container whose first process reaps nothing, that is forever)."""
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        status = Path(f"/proc/{pid}/status")
        if status.exists():
            return "State:\tZ" in status.read_text(encoding="utf-8")
        return False

    SCRIPT = (
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)'])\n"
        "open(sys.argv[1], 'w').write(str(child.pid))\n"
        "time.sleep(600)\n"
    )


class TestTheRunnerEndsWhatItStarts:
    def test_a_deadline_ends_the_child_and_its_children(self, tmp_path: Path) -> None:
        marker = tmp_path / "grandchild.pid"
        runner = Runner(offline=True)
        runner.command = lambda args: [sys.executable, "-c", Tree.SCRIPT, str(marker)]  # type: ignore[method-assign]
        with pytest.raises(TimedOut):
            runner.run([], timeout=3, token=CancelToken())
        grandchild = int(marker.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if Tree.ended(grandchild):
                return
            time.sleep(0.1)
        pytest.fail("the grandchild outlived the deadline")


class TestTheMark:
    def test_the_server_shows_cordons_mark_from_2025_11_25(self, tmp_path: Path) -> None:
        info = Wire(tmp_path).initialize("2025-11-25")["result"]["serverInfo"]
        (icon,) = info["icons"]
        assert icon["mimeType"] == "image/svg+xml" and icon["src"].startswith(
            "data:image/svg+xml;base64,"
        )
        svg = base64.b64decode(icon["src"].split(",", 1)[1]).decode()
        assert svg.startswith("<svg") and "#1f7a6f" in svg and "#d9822b" in svg

    def test_older_versions_carry_no_field_they_lack(self, tmp_path: Path) -> None:
        assert "icons" not in Wire(tmp_path).initialize("2025-06-18")["result"]["serverInfo"]

    def test_modern_results_carry_it_in_server_info(self, tmp_path: Path) -> None:
        reply = Wire(tmp_path).ask(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "server/discover",
                "params": {"_meta": MODERN_META},
            }
        )
        assert reply["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["icons"]


class TestHardening:
    def test_a_spent_call_deadline_starts_no_scan(self) -> None:
        token = CancelToken()
        token.deadline = time.monotonic() - 1
        with pytest.raises(TimedOut):
            Runner(offline=True).run(["--version"], timeout=60, token=token)

    def test_a_client_that_goes_away_ends_the_running_scans(self, tmp_path: Path) -> None:
        class Gone(io.StringIO):
            def write(self, text: str) -> int:
                raise BrokenPipeError

        wire = Wire(tmp_path)
        wire.server.out = Gone()
        token = CancelToken()
        wire.server.inflight["running"] = token
        wire.server.send({"jsonrpc": "2.0", "id": 1, "result": {}})
        assert wire.server.closed and token.cancelled
        wire.server.send({"jsonrpc": "2.0", "id": 2, "result": {}})  # nothing raised

    @pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
    def test_the_audit_log_is_owner_only(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        wire = Wire(tmp_path, audit=log)
        wire.initialize()
        wire.ask(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "search_rules", "arguments": {"limit": 1}},
            }
        )
        assert log.stat().st_mode & 0o777 == 0o600

    def test_an_unwritable_audit_log_still_answers(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path, audit=tmp_path / "missing-dir" / "audit.jsonl")
        wire.initialize()
        reply = wire.ask(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "search_rules", "arguments": {"limit": 1}},
            }
        )
        assert reply["result"]["isError"] is False


class TestContainerLaunches:
    @pytest.mark.parametrize(
        ("config", "image"),
        [
            (
                {"command": "docker", "args": ["run", "-i", "--rm", "-e", "TOKEN", "mcp/github"]},
                "mcp/github",
            ),
            (
                {"command": "/usr/bin/podman", "args": ["run", "--env=A=1", "ghcr.io/org/srv:1.2"]},
                "ghcr.io/org/srv:1.2",
            ),
            (
                {
                    "command": "docker",
                    "args": ["run", "-v", "/x:/y", "--network", "none", "img@sha256:" + "a" * 64],
                },
                "img@sha256:" + "a" * 64,
            ),
            ({"command": "docker", "args": ["ps"]}, None),
            ({"command": "npx", "args": ["-y", "pkg"]}, None),
        ],
    )
    def test_the_image_a_launch_runs(self, config: dict[str, Any], image: str | None) -> None:
        from cordon_scanner.mcp.tools import AgentTools

        assert AgentTools.container_image(config) == image
