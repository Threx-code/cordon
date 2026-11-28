"""The MCP server's refusals, oversized lines, empty batches and start-up checks (`mcp/server.py`)."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
from typing import Any

import pytest
from test_mcp_protocol import MODERN_META, Wire

from cordon_scanner.mcp import server
from cordon_scanner.mcp.runner import CancelToken
from cordon_scanner.mcp.server import INVALID_PARAMS, INVALID_REQUEST, Server
from cordon_scanner.mcp.tools.catalogue import TOOLS
from cordon_scanner.model.client import TOKEN_ENV


class _Base:
    @staticmethod
    def error_of(reply: dict[str, Any]) -> tuple[int, str]:
        return reply["error"]["code"], reply["error"]["message"]


class TestTransport(_Base):
    def test_a_line_larger_than_the_limit_is_answered_and_the_rest_of_it_discarded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(server, "MAX_LINE", 64)
        wire = Wire(tmp_path)
        ping = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}})
        stream = io.StringIO("x" * 300 + "\n" + ping + "\n")
        wire.server.serve(stream)
        replies = wire.replies()
        assert self.error_of(replies[0]) == (INVALID_REQUEST, "message larger than 32 MB")
        assert replies[1]["id"] == 1

    def test_a_message_that_makes_the_server_fail_is_answered_not_fatal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        wire = Wire(tmp_path)

        def broken(line: str) -> None:
            raise RuntimeError("boom")

        monkeypatch.setattr(wire.server, "receive", broken)
        wire.server.serve(io.StringIO('{"jsonrpc": "2.0"}\n'))
        [reply] = wire.replies()
        assert self.error_of(reply) == (-32603, "internal error")
        assert "could not handle a message: RuntimeError" in capsys.readouterr().err


class TestDispatch(_Base):
    def test_an_empty_batch_is_refused(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path)
        wire.send([])
        assert self.error_of(wire.replies()[0]) == (INVALID_REQUEST, "empty batch")

    def test_a_response_to_nothing_we_sent_is_ignored(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path)
        wire.send({"jsonrpc": "2.0", "id": 7, "result": {}})
        assert wire.replies() == []

    def test_params_that_are_not_an_object_are_refused(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path)
        reply = wire.ask({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": 5})
        assert self.error_of(reply) == (INVALID_PARAMS, "params must be an object")

    def test_server_discover_without_the_modern_version_in_meta_is_refused(
        self, tmp_path: Path
    ) -> None:
        wire = Wire(tmp_path)
        reply = wire.ask({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}})
        assert reply["error"]["code"] == INVALID_PARAMS
        assert "needs" in reply["error"]["message"]

    def test_a_modern_ping_is_an_empty_result(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path)
        reply = wire.ask(
            {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"_meta": MODERN_META}}
        )
        assert reply["result"].get("resultType") == "complete"

    def test_tool_arguments_that_are_not_an_object_are_refused(self, tmp_path: Path) -> None:
        wire = Wire(tmp_path)
        reply = wire.ask(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"_meta": MODERN_META, "name": TOOLS[0].name, "arguments": 5},
            }
        )
        assert self.error_of(reply) == (INVALID_PARAMS, "arguments must be an object")


class TestRespond(_Base):
    def test_a_request_whose_handler_fails_is_answered_with_an_internal_error_and_named_on_stderr(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        wire = Wire(tmp_path)

        def boom(method: str, params: Any, token: CancelToken) -> dict[str, Any]:
            raise RuntimeError("boom")

        monkeypatch.setattr(wire.server, "handle", boom)
        wire.server.respond(1, "tools/list", {}, CancelToken())
        [reply] = wire.replies()
        assert self.error_of(reply) == (-32603, "internal error")
        assert "internal error in tools/list: RuntimeError: boom" in capsys.readouterr().err

    def test_a_request_cancelled_before_it_answers_sends_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wire = Wire(tmp_path)
        token = CancelToken()

        def cancelled(method: str, params: Any, given: CancelToken) -> dict[str, Any]:
            given.cancel()
            return {"ok": True}

        monkeypatch.setattr(wire.server, "handle", cancelled)
        wire.server.respond(1, "ping", {}, token)
        assert wire.replies() == []

    def test_a_failure_after_cancelling_is_not_answered(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        wire = Wire(tmp_path)
        token = CancelToken()

        def fails(method: str, params: Any, given: CancelToken) -> dict[str, Any]:
            given.cancel()
            raise RuntimeError("late")

        monkeypatch.setattr(wire.server, "handle", fails)
        wire.server.respond(1, "ping", {}, token)
        assert wire.replies() == []


class TestStartUp(_Base):
    def test_arguments_out_of_range_are_named(self) -> None:
        args = argparse.Namespace(
            max_concurrent=0, rate=10, max_findings=10, timeout=5, per_file_timeout=None
        )
        assert "--max-concurrent 1-64" in str(Server.refused(args))

    def test_a_root_that_cannot_be_used_is_a_start_up_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = Server.main(["--root", str(tmp_path / "missing"), "--allow-private-network"])
        assert code == 3
        assert "cordon-scanner mcp:" in capsys.readouterr().err

    def test_a_model_address_that_is_not_https_is_a_start_up_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = Server.main(
            [
                "--root",
                str(tmp_path),
                "--allow-private-network",
                "--model",
                "ftp://models.example.invalid",
            ]
        )
        assert code == 3
        assert "--model:" in capsys.readouterr().err

    def test_a_valid_model_address_is_allowed_through_to_the_server_which_ends_with_its_input(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("sys.stdin", io.StringIO(""))
        monkeypatch.setenv(TOKEN_ENV, "test-token")
        code = Server.main(
            [
                "--root",
                str(tmp_path),
                "--allow-private-network",
                "--model",
                "https://models.example.invalid",
            ]
        )
        assert code == 0
