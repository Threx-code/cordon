"""`policy pull`: its refusals before any request, the https-only fetch, and what a refused answer prints (`cli/commands/policy.py`)."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.cli.commands.policy import PolicyCommand
from cordon_scanner.cloud.local_store import LocalStore
from cordon_scanner.foundation.errors import ConfigError, ExitCode

ROOT = "ab" * 32


class _Base:
    @staticmethod
    def args(tmp_path: Path, **over: Any) -> argparse.Namespace:
        delegation = tmp_path / "delegation.json"
        if not delegation.exists():
            delegation.write_text(json.dumps({"keys": []}), encoding="utf-8")
        base: dict[str, Any] = {
            "policy_command": "pull",
            "url": "https://store.example.invalid/bundles",
            "root": ROOT,
            "delegation": str(delegation),
            "tenant": "t1",
            "store": str(tmp_path / "store"),
            "replace_root": False,
        }
        return argparse.Namespace(**{**base, **over})


class _Answer:
    """What `opener.open` returns: a status, headers and a readable body."""

    def __init__(self, body: bytes) -> None:
        self.status = 200
        self.headers = {"ETag": '"x"'}
        self._body = body

    def __enter__(self) -> _Answer:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        return self._body


class TestRefusals(_Base):
    def test_anything_but_pull_asks_for_pull(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = PolicyCommand.run(self.args(tmp_path, policy_command=None))
        assert code == int(ExitCode.CONFIG_ERROR)
        assert "policy needs pull" in capsys.readouterr().err

    def test_a_root_that_is_not_hex_is_a_config_error(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="could not be read"):
            PolicyCommand.run(self.args(tmp_path, root="zz"))

    def test_a_missing_delegation_file_is_a_config_error(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="could not be read"):
            PolicyCommand.run(self.args(tmp_path, delegation=str(tmp_path / "none.json")))

    def test_a_root_of_the_wrong_length_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="32 bytes"):
            PolicyCommand.run(self.args(tmp_path, root="ab" * 16))

    def test_a_store_that_trusts_another_root_is_not_changed_without_replace_root(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        LocalStore(tmp_path / "store").put_blob("pin", "root", b"\x01" * 32, "2026-01-01T00:00:00")
        code = PolicyCommand.run(self.args(tmp_path), fetch=lambda url, headers: (500, {}, b""))
        assert code == int(ExitCode.CONFIG_ERROR)
        assert "trusts another root key; pass --replace-root" in capsys.readouterr().err

    def test_an_answer_that_is_not_json_keeps_the_held_bundle(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = PolicyCommand.run(
            self.args(tmp_path), fetch=lambda url, headers: (200, {}, b"<html>")
        )
        assert code == int(ExitCode.CONFIG_ERROR)
        out = capsys.readouterr().out
        assert "bundle not taken" in out
        assert "the bundle held is kept" in out


class TestFetch:
    def test_a_store_that_is_not_https_is_refused_before_any_request(self) -> None:
        with pytest.raises(ConfigError, match="https address"):
            PolicyCommand.fetch("http://store.example.invalid/b", {})

    def test_the_status_headers_and_body_of_the_answer_come_back(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[urllib.request.Request] = []

        class Opener:
            def open(self, request: urllib.request.Request, timeout: float) -> _Answer:
                seen.append(request)
                return _Answer(b"body")

        monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: Opener())
        status, headers, body = PolicyCommand.fetch("https://s.example.invalid/b", {"X-A": "1"})
        assert (status, headers["ETag"], body) == (200, '"x"', b"body")
        assert seen[0].get_header("X-a") == "1"
        assert seen[0].get_method() == "GET"

    def test_an_http_error_is_an_answer_with_its_status_and_no_body(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        headers = Message()
        headers["ETag"] = '"e"'

        class Opener:
            def open(self, request: urllib.request.Request, timeout: float) -> _Answer:
                raise urllib.error.HTTPError(request.full_url, 304, "Not Modified", headers, None)

        monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: Opener())
        assert PolicyCommand.fetch("https://s.example.invalid/b", {}) == (
            304,
            {"ETag": '"e"'},
            b"",
        )
