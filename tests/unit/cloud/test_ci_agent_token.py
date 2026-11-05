"""A CI agent program asked for an OIDC token (`cloud/ci_agent_token`)."""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from cordon_scanner.cloud import ci_agent_token
from cordon_scanner.cloud.ci_agent_token import CiAgentToken


class TestCiAgentToken:
    @staticmethod
    def _run(monkeypatch: pytest.MonkeyPatch, *, stdout: str = "", code: int = 0) -> list[Any]:
        calls: list[Any] = []
        monkeypatch.setattr(ci_agent_token.shutil, "which", lambda name: f"/bin/{name}")

        def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, code, stdout=stdout, stderr="")

        monkeypatch.setattr(ci_agent_token.subprocess, "run", run)
        return calls

    def test_no_agent_on_the_path_gives_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ci_agent_token.shutil, "which", lambda name: None)
        assert CiAgentToken.request(["circleci", "run", "oidc", "get"]) is None

    def test_a_token_is_returned_and_the_arguments_are_fixed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = self._run(monkeypatch, stdout="a.b.c\n")
        assert CiAgentToken.request(["buildkite-agent", "oidc", "request-token"]) == "a.b.c"
        ((argv, kwargs),) = calls
        assert argv == ["/bin/buildkite-agent", "oidc", "request-token"]
        assert kwargs.get("shell") is None and kwargs["timeout"] == 60

    @pytest.mark.parametrize(("stdout", "code"), [("a.b.c", 1), ("not-a-token", 0), ("", 0)])
    def test_a_failure_or_a_non_token_gives_none(
        self, monkeypatch: pytest.MonkeyPatch, stdout: str, code: int
    ) -> None:
        self._run(monkeypatch, stdout=stdout, code=code)
        assert CiAgentToken.request(["circleci", "run", "oidc", "get"]) is None

    def test_an_agent_that_cannot_run_gives_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ci_agent_token.shutil, "which", lambda name: f"/bin/{name}")

        def run(*args: Any, **kwargs: Any) -> None:
            raise subprocess.TimeoutExpired("circleci", 60)

        monkeypatch.setattr(ci_agent_token.subprocess, "run", run)
        assert CiAgentToken.request(["circleci"]) is None
