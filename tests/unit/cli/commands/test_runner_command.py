"""`runner`: what the command refuses before it starts polling, and the configuration it hands the runner (`cli/commands/runner.py`)."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.cli.commands.runner import RunnerCommand
from cordon_scanner.cloud import runner
from cordon_scanner.foundation.errors import ConfigError, ExitCode


class _Base:
    @staticmethod
    def args(**over: Any) -> argparse.Namespace:
        base: dict[str, Any] = {
            "url": "https://cloud.example.invalid",
            "allow_host": ["github.com"],
            "git_credential": [],
            "id": "runner-1",
            "label": [],
            "work_dir": None,
            "once": True,
            "make_fixes": False,
            "allow_online": False,
        }
        return argparse.Namespace(**{**base, **over})

    @pytest.fixture(autouse=True)
    def _token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CORDON_RUNNER_TOKEN", "tok")
        monkeypatch.delenv("GL_TOKEN", raising=False)

    @pytest.fixture
    def served(self, monkeypatch: pytest.MonkeyPatch) -> list[tuple[runner.RunnerConfig, bool]]:
        calls: list[tuple[runner.RunnerConfig, bool]] = []

        def serve(config: runner.RunnerConfig, *, once: bool = False, **_: Any) -> None:
            calls.append((config, once))

        monkeypatch.setattr(runner.CloudRunner, "serve", staticmethod(serve))
        return calls


class TestRefusals(_Base):
    def test_no_token_is_refused_with_the_environment_hint(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("CORDON_RUNNER_TOKEN")
        with pytest.raises(ConfigError, match="CORDON_RUNNER_TOKEN is not set"):
            RunnerCommand.run(self.args())

    def test_a_runner_with_no_allowed_host_is_refused(self) -> None:
        with pytest.raises(ConfigError, match="at least one --allow-host"):
            RunnerCommand.run(self.args(allow_host=[]))

    def test_a_cloud_url_that_is_not_https_is_refused(self) -> None:
        with pytest.raises(ConfigError, match="must be https"):
            RunnerCommand.run(self.args(url="http://cloud.example.invalid"))

    def test_a_credential_for_a_host_the_runner_may_not_clone_from_is_refused(self) -> None:
        with pytest.raises(ConfigError, match="not an --allow-host"):
            RunnerCommand.run(self.args(git_credential=["gitlab.com=GL_TOKEN"]))

    def test_a_credential_whose_variable_is_empty_is_refused(self) -> None:
        with pytest.raises(ConfigError, match="the environment variable GL_TOKEN is empty"):
            RunnerCommand.run(
                self.args(allow_host=["gitlab.com"], git_credential=["gitlab.com=GL_TOKEN"])
            )

    def test_a_credential_naming_no_variable_is_refused(self) -> None:
        with pytest.raises(ConfigError, match=r"\(none\) is empty"):
            RunnerCommand.run(self.args(git_credential=["github.com"]))


class TestServe(_Base):
    def test_the_configuration_carries_hosts_labels_credentials_and_switches(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        served: list[tuple[runner.RunnerConfig, bool]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setenv("GL_TOKEN", "glpat")
        code = RunnerCommand.run(
            self.args(
                allow_host=["GitLab.com", "github.com"],
                git_credential=["gitlab.com=GL_TOKEN"],
                label=["linux"],
                work_dir=str(tmp_path),
                make_fixes=True,
                allow_online=True,
            )
        )
        assert code == int(ExitCode.CLEAN)
        [(config, once)] = served
        assert once is True
        assert config.runner_id == "runner-1"
        assert config.allowed_hosts == frozenset({"gitlab.com", "github.com"})
        assert config.labels == ("linux",)
        assert config.work_dir == tmp_path
        assert config.git_credentials == (runner.CloudRunner.git_credential("gitlab.com", "glpat"),)
        assert config.make_fixes is True
        assert config.allow_online is True
        assert "runner runner-1 polling https://cloud.example.invalid" in capsys.readouterr().err

    def test_a_runner_with_no_id_is_named_by_its_host(
        self,
        monkeypatch: pytest.MonkeyPatch,
        served: list[tuple[runner.RunnerConfig, bool]],
    ) -> None:
        monkeypatch.setattr("socket.gethostname", lambda: "box-7")
        RunnerCommand.run(self.args(id=None))
        assert served[0][0].runner_id == "box-7"
        assert served[0][0].make_fixes is False
