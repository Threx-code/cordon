"""`notify test`: which channel it tries, what it refuses, and the exit code of a failed delivery (`cli/commands/notify.py`)."""

from __future__ import annotations

import argparse
from types import SimpleNamespace
from typing import Any

import pytest

from cordon_scanner.cli.commands.notify import NotifyCommand
from cordon_scanner.foundation.errors import ConfigError, ExitCode
from cordon_scanner.notify.notifier import Notifier


class _Base:
    @staticmethod
    def run(command: str | None = "test", channels: str | None = None, **over: Any) -> int:
        base: dict[str, Any] = {"config": None, "policy": None}
        return NotifyCommand.run(
            argparse.Namespace(notify_command=command, channels=channels, **{**base, **over})
        )

    @pytest.fixture
    def sent(self, monkeypatch: pytest.MonkeyPatch) -> list[Any]:
        """The channels each `send` was given; the deliveries it returns are set by the test."""
        calls: list[Any] = []
        self.answers: list[Any] = []

        def send(self_: Notifier, channels: Any, result: Any, **kwargs: Any) -> list[Any]:
            calls.append((channels, kwargs))
            return list(self.answers)

        monkeypatch.setattr(Notifier, "send", send)
        return calls


class TestRefusals(_Base):
    def test_anything_but_test_prints_usage(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert self.run(command=None) == int(ExitCode.CONFIG_ERROR)
        assert "notify test [CHANNELS]" in capsys.readouterr().err

    def test_no_channel_named_and_none_configured_is_refused(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        monkeypatch.chdir(tmp_path)
        with pytest.raises(ConfigError, match="no channel to test"):
            self.run()

    def test_a_channel_that_does_not_exist_is_a_config_error(self) -> None:
        with pytest.raises(ConfigError, match="notify channel"):
            self.run(channels="carrier-pigeon")


class TestDelivery(_Base):
    def test_every_channel_delivered_exits_clean_and_says_how_many_attempts(
        self, sent: list[Any], capsys: pytest.CaptureFixture[str]
    ) -> None:
        self.answers = [SimpleNamespace(channel="slack", ok=True, attempts=2, error="")]
        assert self.run(channels="slack") == int(ExitCode.CLEAN)
        assert "slack: delivered (2 attempt(s))" in capsys.readouterr().out
        [(channels, kwargs)] = sent
        assert channels == ("slack",)
        assert kwargs["test"] is True
        assert kwargs["gate"] == "passed"

    def test_a_channel_that_failed_is_named_with_its_error_and_the_exit_is_not_clean(
        self, sent: list[Any], capsys: pytest.CaptureFixture[str]
    ) -> None:
        self.answers = [
            SimpleNamespace(channel="slack", ok=True, attempts=1, error=""),
            SimpleNamespace(channel="teams", ok=False, attempts=3, error="403 forbidden"),
        ]
        assert self.run(channels="slack,teams") == int(ExitCode.FINDINGS)
        assert "teams: not delivered: 403 forbidden" in capsys.readouterr().out
