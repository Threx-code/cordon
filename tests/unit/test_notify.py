"""`--notify`: one message when the gate fails, from env-only URLs, never changing the exit code."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cordon_scanner import notify
from cordon_scanner.core.models import Repository, ScanResult
from cordon_scanner.notify import Notifier, Webhooks
from support import MALICIOUS, Support, requires_malicious_corpus

SECRET_TEXT = "ghp_" + "x" * 36


class NotifyHelpers:
    """Helpers for test_notify.py."""

    @staticmethod
    def _result(findings=None, **repo) -> ScanResult:
        findings = findings if findings is not None else (Support.a_finding(),)
        return ScanResult(
            findings=tuple(findings), repository=Repository(root="/work/acme-api", **repo)
        )


class _Recorder:
    def __init__(self, status: int = 200) -> None:
        self.calls: list[tuple[str, bytes, dict[str, str]]] = []
        self.status = status

    def __call__(self, url, body, headers):
        self.calls.append((url, body, dict(headers)))
        return self.status


ENV = {
    "CORDON_NOTIFY_WEBHOOK": "https://hooks.example.test/cordon",
    "CORDON_NOTIFY_WEBHOOK_SECRET": "s3cret",
    "CORDON_NOTIFY_SLACK": "https://hooks.slack.test/services/T/B/X",
    "CORDON_NOTIFY_TEAMS": "https://teams.example.test/workflows/1",
}


class TestChannels:
    def test_channels_are_parsed_in_a_fixed_order(self) -> None:
        assert Notifier.parse_channels("teams, slack,webhook") == ("webhook", "slack", "teams")

    def test_an_unknown_channel_is_refused(self) -> None:
        with pytest.raises(ValueError, match="discord"):
            Notifier.parse_channels("slack,discord")


class TestWebhook:
    def test_the_event_is_signed_and_verifies(self) -> None:
        sent = _Recorder()
        deliveries = Notifier(ENV, transport=sent, clock=lambda: 1_790_000_000).send(
            ["webhook"], NotifyHelpers._result(), reason="1 finding at high", exit_code=1
        )

        assert deliveries[0].ok
        _url, body, headers = sent.calls[0]
        assert headers["X-Cordon-Event"] == "scan.completed"
        assert headers["X-Cordon-Delivery"]
        assert Webhooks.verify("s3cret", headers["X-Cordon-Signature"], body, now=1_790_000_010)
        event = json.loads(body)
        assert event["schema"] == "cordon.event/v1"
        assert event["scan"]["gate"] == "failed"
        assert event["scan"]["target"] == "acme-api"

    def test_a_stale_or_tampered_signature_fails(self) -> None:
        body = b'{"a":1}'
        header = Webhooks.signature("s3cret", 1_000, body)
        assert not Webhooks.verify("s3cret", header, body, now=1_000 + 301)
        assert not Webhooks.verify("s3cret", header, b'{"a":2}', now=1_000)
        assert not Webhooks.verify("wrong", header, body, now=1_000)

    def test_it_is_refused_without_a_secret(self) -> None:
        env = {k: v for k, v in ENV.items() if k != "CORDON_NOTIFY_WEBHOOK_SECRET"}
        sent = _Recorder()
        [delivery] = Notifier(env, transport=sent).send(
            ["webhook"], NotifyHelpers._result(), reason="r", exit_code=1
        )

        assert not delivery.ok and "unsigned" in delivery.error
        assert sent.calls == []


class TestWhatIsSent:
    def test_no_message_or_evidence_leaves(self) -> None:
        finding = Support.a_finding(message=f"token {SECRET_TEXT} in config")
        sent = _Recorder()
        Notifier(ENV, transport=sent).send(
            ["webhook", "slack", "teams"], NotifyHelpers._result([finding]), reason="r", exit_code=1
        )

        for _url, body, _headers in sent.calls:
            assert SECRET_TEXT.encode() not in body
            assert b"in config" not in body

    def test_slack_and_teams_shapes(self) -> None:
        sent = _Recorder()
        Notifier(ENV, transport=sent).send(
            ["slack", "teams"], NotifyHelpers._result(), reason="r", exit_code=1
        )

        slack = json.loads(sent.calls[0][1])
        teams = json.loads(sent.calls[1][1])
        assert slack["text"].startswith("Cordon: acme-api failed its gate")
        assert teams["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"

    def test_long_lists_are_counted_not_listed(self) -> None:
        findings = [Support.a_finding(rule_id=f"TEST.RULE.{i:03d}") for i in range(25)]
        summary = notify.Summary.of(NotifyHelpers._result(findings), reason="r", exit_code=1)

        assert len(summary.listed) == notify.MAX_LISTED
        assert summary.lines()[-1] == "... and 15 more"

    def test_credentials_in_a_remote_are_not_the_target(self) -> None:
        summary = notify.Summary.of(
            NotifyHelpers._result(remote="https://user:pat@github.com/acme/api.git"),
            reason="r",
            exit_code=1,
        )
        assert summary.target == "github.com/acme/api"


class TestFailuresNeverRaise:
    @pytest.mark.parametrize(
        ("env", "error"),
        [
            ({}, "CORDON_NOTIFY_SLACK is not set"),
            ({"CORDON_NOTIFY_SLACK": "http://hooks.slack.test/x"}, "must be an https URL"),
        ],
    )
    def test_configuration_problems_are_deliveries(self, env, error) -> None:
        [delivery] = Notifier(env, transport=_Recorder()).send(
            ["slack"], NotifyHelpers._result(), reason="r", exit_code=1
        )
        assert not delivery.ok and error in delivery.error

    def test_a_rejected_post_names_the_status_not_the_url(self) -> None:
        [delivery] = Notifier(ENV, transport=_Recorder(status=404)).send(
            ["slack"], NotifyHelpers._result(), reason="r", exit_code=1
        )
        assert delivery.error == "HTTP 404 from slack"
        assert "hooks.slack" not in delivery.error

    def test_a_transport_crash_is_contained(self) -> None:
        def boom(*_args):
            raise OSError("connection refused to https://hooks.slack.test/services/T/B/X")

        [delivery] = Notifier(ENV, transport=boom).send(
            ["slack"], NotifyHelpers._result(), reason="r", exit_code=1
        )
        assert not delivery.ok
        assert "hooks.slack" not in delivery.error


class TestTheCommandLine:
    def _run(self, tmp_path: Path, monkeypatch, *extra: str) -> int:
        from cordon_scanner.cli.main import CommandLine

        return CommandLine.main(["scan", str(tmp_path), "--progress", "never", "-q", *extra])

    @requires_malicious_corpus
    def test_a_failed_gate_notifies_and_keeps_its_exit_code(
        self, tmp_path, monkeypatch, capsys
    ) -> None:
        (tmp_path / "setup.py").write_bytes(
            (MALICIOUS / "dropper-shell-python" / "setup.py").read_bytes()
        )
        sent = _Recorder(status=500)
        monkeypatch.setattr(notify.Webhooks, "_post", sent)
        monkeypatch.setenv("CORDON_NOTIFY_SLACK", ENV["CORDON_NOTIFY_SLACK"])

        code = self._run(tmp_path, monkeypatch, "--notify", "slack")

        assert code == 1
        assert len(sent.calls) == 1
        assert "notify slack failed: HTTP 500 from slack" in capsys.readouterr().err

    def test_a_passing_gate_sends_nothing(self, tmp_path, monkeypatch) -> None:
        (tmp_path / "ok.py").write_text("print('hello')\n", encoding="utf-8")
        sent = _Recorder()
        monkeypatch.setattr(notify.Webhooks, "_post", sent)
        monkeypatch.setenv("CORDON_NOTIFY_SLACK", ENV["CORDON_NOTIFY_SLACK"])

        assert self._run(tmp_path, monkeypatch, "--notify", "slack") == 0
        assert sent.calls == []

    def test_an_unknown_channel_is_a_config_error(self, tmp_path, monkeypatch) -> None:
        assert self._run(tmp_path, monkeypatch, "--notify", "pager") == 3
