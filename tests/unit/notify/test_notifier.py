"""The notifier: env-only URLs, nothing sensitive sent, failures contained, retries bounded."""

from __future__ import annotations

import json
import threading
import urllib.error

import pytest

from cordon_scanner.foundation.models import Repository, ScanResult
from cordon_scanner.notify.channel import Message
from cordon_scanner.notify.events import EventSignature
from cordon_scanner.notify.notifier import Notifier
from cordon_scanner.notify.summary import Summary
from cordon_scanner.notify.transport import Reply, RetryPolicy
from support import Support

SECRET_TEXT = "ghp_" + "x" * 36
ENV = {
    "CORDON_NOTIFY_WEBHOOK": "https://hooks.example.test/cordon",
    "CORDON_NOTIFY_WEBHOOK_SECRET": "s3cret",
    "CORDON_NOTIFY_SLACK": "https://hooks.slack.test/services/T/B/X",
    "CORDON_NOTIFY_TEAMS": "https://teams.example.test/workflows/1",
}


class NotifierHelpers:
    """Helpers for test_notifier.py."""

    @staticmethod
    def result(findings=None, **repo) -> ScanResult:
        findings = findings if findings is not None else (Support.a_finding(),)
        return ScanResult(
            findings=tuple(findings), repository=Repository(root="/work/acme-api", **repo)
        )


class _Recorder:
    """A transport that answers from a script, one reply per post, and records each post."""

    def __init__(self, *replies) -> None:
        self.replies = list(replies) or [200]
        self.calls: list[tuple[str, bytes, dict[str, str]]] = []
        self._lock = threading.Lock()

    def __call__(self, url, body, headers):
        with self._lock:
            self.calls.append((url, body, dict(headers)))
            reply = self.replies[min(len(self.calls), len(self.replies)) - 1]
        if isinstance(reply, BaseException):
            raise reply
        return reply


class _Clock:
    """Time that moves only when the notifier sleeps."""

    def __init__(self, start: float = 1_790_000_000) -> None:
        self.now = start
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


class TestChannels:
    def test_channels_are_parsed_in_a_fixed_order(self) -> None:
        assert Notifier.parse_channels("teams, slack,webhook") == ("webhook", "slack", "teams")

    def test_an_unknown_channel_is_refused(self) -> None:
        with pytest.raises(ValueError, match="discord"):
            Notifier.parse_channels("slack,discord")

    def test_a_plugin_channel_is_used_when_given(self) -> None:
        class Pager:
            id = "pager"
            variable = "CORDON_NOTIFY_PAGER"

            def message(self, summary, occasion):
                return Message(json.dumps({"title": summary.headline()}).encode())

        sent = _Recorder()
        [delivery] = Notifier(
            {"CORDON_NOTIFY_PAGER": "https://pager.example.test/x"},
            transport=sent,
            channels=[Pager()],
        ).send(["pager"], NotifierHelpers.result(), reason="r", exit_code=1)

        assert delivery.ok
        assert json.loads(sent.calls[0][1])["title"].startswith("Cordon: acme-api failed")


class TestWebhook:
    def test_the_event_is_signed_and_verifies(self) -> None:
        sent = _Recorder()
        [delivery] = Notifier(ENV, transport=sent, clock=lambda: 1_790_000_000).send(
            ["webhook"], NotifierHelpers.result(), reason="1 finding at high", exit_code=1
        )

        assert delivery.ok
        assert delivery.attempts == 1
        _url, body, headers = sent.calls[0]
        assert headers["X-Cordon-Event"] == "scan.completed"
        assert headers["X-Cordon-Delivery"] == delivery.delivery
        assert EventSignature.verify(
            "s3cret", headers["X-Cordon-Signature"], body, now=1_790_000_010
        )
        event = json.loads(body)
        assert event["schema"] == "cordon.event/v1"
        assert event["scan"]["gate"] == "failed"
        assert event["scan"]["target"] == "acme-api"

    def test_a_stale_or_tampered_signature_fails(self) -> None:
        body = b'{"a":1}'
        header = EventSignature.sign("s3cret", 1_000, body)
        assert not EventSignature.verify("s3cret", header, body, now=1_000 + 301)
        assert not EventSignature.verify("s3cret", header, b'{"a":2}', now=1_000)
        assert not EventSignature.verify("wrong", header, body, now=1_000)

    def test_a_receiver_can_accept_two_secrets_while_rotating(self) -> None:
        body = b'{"a":1}'
        old = EventSignature.sign("old", 1_000, body)
        new = EventSignature.sign("new", 1_000, body)
        assert EventSignature.verify(["new", "old"], old, body, now=1_000)
        assert EventSignature.verify(["new", "old"], new, body, now=1_000)
        assert not EventSignature.verify(
            ["new", "old"], EventSignature.sign("x", 1_000, body), body, now=1_000
        )

    def test_it_is_refused_without_a_secret(self) -> None:
        env = {k: v for k, v in ENV.items() if k != "CORDON_NOTIFY_WEBHOOK_SECRET"}
        sent = _Recorder()
        [delivery] = Notifier(env, transport=sent).send(
            ["webhook"], NotifierHelpers.result(), reason="r", exit_code=1
        )

        assert not delivery.ok and "unsigned" in delivery.error
        assert delivery.attempts == 0
        assert sent.calls == []


class TestWhatIsSent:
    def test_no_message_or_evidence_leaves(self) -> None:
        finding = Support.a_finding(message=f"token {SECRET_TEXT} in config")
        sent = _Recorder()
        Notifier(ENV, transport=sent).send(
            ["webhook", "slack", "teams"],
            NotifierHelpers.result([finding]),
            reason="r",
            exit_code=1,
        )

        assert len(sent.calls) == 3
        for _url, body, _headers in sent.calls:
            assert SECRET_TEXT.encode() not in body
            assert b"in config" not in body

    def test_long_lists_are_counted_not_listed(self) -> None:
        findings = [Support.a_finding(rule_id=f"TEST.RULE.{i:03d}") for i in range(25)]
        summary = Summary.of(NotifierHelpers.result(findings), reason="r", exit_code=1)

        assert len(summary.listed) == Summary.MAX_LISTED
        assert summary.lines()[-1] == "... and 15 more"

    def test_credentials_in_a_remote_are_not_the_target(self) -> None:
        summary = Summary.of(
            NotifierHelpers.result(remote="https://user:pat@github.com/acme/api.git"),
            reason="r",
            exit_code=1,
        )
        assert summary.target == "github.com/acme/api"

    def test_a_passing_gate_says_so(self) -> None:
        sent = _Recorder()
        Notifier(ENV, transport=sent).send(
            ["webhook", "slack"],
            NotifierHelpers.result(()),
            reason="no findings",
            exit_code=0,
            gate="passed",
        )
        assert json.loads(sent.calls[0][1])["scan"]["gate"] == "passed"
        assert json.loads(sent.calls[1][1])["text"] == "Cordon: acme-api passed its gate"

    def test_a_test_message_is_marked(self) -> None:
        sent = _Recorder()
        Notifier(ENV, transport=sent).send(
            ["slack"], NotifierHelpers.result(()), reason="r", exit_code=0, test=True
        )
        assert json.loads(sent.calls[0][1])["text"].startswith("[test] Cordon:")


class TestTriggers:
    def test_the_default_is_failures_and_incomplete_scans(self) -> None:
        on = Notifier.DEFAULT_TRIGGERS
        assert Notifier.fires(on, gate="failed", complete=True)
        assert Notifier.fires(on, gate="passed", complete=False)
        assert not Notifier.fires(on, gate="passed", complete=True)

    def test_passed_is_asked_for(self) -> None:
        assert Notifier.fires(("passed",), gate="passed", complete=True)
        assert not Notifier.fires(("passed",), gate="failed", complete=True)

    def test_an_unknown_trigger_is_refused(self) -> None:
        assert Notifier.parse_triggers("passed, failed") == ("failed", "passed")
        with pytest.raises(ValueError, match="always"):
            Notifier.parse_triggers("always")


class TestRetries:
    def _send(self, *replies, policy=None):
        clock = _Clock()
        sent = _Recorder(*replies)
        [delivery] = Notifier(
            ENV, transport=sent, clock=clock, sleep=clock.sleep, policy=policy
        ).send(["webhook"], NotifierHelpers.result(), reason="r", exit_code=1)
        return delivery, sent, clock

    def test_a_busy_receiver_is_tried_again_under_one_delivery_id(self) -> None:
        delivery, sent, clock = self._send(503, Reply(429, retry_after=3), 200)

        assert delivery.ok and delivery.attempts == 3
        assert clock.slept == [1.0, 3.0]
        assert len({headers["X-Cordon-Delivery"] for _u, _b, headers in sent.calls}) == 1
        assert len({body for _u, body, _h in sent.calls}) == 1

    def test_a_dropped_connection_is_tried_again(self) -> None:
        delivery, _sent, _clock = self._send(urllib.error.URLError("reset"), 200)
        assert delivery.ok and delivery.attempts == 2

    def test_a_wrong_url_is_not_tried_again(self) -> None:
        delivery, _sent, _clock = self._send(404)
        assert not delivery.ok and delivery.attempts == 1
        assert delivery.error == "HTTP 404 from webhook"

    def test_attempts_stop_at_the_limit(self) -> None:
        delivery, _sent, clock = self._send(500)
        assert not delivery.ok and delivery.attempts == 3
        assert delivery.error == "HTTP 500 from webhook"
        assert clock.slept == [1.0, 2.0]

    def test_a_long_retry_after_is_not_waited_for(self) -> None:
        delivery, _sent, clock = self._send(Reply(429, retry_after=3600))
        assert not delivery.ok and delivery.attempts == 1
        assert clock.slept == []

    def test_the_deadline_bounds_the_whole_send(self) -> None:
        policy = RetryPolicy(attempts=10, backoff=(4.0,), deadline=10.0)
        delivery, _sent, clock = self._send(503, policy=policy)
        assert not delivery.ok
        assert sum(clock.slept) <= 10.0
        assert delivery.attempts == 3

    def test_channels_are_sent_at_the_same_time(self) -> None:
        arrived = threading.Barrier(3, timeout=5)

        def together(url, body, headers):
            arrived.wait()
            return 200

        deliveries = Notifier(ENV, transport=together).send(
            ["webhook", "slack", "teams"], NotifierHelpers.result(), reason="r", exit_code=1
        )
        assert [d.ok for d in deliveries] == [True, True, True]
        assert [d.channel for d in deliveries] == ["webhook", "slack", "teams"]


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
            ["slack"], NotifierHelpers.result(), reason="r", exit_code=1
        )
        assert not delivery.ok and error in delivery.error

    def test_a_rejected_post_names_the_status_not_the_url(self) -> None:
        [delivery] = Notifier(ENV, transport=_Recorder(404)).send(
            ["slack"], NotifierHelpers.result(), reason="r", exit_code=1
        )
        assert delivery.error == "HTTP 404 from slack"
        assert "hooks.slack" not in delivery.error

    def test_a_transport_crash_is_contained(self) -> None:
        clock = _Clock()

        def boom(*_args):
            raise OSError("connection refused to https://hooks.slack.test/services/T/B/X")

        [delivery] = Notifier(ENV, transport=boom, clock=clock, sleep=clock.sleep).send(
            ["slack"], NotifierHelpers.result(), reason="r", exit_code=1
        )
        assert not delivery.ok
        assert "hooks.slack" not in delivery.error

    def test_a_malformed_url_is_not_tried_again(self) -> None:
        def malformed(*_args):
            raise ValueError("bad URL")

        [delivery] = Notifier(ENV, transport=malformed).send(
            ["slack"], NotifierHelpers.result(), reason="r", exit_code=1
        )
        assert not delivery.ok and delivery.attempts == 1
        assert delivery.error == "ValueError delivering to slack"

    def test_a_channel_that_crashes_is_contained(self) -> None:
        class Broken:
            id = "broken"
            variable = "CORDON_NOTIFY_BROKEN"

            def message(self, summary, occasion):
                raise RuntimeError("bug in a plugin")

        [delivery] = Notifier(
            {"CORDON_NOTIFY_BROKEN": "https://x.example.test/"},
            transport=_Recorder(),
            channels=[Broken()],
        ).send(["broken"], NotifierHelpers.result(), reason="r", exit_code=1)
        assert not delivery.ok and delivery.error == "RuntimeError"
