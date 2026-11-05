"""The built-in channels send exactly what the notifier sent before it became a package.

`tests/unit/data/notify/sent.json` was recorded from the single-module notifier (0.6.0) for three
scans; the version is written `@VERSION@` so a release does not change it. Every body and header
must match byte for byte, and the webhook's signature must verify (it signs the version, so it is
checked rather than compared).
"""

from __future__ import annotations

import json

import pytest

from cordon_scanner.foundation.results import Repository, ScanResult
from cordon_scanner.notify.channel import Channel
from cordon_scanner.notify.channels.slack import SlackChannel
from cordon_scanner.notify.channels.teams import TeamsChannel
from cordon_scanner.notify.channels.webhook import WebhookChannel
from cordon_scanner.notify.events import EventSignature
from cordon_scanner.notify.notifier import Notifier
from cordon_scanner.notify.summary import Summary
from cordon_scanner.version import __version__
from support import ROOT, Support

SENT = ROOT / "tests" / "unit" / "data" / "notify" / "sent.json"
ENV = {
    "CORDON_NOTIFY_WEBHOOK": "https://hooks.example.test/cordon",
    "CORDON_NOTIFY_WEBHOOK_SECRET": "s3cret",
    "CORDON_NOTIFY_SLACK": "https://hooks.slack.test/services/T/B/X",
    "CORDON_NOTIFY_TEAMS": "https://teams.example.test/workflows/1",
}


class ChannelHelpers:
    """The three scans the golden file was recorded from."""

    @staticmethod
    def result(name: str) -> ScanResult:
        if name == "one-finding":
            return ScanResult(
                findings=(Support.a_finding(),), repository=Repository(root="/work/acme-api")
            )
        if name == "many-findings":
            findings = tuple(Support.a_finding(rule_id=f"TEST.RULE.{i:03d}") for i in range(25))
            repository = Repository(
                root="/work/acme-api",
                remote="https://user:pat@github.com/acme/api.git",
                revision="0123456789abcdef",
            )
            return ScanResult(findings=findings, repository=repository)
        return ScanResult(
            findings=(),
            repository=Repository(root="/work/acme-api", remote="git@github.com:acme/api.git"),
        )

    @staticmethod
    def golden() -> dict:
        return json.loads(SENT.read_text(encoding="utf-8").replace("@VERSION@", __version__))


class TestTheSameAsBefore:
    @pytest.mark.parametrize("case", ["one-finding", "many-findings", "no-findings"])
    def test_every_channel_sends_the_recorded_bytes(self, case: str) -> None:
        sent: list[tuple[str, bytes, dict[str, str]]] = []

        def record(url, body, headers):
            sent.append((url, body, dict(headers)))
            return 200

        Notifier(ENV, transport=record, clock=lambda: 1_790_000_000).send(
            ["webhook", "slack", "teams"],
            ChannelHelpers.result(case),
            reason="1 finding at high",
            exit_code=1,
        )

        golden = ChannelHelpers.golden()[case]
        # The channels are sent to concurrently, so the sends arrive in any order: each is matched
        # to its channel by the URL it went to.
        by_url = {url: (body, headers) for url, body, headers in sent}
        assert len(sent) == 3 and sorted(by_url) == sorted(golden[c][0] for c in golden)
        for channel in ("webhook", "slack", "teams"):
            want_url, want_body, want_headers = golden[channel]
            body, headers = by_url[want_url]
            assert body.decode() == want_body
            signature = headers.pop("X-Cordon-Signature", None)
            headers.pop("X-Cordon-Delivery", None)
            want = {k: v for k, v in want_headers.items() if k != "X-Cordon-Signature"}
            assert headers == want
            if channel == "webhook":
                assert "X-Cordon-Signature" in want_headers
                assert EventSignature.verify("s3cret", signature, body, now=1_790_000_000)


class TestThePort:
    @pytest.mark.parametrize("channel", [WebhookChannel(), SlackChannel(), TeamsChannel()])
    def test_each_built_in_channel_implements_it(self, channel: object) -> None:
        assert isinstance(channel, Channel)

    def test_the_registry_finds_the_built_ins_in_their_order(self) -> None:
        assert [c.id for c in Notifier.available()] == ["webhook", "slack", "teams"]

    def test_slack_cuts_a_long_header(self) -> None:
        result = ScanResult(findings=(), repository=Repository(root="/work/" + "a" * 300))
        summary = Summary.of(result, reason="r", exit_code=1)
        header = SlackChannel().blocks(summary)["blocks"][0]["text"]["text"]
        assert len(header) == SlackChannel.HEADER_LIMIT
