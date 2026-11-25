"""A device reports each feed serial pair it ran scans on once, to the feed-serials endpoint, with two fields and nothing else."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import ClassVar

import pytest

from cordon_scanner.cloud import CloudError
from cordon_scanner.cloud.agent.feed_serials import KIND, PATH, FeedSerials
from cordon_scanner.cloud.local_store import LocalStore
from kits.bundle_kit import T0


class Wire:
    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.calls: list[tuple[str, str, dict[str, object], dict[str, str]]] = []

    def __call__(
        self, method: str, url: str, *, body: bytes | None, headers: dict[str, str]
    ) -> tuple[int, bytes]:
        self.calls.append((method, url, json.loads(body or b"{}"), headers))
        return self.status, b"{}"


class TestAFeedSerialIsReportedOnce:
    FEED: ClassVar[dict[str, object]] = {
        "serial": "41",
        "intel_serial": "9007",
        "packs": {"a": "1.0.0"},
    }

    def test_a_new_pair_queues_one_record_with_the_two_fields_only(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path)
        assert FeedSerials.queue(store, self.FEED, T0) is True
        (item,) = [i for i in store.pending() if i.kind == KIND]
        assert json.loads(item.body) == {"intel_serial": "9007", "serial": "41"}

    def test_the_same_pair_again_queues_nothing(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path)
        FeedSerials.queue(store, self.FEED, T0)
        assert FeedSerials.queue(store, self.FEED, T0 + timedelta(hours=1)) is False
        assert len(store.pending()) == 1

    def test_a_new_serial_is_reported_and_a_device_with_no_feed_says_none(
        self, tmp_path: Path
    ) -> None:
        store = LocalStore(tmp_path)
        FeedSerials.queue(store, self.FEED, T0)
        assert FeedSerials.queue(store, {**self.FEED, "serial": "42"}, T0) is True
        assert FeedSerials.queue(store, {"serial": "none", "intel_serial": "none"}, T0) is True
        assert len(store.pending()) == 3

    @pytest.mark.parametrize("bad", ["", "4 1", "1" * 13, "-1", 41, None])
    def test_a_value_that_is_not_a_serial_is_not_queued(self, tmp_path: Path, bad: object) -> None:
        store = LocalStore(tmp_path)
        assert FeedSerials.queue(store, {"serial": bad, "intel_serial": "1"}, T0) is False
        assert store.pending() == []


class TestSending:
    def queued(self, tmp_path: Path):
        store = LocalStore(tmp_path)
        FeedSerials.queue(store, {"serial": "41", "intel_serial": "9007"}, T0)
        return store, store.pending()[0]

    def test_it_posts_the_sighting_to_the_device_endpoint_with_the_device_token(
        self, tmp_path: Path
    ) -> None:
        _, item = self.queued(tmp_path)
        wire = Wire()
        FeedSerials.send(item, url="https://cloud.example.invalid", token="t0k", transport=wire)
        ((method, url, body, headers),) = wire.calls
        assert (method, url.endswith(PATH)) == ("POST", True)
        assert body == {"sightings": [{"intel_serial": "9007", "serial": "41"}]}
        assert headers["Authorization"] == "Bearer t0k"

    def test_a_refusal_raises_and_the_record_stays_queued(self, tmp_path: Path) -> None:
        store, _ = self.queued(tmp_path)
        wire = Wire(status=400)
        drained = store.drain(
            lambda item: FeedSerials.send(
                item, url="https://cloud.example.invalid", token="t", transport=wire
            )
        )
        assert (drained.sent, drained.left) == (0, 1)

    def test_a_sent_record_leaves_the_queue(self, tmp_path: Path) -> None:
        store, _ = self.queued(tmp_path)
        drained = store.drain(
            lambda item: FeedSerials.send(
                item, url="https://cloud.example.invalid", token="t", transport=Wire()
            )
        )
        assert (drained.sent, drained.left) == (1, 0)

    def test_without_a_device_token_nothing_is_sent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("CORDON_DEVICE_TOKEN", raising=False)
        _, item = self.queued(tmp_path)
        wire = Wire()
        with pytest.raises(CloudError, match="CORDON_DEVICE_TOKEN"):
            FeedSerials.send(item, url="https://cloud.example.invalid", transport=wire)
        assert wire.calls == []
