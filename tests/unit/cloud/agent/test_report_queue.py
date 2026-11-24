"""BP-8-8: a device report that cannot be sent waits in the local store and goes first next run; a refusal is never queued."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.cloud import CloudError
from cordon_scanner.cloud.agent.report_queue import ReportQueue
from cordon_scanner.cloud.device import DeviceInventory
from cordon_scanner.cloud.local_store import LocalStore

URL = "https://api.cordon.test"


class Cloud:
    """A fake cloud: what each call answers, and the bodies it received in order."""

    def __init__(self, *answers: Any) -> None:
        self.answers = list(answers)
        self.received: list[dict[str, Any]] = []

    def __call__(
        self, method: str, url: str, *, body: bytes | None, headers: dict[str, str]
    ) -> tuple[int, bytes]:
        answer = self.answers.pop(0) if self.answers else (202, b'{"receipt": "r"}')
        if isinstance(answer, Exception):
            raise answer
        if answer[0] < 300:
            self.received.append(json.loads(body or b"{}"))
        return answer


class Kit:
    DOWN = CloudError("could not reach api.cordon.test (connection refused)")

    @staticmethod
    def report(label: str, device: str = "d" * 32) -> dict[str, Any]:
        return {"device": {"install_id": device}, "inventory": {"tools": [label]}, "findings": []}

    @staticmethod
    def send(payload: dict[str, Any], store: LocalStore, cloud: Cloud) -> str:
        return DeviceInventory.report(payload, url=URL, token="dt", transport=cloud, store=store)


class Stored:
    @pytest.fixture
    def store(self, tmp_path: Path) -> LocalStore:
        return LocalStore(tmp_path / "device")


class TestALostNetwork(Stored):
    def test_queues_the_report_and_the_next_run_sends_it_first(self, store: LocalStore) -> None:
        assert Kit.send(Kit.report("one"), store, Cloud(Kit.DOWN)) == ReportQueue.QUEUED
        assert len(store.pending()) == 1
        cloud = Cloud((202, b'{"receipt": "r1"}'), (202, b'{"receipt": "r2"}'))
        assert Kit.send(Kit.report("two"), store, cloud) == "r2"
        assert [r["inventory"]["tools"] for r in cloud.received] == [["one"], ["two"]]
        assert store.pending() == []

    def test_a_server_error_is_queued_even_when_its_body_is_not_json(
        self, store: LocalStore
    ) -> None:
        assert (
            Kit.send(Kit.report("one"), store, Cloud((502, b"<html>bad gateway</html>")))
            == ReportQueue.QUEUED
        )
        assert (
            Kit.send(Kit.report("two"), store, Cloud((503, b'{"error": "busy"}')))
            == ReportQueue.QUEUED
        )
        assert len(store.pending()) == 1

    def test_the_network_still_down_next_run_keeps_the_newest_report_only(
        self, store: LocalStore
    ) -> None:
        Kit.send(Kit.report("one"), store, Cloud(Kit.DOWN))
        Kit.send(Kit.report("two"), store, Cloud(Kit.DOWN))
        (waiting,) = store.pending()
        assert json.loads(waiting.body)["inventory"]["tools"] == ["two"]

    def test_a_newer_report_of_another_device_does_not_replace_it(self, store: LocalStore) -> None:
        Kit.send(Kit.report("a", "a" * 32), store, Cloud(Kit.DOWN))
        Kit.send(Kit.report("b", "b" * 32), store, Cloud(Kit.DOWN))
        assert sorted(json.loads(p.body)["inventory"]["tools"][0] for p in store.pending()) == [
            "a",
            "b",
        ]

    def test_the_queue_is_bounded(self, tmp_path: Path) -> None:
        small = LocalStore(tmp_path / "small", max_pending=1)
        Kit.send(Kit.report("a", "a" * 32), small, Cloud(Kit.DOWN))
        Kit.send(Kit.report("b", "b" * 32), small, Cloud(Kit.DOWN))
        assert len(small.pending()) == 1 and small.refused() == 1


class TestARefusal(Stored):
    @pytest.mark.parametrize("status", [400, 401, 403, 422])
    def test_is_raised_and_never_queued(self, store: LocalStore, status: int) -> None:
        with pytest.raises(CloudError, match="refused"):
            Kit.send(Kit.report("one"), store, Cloud((status, b'{"error": "no"}')))
        assert store.pending() == []

    def test_a_queued_report_the_cloud_refuses_leaves_the_queue_and_the_new_one_still_goes(
        self, store: LocalStore
    ) -> None:
        Kit.send(Kit.report("old"), store, Cloud(Kit.DOWN))
        cloud = Cloud((422, b'{"error": "schema"}'), (202, b'{"receipt": "r2"}'))
        assert Kit.send(Kit.report("new"), store, cloud) == "r2"
        assert [r["inventory"]["tools"] for r in cloud.received] == [
            ["new"]
        ] and store.pending() == []


class TestNoStore:
    def test_without_a_store_a_lost_network_is_raised_as_before(self) -> None:
        with pytest.raises(CloudError, match="could not reach"):
            DeviceInventory.report(
                Kit.report("one"), url=URL, token="dt", transport=Cloud(Kit.DOWN)
            )
