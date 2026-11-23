"""`agent report` always sends how well it collected: degraded with its reason when the device's policy bundle has expired or is missing, complete when it is valid; the post is stubbed, no network."""

from __future__ import annotations

import argparse
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.cli.commands.agent import AgentCommand
from cordon_scanner.cloud import device
from cordon_scanner.cloud.agent.collection_status import STORE_ENV, CollectionStatus
from cordon_scanner.cloud.local_store import LocalStore
from kits.bundle_kit import T0, Kit, Platform


class Posted:
    """The report the command posted."""

    def __init__(self) -> None:
        self.payloads: list[dict[str, Any]] = []

    def __call__(self, payload: dict[str, Any], **_: Any) -> str:
        self.payloads.append(payload)
        return "receipt-1"


class Run:
    @staticmethod
    def report(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path, store: Path | None, clock: object
    ) -> dict[str, Any]:
        posted = Posted()
        monkeypatch.setattr(device.DeviceInventory, "report", staticmethod(posted))
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        (tmp_path / "home").mkdir(exist_ok=True)
        if store is None:
            monkeypatch.delenv(STORE_ENV, raising=False)
        else:
            monkeypatch.setenv(STORE_ENV, str(store))
        monkeypatch.setattr(CollectionStatus, "now", staticmethod(lambda: clock))
        code = AgentCommand.run(argparse.Namespace(agent_command="report", url=None))
        assert code == 0 and len(posted.payloads) == 1
        return posted.payloads[0]

    @staticmethod
    def bundle_store(tmp_path: Path) -> Path:
        platform = Platform()
        store = tmp_path / "store"
        runtime = Kit.runtime(platform, LocalStore(store))
        runtime.accept([Kit.first(platform)], T0)
        return store


class TestTheReportSaysHowItWasCollected:
    def test_with_a_valid_bundle_it_says_complete(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        store = Run.bundle_store(tmp_path)
        payload = Run.report(monkeypatch, tmp_path, store, T0 + timedelta(hours=1))
        assert payload["collection"] == {"status": "complete"}

    def test_with_an_expired_bundle_it_says_degraded_bundle_expired_and_still_reports_what_it_found(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        store = Run.bundle_store(tmp_path)
        payload = Run.report(monkeypatch, tmp_path, store, T0 + timedelta(days=30))
        assert payload["collection"] == {"status": "degraded", "reason": "bundle_expired"}
        assert payload["schema"] == device.SCHEMA and "inventory" in payload

    def test_with_a_store_holding_no_bundle_it_says_policy_unavailable(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        empty = tmp_path / "empty"
        LocalStore(empty)
        payload = Run.report(monkeypatch, tmp_path, empty, T0)
        assert payload["collection"] == {"status": "degraded", "reason": "policy_unavailable"}

    def test_with_no_device_store_the_field_is_still_sent_and_says_complete(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        payload = Run.report(monkeypatch, tmp_path, None, T0)
        assert payload["collection"] == {"status": "complete"}

    def test_the_degraded_one_clears_with_the_next_complete_report(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        store = Run.bundle_store(tmp_path)
        first = Run.report(monkeypatch, tmp_path, store, T0 + timedelta(days=30))
        second = Run.report(monkeypatch, tmp_path, store, T0 + timedelta(hours=2))
        assert (first["collection"]["status"], second["collection"]["status"]) == (
            "degraded",
            "complete",
        )
