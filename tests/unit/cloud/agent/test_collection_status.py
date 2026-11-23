"""An agent whose bundle expired, whose policy is unavailable or whose key expired keeps collecting and says its collection is degraded, with a reason from one shared list; complete once fixed."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.cloud.agent.collection_status import CollectionStatus
from cordon_scanner.cloud.device import DeviceInventory
from cordon_scanner.cloud.local_runtime import LocalRuntime
from cordon_scanner.cloud.local_store import LocalStore
from kits.bundle_kit import T0, Kit, Platform
from support import ROOT

ACCEPTED = json.loads(
    (ROOT / "tests" / "unit" / "data" / "collection" / "accepted.json").read_text(encoding="utf-8")
)


class Shape:
    @staticmethod
    def accepted(value: Any) -> bool:
        """The platform's rule (`devices/helpers/report.py` Report.collection), written out: an object of status and reason only; a degraded status gives one reason of the list, a complete one none."""
        if not isinstance(value, dict) or set(value) - {"status", "reason"}:
            return False
        status, reason = value.get("status", "complete"), value.get("reason", "")
        if status not in ACCEPTED["statuses"] or not isinstance(reason, str):
            return False
        if (status == "degraded") != (reason != ""):
            return False
        return not reason or reason in ACCEPTED["reasons"]


class TestTheSharedList:
    def test_the_agent_and_the_platform_list_the_same_three_reasons(self) -> None:
        assert list(CollectionStatus.REASONS) == ACCEPTED["reasons"]

    def test_the_vector_is_what_the_shape_rule_says(self) -> None:
        assert all(Shape.accepted(v) for v in ACCEPTED["accepted"])
        assert not any(Shape.accepted(v) for v in ACCEPTED["refused"])


class TestWhatTheAgentSends:
    @pytest.mark.parametrize("reason", CollectionStatus.REASONS)
    def test_each_reason_gives_a_degraded_object_the_platform_accepts(self, reason: str) -> None:
        payload = CollectionStatus.payload(reason)
        assert payload == {"status": "degraded", "reason": reason} and Shape.accepted(payload)

    def test_no_reason_gives_complete(self) -> None:
        assert CollectionStatus.payload(None) == {"status": "complete"}
        assert Shape.accepted(CollectionStatus.payload(None))

    def test_a_reason_the_agent_made_up_is_refused_before_it_is_sent(self) -> None:
        with pytest.raises(ValueError, match="one reason of"):
            CollectionStatus.payload("my own words")

    def test_the_report_carries_it_and_still_carries_what_was_found(self, tmp_path: Path) -> None:
        (tmp_path / ".cursor").mkdir()
        (tmp_path / ".cursor" / "mcp.json").write_text(
            '{"mcpServers": {"x": {"command": "node", "args": ["a.js"]}}}', encoding="utf-8"
        )
        degraded = DeviceInventory.collect(tmp_path, CollectionStatus.payload("bundle_expired"))
        complete = DeviceInventory.collect(tmp_path, CollectionStatus.payload(None))
        assert degraded["collection"] == {"status": "degraded", "reason": "bundle_expired"}
        assert degraded["inventory"] == complete["inventory"] and complete["collection"] == {
            "status": "complete"
        }

    def test_a_report_with_no_status_given_has_no_collection_key(self, tmp_path: Path) -> None:
        assert "collection" not in DeviceInventory.collect(tmp_path)


class TestWhyTheRuntimeSaysDegraded:
    def runtime(self, tmp_path: Path, *, accept: bool = True) -> tuple[LocalRuntime, Platform]:
        platform = Platform()
        runtime = Kit.runtime(platform, LocalStore(tmp_path))
        if accept:
            runtime.accept([Kit.first(platform)], T0)
        return runtime, platform

    def test_a_held_unexpired_bundle_is_complete(self, tmp_path: Path) -> None:
        runtime, _ = self.runtime(tmp_path)
        assert runtime.collection_reason(T0 + timedelta(minutes=1)) is None

    def test_no_bundle_held_is_policy_unavailable(self, tmp_path: Path) -> None:
        runtime, _ = self.runtime(tmp_path, accept=False)
        assert runtime.collection_reason(T0) == "policy_unavailable"

    def test_a_bundle_past_its_expiry_is_bundle_expired(self, tmp_path: Path) -> None:
        runtime, _ = self.runtime(tmp_path)
        assert runtime.collection_reason(T0 + timedelta(days=3650)) in (
            "bundle_expired",
            "key_expired",
        )

    def test_every_reason_it_gives_is_on_the_shared_list(self, tmp_path: Path) -> None:
        runtime, _ = self.runtime(tmp_path)
        for days in (0, 30, 400, 4000):
            reason = runtime.collection_reason(T0 + timedelta(days=days))
            assert reason is None or reason in CollectionStatus.REASONS
