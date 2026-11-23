"""A change that raises the legitimate incomplete rate fails the gate, and the rate is told apart from content blocks."""

from __future__ import annotations

from pathlib import Path

from bench.cdi.gate import Gate
from bench.cdi.test_gate import BEN_CLEAN, MAL, GateKit

MAL_ON = {"m1": (1, MAL, 1.0), "m2": (1, MAL, 1.0)}


class Kit:
    @staticmethod
    def decide(tmp_path: Path, ben_on: dict) -> tuple[dict, dict]:
        return Gate.evaluate(GateKit.spec(tmp_path, MAL_ON, ben_on))

    @staticmethod
    def benign(**changes: tuple[object, list, float]) -> dict:
        return {**BEN_CLEAN, **changes}


class TestAChangeThatRaisesLegitIncompleteness:
    def test_a_legitimate_unit_the_change_leaves_unread_to_the_end_fails_the_gate(
        self, tmp_path: Path
    ) -> None:
        _, decision = Kit.decide(tmp_path, Kit.benign(b0=(4, [], 1.0)))
        assert decision["gates"]["legit_incomplete"]["result"] == "fail"
        assert decision["outcome"] == "reject"
        assert (
            "1 legitimate units newly not read" in decision["gates"]["legit_incomplete"]["reason"]
        )

    def test_a_crash_and_a_timeout_count_as_not_read_to_the_end(self, tmp_path: Path) -> None:
        for exit_status in ("timeout", 2, 3):
            _, decision = Kit.decide(tmp_path, Kit.benign(b1=(exit_status, [], 1.0)))
            assert decision["gates"]["legit_incomplete"]["result"] == "fail", exit_status

    def test_a_change_that_leaves_every_legitimate_unit_read_passes(self, tmp_path: Path) -> None:
        _, decision = Kit.decide(tmp_path, BEN_CLEAN)
        assert decision["gates"]["legit_incomplete"]["result"] == "pass"
        assert decision["outcome"] == "shadow"

    def test_a_unit_that_was_already_incomplete_before_the_change_is_not_new(
        self, tmp_path: Path
    ) -> None:
        off = {**BEN_CLEAN, "b0": (4, [], 1.0)}
        spec = GateKit.spec(tmp_path, MAL_ON, Kit.benign(b0=(4, [], 1.0)))
        spec["sets"][1]["off"] = GateKit.scans(tmp_path / "bo2", off)
        _, decision = Gate.evaluate(spec)
        assert decision["gates"]["legit_incomplete"]["result"] == "pass"

    def test_a_unit_that_becomes_read_to_the_end_is_not_a_rise(self, tmp_path: Path) -> None:
        spec = GateKit.spec(tmp_path, MAL_ON, BEN_CLEAN)
        spec["sets"][1]["off"] = GateKit.scans(tmp_path / "bo2", {**BEN_CLEAN, "b0": (4, [], 1.0)})
        _, decision = Gate.evaluate(spec)
        assert decision["gates"]["legit_incomplete"]["result"] == "pass"

    def test_a_scan_that_says_its_content_was_not_all_read_is_incomplete(self) -> None:
        assert Gate.incomplete({"exit": 0, "content_complete": False}) is True
        assert Gate.incomplete({"exit": 0, "content_complete": True}) is False
        assert Gate.incomplete({"exit": 0}) is False and Gate.incomplete(None) is False


class TestToldApartFromContentBlocks:
    def test_a_content_block_is_not_an_incompleteness_and_an_incompleteness_is_not_a_block(
        self, tmp_path: Path
    ) -> None:
        run, _ = Kit.decide(tmp_path, Kit.benign(b0=(1, MAL, 1.0), b1=(4, [], 1.0)))
        entry = run["metrics"]["sets"]["ben"]
        assert (entry["new_blocks"], entry["new_incomplete"]) == (1, 1)
        assert entry["incomplete_on"] == 1 and entry["malware_class_on"] == 1

    def test_the_rate_is_measured_on_legitimate_sets_only(self, tmp_path: Path) -> None:
        run, _ = Gate.evaluate(
            GateKit.spec(tmp_path, {"m1": (4, [], 1.0), "m2": (1, MAL, 1.0)}, BEN_CLEAN)
        )
        assert "new_incomplete" not in run["metrics"]["sets"]["mal"]
        assert run["metrics"]["sets"]["ben"]["new_incomplete"] == 0
