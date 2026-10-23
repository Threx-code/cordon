"""The evaluation gate decides from archived scans alone (CDI §4, §9.6, §9.7)."""

from __future__ import annotations

import json
from pathlib import Path

from bench.cdi.gate import Gate

MAL = [["MALWARE.DROPPER.001", "critical", "high", "malicious"]]
SECRET = [["SECRET.AWS.ACCESS_KEY.001", "high", "high", "suspicious"]]


class GateKit:
    @staticmethod
    def scans(path: Path, rows: dict[str, tuple[object, list[list[str]], float]]) -> str:
        path.write_text(
            "".join(
                json.dumps({"file": f, "exit": e, "findings": fs, "seconds": s}) + "\n"
                for f, (e, fs, s) in rows.items()
            ),
            encoding="utf-8",
        )
        return str(path)

    @staticmethod
    def spec(tmp_path: Path, mal_on: dict, ben_on: dict, **extra) -> dict:
        mal_off = {"m1": (1, MAL, 1.0), "m2": (0, [], 1.0)}
        ben_off = {f"b{i}": (0, [], 1.0) for i in range(5)}
        scans = GateKit.scans
        return {
            "candidate_id": "cand:1",
            "sets": [
                {
                    "name": "mal",
                    "kind": "malware",
                    "area": "pypi",
                    "off": scans(tmp_path / "mo", mal_off),
                    "on": scans(tmp_path / "mn", mal_on),
                },
                {
                    "name": "ben",
                    "kind": "benign",
                    "area": "pypi",
                    "off": scans(tmp_path / "bo", ben_off),
                    "on": scans(tmp_path / "bn", ben_on),
                },
            ],
            **extra,
        }


BEN_CLEAN = {f"b{i}": (0, [], 1.0) for i in range(5)}


class TestTheGates:
    def test_a_gain_with_nothing_lost_earns_shadow_never_blocking(self, tmp_path: Path) -> None:
        _, decision = Gate.evaluate(
            GateKit.spec(tmp_path, {"m1": (1, MAL, 1.0), "m2": (1, MAL, 1.0)}, BEN_CLEAN)
        )
        assert decision["outcome"] == "shadow"
        assert decision["gates"]["lose_zero"]["result"] == "pass"

    def test_losing_one_caught_sample_rejects(self, tmp_path: Path) -> None:
        _, decision = Gate.evaluate(
            GateKit.spec(tmp_path, {"m1": (0, [], 1.0), "m2": (1, MAL, 1.0)}, BEN_CLEAN)
        )
        assert (
            decision["outcome"] == "reject" and decision["gates"]["lose_zero"]["result"] == "fail"
        )

    def test_a_new_benign_block_rejects_and_is_listed(self, tmp_path: Path) -> None:
        ben = {**BEN_CLEAN, "b0": (1, MAL, 1.0)}
        run, decision = Gate.evaluate(
            GateKit.spec(tmp_path, {"m1": (1, MAL, 1.0), "m2": (0, [], 1.0)}, ben)
        )
        assert decision["gates"]["new_benign"]["result"] == "fail" and run["new_benign_blocks"] == [
            "ben:b0"
        ]

    def test_a_secret_only_block_is_not_a_malware_false_block(self, tmp_path: Path) -> None:
        ben = {**BEN_CLEAN, "b0": (1, SECRET, 1.0)}
        _, decision = Gate.evaluate(
            GateKit.spec(tmp_path, {"m1": (1, MAL, 1.0), "m2": (0, [], 1.0)}, ben)
        )
        assert decision["gates"]["new_benign"]["result"] == "pass"

    def test_training_on_an_eval_sample_rejects(self, tmp_path: Path) -> None:
        (tmp_path / "train").write_text("k1\nk2\n", encoding="utf-8")
        (tmp_path / "held").write_text("k2\nk3\n", encoding="utf-8")
        lineage = {"train_keys": str(tmp_path / "train"), "eval_keys": [str(tmp_path / "held")]}
        _, decision = Gate.evaluate(
            GateKit.spec(
                tmp_path, {"m1": (1, MAL, 1.0), "m2": (0, [], 1.0)}, BEN_CLEAN, lineage=lineage
            )
        )
        assert decision["gates"]["lineage"]["result"] == "fail"

    def test_a_slower_candidate_past_the_ratio_rejects(self, tmp_path: Path) -> None:
        slow = {"m1": (1, MAL, 9.0), "m2": (0, [], 9.0)}
        _, decision = Gate.evaluate(GateKit.spec(tmp_path, slow, BEN_CLEAN))
        assert decision["gates"]["runtime"]["result"] == "fail"

    def test_a_small_benign_set_is_reported_as_insufficient_evidence(self, tmp_path: Path) -> None:
        _, decision = Gate.evaluate(
            GateKit.spec(tmp_path, {"m1": (1, MAL, 1.0), "m2": (0, [], 1.0)}, BEN_CLEAN)
        )
        assert decision["gates"]["benign_bar_evidence"]["result"] == "insufficient"
