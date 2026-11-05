"""Scoring archived scans into scorecard entries uses the gate's definitions, group by group."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from bench.cdi.score import Score

MAL = [["MALWARE.DROPPER.001", "critical", "high", "malicious"]]
SECRET = [["SECRET.AWS.ACCESS_KEY.001", "high", "high", "suspicious"]]


class ScoreKit:
    @staticmethod
    def scans(tmp_path: Path, rows: list[tuple[str, object, list]]) -> Path:
        path = tmp_path / "scans.jsonl"
        path.write_text(
            "".join(json.dumps({"file": f, "exit": e, "findings": fs}) + "\n" for f, e, fs in rows),
            encoding="utf-8",
        )
        return path


class TestScore:
    def test_a_failed_malware_scan_is_a_miss(self, tmp_path: Path) -> None:
        scans = ScoreKit.scans(tmp_path, [("a", 1, MAL), ("b", 0, []), ("c", "timeout", [])])
        assert Score.tally(scans, "malware", {}) == {
            "all": {"k": 1, "n": 3, "failed": 1, "secret_only": 0}
        }

    def test_a_secret_only_block_is_not_a_malware_block(self, tmp_path: Path) -> None:
        scans = ScoreKit.scans(tmp_path, [("a", 1, MAL), ("b", 1, SECRET), ("c", 0, [])])
        tally = Score.tally(scans, "benign", {})["all"]
        assert (tally["k"], tally["secret_only"], tally["n"]) == (1, 1, 3)

    def test_units_are_tallied_by_their_group_after_the_mount_prefix(self, tmp_path: Path) -> None:
        scans = ScoreKit.scans(tmp_path, [("q/x", 1, MAL), ("q/y", 0, [])])
        tallies = Score.tally(scans, "benign", {"x": "native", "y": "random"}, prefix="q/")
        assert tallies["native"]["k"] == 1 and tallies["random"]["n"] == 1

    def test_metrics_carry_counts_never_rounded_rates(self, tmp_path: Path) -> None:
        args = argparse.Namespace(
            id_prefix="pypi.heldout",
            label="PyPI",
            area="pypi",
            kind="benign",
            set="s",
            split="held-out",
            scanner="b00d203",
            date="2026-10-24",
            scans=ScoreKit.scans(tmp_path, [("a", 0, [])]),
        )
        out = Score.metrics({"random": {"k": 2, "n": 800, "failed": 0, "secret_only": 1}}, args)
        metric = out["pypi.heldout.random"]
        assert (metric["k"], metric["n"], metric["kind"]) == (2, 800, "benign_rate")
        assert "pct" not in metric
