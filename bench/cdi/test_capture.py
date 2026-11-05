"""Live capture intake: only usable labels enter, the split follows the bytes, misses come from dev only."""

from __future__ import annotations

import json
from pathlib import Path

from bench.cdi.capture import CaptureIntake


class CaptureKit:
    @staticmethod
    def manifest(tmp_path: Path, *rows: dict) -> Path:
        path = tmp_path / "manifest.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        return path

    @staticmethod
    def row(sha: str, state: str = "confirmed_malicious", tier: str = "confirmed") -> dict:
        return {
            "ecosystem": "npm",
            "sha256": sha,
            "state": state,
            "tier": tier,
            "file": f"npm/{sha}.tgz",
        }


class TestCaptureIntake:
    def test_only_a_confirmed_or_corroborated_malicious_label_enters(self, tmp_path: Path) -> None:
        manifest = CaptureKit.manifest(
            tmp_path,
            CaptureKit.row("a" * 64),
            CaptureKit.row("b" * 64, tier="corroborated"),
            CaptureKit.row("c" * 64, state="suspicious", tier="silver"),
            CaptureKit.row("d" * 64, state="", tier=""),
            CaptureKit.row("e" * 64, state="confirmed_benign"),
        )
        assert [r["sha256"][0] for r in CaptureIntake.labelled(manifest)] == ["a", "b"]

    def test_the_same_bytes_under_two_names_enter_once(self, tmp_path: Path) -> None:
        manifest = CaptureKit.manifest(tmp_path, CaptureKit.row("a" * 64), CaptureKit.row("a" * 64))
        assert len(CaptureIntake.labelled(manifest)) == 1

    def test_the_split_depends_on_the_bytes_alone_and_uses_both_halves(self) -> None:
        rows = [CaptureKit.row(f"{i:064x}") for i in range(200)]
        halves = CaptureIntake.split(rows)
        assert halves == CaptureIntake.split(list(reversed(rows)))
        assert len(halves["dev"]) + len(halves["sealed"]) == 200
        assert 60 < len(halves["dev"]) < 140

    def test_a_miss_is_a_unit_not_blocked_and_a_failed_scan_is_a_miss(self, tmp_path: Path) -> None:
        records = tmp_path / "off.jsonl"
        records.write_text(
            json.dumps({"file": "npm/x.tgz", "exit": 1})
            + "\n"
            + json.dumps({"file": "npm/y.tgz", "exit": 0})
            + "\n"
            + json.dumps({"file": "npm/z.tgz", "exit": "timeout"})
            + "\n",
            encoding="utf-8",
        )
        units = ["npm/x.tgz", "npm/y.tgz", "npm/z.tgz", "npm/never-scanned.tgz"]
        assert CaptureIntake.misses(records, units) == units[1:]

    def test_a_benign_set_names_its_records_and_mount(self) -> None:
        spec = CaptureIntake.benign_set("npm-benign=/c/n/off.jsonl:n/")
        assert (spec["name"], spec["kind"], spec["off"], spec["prefix"]) == (
            "npm-benign",
            "benign",
            "/c/n/off.jsonl",
            "n/",
        )
