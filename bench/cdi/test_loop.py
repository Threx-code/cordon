"""The loop's exactness: only units a pack's patterns match can change, and merging keeps the rest."""

from __future__ import annotations

import json
from pathlib import Path

from bench.cdi.discover import Discovery
from bench.cdi.loop import CdiLoop, PackMatch

SHARED = "run: send-marker --to collector.invalid --token placeholder-value"


class LoopKit:
    @staticmethod
    def unit(root: Path, name: str, text: str) -> None:
        path = root / name / ".github" / "workflows"
        path.mkdir(parents=True)
        (path / "ci.yml").write_text(text + "\n", encoding="utf-8")

    @staticmethod
    def pack(tmp_path: Path) -> Path:
        misses = []
        for i in range(3):
            LoopKit.unit(tmp_path / "m", f"m{i}", SHARED)
            misses.append(str(tmp_path / "m" / f"m{i}"))
        text, _ = Discovery.run(
            misses, [], min_support=3, max_rules=5, pack_id="cdi.t", reference="t", paths=[]
        )
        assert text is not None
        path = tmp_path / "rulepack-cdi-t.yaml"
        path.write_text(text, encoding="utf-8")
        return path


class TestTheLoop:
    def test_only_units_the_pack_matches_are_touched(self, tmp_path: Path) -> None:
        pack = LoopKit.pack(tmp_path)
        LoopKit.unit(tmp_path / "s", "hit", SHARED)
        LoopKit.unit(tmp_path / "s", "miss", "run: echo nothing to see in this step")
        assert PackMatch.units(pack, tmp_path / "s", ["hit", "miss"]) == ["hit"]

    def test_merging_replaces_the_rescanned_rows_and_keeps_the_rest(self, tmp_path: Path) -> None:
        off = tmp_path / "off.jsonl"
        off.write_text(
            "".join(json.dumps({"file": f, "exit": 0}) + "\n" for f in ("a", "b")), encoding="utf-8"
        )
        fresh = tmp_path / "fresh.jsonl"
        fresh.write_text(json.dumps({"file": "g/b", "exit": 1}) + "\n", encoding="utf-8")
        out = tmp_path / "on.jsonl"
        CdiLoop.merged(off, fresh, out, prefix="g/")
        rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
        assert rows == [{"file": "a", "exit": 0}, {"file": "b", "exit": 1}]

    def test_a_supplied_pack_skips_discovery_and_is_gated_the_same(self, tmp_path: Path) -> None:
        pack = LoopKit.pack(tmp_path)
        LoopKit.unit(tmp_path / "s", "quiet", "run: echo nothing to see in this step")
        off = tmp_path / "off.jsonl"
        off.write_text(
            json.dumps({"file": "quiet", "exit": 0, "seconds": 1.0}) + "\n", encoding="utf-8"
        )
        config = {
            "root": str(tmp_path / "s"),
            "tools": str(tmp_path / "no-tools"),
            "pack": str(pack),
            "pack_id": "cdi.t",
            "sets": [
                {
                    "name": "benign",
                    "kind": "benign",
                    "area": "actions",
                    "split": "work",
                    "off": str(off),
                }
            ],
        }
        result = CdiLoop.run(config, tmp_path / "work", None)
        report = json.loads(
            (tmp_path / "work" / "discovery_report.json").read_text(encoding="utf-8")
        )
        assert report["kind"] == "SuppliedPack"
        # No reach listing configured: the gate refuses a pack it cannot see the reach of.
        assert result["gates"]["reach"]["result"] == "fail"
        assert result["rescanned"] == {"benign": {"units": 1, "matched_and_rescanned": 0}}
        assert (tmp_path / "work" / "promotion_decision.json").is_file()

    def test_reach_counts_matches_in_every_listed_area(self, tmp_path: Path) -> None:
        pack = LoopKit.pack(tmp_path)
        LoopKit.unit(tmp_path / "r", "hit", SHARED)
        LoopKit.unit(tmp_path / "r", "quiet", "run: echo nothing to see in this step")
        listing = tmp_path / "npm.txt"
        listing.write_text("hit\nquiet\n", encoding="utf-8")
        reach = PackMatch.reach(
            pack, [{"area": "npm", "root": str(tmp_path / "r"), "listing": str(listing)}], 2
        )
        assert (reach["npm"]["units"], reach["npm"]["matched"], reach["npm"]["examples"]) == (
            2,
            1,
            ["hit"],
        )

    def test_a_rule_scoped_to_workflows_does_not_reach_other_files(self, tmp_path: Path) -> None:
        misses = []
        for i in range(3):
            LoopKit.unit(tmp_path / "m", f"m{i}", SHARED)
            misses.append(str(tmp_path / "m" / f"m{i}"))
        text, _ = Discovery.run(
            misses,
            [],
            min_support=3,
            max_rules=5,
            pack_id="cdi.t",
            reference="t",
            paths=["**/.github/workflows/*.yml"],
        )
        pack = tmp_path / "rulepack-cdi-t.yaml"
        pack.write_text(text or "", encoding="utf-8")
        (tmp_path / "r" / "readme").mkdir(parents=True)
        (tmp_path / "r" / "readme" / "README.md").write_text(SHARED + "\n", encoding="utf-8")
        LoopKit.unit(tmp_path / "r", "wf", SHARED)
        assert PackMatch.units(pack, tmp_path / "r", ["readme", "wf"]) == ["wf"]
