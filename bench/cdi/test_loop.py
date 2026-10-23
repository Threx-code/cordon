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
