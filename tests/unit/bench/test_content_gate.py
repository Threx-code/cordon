"""The narrowing gate (`bench/tools/content_gate.py`, release 0.8.0 item 18): content blocks compared
per unit, never exit statuses. Rows are built here in the harness's shape; no corpus is read."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from support import ROOT as REPO

sys.path.insert(0, str(REPO / "bench" / "tools"))

from content_gate import ContentGate, GateInputError

CONTENT = ["MALWARE.DROPPER.001", "critical", "high", "malicious", "setup.py", None, "capability"]
INTEL = ["MALWARE.PACKAGE.KNOWN.001", "critical", "high", "malicious", ".", None, "advisory"]


class GateKit:
    @staticmethod
    def row(unit: str, *findings: list, exit: int = 1, complete: bool = True) -> dict:
        return {
            "file": unit,
            "exit": exit,
            "complete": complete,
            "content_complete": complete,
            "findings": list(findings),
        }

    @staticmethod
    def write(path: Path, *rows: dict) -> Path:
        path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        return path

    @staticmethod
    def run(tmp_path: Path, kind: str, before: list, after: list, *extra: str) -> int:
        b = GateKit.write(tmp_path / "before.jsonl", *before)
        a = GateKit.write(tmp_path / "after.jsonl", *after)
        return ContentGate.main([str(b), str(a), "--kind", kind, *extra])


class TestMalware:
    def test_a_content_block_hidden_by_intel_is_still_lost(self, tmp_path) -> None:
        # 07398602's shape: the exit stayed 1 by intel, the content block went.
        before = [GateKit.row("m1", CONTENT, INTEL)]
        after = [GateKit.row("m1", INTEL)]
        assert GateKit.run(tmp_path, "malware", before, after) == 1

    def test_an_unchanged_block_passes(self, tmp_path) -> None:
        rows = [GateKit.row("m1", CONTENT), GateKit.row("m2", exit=0)]
        assert GateKit.run(tmp_path, "malware", rows, rows) == 0

    def test_a_named_trade_passes_and_is_reported(self, tmp_path) -> None:
        accept = tmp_path / "accept.tsv"
        accept.write_text("m1\tthe hook is a person-run CLI (owner 11-07)\n", encoding="utf-8")
        report = tmp_path / "r.json"
        code = GateKit.run(
            tmp_path, "malware", [GateKit.row("m1", CONTENT)], [GateKit.row("m1", exit=0)],
            "--accept", str(accept), "--json", str(report),
        )  # fmt: skip
        assert code == 0
        data = json.loads(report.read_text(encoding="utf-8"))
        assert data["accepted"][0]["rules_lost"] == ["MALWARE.DROPPER.001"]

    def test_a_scan_that_breaks_fails_even_with_a_block_before_and_after(self, tmp_path) -> None:
        before = [GateKit.row("m1", CONTENT)]
        after = [GateKit.row("m1", CONTENT, exit=4, complete=False)]
        assert GateKit.run(tmp_path, "malware", before, after) == 1


class TestBenign:
    def test_a_new_content_block_fails(self, tmp_path) -> None:
        before = [GateKit.row("b1", exit=0)]
        after = [GateKit.row("b1", CONTENT)]
        assert GateKit.run(tmp_path, "benign", before, after) == 1

    def test_a_cleared_block_passes(self, tmp_path) -> None:
        before = [GateKit.row("b1", CONTENT)]
        after = [GateKit.row("b1", exit=0)]
        assert GateKit.run(tmp_path, "benign", before, after) == 0


class TestInputs:
    def test_a_unit_missing_from_one_side_cannot_be_compared(self, tmp_path) -> None:
        before = [GateKit.row("m1", CONTENT), GateKit.row("m2", CONTENT)]
        after = [GateKit.row("m1", CONTENT)]
        assert GateKit.run(tmp_path, "malware", before, after) == 2

    def test_two_rows_for_one_unit_that_disagree_are_refused(self, tmp_path) -> None:
        path = GateKit.write(
            tmp_path / "x.jsonl", GateKit.row("m1", CONTENT), GateKit.row("m1", exit=0)
        )
        with pytest.raises(GateInputError):
            ContentGate.rows(path)

    def test_a_timeout_row_is_a_failed_scan(self, tmp_path) -> None:
        path = GateKit.write(tmp_path / "x.jsonl", {"file": "m1", "exit": "timeout"})
        score = ContentGate.rows(path)["m1"]
        assert not score.complete and not score.blocked

    def test_an_accepted_unit_needs_a_reason(self, tmp_path) -> None:
        accept = tmp_path / "a.tsv"
        accept.write_text("m1\n", encoding="utf-8")
        with pytest.raises(GateInputError):
            ContentGate.accepted(accept)
