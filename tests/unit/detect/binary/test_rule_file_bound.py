"""The rule-file engine's per-file bound (rule_engine.scan.Search.MOST): a file with more places to
try than the bound, in all of its strings together, is refused instead of built in memory, and the
refusal fails the gate (SUSPECT.RULEFILE.UNBOUNDED.001, HIGH): a file padded on purpose to reach the
bound (malware followed by megabytes of zeros) is never passed as clean. Run on 8 MB of zeros with
the bound lowered, so CI can afford it, with the peak memory asserted."""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path

import pytest

from cordon_scanner.detect.binary.rule_engine.lang import RuleError, Rules
from cordon_scanner.detect.binary.rule_engine.scan import Search, Unbounded

ZEROS = bytes(8 << 20)


class Bound:
    @staticmethod
    def peak_mb() -> int:
        """The process's peak resident memory in MB (where the platform reports it; else 0)."""
        try:
            import resource
        except ImportError:  # not on Windows
            return 0
        return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) // 1024


class TestTheBound:
    def test_one_string_past_the_bound_refuses_the_file(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(Search, "MOST", 100_000)
        rules = Rules.compile("rule z { strings: $z = { 00 00 00 00 } condition: #z > 5 }")
        before = Bound.peak_mb()
        with pytest.raises(RuleError) as caught:
            rules.match(ZEROS)
        assert isinstance(caught.value.__cause__, Unbounded)
        assert Bound.peak_mb() - before < 200

    def test_the_bound_is_the_files_not_each_strings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Five strings of 30,000 places each fit a bound of 100,000 one by one, not together."""
        monkeypatch.setattr(Search, "MOST", 100_000)
        data = b"".join(bytes([i]) * 4 + b"x" for i in range(1, 6)) * 30_000
        strings = " ".join(f"$s{i} = {{ {i:02x} {i:02x} }}" for i in range(1, 6))
        alone = Rules.compile("rule a { strings: $s1 = { 01 01 } condition: #s1 > 0 }")
        assert [m.rule for m in alone.match(data)] == ["a"]
        together = Rules.compile(f"rule b {{ strings: {strings} condition: all of them }}")
        with pytest.raises(RuleError) as caught:
            together.match(data)
        assert isinstance(caught.value.__cause__, Unbounded)

    def test_under_the_bound_nothing_changes(self) -> None:
        rules = Rules.compile("rule z { strings: $z = { 00 00 00 00 } condition: #z == 997 }")
        assert [m.rule for m in rules.match(bytes(1000))] == ["z"]


class TestFailClosed:
    def test_a_padded_file_fails_the_scan(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(Search, "MOST", 100_000)
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "pad.bin").write_bytes(ZEROS)
        rules = tmp_path / "r.yar"
        rules.write_text(
            'rule z { meta: category = "malicious" strings: $z = { 00 00 00 00 } condition: #z > 5 }',
            encoding="utf-8",
        )
        out = tmp_path / "out.json"
        argv = ["cordon-scanner", "scan", str(tmp_path / "pkg"), "--offline", "--no-color", "--quiet",
                "--rule-file", str(rules), "-f", f"json:{out}"]  # fmt: skip
        monkeypatch.setattr(sys, "argv", argv)
        with pytest.raises(SystemExit) as code:
            runpy.run_module("cordon_scanner", run_name="__main__")
        report = json.loads(out.read_text(encoding="utf-8"))
        ids = {f["rule_id"]: f["severity"] for f in report["findings"]}
        assert ids.get("SUSPECT.RULEFILE.UNBOUNDED.001") == "high"
        assert report["complete"] is False
        assert code.value.code not in (0, None)
