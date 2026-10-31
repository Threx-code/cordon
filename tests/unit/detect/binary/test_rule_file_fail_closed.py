"""The rule-file engine's per-file bound (rule_engine.anchoring.places.Places.MOST): a file with more places to
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

from cordon_scanner.detect.binary import rule_files
from cordon_scanner.detect.binary.modules.values import Module
from cordon_scanner.detect.binary.rule_engine import scan, threads
from cordon_scanner.detect.binary.rule_engine.anchoring.places import Places, Unbounded
from cordon_scanner.detect.binary.rule_engine.anchoring.stream import Streams
from cordon_scanner.detect.binary.rule_engine.lang import RuleError, Rules

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
        monkeypatch.setattr(Places, "MOST", 100_000)
        monkeypatch.setattr(
            Streams, "ABOVE", 1 << 40
        )  # the whole-list hunt, which the bound guards
        rules = Rules.compile("rule z { strings: $z = { 00 00 00 00 } condition: #z > 5 }")
        before = Bound.peak_mb()
        with pytest.raises(RuleError) as caught:
            rules.match(ZEROS)
        assert isinstance(caught.value.__cause__, Unbounded)
        assert Bound.peak_mb() - before < 200

    def test_the_bound_is_the_files_not_each_strings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Five strings of 30,000 places each fit a bound of 100,000 one by one, not together."""
        monkeypatch.setattr(Places, "MOST", 100_000)
        monkeypatch.setattr(Streams, "ABOVE", 1 << 40)
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


class Scan:
    """One CLI scan of `files` against `rule`, as the Action and the guard hook run it."""

    @staticmethod
    def run(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, files: dict[str, bytes], rule: str
    ) -> tuple[int, dict[str, str], str]:
        (tmp_path / "pkg").mkdir()
        for name, data in files.items():
            (tmp_path / "pkg" / name).write_bytes(data)
        rules = tmp_path / "r.yar"
        rules.write_text(rule, encoding="utf-8")
        out = tmp_path / "out.json"
        argv = ["cordon-scanner", "scan", str(tmp_path / "pkg"), "--offline", "--no-color", "--quiet",
                "--rule-file", str(rules), "-f", f"json:{out}"]  # fmt: skip
        monkeypatch.setattr(sys, "argv", argv)
        with pytest.raises(SystemExit) as code:
            runpy.run_module("cordon_scanner", run_name="__main__")
        report = json.loads(out.read_text(encoding="utf-8"))
        found = {f["rule_id"]: f["severity"] for f in report["findings"]}
        why = next((f["message"] for f in report["findings"] if f["rule_id"] == UNMATCHED), "")
        assert report["complete"] is False
        return int(code.value.code or 0), found, why


UNMATCHED = "SUSPECT.RULEFILE.UNMATCHED.001"
MALWARE = 'rule z { meta: category = "malicious" strings: $z = { 00 00 00 00 } condition: #z > 5 }'


class TestEveryCauseFailsClosed:
    """Each way the matched file can stop a match fails the scan (a non-zero exit), named."""

    def test_the_places_bound(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Places, "MOST", 100_000)
        monkeypatch.setattr(Streams, "ABOVE", 1 << 40)
        code, found, why = Scan.run(tmp_path, monkeypatch, {"pad.bin": ZEROS}, MALWARE)
        assert code != 0 and found.get(UNMATCHED) == "high" and "places to try" in why

    def test_the_time_allowed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(rule_files, "MATCH_TIMEOUT_SECONDS", 0)
        code, found, why = Scan.run(tmp_path, monkeypatch, {"pad.bin": bytes(1 << 20)}, MALWARE)
        assert (
            code != 0 and found.get(UNMATCHED) == "high" and "longer than the time allowed" in why
        )

    def test_the_thread_limit(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(threads, "MAX_THREADS", 2)
        rule = 'rule r { meta: category = "malicious" strings: $r = /a[ab]{0,40}b/ condition: $r }'
        code, found, why = Scan.run(tmp_path, monkeypatch, {"x.bin": b"\x00" + b"ab" * 200}, rule)
        assert code != 0 and found.get(UNMATCHED) == "high" and "too many threads" in why

    def test_a_module_that_cannot_read_the_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Rules.loaded(None)

        def broken(file: bytes) -> dict[str, object]:
            raise ValueError("a header the reader could not read")

        monkeypatch.setitem(Rules.BUILT_IN, "pe", Module(Rules.BUILT_IN["pe"].schema, broken))
        rule = 'import "pe" rule r { meta: category = "malicious" condition: pe.number_of_sections > 0 }'
        code, found, why = Scan.run(tmp_path, monkeypatch, {"x.exe": b"MZ" + bytes(500)}, rule)
        assert code != 0 and found.get(UNMATCHED) == "high" and "could not read" in why

    def test_a_rule_file_that_does_not_compile_is_configuration(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The operator's own mistake, not the file's doing: reported, not a finding against a file."""
        _code, found, _ = Scan.run(
            tmp_path, monkeypatch, {"x.bin": b"abc"}, "rule r { condition: nonsense( }"
        )
        assert "OPERATIONAL.RULEFILE.UNAVAILABLE" in found and UNMATCHED not in found


class TestTheStream:
    def test_the_zeros_are_matched_in_bounded_memory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Streamed, 8 MB of zeros is matched, not refused, and holds the matches and nothing more."""
        monkeypatch.setattr(Places, "MOST", 100_000)
        rules = Rules.compile("rule z { strings: $z = { 00 00 00 00 } condition: #z > 5 }")
        before = Bound.peak_mb()
        found = rules.match(ZEROS)
        assert [m.rule for m in found] == ["z"] and len(
            found[0].strings
        ) == scan.MAX_HITS  # stopped where the whole-list hunt stops
        assert Bound.peak_mb() - before < 1200  # the matches themselves; no list of every place
