"""The benchmark reports what a user saw, in five levels, with intervals.

```
  exit 1 + only the known-release rule  -> known      exit 0/4 + a medium-or-higher finding -> warned
  exit 1 + a content finding that gates -> blocked    exit 0/4 + low or info only           -> noted
  anything else from the scanner        -> error      exit 0/4 + nothing                    -> clean
```
"""

from __future__ import annotations

import sys

from support import ROOT as REPO

sys.path.insert(0, str(REPO / "bench" / "tools"))
sys.path.insert(0, str(REPO / "bench" / "suites"))
sys.path.insert(0, str(REPO / "bench"))

from run import KNOWN_RELEASE_RULE, Levels, SuiteResult, Verdict, Wilson


class TestLevels:
    def test_a_known_release_alone_is_known(self) -> None:
        assert (
            Levels.of(1, [[KNOWN_RELEASE_RULE, "critical", "confirmed", "malicious", "x"]])
            == "known"
        )

    def test_a_known_dependency_is_known_too(self) -> None:
        findings = [["MALWARE.DEPENDENCY.KNOWN.001", "critical", "confirmed", "malicious", "x"]]
        assert Levels.of(1, findings) == "known"

    def test_a_content_block_is_blocked(self) -> None:
        findings = [["SUSPECT.DROPPER.001", "high", "medium", "suspicious", "a.js"]]
        assert Levels.of(1, findings) == "blocked"

    def test_a_medium_finding_that_passes_is_a_warning(self) -> None:
        assert (
            Levels.of(0, [["SUSPECT.EXFIL.001", "medium", "medium", "suspicious", "a.py"]])
            == "warned"
        )

    def test_a_high_finding_below_the_confidence_gate_is_still_a_warning(self) -> None:
        assert (
            Levels.of(0, [["SUSPECT.AGENT.ATR.X.001", "high", "low", "suspicious", "SKILL.md"]])
            == "warned"
        )

    def test_operational_notes_do_not_warn(self) -> None:
        assert (
            Levels.of(0, [["OPERATIONAL.SCAN.INCOMPLETE.001", "medium", "high", "operational", ""]])
            == "clean"
        )

    def test_low_only_is_noted_and_nothing_is_clean(self) -> None:
        assert Levels.of(0, [["SUSPECT.X.001", "low", "low", "suspicious", ""]]) == "noted"
        assert Levels.of(0, []) == "clean"
        assert Levels.of(2, []) == "error"


class TestRates:
    def test_both_benign_rates_with_intervals(self) -> None:
        suite = SuiteResult("benign")
        levels = ["clean"] * 96 + ["warned"] * 3 + ["blocked"] + ["known"] * 5
        suite.verdicts = [
            Verdict("cordon", f"s{i}", level == "blocked", level=level)
            for i, level in enumerate(levels)
        ]
        row = suite.rates()["cordon, levels"]
        assert row["not_blocked"] == 0.99 and row["no_warning"] == 0.96
        low, high = row["no_warning_95"]
        assert low < 0.96 < high

    def test_a_perfect_small_sample_does_not_claim_98(self) -> None:
        low, _ = Wilson.interval(150, 150)
        assert low < 0.98
