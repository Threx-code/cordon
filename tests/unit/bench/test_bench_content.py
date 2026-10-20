"""Content recall counts only what the package's own bytes showed (`bench/tools/content.py`, #21).

```
  exit 1 + a known-sample match                 -> known    (intel, never content)
  exit 1 + only intel findings failing the gate -> intel    (a feed, a registry record, clamav)
  exit 1 + a content finding failing the gate   -> blocked  (content recall)
  a scan that failed                            -> error    (a sample not caught: lowers recall)
```
"""

from __future__ import annotations

import re
import sys
from typing import ClassVar

from support import ROOT as REPO

sys.path.insert(0, str(REPO / "bench" / "tools"))
sys.path.insert(0, str(REPO / "bench" / "suites"))
sys.path.insert(0, str(REPO / "bench"))

from content import CONTENT_DETECTORS, INTEL_DETECTORS, Content
from run import SuiteResult, Verdict
from timesplit import Levels, TimeSplit

from cordon_scanner import Scanner
from cordon_scanner.foundation.config import Config


class TestLevels:
    @staticmethod
    def row(rule: str, detector: str, severity: str = "critical", confidence: str = "high") -> list:
        category = "malicious" if rule.startswith("MALWARE.") else "suspicious"
        return [rule, severity, confidence, category, "a.js", "", detector]

    def test_a_known_match_outranks_a_content_block(self) -> None:
        findings = [
            self.row("MALWARE.PACKAGE.KNOWN.001", "advisory"),
            self.row("MALWARE.DROPPER.001", "capability"),
        ]
        assert Levels.of(1, findings) == "known"

    def test_a_block_intel_alone_made_is_not_content(self) -> None:
        findings = [self.row("MALWARE.CLAMAV.SIGNATURE.001", "clamav")]
        assert Levels.of(1, findings) == "intel"

    def test_a_release_history_rule_from_a_content_detector_is_not_content(self) -> None:
        findings = [self.row("SUSPECT.RELEASE.NEW_PUBLISHER.001", "manifest", severity="high")]
        assert Levels.of(1, findings) == "intel"

    def test_a_content_block_beside_intel_is_content(self) -> None:
        findings = [
            self.row("MALWARE.CLAMAV.SIGNATURE.001", "clamav"),
            self.row("MALWARE.DROPPER.001", "capability"),
        ]
        assert Levels.of(1, findings) == "blocked"

    def test_a_content_finding_below_the_gate_does_not_make_the_block_content(self) -> None:
        findings = [
            self.row("MALWARE.CLAMAV.SIGNATURE.001", "clamav"),
            self.row("SUSPECT.OBFUSCATION.LONGLINE.001", "obfuscation", severity="low"),
        ]
        assert Levels.of(1, findings) == "intel"

    def test_rows_recorded_without_a_detector_read_as_before(self) -> None:
        findings = [["SUSPECT.DROPPER.001", "high", "medium", "suspicious", "a.js"]]
        assert Levels.of(1, findings) == "blocked"


class TestRecallOverEverySample:
    LISTING: ClassVar[dict[str, object]] = {"frozen": "f", "head": "h"}

    def test_a_failed_scan_lowers_content_recall(self) -> None:
        rows = [{"level": "blocked"}] * 8 + [{"level": "error"}] * 2
        summary = TimeSplit.summary(self.LISTING, rows)
        assert summary["content_recall"] == 0.8
        assert summary["content_recall_answered"] == 1.0
        assert summary["errors"] == 2

    def test_intel_blocks_count_with_intel_never_as_content(self) -> None:
        rows = [{"level": "blocked"}] * 6 + [{"level": "intel"}] * 2 + [{"level": "known"}] * 2
        summary = TimeSplit.summary(self.LISTING, rows)
        assert summary["content_recall"] == 0.6
        assert summary["recall_with_intel"] == 1.0

    def test_the_98_claim_needs_enough_samples_counting_the_failed_ones(self) -> None:
        rows = [{"level": "blocked"}] * 640 + [{"level": "error"}] * 10
        assert TimeSplit.summary(self.LISTING, rows)["enough_for_a_98_claim"]

    def test_the_suite_content_rate_counts_failed_scans_against_it(self) -> None:
        verdicts = [Verdict("cordon", f"s{i}", True, "", 0.0, level="blocked") for i in range(3)]
        verdicts += [Verdict("cordon", "s3", True, "", 0.0, level="intel")]
        verdicts += [Verdict("cordon", "s4", None, "", 0.0, level="error")]
        content = SuiteResult("s", verdicts).rates()["cordon, content only"]
        assert content["blocked"] == 3
        assert content["rate"] == 0.6
        assert content["rate_answered"] == 0.75

    def test_a_benign_block_by_intel_still_counts_against_the_benign_rate(self) -> None:
        verdicts = [Verdict("cordon", f"s{i}", False, "", 0.0, level="clean") for i in range(3)]
        verdicts += [Verdict("cordon", "s3", True, "", 0.0, level="intel")]
        levels = SuiteResult("s", verdicts).rates()["cordon, levels"]
        assert levels["not_blocked"] == 0.75


class TestEveryDetectorIsClassified:
    @staticmethod
    def detectors() -> set[str]:
        """Every detector a finding can carry: the ones the engine registers, and the ones the
        engine and the decision layer emit findings under themselves."""
        engine = Scanner(Config.default().with_overrides(use_cache=False))._engine
        registered = {d.id for d in engine.detectors}
        emitted: set[str] = set()
        for path in (REPO / "src" / "cordon_scanner").rglob("*.py"):
            emitted |= set(re.findall(r'detector="([a-z][a-z-]*)"', path.read_text("utf-8")))
        return registered | emitted

    def test_each_is_content_or_intel_and_never_both(self) -> None:
        assert not CONTENT_DETECTORS & INTEL_DETECTORS
        unclassified = self.detectors() - CONTENT_DETECTORS - INTEL_DETECTORS
        assert not unclassified, (
            f"classify {sorted(unclassified)} in bench/tools/content.py: content if it reads only the "
            "package's own bytes, intel if it reads a feed, a registry, history or known samples"
        )

    def test_an_unclassified_detector_is_intel(self) -> None:
        assert not Content.is_content("MALWARE.NEW.001", "a-detector-nobody-classified")
