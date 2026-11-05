"""The default text view, once the gate is known: what fails it in full, the rest as one line
(review 98, FP-9). `-v` and the machine formats keep every finding."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.report.base import ReportOptions
from cordon_scanner.report.text import TextReporter

SOURCE = (
    "const https = require('https');\n"
    "function ping() {\n"
    "  if (process.env.CI) return;\n"
    "  https.get('https://example.invalid/v1/ping');\n"
    "}\n"
    "module.exports = ping;\n"
)


class TieredKit:
    @staticmethod
    def result(tmp_path: Path):
        (tmp_path / "ping.js").write_text(SOURCE, encoding="utf-8")
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)

    @staticmethod
    def text(result, opts: ReportOptions) -> str:
        return b"".join(TextReporter().render(result, opts)).decode()


class TestTieredText:
    def test_a_gate_failure_is_printed(self, tmp_path: Path) -> None:
        result = TieredKit.result(tmp_path)
        rules = {f.rule_id for f in result.findings}
        assert "SUSPECT.ANTI_ANALYSIS.001" in rules
        failing = frozenset(
            f.fingerprint for f in result.findings if f.rule_id == "SUSPECT.ANTI_ANALYSIS.001"
        )
        text = TieredKit.text(result, ReportOptions(color=False, blocking=failing))
        assert "SUSPECT.ANTI_ANALYSIS.001" in text

    def test_below_the_gate_is_one_line(self, tmp_path: Path) -> None:
        result = TieredKit.result(tmp_path)
        text = TieredKit.text(result, ReportOptions(color=False, blocking=frozenset()))
        assert "SUSPECT.ANTI_ANALYSIS.001" not in text
        assert "below the failure policy" in text

    def test_quiet_drops_the_line(self, tmp_path: Path) -> None:
        result = TieredKit.result(tmp_path)
        text = TieredKit.text(result, ReportOptions(color=False, blocking=frozenset(), quiet=True))
        assert "below the failure policy" not in text

    def test_verbose_and_the_library_default_keep_everything(self, tmp_path: Path) -> None:
        result = TieredKit.result(tmp_path)
        tiered = ReportOptions(color=False, blocking=frozenset())
        for opts in (replace(tiered, verbose=True), ReportOptions(color=False)):
            assert "SUSPECT.ANTI_ANALYSIS.001" in TieredKit.text(result, opts)


class TestTheIncompletePointer:
    """An incomplete scan points the reader at its coverage notes only where they are: above, when
    they printed; behind `-v`, when the tiered view left them out; nowhere, when there are none.
    It said "see the coverage notes above" whatever was above."""

    @staticmethod
    def incomplete(tmp_path: Path, *severities):
        from cordon_scanner.foundation.models import Severity
        from cordon_scanner.foundation.results import OperationalFinding

        result = TieredKit.result(tmp_path)
        notes = [
            OperationalFinding.build(
                path="big.js",
                rule_id=f"OPERATIONAL.TEST.{i}",
                message="not read in full",
                remediation="-",
                severity=getattr(Severity, s),
            )
            for i, s in enumerate(severities)
        ]
        kept = [f for f in result.findings if f.category.value != "operational"]
        return replace(result, findings=tuple(kept + notes), complete=False)

    def test_notes_that_printed_are_pointed_to_above(self, tmp_path: Path) -> None:
        result = self.incomplete(tmp_path, "MEDIUM")
        text = TieredKit.text(result, ReportOptions(color=False, blocking=frozenset()))
        assert "not read in full" in text
        assert "see the coverage notes above" in text

    def test_notes_the_tiered_view_left_out_are_pointed_to_behind_verbose(
        self, tmp_path: Path
    ) -> None:
        result = self.incomplete(tmp_path, "INFO", "INFO")
        text = TieredKit.text(result, ReportOptions(color=False, blocking=frozenset()))
        assert "not read in full" not in text
        assert "notes above" not in text
        assert "2 coverage note(s) with -v" in text

    def test_no_notes_no_pointer(self, tmp_path: Path) -> None:
        result = self.incomplete(tmp_path)
        text = TieredKit.text(result, ReportOptions(color=False, blocking=frozenset()))
        assert "scan INCOMPLETE" in text
        assert "coverage notes" not in text
