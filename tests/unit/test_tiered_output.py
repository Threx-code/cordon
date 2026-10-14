"""The default text view, once the gate is known: what fails it in full, the rest as one line
(review 98, FP-9). `-v` and the machine formats keep every finding."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
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
