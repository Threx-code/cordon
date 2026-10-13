"""Bidi controls in bundled strings, as against Trojan Source (review 98, FP-7).

The control is written at run time from an escape, so this file does not itself carry one.
"""

from __future__ import annotations

from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.core.models import Severity

RLO = "‮"


class BidiKit:
    @staticmethod
    def severities(tmp_path: Path, path: str, text: str) -> set[Severity]:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        config = Config.default().with_overrides(use_cache=False, severity_threshold=Severity.INFO)
        result = Scanner(config).scan(tmp_path)
        return {f.severity for f in result.findings if f.rule_id == "SUSPECT.OBFUSCATION.BIDI.001"}


class TestBidi:
    def test_in_a_bundled_string_it_is_display_data(self, tmp_path: Path) -> None:
        found = BidiKit.severities(tmp_path, "static/js/katex.min.js", f'var dir="{RLO}";\n')
        assert found == {Severity.INFO}

    def test_in_hand_written_source_it_stays_high(self, tmp_path: Path) -> None:
        found = BidiKit.severities(tmp_path, "src/app.js", f'var role = "user{RLO} // admin";\n')
        assert found == {Severity.HIGH}

    def test_in_a_bundled_comment_it_is_not_demoted(self, tmp_path: Path) -> None:
        # Generated output keeps its existing ceiling (MEDIUM); only a string is display data.
        found = BidiKit.severities(tmp_path, "dist/app.js", f"/* {RLO} */ var a = 1;\n")
        assert found and all(s > Severity.INFO for s in found)
