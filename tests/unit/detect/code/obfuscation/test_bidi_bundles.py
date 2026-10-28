"""Bidi controls in bundled strings, as against Trojan Source (review 98, FP-7).

The control is written at run time from an escape, so this file does not itself carry one.
"""

from __future__ import annotations

from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Severity

RLO = "‮"  # U+202E RIGHT-TO-LEFT OVERRIDE -- the Trojan Source primitive
LRE = "‪"  # LEFT-TO-RIGHT EMBEDDING (opener)
PDF = "‬"  # POP DIRECTIONAL FORMATTING (closes an embedding)
RLI = "⁧"  # RIGHT-TO-LEFT ISOLATE (opener)
PDI = "⁩"  # POP DIRECTIONAL ISOLATE (closes an isolate)


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

    def test_a_balanced_inert_embedding_in_a_literal_is_display_data(self, tmp_path: Path) -> None:
        # census D: a phone number wrapped in LRE..PDF inside a string literal, in hand-written
        # source, is an iOS-style display label -- it reorders only its own digits, not the code.
        found = BidiKit.severities(tmp_path, "src/fmt.py", f"label = '{LRE}158 8020 6986{PDF}'\n")
        assert found == {Severity.INFO}, found

    def test_a_stretched_string_with_a_delimiter_stays_high(self, tmp_path: Path) -> None:
        # Trojan Source stretched-string variant (CVE-2021-42574): a balanced isolate inside a
        # literal whose span carries code delimiters -- a paren and a semicolon -- so the text
        # after it re-reads. The delimiter in the span is non-inert, so it stays high.
        found = BidiKit.severities(tmp_path, "src/app.py", f'cmd = "run{RLI}); drop(){PDI}safe"\n')
        assert found == {Severity.HIGH}, found

    def test_an_override_anywhere_keeps_a_balanced_embedding_high(self, tmp_path: Path) -> None:
        # Even a balanced inert embedding stays high if the file also carries an override: the
        # override is the attack primitive, and its presence is not excused by display data.
        text = f"label = '{LRE}158 8020{PDF}'\nrole = \"user{RLO} // admin\"\n"
        found = BidiKit.severities(tmp_path, "src/app.py", text)
        assert Severity.HIGH in found, found
