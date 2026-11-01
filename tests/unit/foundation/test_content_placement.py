"""foundation.content (item 48): a match is shown at its first byte that is not a line terminator. A
pattern may begin with whitespace, so a match can start on the newline ending the line before it; the
user's v0.6.0 report showed SUSPECT.AGENT.ATR.PROMPT_INJECTION.001 at .cursorrules:1:28, line 1's
newline, with line 1's harmless text as evidence, while the injection is on line 2."""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from support import ROOT

SAMPLE = ROOT / "corpus" / "malicious" / "agent-rules-injection"
MALICIOUS = ROOT / "corpus" / "malicious"


class TestPlacement:
    @pytest.mark.parametrize(
        ("raw", "offset", "where"),
        [
            (b"first line\nsecond\n", 10, (2, 1)),  # on line 1's newline: placed on line 2
            (b"first line\r\nsecond\n", 10, (2, 1)),  # on a CRLF's carriage return
            (b"first\n\n\nfourth\n", 5, (4, 1)),  # a run of empty lines
            (b"first line\nsecond\n", 3, (1, 4)),  # inside a line: unchanged
        ],
    )
    def test_a_match_starting_on_a_terminator_is_placed_after_it(self, raw, offset, where) -> None:
        content = FileContent.from_bytes("x.txt", raw)
        assert (content.line_of(offset), content.column_of(offset)) == where

    def test_only_terminators_left_keeps_the_offset(self) -> None:
        content = FileContent.from_bytes("x.txt", b"last line\n")
        assert content.line_of(9) == 1

    def test_a_match_s_last_byte_is_not_moved(self) -> None:
        """`place=False`: a match that ends with its line's newline ends on that line."""
        content = FileContent.from_bytes("x.txt", b"first line\nsecond\n")
        assert content.line_of(10, place=False) == 1
        assert content.column_of(10, place=False) == 11


class TestTheReportedCase:
    def test_the_injection_is_on_its_own_line(self) -> None:
        result = Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(
            SAMPLE
        )
        found = [
            f
            for f in result.findings
            if f.location.path.endswith(".cursorrules") and f.location.line
        ]
        assert found
        assert all(f.location.line == 2 for f in found), [
            (f.rule_id, f.location.line, f.location.column) for f in found
        ]


class TestEveryRuleIsPlacedOnContent:
    """Over every malicious corpus sample, every finding with a line and column: the byte there is
    not a line terminator, whichever rule placed it."""

    @pytest.mark.parametrize(
        "sample", sorted(p for p in MALICIOUS.iterdir() if p.is_dir()), ids=lambda p: p.name
    )
    def test_no_finding_points_at_a_line_end(self, sample: Path) -> None:
        result = Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(
            sample
        )
        bad = []
        for f in result.findings:
            loc = f.location
            if not (loc.line and loc.column) or "!" in (loc.path or "") or "#" in (loc.path or ""):
                continue
            target = sample / loc.path if not Path(loc.path).is_absolute() else Path(loc.path)
            if not target.is_file():
                continue
            lines = target.read_bytes().split(b"\n")
            if loc.line > len(lines):
                continue
            line = lines[loc.line - 1].rstrip(b"\r")
            if loc.column > len(line) and line:
                bad.append((f.rule_id, loc.path, loc.line, loc.column, len(line)))
        assert not bad, bad


class TestTheNameLineStillDecides:
    """detect/secrets/values.py's WRAPPED_ASSIGNMENT reads the line BEFORE a value: `TOKEN =` gives
    its name to the value on the next line (modelling team's review of note 48). Placed at the value's
    first byte, the name line is the one before, as the rule means; a wrapped assignment is graded as
    the same assignment on one line."""

    #: An AWS-shaped access key id, built here so this file holds no key-shaped literal.
    KEY = "AKIA" + "Q" * 4 + "7" * 4 + "Z" * 8

    @staticmethod
    def graded(tmp_path, text: str, name: str) -> list[tuple[str, str]]:
        root = tmp_path / name
        root.mkdir()
        (root / "settings.js").write_text(text, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(root)
        return sorted(
            (f.rule_id, f.severity.name) for f in result.findings if f.rule_id.startswith("SECRET.")
        )

    @pytest.mark.parametrize("name", ["EXAMPLE_ACCESS_KEY", "ACCESS_KEY"])
    def test_wrapped_is_graded_as_one_line(self, tmp_path, name: str) -> None:
        # the form the rule reads: a line ending in `=` gives its name to the value on the next line
        one = self.graded(tmp_path, f'const {name} = "{self.KEY}";\n', "one")
        wrapped = self.graded(tmp_path, f'const {name} =\n    "{self.KEY}";\n', "wrapped")
        assert wrapped == one
