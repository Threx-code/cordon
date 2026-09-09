"""The coverage matrix must describe what ships.

A hand-kept matrix drifts, and a drifted one claims coverage that is not there.
That is the same failure this scanner is built to prevent in the code it reads,
so it would be a poor thing to ship in its own documentation.

The document is generated, and this fails when the file on disk disagrees with
what the tool actually contains -- which means adding a rule without
regenerating fails the build rather than quietly leaving the matrix wrong.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from matrix import render, shipped_rules

MATRIX = Path(__file__).resolve().parents[2] / "docs" / "05-COVERAGE-MATRIX.md"


@pytest.mark.skipif(not MATRIX.exists(), reason="docs/ is not shipped in the sdist")
class TestTheMatrixIsCurrent:
    def test_it_matches_what_the_tool_ships(self) -> None:
        assert MATRIX.read_text(encoding="utf-8") == render(), (
            "docs/05-COVERAGE-MATRIX.md is out of date. Regenerate it:\n"
            "    python tests/matrix.py > docs/05-COVERAGE-MATRIX.md"
        )

    def test_every_shipped_rule_appears(self) -> None:
        text = MATRIX.read_text(encoding="utf-8")
        missing = [rule_id for rule_id in shipped_rules() if f"`{rule_id}`" not in text]
        assert not missing, f"rules absent from the coverage matrix: {sorted(missing)}"

    def test_it_is_not_vacuous(self) -> None:
        """Guards the two above from passing on an empty enumeration."""
        assert len(shipped_rules()) > 40


@pytest.mark.skipif(not MATRIX.exists(), reason="docs/ is not shipped in the sdist")
class TestItSaysWhatIsMissing:
    """A matrix listing only what exists is an advertisement, not a document."""

    def test_the_limits_are_stated(self) -> None:
        text = MATRIX.read_text(encoding="utf-8")
        for expected in (
            "Runtime behaviour",
            "require `--online`",
            "inherit no behavioural rules",
        ):
            assert expected in text, expected
