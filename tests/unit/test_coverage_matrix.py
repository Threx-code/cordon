"""The coverage matrix must describe what ships.

A hand-kept matrix drifts, and a drifted one claims coverage that is not there.
That is the same failure this scanner is built to prevent in the code it reads,
so it would be a poor thing to ship in its own documentation.

The document is generated, and this fails when the file on disk disagrees with
what the tool actually contains -- which means adding a rule without
regenerating fails the build rather than quietly leaving the matrix wrong.
"""

from __future__ import annotations

import re
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

    def test_every_flag_the_matrix_names_exists(self) -> None:
        """The matrix is generated from the shipped rules and CI fails on
        drift, but nothing tied the FLAGS it names to the parser. So it told
        users the registry checks "require `--online`" while no such flag
        existed anywhere in the CLI: five written, tested, shipped rules that
        no documented invocation could reach.

        A rule that cannot be run is not coverage, and a document is not a
        control unless something checks it.
        """
        from cordon_scanner.cli.main import CommandLine

        text = MATRIX.read_text(encoding="utf-8")
        parser = CommandLine.build_parser()
        known = set(parser.format_help().split())
        for action in parser._subparsers._group_actions:
            for sub in action.choices.values():
                known.update(sub.format_help().split())

        # The matrix also documents how to regenerate the policies it counts,
        # and that is a different program. The guard is the same either way: a
        # documented invocation has to be runnable, so the release scripts'
        # own options count as known.
        for script in sorted((MATRIX.parents[1] / "scripts").glob("*.py")):
            known.update(
                re.findall(
                    r"add_argument\(\s*\"(--[a-z][a-z-]+)\"", script.read_text(encoding="utf-8")
                )
            )

        # `--` then a letter, which excludes markdown's own horizontal rule.
        named = set(re.findall(r"--[a-z][a-z-]+", text))
        missing = sorted(flag for flag in named if flag not in known)
        assert not missing, f"the matrix names flags nothing here has: {missing}"


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
