"""A scan stops being complete in one place, which records why (`Accumulator.incomplete`, `gap`,
`named_elsewhere`): an assignment to `acc.complete` anywhere else would leave a gap whose cause the
gate never sees, the fail-open item 27 closed. And every content cause the gate blocks on is a rule
the scanner can actually report, so a misspelt id cannot quietly never block."""

from __future__ import annotations

import ast

from cordon_scanner.foundation.results import CONTENT_GAPS
from support import ROOT

SRC = ROOT / "src" / "cordon_scanner"
ACCUMULATOR = SRC / "engine" / "pipeline" / "accumulator.py"


class CompletenessKit:
    @staticmethod
    def assignments() -> list[str]:
        """Every `<...acc>.complete = ...` outside the accumulator, as file:line."""
        found = []
        for path in sorted(SRC.rglob("*.py")):
            if path == ACCUMULATOR:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                targets = (
                    node.targets
                    if isinstance(node, ast.Assign)
                    else [node.target]
                    if isinstance(node, ast.AugAssign | ast.AnnAssign)
                    else []
                )
                for target in targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and target.attr == "complete"
                        and ast.unparse(target.value).split(".")[-1] == "acc"
                    ):
                        found.append(f"{path.relative_to(SRC)}:{node.lineno}")
        return found


class TestOneCall:
    def test_nothing_outside_the_accumulator_sets_completeness(self) -> None:
        assert CompletenessKit.assignments() == []

    def test_every_content_cause_is_a_rule_the_scanner_reports(self) -> None:
        source = "\n".join(p.read_text(encoding="utf-8") for p in SRC.rglob("*.py"))
        unknown = sorted(
            rule
            for rule in CONTENT_GAPS
            if source.count(f'"{rule}"') < 2  # the table, and a use
        )
        assert unknown == []
