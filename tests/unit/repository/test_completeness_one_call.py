"""A scan stops being complete in one place, which records why (`Accumulator.incomplete`, `gap`,
`named_elsewhere`): an assignment to `acc.complete` anywhere else would leave a gap whose cause the
gate never sees, the fail-open item 27 closed. Every cause named as not the content's is a rule the
scanner can actually report, so a misspelt id cannot quietly stand for nothing. And a walk error
names its cause from the walker's own reasons or an errno, never from a message's words."""

from __future__ import annotations

import ast

from cordon_scanner.foundation.results import NOT_CONTENT_GAPS
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

    def test_every_cause_named_not_the_content_s_is_a_rule_the_scanner_reports(self) -> None:
        source = "\n".join(p.read_text(encoding="utf-8") for p in SRC.rglob("*.py"))
        unknown = sorted(
            rule
            for rule in NOT_CONTENT_GAPS
            if source.count(f'"{rule}"') < 2  # the table, and a use
        )
        assert unknown == []

    def test_a_walk_error_s_cause_is_never_its_words(self) -> None:
        """Every WalkError the walker builds directly names its cause by one of its own reasons;
        `WalkError.of` alone builds one from an OSError, by its errno."""
        tree = ast.parse((SRC / "foundation" / "files" / "walk.py").read_text(encoding="utf-8"))
        of = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "of")
        inside_of = {id(n) for n in ast.walk(of)}
        causes = [
            ast.unparse(node.args[2])
            for node in ast.walk(tree)
            if id(node) not in inside_of
            if isinstance(node, ast.Call)
            and ast.unparse(node.func) == "WalkError"
            and len(node.args) == 3
        ]
        assert causes and all(c.startswith("WalkError.") for c in causes)
