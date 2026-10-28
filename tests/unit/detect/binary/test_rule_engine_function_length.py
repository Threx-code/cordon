"""No function in the rule engine runs past 90 lines -- a maintainability floor measured, not asserted.

Every `rule_*` module under detect/binary is scanned; a def (or nested def) longer than 90 physical lines
fails. 90 is the measured cut: the only two functions that exceeded it were modules.pe._functions (a 14-way
Call dispatch, now split into _import_calls/_import_rva_calls/_export_calls/_section_calls/_resource_calls)
and modules.dotnet's table catalog (now a ClassVar data table, not a function). The next longest are the string
matcher's hot loops in rule_engine.pattern (run 85, _pass 82, _settle 78), deliberately inline for speed, and the
readers' parse orchestration (modules.pe._read 88, _resources 76) -- all under 90. A new long function is a
regression to split.
"""

from __future__ import annotations

import ast

from support import ROOT

CAP = 90
BINARY = ROOT / "src" / "cordon_scanner" / "detect" / "binary"


class Lengths:
    @staticmethod
    def over_cap() -> list[str]:
        out: list[str] = []
        for path in sorted(
            p
            for d in ("rule_engine", "modules")
            for p in (BINARY / d).glob("*.py")
            if p.name != "__init__.py"
        ):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    length = (node.end_lineno or node.lineno) - node.lineno + 1
                    if length > CAP:
                        out.append(f"{path.stem}.{node.name}: {length} lines")
        return out


class TestRuleEngineFunctionLength:
    def test_no_function_in_the_rule_engine_is_over_90_lines(self) -> None:
        assert Lengths.over_cap() == []

    def test_the_cap_actually_measures_length(self) -> None:
        body = "\n".join(f"    x{i} = {i}" for i in range(95))
        tree = ast.parse(f"def f():\n{body}\n")
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
        assert (node.end_lineno or node.lineno) - node.lineno + 1 > CAP
