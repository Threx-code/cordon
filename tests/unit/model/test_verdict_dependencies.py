"""SI-T15: the gradient-boosted trees ship as data inside the scanner and are evaluated with no dependency: the evaluator imports nothing beyond
the standard library and the scanner itself, and loading it brings in no numeric or learning library."""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

from support import ROOT

EVALUATORS = (
    "src/cordon_scanner/decide/verdict.py",
    "src/cordon_scanner/decide/verdict_features.py",
    "src/cordon_scanner/decide/feature_schema.py",
    "src/cordon_scanner/model/features.py",
)
LEARNING = ("numpy", "scipy", "sklearn", "lightgbm", "xgboost", "pandas", "torch", "joblib")


class Imports:
    @staticmethod
    def roots(path: Path) -> set[str]:
        found: set[str] = set()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                found.update(alias.name.partition(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.add(node.module.partition(".")[0])
        return found


class TestTheTreesAreEvaluatedWithNoDependency:
    def test_the_evaluator_imports_only_the_standard_library_and_the_scanner(self) -> None:
        allowed = set(sys.stdlib_module_names) | {"cordon_scanner", "__future__"}
        for relative in EVALUATORS:
            assert Imports.roots(ROOT / relative) <= allowed, (
                relative,
                Imports.roots(ROOT / relative) - allowed,
            )

    def test_loading_it_loads_no_numeric_or_learning_library(self) -> None:
        code = (
            "import sys\n"
            "import cordon_scanner.decide.verdict, cordon_scanner.decide.verdict_features, cordon_scanner.model.features\n"
            f"bad = [m for m in {LEARNING!r} if m in sys.modules]\n"
            "print(','.join(bad))\n"
        )
        done = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=False,
            cwd=ROOT / "src",
            env={"PYTHONPATH": str(ROOT / "src"), "PATH": os.environ.get("PATH", "")},
        )
        assert done.returncode == 0, done.stderr[-400:]
        assert done.stdout.strip() == ""

    def test_the_evaluators_exist_so_the_check_cannot_pass_by_looking_at_nothing(self) -> None:
        assert all((ROOT / relative).is_file() for relative in EVALUATORS)
