"""Row BP-0-2: no enforcement point keeps logic of its own for "is this allowed".

The decision is `Decider.decide`, reached by every point through `PointRuntime.ask` (`decide/points.py`). Until the CLI and the
other points are moved onto it (rows BP-8-2 and the ones on top of `decide()`), a few modules still compute a verdict with the
earlier `PolicyGate`. This test keeps that list exact: a module that starts using `PolicyGate` fails it (a new verdict computed
outside the library), and a module that stops using it fails it too, so the list is shortened in the same change and only ever
shrinks.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import ClassVar

from support import ROOT

SRC = ROOT / "src" / "cordon_scanner"


class Sources:
    @staticmethod
    def modules() -> list[Path]:
        return sorted(path for path in SRC.rglob("*.py") if "__pycache__" not in path.parts)

    @staticmethod
    def relative(path: Path) -> str:
        return path.relative_to(SRC).as_posix()

    @classmethod
    def names(cls, path: Path) -> set[str]:
        """Every name a module's code uses or imports (comments and docstrings are not code)."""
        found: set[str] = set()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Name):
                found.add(node.id)
            elif isinstance(node, ast.Attribute):
                found.add(node.attr)
            elif isinstance(node, ast.alias):
                found.add(node.name.rsplit(".", 1)[-1])
            elif isinstance(node, ast.ImportFrom) and node.module:
                found.update(node.module.split("."))
        return found


class TestNoPointComputesAVerdict:
    #: Modules outside `decide/` that still compute a verdict with `PolicyGate`: the CLI and its helpers, the runner, the engine's
    #: gate. Each leaves this list when its row moves it onto `PointRuntime.ask`.
    LEGACY: ClassVar[frozenset[str]] = frozenset(
        {
            "__init__.py",
            "cli/commands/install/context.py",
            "cli/commands/scan/command.py",
            "cli/dependency_payload.py",
            "cloud/runner.py",
            "engine/engine.py",
            "engine/incoming.py",
        }
    )

    def test_the_modules_outside_the_library_that_use_the_old_verdict_are_the_listed_ones(
        self,
    ) -> None:
        users = {
            Sources.relative(path)
            for path in Sources.modules()
            if not Sources.relative(path).startswith("decide/")
            and "PolicyGate" in Sources.names(path)
        }
        assert users == set(self.LEGACY), (
            "the modules that compute a verdict outside decide() changed: "
            f"new {sorted(users - self.LEGACY)}, no longer {sorted(self.LEGACY - users)}"
        )

    def test_only_the_point_runtime_and_the_legacy_bridge_import_the_decision_function(
        self,
    ) -> None:
        importers = {
            Sources.relative(path)
            for path in Sources.modules()
            if "decider" in Sources.names(path)
            and not Sources.relative(path).startswith("decide/decision/")
        }
        assert importers == {"decide/points.py"}, (
            "ask through PointRuntime.ask, not through Decider directly"
        )
