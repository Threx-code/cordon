"""Cordon is its own code: nothing it ships, and nothing that signs its releases, imports a third
party.

Every import in the package -- at module level, inside a function, behind a condition, or named
as a string to `importlib.import_module` or `__import__` -- must be the standard library or Cordon
itself. A dependency is code that runs with the scanner's privileges where the secrets live, so
the rule is checked over the source, not stated: a commit that brings one back fails here.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

from support import ROOT


class Imports:
    OWN = frozenset({"cordon_scanner", "cordon_sandbox"})
    #: `compression` is the standard library from Python 3.14 (PEP 784): read where it exists.
    ALLOWED = frozenset(sys.stdlib_module_names) | {"__future__", "compression"} | OWN
    #: What ships (`src`), what builds it (`build_backend`) and what signs a release
    #: (`scripts/release`).
    TREES = ("src/cordon_scanner", "src/cordon_sandbox", "build_backend", "scripts/release")

    @staticmethod
    def of(path: Path) -> list[tuple[int, str]]:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        found: list[tuple[int, str]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.extend((node.lineno, alias.name) for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.append((node.lineno, node.module))
            elif (
                isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant)
            ):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if name in ("import_module", "__import__") and isinstance(node.args[0].value, str):
                    found.append((node.lineno, node.args[0].value))
        return found

    @staticmethod
    def violations() -> list[str]:
        out: list[str] = []
        for tree in Imports.TREES:
            for path in sorted((ROOT / tree).rglob("*.py")):
                for line, module in Imports.of(path):
                    if module.split(".")[0] not in Imports.ALLOWED:
                        out.append(f"{path.relative_to(ROOT).as_posix()}:{line} imports {module}")
        return out


class TestNoThirdParty:
    def test_the_package_and_the_release_signing_import_only_the_standard_library(self) -> None:
        assert not Imports.violations()

    def test_the_check_sees_an_import_wherever_it_is_written(self, tmp_path: Path) -> None:
        sample = tmp_path / "sample.py"
        sample.write_text(
            "import os\n"
            "def f():\n"
            "    import requests\n"
            "    if x:\n"
            "        from yaml import safe_load\n"
            "    importlib.import_module('tree_sitter')\n"
            "    __import__('sigstore.verify')\n",
            encoding="utf-8",
        )
        names = [m for _, m in Imports.of(sample)]
        assert names == ["os", "requests", "yaml", "tree_sitter", "sigstore.verify"]

    def test_the_package_declares_no_dependencies_and_no_extras(self) -> None:
        import tomllib

        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        assert project["dependencies"] == []
        assert "optional-dependencies" not in project
