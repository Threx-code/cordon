"""The reference engine stays outside Cordon.

Cordon's rule engine is measured against the reference whose rule-file format it reads, and the tools
that need the reference installed live in `scripts/reference/`, run by a maintainer, their results
committed. Nothing Cordon ships or tests may import it, and no dependency list may name it, so it can
never quietly become a dependency again.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import ClassVar

from support import ROOT as REPO


class TestReferenceBoundary:
    #: The reference's import name and its package name.
    MODULE: ClassVar[str] = "yara"
    PACKAGE: ClassVar[str] = "yara-python"
    #: Where Cordon's own code and tests live; `scripts/reference/` is the one place allowed to import it.
    GUARDED: ClassVar[tuple[str, ...]] = ("src", "tests")
    DEPENDENCY_LISTS: ClassVar[tuple[str, ...]] = (
        "pyproject.toml",
        "requirements-build.txt",
        "ci/dev-requirements.in",
        "ci/dev-requirements.txt",
        "action/requirements.txt",
    )

    @staticmethod
    def imports(path: Path) -> set[str]:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
        except SyntaxError:
            return set()  # deliberately malformed sources among the fixtures import nothing
        found: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                found.add(node.module)
        return found

    def test_nothing_cordon_ships_or_tests_imports_the_reference(self) -> None:
        offenders = sorted(
            path.relative_to(REPO).as_posix()
            for top in self.GUARDED
            for path in (REPO / top).rglob("*.py")
            if any(
                name == self.MODULE or name.startswith(self.MODULE + ".")
                for name in self.imports(path)
            )
        )
        assert not offenders, f"only scripts/reference/ may import the reference: {offenders}"

    def test_no_dependency_list_names_the_reference(self) -> None:
        named = [
            name
            for name in self.DEPENDENCY_LISTS
            if (REPO / name).exists()
            and self.PACKAGE in (REPO / name).read_text(encoding="utf-8").lower()
        ]
        assert not named, f"the reference is a measuring tool, never a dependency: {named}"

    def test_the_measuring_tools_are_where_the_readme_says(self) -> None:
        tools = REPO / "scripts" / "reference"
        assert (tools / "README.md").is_file()
        assert any(self.MODULE in self.imports(path) for path in tools.glob("*.py")), (
            "scripts/reference/ is where the reference is used; its tools have moved"
        )
