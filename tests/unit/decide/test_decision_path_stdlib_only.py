"""The decision path is Cordon's own code: it imports nothing outside the standard library and the package.

The decision path is `decide()` and what it reads (`decide/`, `contracts/`), the library that asks it from every point and holds a signed bundle
(`cloud/runtime.py`, `local_runtime.py`, `local_store.py`, `bundle_puller.py`, `bundle_chain.py`, `minimal_record.py`) and the verifier of a
signed envelope (`bundle_chain.py` with its own Ed25519 and `_p256.py`). Every import in them, at the top of a file or inside a function, is
read from the syntax tree: a module that is neither in the standard library nor `cordon_scanner` fails the test the day it is added.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

from support import ROOT

SRC = ROOT / "src" / "cordon_scanner"
FILES = (
    "cloud/runtime.py",
    "cloud/local_runtime.py",
    "cloud/local_store.py",
    "cloud/bundle_puller.py",
    "cloud/bundle_chain.py",
    "cloud/minimal_record.py",
    "cloud/_p256.py",
)
FOLDERS = ("decide", "contracts")
ALLOWED = frozenset({"cordon_scanner", "__future__"}) | frozenset(sys.stdlib_module_names)


class Imports:
    @staticmethod
    def outside(source: str) -> set[str]:
        """The top-level names of every module the source imports (anywhere in it) that are neither standard nor ours."""
        found: set[str] = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                found |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.add(node.module.split(".")[0])
        return found - ALLOWED

    @staticmethod
    def decision_path() -> list[Path]:
        files = [SRC / name for name in FILES]
        for folder in FOLDERS:
            files += sorted((SRC / folder).rglob("*.py"))
        return files


class TestTheDecisionPath:
    def test_the_files_that_make_it_up_exist(self) -> None:
        files = Imports.decision_path()
        assert all(path.is_file() for path in files)
        assert len(files) > 40  # the folders are read whole: a rename that empties one is seen

    @pytest.mark.parametrize(
        "path", Imports.decision_path(), ids=lambda p: p.relative_to(SRC).as_posix()
    )
    def test_each_file_imports_only_the_standard_library_and_the_package(self, path: Path) -> None:
        assert Imports.outside(path.read_text(encoding="utf-8")) == set()


class TestTheCheckItself:
    def test_a_third_party_import_at_the_top_is_found(self) -> None:
        assert Imports.outside("import requests\nfrom yaml import safe_load\n") == {
            "requests",
            "yaml",
        }

    def test_a_third_party_import_inside_a_function_is_found(self) -> None:
        assert Imports.outside("def f():\n    import cryptography.hazmat\n") == {"cryptography"}

    def test_a_submodule_of_the_standard_library_and_a_relative_import_are_not(self) -> None:
        assert (
            Imports.outside(
                "import os.path\nfrom collections.abc import Mapping\nfrom . import sibling\n"
            )
            == set()
        )

    def test_the_package_itself_and_future_are_not(self) -> None:
        assert (
            Imports.outside(
                "from __future__ import annotations\nfrom cordon_scanner.decide import points\n"
            )
            == set()
        )
