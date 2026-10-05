"""Every implementation lives in a class: no function at a module's root.

The architecture rule since 0.5.0 (`reviews/0.5.0-design-gaps.md` section 0): module level holds
imports, constants, type aliases, enums, dataclasses, Protocols and classes, nothing that runs.
Detectors, parsers, commands and tests are classes, with static or class methods where there is
no state. A lambda bound to a module name is the same thing spelled differently, and a `def` inside
a module-level `if`/`try`/`with` is still at the root.

A module-level alias of a class's method is allowed: an entry point (`module:Class.method`) or a
dotted path resolves a module attribute, and an assignment is an adapter, not an implementation.

The code base is fully converted, so there is no baseline: any root function fails.

## Exceptions

* `conftest.py`: pytest shares fixtures across modules only from a conftest's module level.
* PEP 562 `__getattr__` / `__dir__`: the interpreter looks them up on the module itself.

`corpus/` is never read: it holds real malware samples, and parsing is still handling.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class RootFunctionScanner:
    """Finds functions defined at a module's root, by parsing (never importing) each file."""

    TREES = ("src", "tests", "scripts", "bench")
    SKIP_PARTS = frozenset(
        {"__pycache__", ".venv", "venv", "node_modules", ".git", "corpus", "fixtures"}
    )
    EXEMPT_NAMES = frozenset({"conftest.py"})
    MODULE_HOOKS = frozenset({"__getattr__", "__dir__"})

    @classmethod
    def files(cls) -> list[Path]:
        found = []
        for tree in cls.TREES:
            base = ROOT / tree
            if not base.is_dir():
                continue
            for path in base.rglob("*.py"):
                if (
                    cls.SKIP_PARTS & set(path.relative_to(ROOT).parts)
                    or path.name in cls.EXEMPT_NAMES
                ):
                    continue
                found.append(path)
        return sorted(found)

    @classmethod
    def root_functions(cls, tree: ast.Module) -> list[str]:
        names = []
        stack = list(tree.body)
        while stack:
            node = stack.pop(0)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name not in cls.MODULE_HOOKS:
                    names.append(node.name)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(
                node.value, ast.Lambda
            ):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names.extend(f"{ast.unparse(t)} (lambda)" for t in targets)
            elif isinstance(
                node, (ast.If, ast.Try, ast.With, ast.AsyncWith, ast.For, ast.While)
            ) or type(node).__name__ in ("TryStar", "Match"):
                for attr in ("body", "orelse", "finalbody"):
                    stack.extend(getattr(node, attr, []) or [])
                for handler in getattr(node, "handlers", []) or []:
                    stack.extend(handler.body)
                for case in getattr(node, "cases", []) or []:
                    stack.extend(case.body)
        return names

    @classmethod
    def scan(cls) -> dict[str, list[str]]:
        found: dict[str, list[str]] = {}
        for path in cls.files():
            names = cls.root_functions(
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            )
            if names:
                found[path.relative_to(ROOT).as_posix()] = sorted(names)
        return found


class TestClassBasedArchitecture:
    def test_the_scan_reads_the_code_base(self):
        """A path-based guard that silently matches nothing passes forever."""
        files = RootFunctionScanner.files()
        assert len(files) > 200
        assert any(p.parts[-2:] == ("cordon_scanner", "__init__.py") for p in files)
        assert not any("corpus" in p.relative_to(ROOT).parts for p in files)

    def test_the_scanner_sees_every_shape_of_root_function(self):
        tree = ast.parse(
            "import os\n"
            "def plain(): pass\n"
            "async def waits(): pass\n"
            "handler = lambda request: None\n"
            "class Fine:\n"
            "    def method(self): pass\n"
            "alias = Fine.method\n"
            "if TYPE_CHECKING:\n"
            "    def hidden(): pass\n"
            "try:\n"
            "    import fast\n"
            "except ImportError:\n"
            "    def fallback(): pass\n"
            "def __getattr__(name): pass\n"
        )
        assert sorted(RootFunctionScanner.root_functions(tree)) == sorted(
            ["plain", "waits", "handler (lambda)", "hidden", "fallback"]
        )

    def test_no_function_is_written_at_a_module_root(self):
        found = RootFunctionScanner.scan()
        assert not found, (
            "Module-level functions break the class-based architecture rule. Put each in a class "
            "(a static or class method when it holds no state):\n"
            + "\n".join(f"  {path}: {', '.join(names)}" for path, names in found.items())
        )
