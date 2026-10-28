"""Where code goes: the layout of `src/cordon_scanner` and its unit tests (reviews
20-PACKAGE-STRUCTURE.md).

`tests/unit/package_layout.json` names every module's place, and every unit test's: a test lives
in `tests/unit/<place>/`, mirroring the module it tests, or in `repository/`, `bench/` or
`sandbox/` when it tests those rather than a module. Adding a module or a test is one line
there, in the same commit, so a reviewer sees where it went.

Enforced: the table covers every module and test and is consistent. Reported, not yet failed
(`PYTHONPATH=src:tests python tests/unit/repository/test_package_layout.py`): what is not where
the table puts it, directories past their size, modules past their length and imports that
point outward.
"""

from __future__ import annotations

import ast
import collections
import json
import subprocess
from typing import Any, ClassVar

import pytest

from support import ROOT as REPO

ROOT = REPO / "src" / "cordon_scanner"
TABLE = REPO / "tests" / "unit" / "package_layout.json"


class Layout:
    #: Inner to outer: a module may import its own layer and the ones before it.
    LAYERS: ClassVar[dict[str, int]] = {
        "version": 0,
        "foundation": 0,
        "analysis": 1,
        "detect": 2,
        "ecosystems": 2,
        "intel": 2,
        "images": 2,
        "sources": 2,
        "rules": 2,
        "decide": 3,
        "engine": 4,
        "judge": 5,
        "model": 5,
        "notify": 5,
        "cli": 5,
        "report": 5,
        "mcp": 5,
        "cloud": 5,
        "__main__": 6,
    }
    #: Places only tests have: the repository itself, the bench harness, the sandbox package.
    TEST_PLACES: ClassVar[frozenset[str]] = frozenset({"repository", "bench", "sandbox"})
    #: The limits of reviews 21-MAINTAINABILITY.md (the owner's, 2026-10-28): what exceeds one today is
    #: frozen in package_layout.json with its size and may only shrink; when every list is empty the
    #: limits hold with no exceptions.
    MAX_MODULES: ClassVar[int] = 20
    MAX_LINES: ClassVar[int] = 1_000
    MAX_CLASS_LINES: ClassVar[int] = 1_000
    MAX_FUNCTION_LINES: ClassVar[int] = 90
    #: The adapter layers the engine may reach only through the registry and the protocols.
    ADAPTERS: ClassVar[frozenset[str]] = frozenset(
        {"detect", "report", "ecosystems", "sources", "intel"}
    )

    @staticmethod
    def data() -> dict[str, Any]:
        return json.loads(TABLE.read_text(encoding="utf-8"))

    @staticmethod
    def modules() -> list[str]:
        """Every module under src/cordon_scanner, as a path without `.py` (packages' `__init__`
        files go with their directory; a moved module's shim at its old path is not one)."""
        shims = Layout.data().get("shims", {})
        return sorted(
            m
            for p in ROOT.rglob("*.py")
            if "__pycache__" not in p.parts
            and p.name != "__init__.py"
            and (m := p.relative_to(ROOT).with_suffix("").as_posix()) not in shims
        )

    @staticmethod
    def tests() -> dict[str, str]:
        """Every unit test file: its name -> the directory under tests/unit/ it is in now."""
        unit = REPO / "tests" / "unit"
        return {
            p.name: p.parent.relative_to(unit).as_posix().removeprefix(".")
            for p in sorted(unit.rglob("test_*.py"))
            if "__pycache__" not in p.parts and "data" not in p.relative_to(unit).parts
        }

    @classmethod
    def place(cls, module: str, table: dict[str, str]) -> str:
        return table.get(module, module).split("/")[0]

    @classmethod
    def report(cls) -> dict[str, Any]:
        table = cls.data()["modules"]
        here = cls.modules()
        to_move = sorted(m for m in here if table.get(m, m) != m)
        sizes = collections.Counter(m.rsplit("/", 1)[0] if "/" in m else "." for m in here)
        long = {
            m: n
            for m in here
            if (n := len((ROOT / f"{m}.py").read_text(encoding="utf-8").splitlines()))
            > cls.MAX_LINES
        }
        outward = collections.Counter()
        for m in here:
            src = cls.place(m, table)
            tree = ast.parse((ROOT / f"{m}.py").read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    names = [node.module]
                elif isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                for name in names:
                    if not name.startswith("cordon_scanner."):
                        continue
                    dep = name.removeprefix("cordon_scanner.").replace(".", "/")
                    dst = cls.place(dep, table)
                    if cls.LAYERS.get(dst, 0) > cls.LAYERS.get(src, 0):
                        outward[f"{src} -> {dst}"] += 1
        placed = cls.data().get("tests", {})
        tests_away = sum(1 for name, at in cls.tests().items() if placed.get(name, at) != at)
        return {
            "modules": len(here),
            "not_yet_in_place": len(to_move),
            "tests": len(cls.tests()),
            "tests_not_yet_in_place": tests_away,
            "directories_over_size": {
                d: n for d, n in sorted(sizes.items()) if n > cls.MAX_MODULES
            },
            "modules_over_length": dict(sorted(long.items())),
            "imports_pointing_outward": dict(sorted(outward.items())),
        }


class TestTable:
    def test_every_module_has_a_place(self) -> None:
        table = Layout.data()["modules"]
        missing = sorted(set(Layout.modules()) - set(table))
        assert not missing, f"add these to {TABLE.name}: {missing}"

    def test_no_entry_for_a_module_that_does_not_exist(self) -> None:
        table = Layout.data()["modules"]
        gone = sorted(set(table) - set(Layout.modules()))
        assert not gone, f"remove these from {TABLE.name}: {gone}"

    def test_no_two_modules_share_a_place(self) -> None:
        table = Layout.data()["modules"]
        shared = [t for t, n in collections.Counter(table.values()).items() if n > 1]
        assert not shared, shared

    def test_every_place_is_in_a_known_layer(self) -> None:
        table = Layout.data()["modules"]
        unknown = sorted({t.split("/")[0] for t in table.values()} - set(Layout.LAYERS))
        assert not unknown, f"give these a layer in Layout.LAYERS: {unknown}"

    def test_every_shim_is_only_a_shim_to_a_module_that_exists(self) -> None:
        data = Layout.data()
        for old, shim in data.get("shims", {}).items():
            assert shim["to"] in data["modules"], old
            text = (ROOT / f"{old}.py").read_text(encoding="utf-8")
            target = "cordon_scanner." + shim["to"].replace("/", ".")
            assert "sys.modules[__name__] = _module" in text and target in text, old

    def test_every_test_has_a_place_in_a_known_layer(self) -> None:
        placed = Layout.data()["tests"]
        missing = sorted(set(Layout.tests()) - set(placed))
        assert not missing, f"add these to the tests of {TABLE.name}: {missing}"
        assert not sorted(set(placed) - set(Layout.tests())), "tests in the table that are gone"
        unknown = sorted(
            {p.split("/")[0] for p in placed.values() if p}
            - set(Layout.LAYERS)
            - Layout.TEST_PLACES
        )
        assert not unknown, unknown

    def test_test_names_stay_unique(self) -> None:
        # Unit tests are not packages: pytest imports each by its file name.
        unit = REPO / "tests" / "unit"
        names = collections.Counter(
            p.name for p in unit.rglob("test_*.py") if "__pycache__" not in p.parts
        )
        assert not [n for n, c in names.items() if c > 1]

    def test_the_report_runs(self) -> None:
        report = Layout.report()
        assert report["modules"] == len(Layout.data()["modules"])


class Structure:
    """What the repository holds where, measured now: the same reading every check uses."""

    #: The files a directory may hold at its top; everything else lives in a subdirectory.
    TOP_FILES: ClassVar[dict[str, frozenset[str]]] = {
        "src/cordon_scanner": frozenset({"__init__.py", "__main__.py", "version.py", "py.typed"}),
        "src/cordon_scanner/detect": frozenset({"__init__.py", "base.py", "catalogue.py"}),
        "src/cordon_scanner/intel": frozenset({"__init__.py"}),
        "tests": frozenset({"conftest.py", "support.py"}),
        "tests/unit": frozenset({"package_layout.json"}),
        "scripts": frozenset(),
        "bench": frozenset(
            {
                "run.py",
                "Dockerfile",
                "Dockerfile.images",
                "README.md",
                "agent-suite.json",
                "lockfiles.json",
            }
        ),
    }

    @staticmethod
    def frozen() -> dict[str, Any]:
        return Layout.data()["frozen"]

    @staticmethod
    def imports(module: str) -> list[str]:
        """The cordon_scanner modules a module imports, as paths (`engine/engine`)."""
        tree = ast.parse((ROOT / f"{module}.py").read_text(encoding="utf-8"))
        out = []
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            out += [
                n.removeprefix("cordon_scanner.").replace(".", "/")
                for n in names
                if n.startswith("cordon_scanner.")
            ]
        return out

    @classmethod
    def outward(cls) -> set[str]:
        """`module -> imported` for every import that reaches a layer outside the module's own."""
        out = set()
        for m in Layout.modules():
            src = Layout.LAYERS.get(m.split("/")[0], 0)
            for dep in cls.imports(m):
                if Layout.LAYERS.get(dep.split("/")[0], 0) > src:
                    out.add(f"{m} -> {dep}")
        return out

    @staticmethod
    def lengths() -> dict[str, int]:
        return {
            m: len((ROOT / f"{m}.py").read_text(encoding="utf-8").splitlines())
            for m in Layout.modules()
        }

    @staticmethod
    def spans(kind: type) -> dict[str, int]:
        """`module:Qualified.name` -> lines, for every class (or function) in src/cordon_scanner."""
        out: dict[str, int] = {}
        for module in Layout.modules():
            tree = ast.parse((ROOT / f"{module}.py").read_text(encoding="utf-8"))
            todo: list[tuple[ast.AST, str]] = [(tree, "")]
            while todo:
                node, prefix = todo.pop()
                for child in ast.iter_child_nodes(node):
                    named = isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                    here = f"{prefix}{child.name}" if named else prefix  # type: ignore[attr-defined]
                    if named and isinstance(child, kind):
                        out[f"{module}:{here}"] = child.end_lineno - child.lineno + 1  # type: ignore[attr-defined]
                    todo.append((child, f"{here}." if named else prefix))
        return out

    @staticmethod
    def classes() -> dict[str, int]:
        return Structure.spans(ast.ClassDef)

    @staticmethod
    def functions() -> dict[str, int]:
        return Structure.spans((ast.FunctionDef, ast.AsyncFunctionDef))  # type: ignore[arg-type]

    @staticmethod
    def directories() -> dict[str, int]:
        """Python modules per directory, in the package and in the unit tests."""
        sizes: collections.Counter[str] = collections.Counter(
            "src/cordon_scanner/" + m.rsplit("/", 1)[0] for m in Layout.modules() if "/" in m
        )
        for p in (REPO / "tests" / "unit").rglob("*.py"):
            if "__pycache__" not in p.parts and p.name != "__init__.py":
                sizes[p.parent.relative_to(REPO).as_posix()] += 1
        return dict(sizes)

    #: An adapter layer's port: its protocols (`base`) and the discovery of its implementations
    #: (`registry`, which hands back objects typed by those protocols and names none).
    PORTS: ClassVar[frozenset[str]] = frozenset({"", "base", "registry"})

    @classmethod
    def engine_adapters(cls) -> set[str]:
        """`engine -> adapter` for each concrete adapter module the engine imports, from any of its
        modules: the rule is about the engine as a whole, so moving code between the engine's own
        modules neither adds nor removes an entry. An adapter layer's port is not counted."""
        out = set()
        for m in Layout.modules():
            if not m.startswith("engine/"):
                continue
            for dep in cls.imports(m):
                layer, _, rest = dep.partition("/")
                if layer in Layout.ADAPTERS and rest not in cls.PORTS:
                    out.add(f"engine -> {dep}")
        return out

    @staticmethod
    def file_relative() -> set[str]:
        """Source files that locate something from their own position (`__file__`)."""
        out = set()
        for folder in ("src", "tests", "scripts"):
            for p in (REPO / folder).rglob("*.py"):
                rel = p.relative_to(REPO).as_posix()
                if "__pycache__" in p.parts or rel.startswith("tests/conformance/cases/"):
                    continue
                tree = ast.parse(p.read_text(encoding="utf-8"))
                if any(isinstance(n, ast.Name) and n.id == "__file__" for n in ast.walk(tree)):
                    out.add(rel)
        return out


class TestStructure:
    """The rules that keep the repository arranged (reviews 20-PACKAGE-STRUCTURE.md). Each list
    under `frozen` in package_layout.json may only shrink: a check fails when something is added
    to what it freezes, and when an entry no longer applies, so the lists stay exact."""

    def test_every_module_and_test_is_where_the_table_puts_it(self) -> None:
        report = Layout.report()
        assert report["not_yet_in_place"] == 0
        assert report["tests_not_yet_in_place"] == 0

    def test_every_top_level_package_has_a_layer(self) -> None:
        packages = {p.name for p in ROOT.iterdir() if p.is_dir() and p.name != "__pycache__"}
        modules = {p.stem for p in ROOT.glob("*.py") if p.stem != "__init__"}
        assert not sorted((packages | modules) - set(Layout.LAYERS)), "give it a layer, or a home"

    @staticmethod
    def within(
        name: str, now: dict[str, int], frozen: dict[str, int], limit: int, what: str
    ) -> None:
        """Each measured size at most its limit, or its frozen size; each frozen entry still over
        the limit (else remove it) -- so a frozen list only shrinks and stays exact."""
        over = {k: v for k, v in now.items() if v > frozen.get(k, limit)}
        assert not over, f"{name}: past {limit} {what} (or past its frozen size): split it: {over}"
        gone = sorted(k for k in frozen if now.get(k, 0) <= limit)
        assert not gone, f"{name}: back within {limit} {what}: remove from frozen: {gone}"

    def test_no_directory_holds_more_than_20_modules(self) -> None:
        TestStructure.within(
            "directories", Structure.directories(), Structure.frozen()["large_directories"],
            Layout.MAX_MODULES, "modules",
        )  # fmt: skip

    def test_no_class_grows_past_1000_lines(self) -> None:
        TestStructure.within(
            "classes", Structure.classes(), Structure.frozen()["long_classes"],
            Layout.MAX_CLASS_LINES, "lines",
        )  # fmt: skip

    def test_no_function_grows_past_90_lines(self) -> None:
        TestStructure.within(
            "functions", Structure.functions(), Structure.frozen()["long_functions"],
            Layout.MAX_FUNCTION_LINES, "lines",
        )  # fmt: skip

    def test_the_engine_reaches_adapters_only_through_the_registry(self) -> None:
        frozen = set(Structure.frozen()["engine_adapter_imports"])
        now = Structure.engine_adapters()
        assert not sorted(now - frozen), (
            "the engine imports an adapter: register it, use its protocol"
        )
        assert not sorted(frozen - now), "these are gone: remove them from frozen"

    def test_no_loose_files(self) -> None:
        for folder, allowed in Structure.TOP_FILES.items():
            here = {
                p.name
                for p in (REPO / folder).iterdir()
                if p.is_file() and p.name not in (".DS_Store",)
            }
            assert not sorted(here - allowed), f"{folder}: put these in a subdirectory"

    def test_no_module_grows_past_its_length(self) -> None:
        TestStructure.within(
            "modules", Structure.lengths(), Structure.frozen()["long_modules"],
            Layout.MAX_LINES, "lines",
        )  # fmt: skip

    def test_no_new_outward_import(self) -> None:
        frozen = set(Structure.frozen()["outward_imports"])
        now = Structure.outward()
        assert not sorted(now - frozen), "an import that points outward: invert it, or move it"
        assert not sorted(frozen - now), "these are gone: remove them from frozen"

    def test_no_new_path_found_from_a_file_s_own_position(self) -> None:
        # Data is found from the package (foundation/paths.py), tests find the repository from
        # support.ROOT: a file that counts directories from itself breaks when it moves.
        frozen = set(Structure.frozen()["file_relative_paths"])
        now = Structure.file_relative()
        assert not sorted(now - frozen), "use PackagePaths or support.ROOT"
        assert not sorted(frozen - now), "these are gone: remove them from frozen"

    def test_the_repository_root_holds_only_what_it_should(self) -> None:
        if not (REPO / ".git").exists():
            pytest.skip("not a git checkout")
        tracked = subprocess.run(
            ["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True
        ).stdout.split()
        top = {f.split("/")[0] for f in tracked}
        allowed = set(Structure.frozen()["repository_root"])
        assert not sorted(top - allowed), "a new entry at the repository root: give it a home"


if __name__ == "__main__":
    print(json.dumps(Layout.report(), indent=1))
