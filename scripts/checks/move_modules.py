"""Move the scanner's modules to where `tests/unit/package_layout.json` puts them, one place at a time.

    docker run --rm -v "$PWD:/t" -w /t <image> python scripts/checks/move_modules.py foundation

Move only (reviews 20-PACKAGE-STRUCTURE.md): `git mv`, then every reference to a moved module's
dotted path rewritten -- imports, the strings tests patch (`"cordon_scanner.core.x.Y"`), entry
points -- and a shim left at the old path for one release. Nothing else changes.

```
  package_layout.json ──► the moves for one place (old -> new)
        │
        ├─ git mv src/cordon_scanner/<old>.py  src/cordon_scanner/<new>.py   (+ __init__.py)
        ├─ references rewritten in src/ tests/ bench/ scripts/ (Python: over the syntax tree,
        │  imports and string constants only) and pyproject.toml (entry points)
        ├─ shim at the old path: the SAME module object (sys.modules), so private names and
        │  monkeypatches reach it
        └─ package_layout.json updated; move-map.json written (old -> new, dotted and as files)
```

A rewrite touches only the spans the syntax tree names, so code that merely mentions a module in
a comment or a docstring is left as it is (docs are updated by hand in the same commit).
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

PACKAGE = "cordon_scanner"
LAYOUT = Path("tests/unit/package_layout.json")
SHIM_RELEASES = 1

_SHIM = '''"""Moved to `{new}` (reviews 20-PACKAGE-STRUCTURE.md).

This path is kept for one release (until {until}) so code importing it keeps working. It is the
same module, not a copy: names, private ones included, and patches reach the real one.
"""

import sys

from {parent} import {leaf} as _module

sys.modules[__name__] = _module
'''


class Moves:
    @staticmethod
    def dotted(path: str) -> str:
        """`core/models` -> `cordon_scanner.core.models`."""
        return f"{PACKAGE}.{path.replace('/', '.')}"

    @staticmethod
    def plan(layout: dict[str, Any], place: str) -> dict[str, str]:
        """old -> new (paths without `.py`) for the modules whose place starts with `place`."""
        return {
            old: new
            for old, new in layout["modules"].items()
            if old != new and (new == place or new.startswith(place + "/"))
        }

    @staticmethod
    def pattern(moves: dict[str, str]) -> re.Pattern[str]:
        """A moved module's dotted path, whole: not a prefix of a longer name."""
        names = sorted((Moves.dotted(o) for o in moves), key=len, reverse=True)
        return re.compile(r"(?<![\w.])(" + "|".join(map(re.escape, names)) + r")(?![\w])")

    @staticmethod
    def rename(moves: dict[str, str]) -> dict[str, str]:
        return {Moves.dotted(o): Moves.dotted(n) for o, n in moves.items()}

    # -- Python sources ---------------------------------------------------------------------------

    @staticmethod
    def rewrite_python(text: str, moves: dict[str, str]) -> str:
        """`text` with every import of a moved module, and every string constant naming one,
        pointing at its new place. `from cordon_scanner.core import models` is an import of a
        module too, and is rewritten to `from cordon_scanner.foundation import models`."""
        tree = ast.parse(text)
        rx, names = Moves.pattern(moves), Moves.rename(moves)
        lines = text.splitlines(keepends=True)
        starts = [0]
        for line in lines:
            starts.append(starts[-1] + len(line))

        def offset(lineno: int, col: int) -> int:
            # `col_offset` counts UTF-8 bytes.
            line = lines[lineno - 1]
            return starts[lineno - 1] + len(line.encode("utf-8")[:col].decode("utf-8"))

        edits: list[tuple[int, int, str]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                a = offset(node.lineno, node.col_offset)
                b = offset(node.end_lineno or node.lineno, node.end_col_offset or 0)
                segment = text[a:b]
                new = rx.sub(lambda m: names[m.group(1)], segment)
                parents = {Moves.dotted(o).rsplit(".", 1)[0] for o in moves}
                if node.module in parents:
                    new = Moves._split_from(node, new, names)
                if new != segment:
                    edits.append((a, b, new))
            elif isinstance(node, ast.Import):
                a = offset(node.lineno, node.col_offset)
                b = offset(node.end_lineno or node.lineno, node.end_col_offset or 0)
                segment = text[a:b]
                new = rx.sub(lambda m: names[m.group(1)], segment)
                if new != segment:
                    edits.append((a, b, new))
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if rx.search(node.value) is None or node.lineno is None:
                    continue
                a = offset(node.lineno, node.col_offset)
                b = offset(node.end_lineno or node.lineno, node.end_col_offset or 0)
                segment = text[a:b]
                new = rx.sub(lambda m: names[m.group(1)], segment)
                if new != segment:
                    edits.append((a, b, new))
        for a, b, new in sorted(edits, reverse=True):
            text = text[:a] + new + text[b:]
        return text

    @staticmethod
    def _split_from(node: ast.ImportFrom, segment: str, names: dict[str, str]) -> str:
        """`from cordon_scanner.core import models, engine` with the two going to different places:
        one `from` statement per place, in the order written."""
        if node.module is None:
            return segment
        # A name that is not itself a moved module is defined in the package's __init__: it goes
        # where the package went, if the package moved too.
        home = names.get(node.module, node.module)
        groups: dict[str, list[str]] = {}
        for alias in node.names:
            full = f"{node.module}.{alias.name}"
            target = names.get(full)
            parent = target.rsplit(".", 1)[0] if target else home
            text = alias.name + (f" as {alias.asname}" if alias.asname else "")
            groups.setdefault(parent, []).append(text)
        if list(groups) == [home]:
            return segment
        indent = " " * node.col_offset
        return f"\n{indent}".join(
            f"from {parent} import {', '.join(items)}" for parent, items in groups.items()
        )

    # -- other files -----------------------------------------------------------------------------

    @staticmethod
    def rewrite_text(text: str, moves: dict[str, str]) -> str:
        """Entry points and package names in `pyproject.toml`: the dotted path, whole."""
        names = Moves.rename(moves)
        return Moves.pattern(moves).sub(lambda m: names[m.group(1)], text)

    @staticmethod
    def shim(old: str, new: str, until: str) -> str:
        parent, leaf = Moves.dotted(new).rsplit(".", 1)
        return _SHIM.format(new=Moves.dotted(new), until=until, parent=parent, leaf=leaf)

    # -- the move ----------------------------------------------------------------------------------

    @staticmethod
    def git(root: Path, *args: str) -> None:
        subprocess.run(["git", *args], cwd=root, check=True)  # noqa: S603, S607 - fixed git verbs, paths from the layout table

    @staticmethod
    def tidy(root: Path, paths: list[Path]) -> None:
        """Imports a rewrite renamed sort differently: put them back in order, and format."""
        if paths:
            files = [str(p) for p in paths]
            fix = ["ruff", "check", "--no-cache", "-q", "--fix", "--select", "I", *files]
            subprocess.run(fix, cwd=root, check=False)  # noqa: S603 - the repository's own linter
            fmt = ["ruff", "format", "--no-cache", "-q", *files]
            subprocess.run(fmt, cwd=root, check=True)  # noqa: S603 - the repository's own formatter

    @staticmethod
    def follow(paths: list[Path], root: Path = Path()) -> list[Path]:
        """Point the references in `paths` at every module already moved (the layout's shims):
        for files left as they were by `run(skip=...)`, once their author has committed them."""
        layout = json.loads((root / LAYOUT).read_text(encoding="utf-8"))
        moves = {old: shim["to"] for old, shim in layout.get("shims", {}).items()}
        changed = []
        for path in paths:
            text = path.read_text(encoding="utf-8")
            new_text = Moves.rewrite_python(text, moves) if moves else text
            if new_text != text:
                path.write_text(new_text, encoding="utf-8")
                changed.append(path)
        Moves.tidy(root, changed)
        return changed

    @staticmethod
    def test_plan(layout: dict[str, Any], place: str, root: Path) -> dict[str, str]:
        """test file name -> its directory under tests/unit/, for the tests of `place` not yet
        there."""
        unit = root / "tests" / "unit"
        out = {}
        for name, at in layout.get("tests", {}).items():
            if at and (at == place or at.startswith(place + "/")) and (unit / name).exists():
                out[name] = at
        return out

    @staticmethod
    def rewrite_test_imports(text: str, tests: dict[str, str]) -> str:
        """`from unit.test_x import Y` for a test moved to tests/unit/<place>/."""
        if not tests:
            return text
        rx = re.compile(r"(?<![\w.])unit\.(" + "|".join(re.escape(n[:-3]) for n in tests) + r")\b")
        return rx.sub(
            lambda m: f"unit.{tests[m.group(1) + '.py'].replace('/', '.')}.{m.group(1)}", text
        )

    @staticmethod
    def run(
        place: str, until: str, root: Path = Path(), skip: frozenset[Path] = frozenset()
    ) -> tuple[dict[str, str], dict[str, str]]:
        """Move one place's modules and their unit tests (tests/unit/<place>/). Files in `skip`
        (another author's uncommitted work) are neither moved nor rewritten: they keep importing
        the old paths, which the shims serve, until `follow` rewrites them."""
        layout = json.loads((root / LAYOUT).read_text(encoding="utf-8"))
        moves = Moves.plan(layout, place)
        tests = Moves.test_plan(layout, place, root)
        if not moves and not tests:
            return {}, {}
        src = root / "src" / PACKAGE
        skip = frozenset((root / p).resolve() for p in skip)
        held = sorted(o for o in moves if (src / f"{o}.py").resolve() in skip)
        held += sorted(n for n in tests if (root / "tests" / "unit" / n).resolve() in skip)
        if held:
            raise SystemExit(f"these would move but are held by --skip: {held}")
        changed: list[Path] = []
        unit = root / "tests" / "unit"
        for name, at in sorted(tests.items()):
            (unit / at).mkdir(parents=True, exist_ok=True)
            query = ["git", "ls-files", "--error-unmatch", str(unit / name)]
            tracked = subprocess.run(  # noqa: S603 - a fixed git query
                query,
                cwd=root,
                capture_output=True,
                check=False,
            )
            if tracked.returncode == 0:
                Moves.git(root, "mv", str(unit / name), str(unit / at / name))
            else:  # not in git yet (someone's work in progress): moved as a file
                (unit / name).rename(unit / at / name)
        for old, new in sorted(moves.items()):
            target = src / f"{new}.py"
            for parent in reversed(target.relative_to(src).parents[:-1]):
                init = src / parent / "__init__.py"
                if not init.exists():
                    init.parent.mkdir(parents=True, exist_ok=True)
                    init.write_text("", encoding="utf-8")
                    Moves.git(root, "add", str(init))
            Moves.git(root, "mv", str(src / f"{old}.py"), str(target))
        for folder in ("src", "tests", "bench", "scripts"):
            for path in sorted((root / folder).rglob("*.py")):
                if "__pycache__" in path.parts or path.resolve() in skip:
                    continue
                text = path.read_text(encoding="utf-8")
                new_text = Moves.rewrite_python(text, moves) if moves else text
                new_text = Moves.rewrite_test_imports(new_text, tests)
                if new_text != text:
                    path.write_text(new_text, encoding="utf-8")
                    changed.append(path)
        pyproject = root / "pyproject.toml"
        if moves:
            text = pyproject.read_text(encoding="utf-8")
            pyproject.write_text(Moves.rewrite_text(text, moves), encoding="utf-8")
        for old, new in moves.items():
            (src / f"{old}.py").write_text(Moves.shim(old, new, until), encoding="utf-8")
            Moves.git(root, "add", str(src / f"{old}.py"))
            del layout["modules"][old]
            layout["modules"][new] = new
            layout.setdefault("shims", {})[old] = {"to": new, "until": until}
            changed.append(src / f"{old}.py")
        Moves.tidy(root, changed)
        layout["modules"] = dict(sorted(layout["modules"].items()))
        layout["shims"] = dict(sorted(layout.get("shims", {}).items()))
        (root / LAYOUT).write_text(json.dumps(layout, indent=1) + "\n", encoding="utf-8")
        return moves, tests

    @staticmethod
    def main(argv: list[str] | None = None) -> int:
        p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        p.add_argument("place", nargs="?", help="a place in package_layout.json, e.g. foundation")
        p.add_argument("--until", help="the release that removes the shims")
        p.add_argument("--map", type=Path, default=Path("move-map.json"))
        p.add_argument(
            "--skip", type=Path, nargs="*", default=[], help="another author's uncommitted files"
        )
        p.add_argument(
            "--follow", type=Path, nargs="*", help="rewrite these files for every move made"
        )
        a = p.parse_args(argv)
        if a.follow is not None:
            changed = Moves.follow(a.follow)
            print(f"{len(changed)} files now import the moved modules where they are")
            return 0
        if not a.place or not a.until:
            p.error("a place and --until are required")
        if a.place == "all":
            # Every place in one commit: the owner's call (2026-10-20), one gate and one proof.
            total_m, total_t = 0, 0
            layout = json.loads(LAYOUT.read_text(encoding="utf-8"))
            places = sorted(
                {n.split("/")[0] for o, n in layout["modules"].items() if o != n}
                | {t.split("/")[0] for t in layout.get("tests", {}).values() if t}
            )
            files: dict[str, str] = {}
            names: dict[str, str] = {}
            for place in places:
                moves, tests = Moves.run(place, a.until, skip=frozenset(a.skip))
                names |= Moves.rename(moves)
                files |= {
                    f"src/{PACKAGE}/{o}.py": f"src/{PACKAGE}/{n}.py" for o, n in moves.items()
                }
                files |= {f"tests/unit/{n}": f"tests/unit/{at}/{n}" for n, at in tests.items()}
                total_m, total_t = total_m + len(moves), total_t + len(tests)
            a.map.write_text(
                json.dumps({"place": "all", "modules": names, "files": files}, indent=1) + "\n",
                encoding="utf-8",
            )
            print(f"{total_m} modules and {total_t} tests moved; map in {a.map}")
            return 0
        moves, tests = Moves.run(a.place, a.until, skip=frozenset(a.skip))
        files = {f"src/{PACKAGE}/{o}.py": f"src/{PACKAGE}/{n}.py" for o, n in moves.items()}
        files |= {f"tests/unit/{name}": f"tests/unit/{at}/{name}" for name, at in tests.items()}
        a.map.write_text(
            json.dumps({"place": a.place, "modules": Moves.rename(moves), "files": files}, indent=1)
            + "\n",
            encoding="utf-8",
        )
        print(f"{len(moves)} modules and {len(tests)} tests moved to {a.place}/; map in {a.map}")
        return 0


if __name__ == "__main__":
    sys.exit(Moves.main())
