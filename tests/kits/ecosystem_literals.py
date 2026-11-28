"""Every place in the source that lists ecosystems, found by reading the syntax tree (S22).

A site is a set, tuple, list or dict literal whose string members name two or more of the scanner's ecosystems (an id of
`EcosystemRegistry.BY_ID`, or a name `registry_hosts.ALIASES` or the package-URL `TYPES` map to one) and not many words
besides. A site that names all 28 is complete. A narrow one is a feature that covers fewer ecosystems than the scanner supports.

A site is identified without its line number, so an edit elsewhere in the file does not move it: by its file, its anchor (the name
it is assigned to, else the function that holds it) and its number among the sites of that anchor.

    python tests/kits/ecosystem_literals.py write tests/unit/ecosystems/coverage/narrow_sites.json   (the record, from the tree)
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from typing import Any

from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.intel.registries.registry_hosts import ALIASES
from cordon_scanner.sources.package import PackageTarget
from support import ROOT

ALL = frozenset(EcosystemRegistry.BY_ID)
#: An id names itself even where a map folds it into another (`gradle` is served by `maven` for one registry reader, and is its own id).
NAMES: dict[str, str] = {**ALIASES, **PackageTarget.TYPES, **{eco: eco for eco in ALL}}


class Site:
    def __init__(self, path: str, anchor: str, index: int, line: int, ids: frozenset[str]) -> None:
        self.path, self.anchor, self.index, self.line, self.ids = path, anchor, index, line, ids

    @property
    def key(self) -> str:
        return f"{self.path}::{self.anchor}#{self.index}"

    @property
    def complete(self) -> bool:
        return self.ids >= ALL

    def record(self) -> dict[str, Any]:
        return {"site": self.key, "ids": sorted(self.ids)}


class EcosystemLiterals:
    #: Foreign words a site may hold besides ecosystem names, at most as many as it holds names.
    @staticmethod
    def members(node: ast.AST) -> list[ast.expr] | None:
        if isinstance(node, ast.Set | ast.Tuple | ast.List):
            return list(node.elts)
        if isinstance(node, ast.Dict):
            return [key for key in node.keys if key is not None]
        return None

    @classmethod
    def anchors(cls, tree: ast.AST) -> dict[int, str]:
        """For each literal node (by id), the name it is assigned to, else the function that holds it, else `<module>`."""
        found: dict[int, str] = {}

        def visit(node: ast.AST, scope: str, target: str | None) -> None:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                scope = f"{scope}.{node.name}" if scope else node.name
                target = None
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = ast.unparse(node.targets[0])
            elif isinstance(node, ast.AnnAssign):
                target = ast.unparse(node.target)
            if cls.members(node) is not None:
                found[id(node)] = target or scope or "<module>"
            for child in ast.iter_child_nodes(node):
                visit(child, scope, target)

        visit(tree, "", None)
        return found

    @classmethod
    def sites(cls, root: Path, relative_to: Path) -> list[Site]:
        out: list[Site] = []
        for path in sorted(root.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            anchors = cls.anchors(tree)
            counted: dict[str, int] = {}
            for node in ast.walk(tree):
                elements = cls.members(node)
                if not elements:
                    continue
                words = [
                    e.value
                    for e in elements
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)
                ]
                ids = frozenset(NAMES[w] for w in words if w in NAMES)
                foreign = sum(1 for w in words if w not in NAMES)
                if len(ids) < 2 or foreign > len(ids):
                    continue
                anchor = anchors.get(id(node), "<module>")
                number = counted.get(anchor, 0)
                counted[anchor] = number + 1
                out.append(
                    Site(path.relative_to(relative_to).as_posix(), anchor, number, node.lineno, ids)
                )
        return sorted(out, key=lambda s: (s.path, s.anchor, s.index))

    @classmethod
    def narrow(cls, root: Path, relative_to: Path) -> list[Site]:
        return [site for site in cls.sites(root, relative_to) if not site.complete]


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "write":
        found = EcosystemLiterals.narrow(ROOT / "src", ROOT)
        lines = ",\n".join(" " + json.dumps(site.record(), sort_keys=True) for site in found)
        Path(sys.argv[2]).write_text(f"[\n{lines}\n]\n", encoding="utf-8")
        sys.stdout.write(f"{len(found)} narrow sites\n")
    else:
        sys.stderr.write(__doc__ or "")
        sys.exit(2)
