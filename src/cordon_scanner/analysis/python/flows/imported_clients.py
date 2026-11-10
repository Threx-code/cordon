"""HTTP clients a file imports from another file of the same package.

A request made through a client object is a request (`HTTP_CLIENTS`), but the per-file analyser
only knows the clients its own file creates. A stealer that builds `session = httpx.Client()` in
`imports.py` and sends with `session.post(...)` in `entry.py`, which takes the name with
`from .imports import *`, has no sender in either file (group A, 2026-11-10: both
TheThreadingAssistant units, whose theft is otherwise complete). This pass reads every Python file
of the package once, finds each module's top-level client bindings, and follows `from .m import
name` and `from .m import *` to the files that take them, re-exports included, to a fixed point.
The analyser of each file then starts with those names bound, as if the file had made them.

Parsed, never executed. Only files present in the scan are followed; an import that resolves to
no file of the package binds nothing.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from pathlib import PurePosixPath
from typing import Any, ClassVar, Protocol

from cordon_scanner.analysis.python.flows.http_clients import HTTP_CLIENTS
from cordon_scanner.analysis.python.pysyntax import PythonSyntax


class ScannedFile(Protocol):
    """What `of_units` reads of a scan's file (a `FileUnit`): its path and its content."""

    @property
    def path(self) -> str: ...

    @property
    def content(self) -> Any: ...


class ImportedClients:
    """Per file, the names it imports that are HTTP clients made in another of the package's files."""

    #: Rounds of re-export followed (`a` makes it, `b` re-exports it, `c` takes it from `b`...).
    MAX_ROUNDS: ClassVar[int] = 8

    @classmethod
    def of(cls, sources: Mapping[str, str]) -> dict[str, dict[str, str]]:
        """`{path: {name: client constructor}}` for each file that imports a client, and only those."""
        trees: dict[str, ast.Module] = {}
        for path, text in sources.items():
            if not path.endswith(".py"):
                continue
            try:
                tree = PythonSyntax.parse(text)
            except (SyntaxError, ValueError, RecursionError):
                # S2: a file that will not parse offers no client to import; its own analyser
                # reports the unparsed file, so nothing is dropped silently here.
                continue
            if isinstance(tree, ast.Module):
                trees[path] = tree
        exported = {path: cls._made_here(tree) for path, tree in trees.items()}
        owned = {path: cls._bound_here(tree) for path, tree in trees.items()}
        imported: dict[str, dict[str, str]] = {}
        for _ in range(cls.MAX_ROUNDS):
            changed = False
            for path, tree in trees.items():
                own = owned[path]
                for name, client in cls._taken(path, tree, exported, trees):
                    if (
                        name not in own
                        and exported[path].get(name) is None
                        and imported.setdefault(path, {}).get(name) != client
                    ):
                        imported[path][name] = client
                        exported[path][name] = client  # a name taken is a name re-exported
                        changed = True
            if not changed:
                break
        return {path: names for path, names in imported.items() if names}

    @staticmethod
    def _made_here(tree: ast.Module) -> dict[str, str]:
        """Top-level `name = <client constructor>(...)`, through the file's import aliases."""
        aliases: dict[str, str] = {}
        for node in ImportedClients._module_level(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    aliases[alias.asname or alias.name.split(".")[0]] = (
                        alias.name if alias.asname else alias.name.split(".")[0]
                    )
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for alias in node.names:
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        made: dict[str, str] = {}
        for node in ImportedClients._module_level(tree):
            if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)):
                continue
            client = ImportedClients._dotted(node.value.func, aliases)
            if client not in HTTP_CLIENTS:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    made[target.id] = client
        return made

    #: What each kind of statement binds in the file that holds it: names assigned, defined, or
    #: imported from outside the package. An import from a sibling never overrides these.
    _BINDS: ClassVar[dict[type, Callable[[Any], Iterable[str]]]] = {
        ast.Name: lambda n: (n.id,) if isinstance(n.ctx, ast.Store) else (),
        ast.FunctionDef: lambda n: (n.name,),
        ast.AsyncFunctionDef: lambda n: (n.name,),
        ast.ClassDef: lambda n: (n.name,),
        ast.Import: lambda n: (a.asname or a.name.split(".")[0] for a in n.names),
    }

    @classmethod
    def _bound_here(cls, tree: ast.Module) -> frozenset[str]:
        """Names the file binds itself."""
        names: set[str] = set()
        for node in ast.walk(tree):
            binds = cls._BINDS.get(type(node))
            if binds is not None:
                names.update(binds(node))
        return frozenset(names)

    @classmethod
    def of_units(cls, units: Sequence[ScannedFile]) -> dict[str, dict[str, str]] | None:
        """`of` over a scan's Python files (`ScanContext.python_imported_clients`), or None when
        no file imports a client or there is only one file."""
        sources = {
            unit.path: unit.content.text
            for unit in units
            if unit.path.endswith(".py") and not unit.content.is_binary
        }
        if len(sources) < 2:
            return None
        return cls.of(sources) or None

    @staticmethod
    def _module_level(tree: ast.Module) -> Iterator[ast.stmt]:
        """The statements that run when the module is imported: the module's body and the bodies
        of its top-level `try` (every branch) and `if`, recursively, but never a function or class
        body. `try: from httpx import Client / except ImportError: ...` then `session = Client()`
        is a module-level client (TheThreadingAssistant, 2026-11-10); one made in a function is
        not exported."""
        pending: list[ast.stmt] = list(tree.body)
        while pending:
            node = pending.pop(0)
            yield node
            if isinstance(node, ast.Try | ast.TryStar):
                pending[:0] = [
                    *node.body,
                    *(s for h in node.handlers for s in h.body),
                    *node.orelse,
                    *node.finalbody,
                ]
            elif isinstance(node, ast.If):
                pending[:0] = [*node.body, *node.orelse]

    @staticmethod
    def _dotted(node: ast.AST, aliases: Mapping[str, str]) -> str | None:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return None
        parts.append(aliases.get(node.id, node.id))
        return ".".join(reversed(parts))

    @classmethod
    def _taken(
        cls,
        path: str,
        tree: ast.Module,
        exported: Mapping[str, Mapping[str, str]],
        trees: Mapping[str, ast.Module],
    ) -> list[tuple[str, str]]:
        """The client names this file's `from ... import` statements take from the package."""
        out: list[tuple[str, str]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            source = cls._module_file(path, node, trees)
            if source is None or source == path:
                continue
            offered = exported.get(source, {})
            for alias in node.names:
                if alias.name == "*":
                    out.extend(
                        (name, client)
                        for name, client in offered.items()
                        if not name.startswith("_")
                    )
                elif alias.name in offered:
                    out.append((alias.asname or alias.name, offered[alias.name]))
        return out

    @staticmethod
    def _module_file(
        path: str, node: ast.ImportFrom, trees: Mapping[str, ast.Module]
    ) -> str | None:
        """The package file `from <module> import ...` names, relative or absolute, if shipped."""
        here = PurePosixPath(path).parent
        if node.level:
            base = here
            for _ in range(node.level - 1):
                base = base.parent
            stems = [base / node.module.replace(".", "/")] if node.module else [base]
        else:
            if not node.module:
                return None
            relative = node.module.replace(".", "/")
            # An absolute import of the package's own module: tried against every ancestor of
            # the importing file, so `from pkg.imports import *` in `src/pkg/entry.py` finds it.
            stems = [ancestor / relative for ancestor in (here, *here.parents)]
        for stem in stems:
            for candidate in (f"{stem}.py", f"{stem}/__init__.py"):
                key = candidate[2:] if candidate.startswith("./") else candidate
                if key in trees:
                    return key
        return None


__all__ = ["ImportedClients"]
