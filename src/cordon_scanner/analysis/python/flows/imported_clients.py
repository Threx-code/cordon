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
import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
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


@dataclass(frozen=True, slots=True)
class ImportLine:
    """One `from <module> import <names>` of a file, kept without its tree."""

    module: str | None
    level: int
    names: tuple[tuple[str, str | None], ...]


@dataclass(frozen=True, slots=True)
class FileSummary:
    """What the cross-file maps read of one file: the names it binds, its `from ... import` lines,
    its top-level functions, and what each exporter found it offers (`{kind: {name: value}}`)."""

    bound: frozenset[str]
    imports: tuple[ImportLine, ...]
    functions: frozenset[str]
    exported: Mapping[str, Mapping[str, str]]


#: An exporter: the words a file must hold for it to run (None: always), and what it reads of a tree.
Exporter = tuple["re.Pattern[str] | None", Callable[[ast.Module], dict[str, str]]]


class FileSummaries:
    """One parse per file, one file at a time, its tree dropped before the next is parsed.

    The cross-file maps used to keep every file's tree of the package alive together: a package of
    11,766 Python files or 74 MB of source (datadog_api_client, kubernetes in the 16,274 benign gate
    units) took a scan past 4 GB, the scanner-DoS class. A summary is the names and import lines a
    file holds, a small fraction of its tree, so the peak is the largest single file's parse.
    """

    @staticmethod
    def build(
        sources: Mapping[str, str], exporters: Mapping[str, Exporter]
    ) -> dict[str, FileSummary]:
        summaries: dict[str, FileSummary] = {}
        for path, text in sources.items():
            if not path.endswith(".py"):
                continue
            try:
                tree = PythonSyntax.parse(text)
            except (SyntaxError, ValueError, RecursionError):
                # S2: a file that will not parse offers nothing to import; its own analyser
                # reports the unparsed file, so nothing is dropped silently here.
                continue
            if not isinstance(tree, ast.Module):
                continue
            summaries[path] = FileSummary(
                bound=ImportedClients._bound_here(tree),
                imports=FileSummaries._import_lines(tree),
                functions=frozenset(
                    f.name
                    for f in tree.body
                    if isinstance(f, ast.FunctionDef | ast.AsyncFunctionDef)
                ),
                exported={
                    kind: (read(tree) if words is None or words.search(text) else {})
                    for kind, (words, read) in exporters.items()
                },
            )
            del tree
        return summaries

    @staticmethod
    def _import_lines(tree: ast.Module) -> tuple[ImportLine, ...]:
        return tuple(
            ImportLine(node.module, node.level, tuple((a.name, a.asname) for a in node.names))
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )


class ImportedClients:
    """Per file, the names it imports that are HTTP clients made in another of the package's files."""

    #: Rounds of re-export followed (`a` makes it, `b` re-exports it, `c` takes it from `b`...).
    MAX_ROUNDS: ClassVar[int] = 8

    @classmethod
    def of(cls, sources: Mapping[str, str]) -> dict[str, dict[str, str]]:
        """`{path: {name: client constructor}}` for each file that imports a client, and only those."""
        summaries = FileSummaries.build(sources, {"made": (None, cls._made_here)})
        return cls.follow(summaries, "made")

    @classmethod
    def runners_of(cls, sources: Mapping[str, str]) -> dict[str, dict[str, str]]:
        """`{path: {name: "0,2"}}` for each file that imports a function another file of the package
        defines at its top level and that runs its own parameters at those positions as a command
        (`ReceivedRuns._runners`): `def run_cmd(cmd): subprocess.check_output(cmd.split())` in
        `utils.py`, called from the bot handler that took it with `from .utils import run_cmd`.
        Followed through imports and re-exports like the clients."""
        summaries = FileSummaries.build(sources, {"runs": (cls._SINK_WORDS, cls._runs_here)})
        if len(summaries) < 2:
            return {}
        return cls.follow(summaries, "runs", modules=True)

    @classmethod
    def follow(
        cls, summaries: Mapping[str, FileSummary], kind: str, *, modules: bool = False
    ) -> dict[str, dict[str, str]]:
        """`_follow` over one exporter's findings in a set of summaries."""
        return cls._follow(
            summaries,
            {path: dict(s.exported.get(kind, {})) for path, s in summaries.items()},
            modules=modules,
        )

    #: A file with none of these cannot run a command, so its analyser is not started for it.
    _SINK_WORDS: ClassVar[re.Pattern[str]] = re.compile(
        r"subprocess|system|popen|Popen|exec|eval|spawn|compile|getoutput|check_(?:call|output)"
    )

    @classmethod
    def _follow(
        cls,
        summaries: Mapping[str, FileSummary],
        exported: dict[str, dict[str, str]],
        *,
        modules: bool = False,
    ) -> dict[str, dict[str, str]]:
        """What each file takes of `exported` (each file's own names) through the package's imports,
        re-exports included, to a fixed point."""
        imported: dict[str, dict[str, str]] = {}
        for _ in range(cls.MAX_ROUNDS):
            changed = False
            for path, summary in summaries.items():
                own = summary.bound
                for name, client in cls._taken(path, summary, exported, summaries, modules=modules):
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
    def _runs_here(tree: ast.Module) -> dict[str, str]:
        """Top-level functions that run one of their own parameters, by position."""
        from cordon_scanner.analysis.python.pyast import PythonAnalyzer

        top = {
            node.name
            for node in ImportedClients._module_level(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        if not top:
            return {}
        analyzer = PythonAnalyzer._prepared(tree)
        analyzer._walk(tree)
        return {
            name: ",".join(str(i) for i in sorted(positions))
            for name, positions in analyzer._runners(tree).items()
            if name in top
        }

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
    def runners_of_units(cls, units: Sequence[ScannedFile]) -> dict[str, dict[str, str]] | None:
        """`runners_of` over a scan's Python files (`ScanContext.python_imported_runners`)."""
        sources = {
            unit.path: unit.content.text
            for unit in units
            if unit.path.endswith(".py") and not unit.content.is_binary
        }
        if len(sources) < 2:
            return None
        return cls.runners_of(sources) or None

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
        summary: FileSummary,
        exported: Mapping[str, Mapping[str, str]],
        paths: Mapping[str, Any],
        *,
        modules: bool = False,
    ) -> list[tuple[str, str]]:
        """The names this file's `from ... import` statements take from the package. With
        `modules`, `from . import core` also takes what `core.py` exports, by its bare names: the
        file reaches them as `core.run_cmd`, and the analyser matches a call by that last name."""
        out: list[tuple[str, str]] = []
        for node in summary.imports:
            source = cls._module_file(path, node, paths)
            if source == path:
                continue
            offered = exported.get(source, {}) if source is not None else {}
            for alias_name, alias_as in node.names:
                if source is None and not modules:
                    break
                if alias_name == "*":
                    out.extend(
                        (name, client)
                        for name, client in offered.items()
                        if not name.startswith("_")
                    )
                elif alias_name in offered:
                    out.append((alias_as or alias_name, offered[alias_name]))
                elif modules:
                    named = ImportLine(
                        f"{node.module}.{alias_name}" if node.module else alias_name, node.level, ()
                    )
                    member = cls._module_file(path, named, paths)
                    if member is not None and member != path:
                        out.extend(
                            (name, value)
                            for name, value in exported.get(member, {}).items()
                            if not name.startswith("_")
                        )
        return out

    @staticmethod
    def _module_file(path: str, node: ImportLine, paths: Mapping[str, Any]) -> str | None:
        """The package file `from <module> import ...` names, relative or absolute, if shipped.

        A file inside an archive is named `archive!member` (`pkg-1.0-py3-none-any.whl!pkg/a.py`):
        the import is resolved inside the archive, whose name is only the prefix the keys carry."""
        archive, bang, member = path.rpartition("!")
        prefix = archive + bang
        here = PurePosixPath(member).parent
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
                key = prefix + (candidate[2:] if candidate.startswith("./") else candidate)
                if key in paths:
                    return key
        return None


__all__ = ["FileSummaries", "FileSummary", "ImportLine", "ImportedClients"]
