"""Names a package's files send for another of its files: a value bound in one module and handed to a
request in a module that imports it by name (`ScanContext.python_sent_names`).

A destination is often written down in the package's `__init__.py` or a settings module, never read
there, and posted from the modules that import it: `HOOK = "<drop point>"` in `pkg/__init__.py`,
`from pkg import HOOK` and `requests.post(HOOK, ...)` in `pkg/report.py`. The file that binds the
destination makes no request of its own, so a reading of that file alone sees a destination named,
not one sent (`DestinationLabels.sent_at_import`); this map is the other file's half of it.

Each file is summarised once (`FileSummaries`): the names it takes by `from ... import` and passes
inside the arguments of a sending call. The map runs the other way, to the file that binds each name.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Mapping
from typing import ClassVar

from cordon_scanner.analysis.python.flows.imported_clients import (
    Exporter,
    FileSummary,
    ImportedClients,
    ImportLine,
)
from cordon_scanner.analysis.python.pyfacts import PRIMITIVES
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability


class SentNames:
    #: The last part of every call the analyser counts as a send (`requests.post` -> `post`,
    #: `urllib.request.urlopen` -> `urlopen`): a call is matched by its last name, as the runner
    #: map's are, since a client may be bound to any name. Constructors (`httpx.Client`,
    #: `smtplib.SMTP`, `HTTPSConnection`) are left out: a URL handed to one is a destination
    #: named, not a request (`DestinationLabels.sent_at_import`, evidently 0.7.23).
    SENDS: ClassVar[frozenset[str]] = frozenset(
        last
        for last in (
            name.rsplit(".", 1)[-1]
            for name, capability in PRIMITIVES.items()
            if capability is Capability.EGRESS
        )
        if not last[:1].isupper()
    )

    #: A file holding none of these makes no request, so it is not read for this map.
    _WORDS: ClassVar[re.Pattern[str]] = re.compile(
        "|".join(re.escape(name) for name in sorted(SENDS, key=lambda n: (-len(n), n)))
    )

    #: Importing files counted per name, at most (the value crosses isolation as up to 3 digits).
    _MOST: ClassVar[int] = 999

    @classmethod
    def exporter(cls) -> Exporter:
        """The summary's reading of one file: `{name: "1"}` for each name the file takes with
        `from ... import` and passes inside a sending call's arguments."""
        return (cls._WORDS, cls._sent_here)

    @classmethod
    def _sent_here(cls, tree: ast.Module) -> dict[str, str]:
        taken = {
            alias.asname or alias.name
            for node in PythonSyntax.walked_of(tree, ast.ImportFrom)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
            if alias.name != "*"
        }
        if not taken:
            return {}
        sent: dict[str, str] = {}
        for call in PythonSyntax.walked_of(tree, ast.Call):
            if not isinstance(call, ast.Call) or cls._last_name(call.func) not in cls.SENDS:
                continue
            for part in [*call.args, *(k.value for k in call.keywords)]:
                for node in ast.walk(part):
                    if isinstance(node, ast.Name) and node.id in taken:
                        sent[node.id] = "1"
        return sent

    @staticmethod
    def _last_name(func: ast.expr) -> str | None:
        if isinstance(func, ast.Name):
            return func.id
        return func.attr if isinstance(func, ast.Attribute) else None

    @classmethod
    def from_summaries(cls, summaries: Mapping[str, FileSummary]) -> dict[str, dict[str, str]]:
        """`{path: {name: count}}`: the names each file binds that other files of the package import
        by name and send, with how many files do. A name a file only re-exports is not followed."""
        out: dict[str, dict[str, str]] = {}
        for path, summary in summaries.items():
            sent = summary.exported.get("sends") or {}
            if not sent:
                continue
            for line in summary.imports:
                for name, asname in line.names:
                    if (asname or name) not in sent:
                        continue
                    source = next(
                        (
                            s
                            for s in cls._sources(path, line, summaries)
                            if s != path and name in summaries[s].bound
                        ),
                        None,
                    )
                    if source is not None:
                        names = out.setdefault(source, {})
                        names[name] = str(min(int(names.get(name, "0")) + 1, cls._MOST))
        return out

    @staticmethod
    def _sources(path: str, line: ImportLine, summaries: Mapping[str, FileSummary]) -> list[str]:
        """The files `from <module> import ...` may name: the one `_module_file` resolves first,
        then, for an absolute import, the package or module of that dotted name anywhere under the
        importing file's top directory. A package that ships `pkg/pkg.py` beside `pkg/__init__.py`
        has `from pkg import HOOK` resolved to the sibling by the nearest-directory search, where
        Python's absolute import takes the package (loveclose 0.0.1)."""
        first = ImportedClients._module_file(path, line, summaries)
        found = [first] if first is not None else []
        if line.level or not line.module:
            return found
        archive, bang, member = path.rpartition("!")
        top = f"{archive}{bang}{member.split('/', 1)[0]}/"
        stem = line.module.replace(".", "/")
        found += sorted(
            p
            for p in summaries
            if p != first
            and p.startswith(top)
            and p.endswith((f"/{stem}/__init__.py", f"/{stem}.py"))
        )
        return found


__all__ = ["SentNames"]
