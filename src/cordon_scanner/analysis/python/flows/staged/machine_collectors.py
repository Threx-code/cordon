"""Which functions of a package collect a fingerprint of the machine, and which files import them.

The cross-file half of `machine_reports`: a fingerprint of the machine sent out, and a program the answer names run: a server choosing,
per machine, what to install.

is-it-ai 0.1.1: `context.get_context()` reads environment variables and the platform and hashes
files at paths a shipped config names; `verifier.verify()` posts `json.dumps(get_context())` to a
host from that config; `_parse_report(response)` downloads the URL the answer names, makes it
executable and starts it. Each half is ordinary: a self-updater asks a release API which build to
fetch and runs the installer; a telemetry client reports the platform. What a self-updater does not
send is the environment and hashes of the user's files, and what telemetry does not do is run the
answer. Together they are a server deciding, from who the machine is, what runs on it.

`MachineCollectors.of(sources)`: `{path: {name: "0"}}` for each file that imports, from another file
of the package, a top-level function that reads machine context (`os.environ`, `os.getenv`,
`platform.*`, `socket.gethostname`, `getpass.getuser`, `uuid.getnode`) and reads or hashes files
(`open`, `read_bytes`, `read_text`, `hashlib.*`, `glob.*`), directly or through a function of its
own file it calls (`ScanContext.python_imported_collectors`; the runner map's shape).

`machine report answered with a program: <sink>`: a request whose arguments carry the result of a
call to such a function (directly or through one binding), in a file whose own analysis found a
fetched program run (FETCH_EXEC).
"""

from __future__ import annotations

import ast
import re
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.python.flows.imported_clients import (
    Exporter,
    FileSummaries,
    ImportedClients,
)

if TYPE_CHECKING:
    from cordon_scanner.analysis.python.flows.imported_clients import ScannedFile


class MachineCollectors:
    """Which functions of a package collect a fingerprint of the machine, and who imports them."""

    _CONTEXT: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:os\.environ(?:\.get)?|os\.getenv|platform\.\w+|socket\.gethostname|getpass\.getuser|"
        r"uuid\.getnode|os\.uname|os\.getlogin)$"
    )
    _FILES: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:open|.*\.read_bytes|.*\.read_text|hashlib\.\w+|glob\.\w+|os\.walk|os\.listdir)$"
    )
    #: A file with none of these collects no machine context; it is not parsed for this.
    _WORDS: ClassVar[re.Pattern[str]] = re.compile(r"environ|getenv|platform|gethostname|getuser")

    @classmethod
    def of_units(cls, units: Sequence[ScannedFile]) -> dict[str, dict[str, str]] | None:
        sources = {
            unit.path: unit.content.text
            for unit in units
            if unit.path.endswith(".py") and not unit.content.is_binary
        }
        if len(sources) < 2:
            return None
        return cls.of(sources) or None

    @classmethod
    def of(cls, sources: Mapping[str, str]) -> dict[str, dict[str, str]]:
        summaries = FileSummaries.build(sources, {"collects": cls.exporter()})
        if len(summaries) < 2:
            return {}
        return ImportedClients.follow(summaries, "collects", modules=True)

    @classmethod
    def exporter(cls) -> Exporter:
        """What `FileSummaries.build` runs for this map: the context words, and the reader."""
        return (cls._WORDS, cls._collects_here)

    @classmethod
    def _collects_here(cls, tree: ast.Module) -> dict[str, str]:
        functions = {
            node.name: node
            for node in ImportedClients._module_level(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        calls = {name: cls._calls(fn) for name, fn in functions.items()}
        found: dict[str, str] = {}
        for name, made in calls.items():
            reach = set(made)
            for helper in made & set(calls):
                reach |= calls[helper]
            if any(cls._CONTEXT.match(c) for c in reach) and any(
                cls._FILES.match(c) for c in reach
            ):
                found[name] = "0"
        return found

    @staticmethod
    def _calls(function: ast.AST) -> set[str]:
        def dotted(n: ast.AST) -> str:
            if isinstance(n, ast.Attribute):
                return dotted(n.value) + "." + n.attr
            return n.id if isinstance(n, ast.Name) else ""

        names = {dotted(c.func) for c in ast.walk(function) if isinstance(c, ast.Call)}
        names |= {
            dotted(a)
            for a in ast.walk(function)
            if isinstance(a, ast.Attribute) and dotted(a) == "os.environ"
        }
        return {n for n in names if n}


__all__ = ["MachineCollectors"]
