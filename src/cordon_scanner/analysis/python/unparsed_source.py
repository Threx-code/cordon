"""Package source that runs and does not parse: read as Python 2, or a content gap (09 3a).

Nearly every Python reader skips source it cannot parse (`except SyntaxError: return ...`), so a
package whose `__init__.py`, or a module it imports, did not parse was scanned as complete with
nothing in it: an 85 KB `__init__.py` that no reader read passed (M3, project47). A file that runs
when the package is installed or imported, and that this Python will not parse, is now one of:

```
  running files = install closure (setup.py, hooks, what they import)
                + import entries (a package's top-level __init__.py) + what they import
        │
        ▼  does not parse
  Python 2 / 3.6 (PythonTwoReader) ───────► read as code: `<path>#as-python.py`, every detector
        │ no                                 reads it with the file's running context
        ▼
  newer syntax than this Python on the line it stopped at ─────────────► SOURCE.UNPARSED, a gap
  a modelled grammar's construct there, or the reader's bound reached ─► SOURCE.UNPARSED, a gap
  an act token anywhere in the file (exec, decode, process, network, …) ► SOURCE.UNPARSED, a gap
  otherwise: no CPython compiles it, so it runs nothing ────────────────► SOURCE.BROKEN, said
```

The last line is the one exemption (cordon-47, 2026-11-07): a file no grammar accepts executes
nothing under CPython, but another module could still slice it and run the pieces, so a file
carrying any act token stays a gap. setup.py itself is the manifest parser's (MANIFEST.UNPARSED /
NOT_PYTHON3). A file nothing runs at install or import -- a test, a template, an unused module -- is
not a gap here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.python.python_two_reader import PythonTwoReader
from cordon_scanner.analysis.python.statements import PythonTwo
from cordon_scanner.foundation.paths import ContainerPaths

if TYPE_CHECKING:
    from cordon_scanner.foundation.models import Finding


@dataclass(frozen=True, slots=True)
class Decision:
    """parses | reading (with the Python 3 text) | gap | broken."""

    kind: str
    reading: str | None = None


class UnparsedSource:
    RULE = "OPERATIONAL.SOURCE.UNPARSED"
    BROKEN = "OPERATIONAL.SOURCE.BROKEN"

    #: Syntax newer than this Python (3.13, 3.14) on a line: type-parameter defaults, template
    #: strings. Not readable here, so a gap, never "broken".
    NEWER: ClassVar[re.Pattern[str]] = re.compile(
        r"^\s*(?:(?:async\s+)?def|class|type)\s+\w+\s*\[[^\]]*="
        r"|(?<![\w.'\"])(?:[tT][rR]?|[rR][tT])['\"]"
    )
    #: What could run a file's pieces, or what a payload does (cordon-47's guard): code execution,
    #: imports by name, decoding, processes, the network, pickle and ctypes loads.
    ACT: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:exec|eval|compile|__import__|importlib|base64|b64decode|b32decode|b16decode|"
        r"a85decode|b85decode|zlib|marshal|codecs|subprocess|system|popen|Popen|spawn\w*|"
        r"socket|urllib\d?|urlopen|requests|httplib|http\.client|http\.server|pickle|cPickle|"
        r"ctypes|CDLL|WinDLL)\b|\bimport\s+http\b|\bfrom\s+http\b"
    )

    @staticmethod
    def runs_as_source(path: str, running: set[str]) -> bool:
        """Whether `path` is package source this step decides: a running `.py`, not setup.py (the
        manifest parser's: MANIFEST.UNPARSED / NOT_PYTHON3)."""
        return (
            path in running and path.endswith(".py") and ContainerPaths.basename(path) != "setup.py"
        )

    @staticmethod
    def decide(text: str) -> Decision:
        """A running file's text, decided as the module docstring draws it."""
        from cordon_scanner.analysis.python.pysyntax import PythonSyntax

        try:
            PythonSyntax.parse(text)
            return Decision("parses")
        except SyntaxError:
            pass
        except (ValueError, RecursionError, MemoryError):
            return Decision("gap")
        reading = PythonTwoReader.read(text)
        if reading.text is not None:
            return Decision("reading", reading.text)
        if UnparsedSource.blocks(text, reading.partial, reading.stuck_line):
            return Decision("gap")
        return Decision("broken")

    @staticmethod
    def blocks(text: str, partial: str, line: int | None) -> bool:
        """Whether a file no reading makes Python stays a gap: the reader's bound reached (no line),
        a newer or modelled grammar's construct on the line it stopped at, or an act anywhere."""
        if line is None:
            return True
        lines = partial.splitlines()
        stopped = lines[line - 1] if 1 <= line <= len(lines) else ""
        if UnparsedSource.NEWER.search(stopped) or PythonTwo.construct(partial, line):
            return True
        return UnparsedSource.ACT.search(text) is not None

    @staticmethod
    def gap(path: str) -> Finding:
        from cordon_scanner.foundation.models import Severity
        from cordon_scanner.foundation.results import OperationalFinding

        return OperationalFinding.build(
            path=path,
            rule_id=UnparsedSource.RULE,
            message=(
                f"{path} runs when the package is installed or imported, and it does not "
                "parse: what it does was not read."
            ),
            remediation="Vet this file by hand before installing the package.",
            severity=Severity.MEDIUM,
        )

    @staticmethod
    def broken(path: str) -> Finding:
        from cordon_scanner.foundation.results import OperationalFinding

        return OperationalFinding.build(
            path=path,
            rule_id=UnparsedSource.BROKEN,
            message=(
                f"{path} is imported or run, and no Python compiles it: importing it fails, "
                "so nothing in it runs. It names nothing that could run its pieces."
            ),
            remediation="Fix the file, or drop it from the package.",
        )


__all__ = ["Decision", "UnparsedSource"]
