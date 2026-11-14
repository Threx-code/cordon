"""A command that switches the machine's antivirus off for what the package is about to run.

rainbowcolors 0.1.0 (a terminal-colour library) runs, from the function that prints in colour,
`powershell -ExecutionPolicy Bypass ... Add-MpPreference -ExclusionPath <folder> -ExclusionProcess
<folder>\\<exe>` with no window, before and after it downloads an executable into that folder and
starts it. A library has no reason to tell Defender to stop looking at a folder: the exclusion is
there so that what lands in it is not scanned.

`antivirus exclusion added: <call>`: a process start whose command text (its literal pieces,
through f-strings, `+`, list items and the function's own bindings) names a Defender preference
change that excludes or disables scanning: `Add-MpPreference`/`Set-MpPreference` with an
`-Exclusion*` option or a `-Disable*` switch, or the equivalent registry write under
`Windows Defender\\Exclusions`.
"""

from __future__ import annotations

import ast
import re
from typing import ClassVar

from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore
from cordon_scanner.analysis.python.pyfacts import PRIMITIVES
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability


class AvExclusions(AnalyzerCore):
    """`_antivirus_exclusions` and what it needs."""

    _PREFERENCE: ClassVar[re.Pattern[str]] = re.compile(r"(?i)\b(?:add|set)-mppreference\b")
    _EXCLUDE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)-exclusion(?:path|process|extension|ipaddress)\b|-disable[a-z]+\b"
    )
    _REGISTRY: ClassVar[re.Pattern[str]] = re.compile(r"(?i)windows defender\\+exclusions")

    def _antivirus_exclusions(self, tree: ast.AST) -> None:
        scopes: list[ast.AST] = [
            *PythonSyntax.of(tree, ast.FunctionDef),
            *PythonSyntax.of(tree, ast.AsyncFunctionDef),
            tree,
        ]
        seen: set[int] = set()
        for scope in scopes:
            values = self._scope_strings(scope)
            for call in PythonSyntax.within(scope, ast.Call):
                if id(call) in seen:
                    continue
                seen.add(id(call))
                resolved = self._resolve_callee(call)
                if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.SPAWN:
                    continue
                text = " ".join(
                    self._command_texts(
                        [*resolved[1].args, *(k.value for k in resolved[1].keywords)], values
                    )
                )
                if self._excludes(text):
                    self._record(
                        Capability.SPAWN,
                        call,
                        f"antivirus exclusion added: {resolved[0]}",
                        text[:200],
                    )

    @classmethod
    def _excludes(cls, text: str) -> bool:
        return bool(
            (cls._PREFERENCE.search(text) and cls._EXCLUDE.search(text))
            or cls._REGISTRY.search(text)
        )

    @staticmethod
    def _scope_strings(scope: ast.AST) -> dict[str, list[ast.AST]]:
        found: dict[str, list[ast.AST]] = {}
        for node in PythonSyntax.within(scope, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    found.setdefault(target.id, []).append(node.value)
        return found

    @staticmethod
    def _command_texts(parts: list[ast.AST], values: dict[str, list[ast.AST]]) -> list[str]:
        """The literal text a command is built from, through names bound in the scope (two hops)."""
        texts: list[str] = []
        pending = [(p, 0) for p in parts]
        while pending:
            node, hops = pending.pop()
            for n in ast.walk(node):
                if isinstance(n, ast.Constant) and isinstance(n.value, str):
                    texts.append(n.value)
                elif isinstance(n, ast.Name) and hops < 2:
                    pending.extend((v, hops + 1) for v in values.get(n.id, [])[:3])
        return texts


__all__ = ["AvExclusions"]
