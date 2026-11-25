"""The Python flow facts with every source and sink kind the row names, for measurement runs and tests.

`PythonFlowFacts` is what the verdict reads, and it is left as it is. This reads the same way with four more sources (`network_response`, `browser`, `clipboard`, `wallet_key`) and two more
sinks (`file`: a source's value reaching the path or the content of a file open or write, the shapes of a dropper and of staging; `execute`: `exec`, `eval`, `compile`), so a measurement run can
record a Python package's flows in the same nine-by-six words as a JavaScript one. Facts, never findings; nothing in the scan reads it.
"""

from __future__ import annotations

import ast
import re
from typing import ClassVar

from cordon_scanner.analysis.python.py_flow import Label
from cordon_scanner.analysis.python.py_flow_facts import PythonFlowFacts


class PythonMeasureFlows(PythonFlowFacts):
    KINDS: ClassVar[tuple[str, ...]] = (
        *PythonFlowFacts.KINDS,
        "network_response",
        "browser",
        "clipboard",
        "wallet_key",
    )
    CLIPBOARD_CALLS: ClassVar[frozenset[str]] = frozenset(
        {"pyperclip.paste", "pyperclip.waitForPaste", "clipboard.paste", "pyclip.paste"}
    )
    BROWSER_MODULES: ClassVar[tuple[str, ...]] = ("browser_cookie3.", "browser_history.")
    WALLET_NAME: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)^(?:private_?key|secret_?key|wallet_?key|mnemonic|seed_?phrase)$"
    )
    SINKS: ClassVar[dict[str, frozenset[str]]] = {
        **PythonFlowFacts.SINKS,
        "file": frozenset(
            {
                "open",
                "io.open",
                "os.open",
                "shutil.copy",
                "shutil.copyfile",
                "shutil.copy2",
                "shutil.copytree",
                "shutil.move",
                "write",
                "writelines",
                "write_text",
                "write_bytes",
            }
        ),
        "execute": frozenset({"exec", "eval", "compile"}),
    }
    NAMED: ClassVar[tuple[str, ...]] = ("connection", "file")
    """The sinks that are methods of an object (`s.sendall(x)`, `handle.write(x)`): matched by the method's name."""

    def seed(self, node: ast.AST) -> Label | None:
        found = super().seed(node)
        if found is not None:
            return found
        if isinstance(node, ast.Name) and self.WALLET_NAME.match(node.id):
            return self._kind("wallet_key")
        if isinstance(node, ast.Call):
            dotted = self.dotted(node.func) or ""
            if dotted in self.CLIPBOARD_CALLS:
                return self._kind("clipboard")
            if dotted.startswith(self.BROWSER_MODULES):
                return self._kind("browser")
            if dotted in self.SINKS["request"]:
                return self._kind("network_response")
        return None

    def _sink(self, node: ast.Call) -> str | None:
        dotted = self.dotted(node.func) or ""
        name = self.name(node.func) or ""
        for sink, names in self.SINKS.items():
            if dotted in names or (sink in self.NAMED and name in names):
                return sink
        return None

    @classmethod
    def file_flows(cls, source: str) -> set[tuple[str, str, str]]:
        """Only the flows into a file."""
        return {flow for flow in cls.of(source) if flow[1] == "file"}


__all__ = ["PythonMeasureFlows"]
