"""The `python` rule module: one Python file's source-to-sink flows.

    python.flow(source, sink, destination)   as `js.flow`, read by `PythonFlowFacts.of`
    python.flows / sinks / place             as the `js` module's

`PythonFlowFacts.of` is the reader `ReachedFlows` runs over reached Python files. A file that is
not Python (.py, or a `python` script), past `ReachedFlows.MAX_SIZE`, or one the reader gives up
on has every field undefined.
"""

from __future__ import annotations

from typing import ClassVar

from cordon_scanner.detect.binary.modules.scanner_facts.facts import FileFlows


class Python(FileFlows):
    LANGUAGE: ClassVar[str] = "py"

    @staticmethod
    def read(text: str) -> list[tuple[str, str, str]]:
        from cordon_scanner.analysis.python.py_flow_facts import PythonFlowFacts

        return sorted(PythonFlowFacts.of(text))


__all__ = ["Python"]
