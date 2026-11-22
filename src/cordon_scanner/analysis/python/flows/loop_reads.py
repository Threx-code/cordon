"""A loop over a response yields the response (`ExecutionFlows._downloaded_and_run`).

`for chunk in r.iter_content(8192)`, `for line in resp`, `async for part in r.content.iter_chunked(n)`:
each chunk is the download as much as `r.content` is, so the loop's names join the fetched names
(runtimeutils, 2026-11-10: a stream written to disk a chunk at a time, then started, raised
nothing). Run to a fixed point, bounded: a loop over a loop's chunks is the same download.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from typing import ClassVar

from cordon_scanner.analysis.python.pysyntax import PythonSyntax


class LoopReads:
    """Names bound by loops over something fetched."""

    MAX_ROUNDS: ClassVar[int] = 4

    @classmethod
    def fetched_through(
        cls, tree: ast.AST, fetched: set[str], egress: Callable[[ast.AST], bool]
    ) -> None:
        """Add to `fetched` every loop target whose loop iterates a fetched name or a request."""
        loops = list(PythonSyntax.of(tree, ast.For, ast.AsyncFor))
        for _ in range(cls.MAX_ROUNDS):
            before = len(fetched)
            for loop in loops:
                fed = egress(loop.iter) or any(
                    isinstance(part, ast.Name) and part.id in fetched
                    for part in PythonSyntax.within(loop.iter, ast.Name)
                )
                if fed:
                    fetched.update(
                        part.id
                        for part in PythonSyntax.within(loop.target, ast.Name)
                        if isinstance(part, ast.Name)
                    )
            if len(fetched) == before:
                return


__all__ = ["LoopReads"]
