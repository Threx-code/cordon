"""The JavaScript parse tree's memory grows with the source and no faster, and stays under a
measured ceiling per source byte (review 98, D4: 635 MB for a 10 MB bundle on the release, 420 MB
with compact nodes, the arena to follow).

The source is generated: functions with calls, members, strings, arrays and objects, the shapes a
bundle is made of. Memory is what tracemalloc sees allocated across the parse, the source itself
excluded; the tree is dropped and collected between sizes.
"""

from __future__ import annotations

import gc
import tracemalloc

import pytest

from cordon_scanner.analysis.javascript.front.parser import Parser

pytestmark = pytest.mark.perf


class TreeSlope:
    CEILING_BYTES_PER_BYTE = 70
    """The most the tree may cost per source byte (measured: 58 with compact nodes on generated functions; 41 on the worm bundle)."""

    @staticmethod
    def source(functions: int) -> str:
        return "".join(
            f"function f{n}(a, b) {{\n"
            f"  const x = a.b.c({n}, 'text {n}', [1, 2, b]);\n"
            f"  if (x && b.d) {{ return {{ k: x, v: b[a] }}; }}\n"
            f"  return a ? b : null;\n"
            f"}}\n"
            for n in range(functions)
        )

    @staticmethod
    def tree_bytes(text: str) -> int:
        """Bytes allocated across the parse and still held by the tree."""
        gc.collect()
        tracemalloc.start()
        try:
            tree = Parser(text, typescript=False, jsx=True).program()
            gc.collect()
            held, _peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        del tree
        gc.collect()
        return held


class TestTheTreeGrowsWithTheSource:
    def test_four_times_the_source_costs_at_most_four_and_a_half_times(self) -> None:
        small, large = TreeSlope.source(2_000), TreeSlope.source(8_000)
        held_small, held_large = TreeSlope.tree_bytes(small), TreeSlope.tree_bytes(large)
        per_byte_small = held_small / len(small)
        per_byte_large = held_large / len(large)
        assert per_byte_large <= 1.1 * per_byte_small, (
            f"{per_byte_large:.1f} bytes per source byte at 4x, {per_byte_small:.1f} at 1x"
        )
        assert per_byte_large <= TreeSlope.CEILING_BYTES_PER_BYTE, (
            f"{per_byte_large:.1f} bytes per source byte; ceiling {TreeSlope.CEILING_BYTES_PER_BYTE}"
        )
