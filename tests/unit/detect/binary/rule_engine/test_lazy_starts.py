"""A lazy hunt's starts are held one at a time (`_Hunt.starts(lazy=True)`, read by the streamed hunt
in `anchoring/stream`), interpreted or compiled: mypyc turns a generator expression passed on into a
list, so the prefiltered starts are a `map` over the matches, never a comprehension. Over 20 MB with a
start at every other byte, taking a few starts holds a few, not 10 million."""

from __future__ import annotations

import tracemalloc

from cordon_scanner.detect.binary.rule_engine.lang import Rules
from cordon_scanner.detect.binary.rule_engine.scan import _Hunt


class TestLazyStarts:
    SIZE = 20 << 20

    def test_a_few_starts_hold_a_few(self) -> None:
        rules = Rules.compile("rule r { strings: $r = /(a|bb)z/ condition: $r }")
        search = rules.rules[0].strings[0].search
        assert search is not None
        data = b"az" * (self.SIZE // 2)  # a start at every other byte: 10 million of them
        hunt = _Hunt(search, data, None, None)
        # the prefiltered branch: no path of two steps to run masks along, a prefilter to start from
        assert hunt._along(0) is None and hunt._ahead(0) is not None
        tracemalloc.start()
        try:
            starts = iter(hunt.starts(0, lazy=True))
            first = [next(starts) for _ in range(10)]
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert first == list(range(0, 20, 2))
        assert peak < 8 << 20, f"{peak:,} bytes held for 10 starts"
