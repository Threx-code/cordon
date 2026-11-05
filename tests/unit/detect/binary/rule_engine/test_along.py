"""anchoring.along.Along: the starts of a part with no anchor, worked a window at a time, are the
starts the whole file gives at once (any window size, any path, data dense in the path's bytes),
and the masks a call holds are bounded by the window, not the file: an anchorless pattern over
16 MB holds a small fraction of what whole-file masks did (89.5 MB whole-file, 6.6 MB windowed, measured)."""

from __future__ import annotations

import tracemalloc

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cordon_scanner.detect.binary.rule_engine.anchoring.along import Along
from cordon_scanner.detect.binary.rule_engine.lang import Rules

TABLE = st.sampled_from(
    [
        bytes(1 if b in want else 0 for b in range(256))
        for want in (b"a", b"ab", b"b0", b"\x00", b"a\x00b1")
    ]
)


class Whole:
    @staticmethod
    def starts(steps: list[bytes], data: bytes, segments: int | None) -> list[int]:
        """The starts over the whole data at once, as before the windows."""
        alive = Along.alive(steps, data, segments) if data else 0
        found = alive.to_bytes(len(data), "little") if data else b""
        return [i for i, b in enumerate(found) if b]


class TestTheSameStarts:
    @settings(max_examples=2000, deadline=None, suppress_health_check=list(HealthCheck))
    @given(
        steps=st.lists(TABLE, min_size=2, max_size=12),
        data=st.lists(
            st.sampled_from([b"a", b"b", b"0", b"1", b"\x00", b"aaaa"]), max_size=120
        ).map(b"".join),
        window=st.integers(1, 40),
        segments=st.sampled_from([None, 1, 2, 3]),
    )
    def test_windows_give_the_whole_file_starts(
        self, steps: list[bytes], data: bytes, window: int, segments: int | None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:  # fmt: skip
        monkeypatch.setattr(Along, "WINDOW", window)
        assert list(Along.lazy(steps, data, segments)) == Whole.starts(steps, data, segments)
        assert Along.listed(steps, data, segments, None) == Whole.starts(steps, data, segments)

    def test_the_budget_is_spent_and_bounds(self) -> None:
        steps = [bytes(1 if b == 0x61 else 0 for b in range(256))] * 2
        budget = [10]
        assert Along.listed(steps, b"aaaaa", None, budget) == [0, 1, 2, 3]
        assert budget == [6]
        with pytest.raises(Exception, match="places"):
            Along.listed(steps, b"a" * 20, None, [5])


class TestMemory:
    @staticmethod
    def peak(rules: Rules, data: bytes) -> tuple[list, int]:
        tracemalloc.start()
        try:
            rules.match(data[:4096])
            tracemalloc.reset_peak()
            before, _ = tracemalloc.get_traced_memory()
            found = rules.match(data, timeout=600)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        return [m.strings for m in found], peak - before

    def test_an_anchorless_pattern_over_16_mb_holds_little(self) -> None:
        """What a part with no anchor holds is a window's masks, never the file's: whole-file masks
        took 89.5 MB on 16 MB. Held per window it does not grow with the input. The window's cost
        is the interpreter's: 6.3 MB at 16, 32 and 64 MB on 3.13; on 3.14 28.7, 12.7 and 11.7 MB, and
        33.4 MB (macOS) and 35.7 MB (Windows) at 16 MB on CI (5 Nov). So the bound is on growth, with
        a ceiling far from the whole file's."""
        rules = Rules.compile(r"rule r { strings: $r = /[a-c][0-3][a-c][0-3][a-c]/ condition: $r }")
        data = (b"a1b2x" * 3_355_444)[: 16 << 20]
        data = data[: 10 << 20] + b"a1b2c" + data[(10 << 20) + 5 :]  # one match, 10 MB in
        found, small = self.peak(rules, data)
        assert found == [[(10 << 20, "$r", b"a1b2c")]]
        assert small < 48 << 20  # whole-file masks: 89.5 MB on these 16 MB
        _, large = self.peak(rules, data * 4)
        assert large < small + (8 << 20), (small, large)  # four times the input, no more held
