"""scan._Hunt._viable, read at the asked offset: the same answer, at every position, as the
whole-data masks it replaces (kept here as the reference): each path step's byte in its class,
forwards from the position and backwards before it, the first `_Hunt.SEGMENTS` runs of one class
read, a byte outside the data in no class."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from cordon_scanner.detect.binary.rule_engine.scan import _Hunt

CLASSES = [
    bytes(1 if b in set(cls) else 0 for b in range(256))
    for cls in (b"a", b"ab", b"\x00", b"abc\x00", b"b")
]


class Reference:
    @staticmethod
    def mask(data: bytes, steps: list[bytes], backwards: bool) -> int:
        def m(table: bytes) -> int:
            return int.from_bytes(data.translate(table), "little")

        def placed(v: int, i: int) -> int:
            return v << (8 * (i + 1)) if backwards else v >> (8 * i)

        alive = placed(m(steps[0]), 0)
        i, used = 1, 1
        while i < len(steps) and alive and used < _Hunt.SEGMENTS:
            used += 1
            same = 1
            while i + same < len(steps) and steps[i + same] == steps[i]:
                same += 1
            run, covered = m(steps[i]), 1
            while covered * 2 <= same:
                run &= (run << (8 * covered)) if backwards else (run >> (8 * covered))
                covered *= 2
            if covered < same:
                extra = 8 * (same - covered)
                run &= (run << extra) if backwards else (run >> extra)
            alive &= placed(run, i)
            i += same
        return alive


class TestTheSameAnswer:
    @settings(max_examples=3000, deadline=None)
    @given(
        data=st.lists(st.sampled_from([b"a", b"b", b"c", b"\x00", b"aa", b"ab"]), max_size=40).map(
            b"".join
        ),
        ahead=st.lists(st.sampled_from(CLASSES), min_size=0, max_size=40),
        behind=st.lists(st.sampled_from(CLASSES), min_size=0, max_size=40),
    )
    def test_every_position(self, data: bytes, ahead: list[bytes], behind: list[bytes]) -> None:
        n = len(data)
        alive = (1 << (8 * (n + 1))) - 1
        if len(ahead) >= 2:
            alive &= Reference.mask(data, ahead, backwards=False)
        if len(behind) >= 2:
            alive &= Reference.mask(data, behind, backwards=True)
        want = alive.to_bytes(n + 1, "little")
        reads = (
            _Hunt._reads(ahead) if len(ahead) >= 2 else [],
            _Hunt._reads(behind) if len(behind) >= 2 else [],
        )
        for at in range(n + 1):
            got = all(at + k < n and t[data[at + k]] for k, t in reads[0]) and all(
                at - k - 1 >= 0 and t[data[at - k - 1]] for k, t in reads[1]
            )
            assert got == bool(want[at]), at
