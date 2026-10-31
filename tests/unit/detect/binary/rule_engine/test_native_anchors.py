"""rule_engine.automaton: the native anchor automaton (cordon_scanner._native._anchors) and the Python
reading give the same answers. A property over random anchor sets and random or adversarial data
holds `present` and `positions` (with a cap) equal both ways, with and without case folding; the
number of cases is CORDON_NATIVE_EXAMPLES (2,000 by default; the proof runs 100,000). Eight threads
scanning with one automaton at once get the answers one thread gets. Skipped, and saying why, where
the extension is not built."""

from __future__ import annotations

import os
import threading

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cordon_scanner.detect.binary.rule_engine.automaton import Automaton

EXAMPLES = int(os.environ.get("CORDON_NATIVE_EXAMPLES", "2000"))
NATIVE = pytest.mark.skipif(not Automaton.NATIVE, reason=str(Automaton.WHY))

BYTES = st.sampled_from([b"a", b"b", b"A", b"\x00", b"\xff", b"ab", b"aa"])
NEEDLE = st.one_of(
    st.binary(min_size=1, max_size=6),
    st.lists(BYTES, min_size=1, max_size=5).map(b"".join),
)
DATA = st.one_of(
    st.binary(max_size=300),
    st.lists(BYTES, max_size=200).map(b"".join),
    st.integers(0, 400).map(lambda n: b"a" * n),
    st.integers(0, 400).map(lambda n: b"\x00" * n),
)


class Both:
    @staticmethod
    def answers(
        needles: list[bytes], data: bytes, fold: bool, cap: int, native: bool
    ) -> tuple[object, object]:
        a = Automaton(needles, fold=fold, native=native)
        assert a.native is native
        return a.present(data), a.positions(data, range(len(needles)), cap)


@NATIVE
class TestTheSameAnswers:
    @settings(max_examples=EXAMPLES, deadline=None, suppress_health_check=list(HealthCheck))
    @given(
        needles=st.lists(NEEDLE, max_size=40, unique=True),
        data=DATA,
        fold=st.booleans(),
        cap=st.integers(0, 40),
    )
    def test_native_and_python_agree(
        self, needles: list[bytes], data: bytes, fold: bool, cap: int
    ) -> None:
        if fold:
            needles = sorted({n.lower() for n in needles})
        assert Both.answers(needles, data, fold, cap, True) == Both.answers(
            needles, data, fold, cap, False
        )

    def test_an_empty_needle_occurs_everywhere(self) -> None:
        for native in (True, False):
            a = Automaton([b"", b"x"], native=native)
            assert a.present(b"ab") == [0]
            assert a.positions(b"ab", [0, 1], 5) == {0: [0, 1, 2], 1: []}
            assert a.positions(b"abcdef", [0], 3) == {0: None}

    def test_a_needle_twice_is_refused(self) -> None:
        with pytest.raises(ValueError, match="twice"):
            Automaton([b"a", b"a"])

    def test_it_is_never_pickled(self) -> None:
        import pickle

        with pytest.raises(TypeError):
            pickle.dumps(Automaton([b"ab"])._c)


@NATIVE
class TestThreads:
    def test_eight_threads_share_one_automaton(self) -> None:
        needles = [bytes([i, i + 1, i + 2]) for i in range(0, 200, 3)] + [b"\x00\x00"]
        a = Automaton(needles)
        data = bytes(range(256)) * 400 + b"\x00" * 5000
        want = (a.present(data), a.positions(data, range(len(needles)), 10_000))
        got: list[object] = []

        def scan() -> None:
            for _ in range(5):
                got.append((a.present(data), a.positions(data, range(len(needles)), 10_000)))

        threads = [threading.Thread(target=scan) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(got) == 40 and all(g == want for g in got)


class TestTheReading:
    def test_the_status_names_the_matcher(self) -> None:
        assert Automaton.NATIVE is (Automaton.MODULE is not None)
        assert isinstance(Automaton.WHY, str) and Automaton.WHY
