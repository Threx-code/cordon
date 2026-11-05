"""rule_engine.anchoring.automaton: the native anchor automaton (cordon_scanner._native._anchors) and the Python
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

from cordon_scanner.detect.binary.rule_engine.anchoring.automaton import Automaton, TextCheck
from support import PeakMemory

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
            pickle.dumps(Automaton([bytes([i, 7]) for i in range(40)])._c)


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


@NATIVE
class TestArgumentShapes:
    """The extension's own arguments: any shape a caller passes is answered or refused with an
    exception, never a crash (the security review's findings 1, 4 and 6)."""

    @staticmethod
    def native() -> object:
        return Automaton.MODULE.Automaton([bytes([i, 7]) for i in range(40)])

    def test_an_index_that_changes_the_list_is_refused(self) -> None:
        ids: list[object] = []

        class Evil:
            def __index__(self) -> int:
                ids.clear()
                return 0

        ids.extend([Evil(), 1, 2])
        with pytest.raises(TypeError, match="not an int"):
            self.native().positions(b"\x01\x07", ids, 5)  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        "ids",
        [(0, 1), [0, 1], range(2), iter([0, 1]), (i for i in (0, 1))],
    )
    def test_any_sequence_of_ints(self, ids: object) -> None:
        got = self.native().positions(b"\x00\x07\x01\x07", ids, 5)  # type: ignore[attr-defined]
        assert {k: bytes(v) for k, v in got.items()} == {
            0: (0).to_bytes(8, "little"),
            1: (2).to_bytes(8, "little"),
        }

    @pytest.mark.parametrize(
        ("ids", "cap", "error"),
        [
            ([True], 5, TypeError), ([1.0], 5, TypeError), (["0"], 5, TypeError), ([-1], 5, IndexError),
            ([40], 5, IndexError), ([1 << 70], 5, OverflowError), ([0, 0], 5, ValueError),
            ([0], -1, ValueError), ([0], 1 << 30, ValueError), (5, 5, TypeError), (list(range(41)), 5, ValueError),
        ],
    )  # fmt: skip
    def test_bad_ids_and_caps_are_refused(
        self, ids: object, cap: int, error: type[Exception]
    ) -> None:
        with pytest.raises(error):
            self.native().positions(b"\x00\x07", ids, cap)  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        "data",
        [
            b"\x00\x07",
            bytearray(b"\x00\x07"),
            memoryview(b"\x00\x07"),
            type("B", (bytes,), {})(b"\x00\x07"),
        ],
    )
    def test_any_contiguous_buffer(self, data: object) -> None:
        a = self.native()
        assert a.present(data) == [0]  # type: ignore[attr-defined]
        assert list(a.positions(data, [0], 3)) == [0]  # type: ignore[attr-defined]

    @pytest.mark.parametrize("data", ["text", 5, None, memoryview(b"\x00\x07\x00\x07")[::2]])
    def test_what_is_not_a_contiguous_buffer_is_refused(self, data: object) -> None:
        a = self.native()
        with pytest.raises((TypeError, BufferError, ValueError)):
            a.present(data)  # type: ignore[attr-defined]
        with pytest.raises((TypeError, BufferError, ValueError)):
            a.positions(data, [0], 3)  # type: ignore[attr-defined]

    def test_a_large_cap_costs_only_what_is_found(self) -> None:

        a = Automaton.MODULE.Automaton([bytes([i, i, i]) for i in range(40)])
        before = PeakMemory.kib()
        got = a.positions(
            b"\x05\x05\x05", list(range(40)), 1 << 24
        )  # 40 x 16 M offsets if allocated up front
        after = PeakMemory.kib()
        assert got[5] == (0).to_bytes(8, "little") and all(
            got[i] == b"" for i in range(40) if i != 5
        )
        assert after - before < 64 * 1024  # KB: far below the 5 GB an up-front allocation would ask

    def test_build_refuses_bad_needles(self) -> None:
        for needles, error in (
            ([b""], ValueError),
            ([b"a", b"a"], ValueError),
            (["a"], TypeError),
            (5, TypeError),
        ):
            with pytest.raises(error):
                Automaton.MODULE.Automaton(needles)
        a = self.native()
        with pytest.raises(RuntimeError, match="already built"):
            a.__init__([b"x"])  # type: ignore[misc]


@NATIVE
class TestTheTextCheck:
    """The native text check (`_anchors.check_text`) and its Python twin give each offset the same
    length, every mode (ascii, wide, nocase, xor, together), offsets past either end included."""

    @settings(max_examples=EXAMPLES, deadline=None, suppress_health_check=list(HealthCheck))
    @given(
        text=st.binary(min_size=1, max_size=6) | st.sampled_from([b"aB", b"\x00", b"ab\x00"]),
        data=DATA,
        mode=st.integers(0, 15),
        extra=st.lists(st.integers(-3, 400), max_size=20),
    )
    def test_native_and_python_agree(
        self, text: bytes, data: bytes, mode: int, extra: list[int]
    ) -> None:
        offsets = sorted({*range(len(data) + 2), *extra})
        assert TextCheck.lengths(data, offsets, text, mode, native=True) == TextCheck.lengths(
            data, offsets, text, mode, native=False
        )

    def test_bad_arguments_are_refused(self) -> None:
        with pytest.raises(ValueError, match="int64"):
            Automaton.MODULE.check_text(b"ab", b"\x00\x00\x00", b"a", 1)
        with pytest.raises(TypeError):
            Automaton.MODULE.check_text("ab", b"", b"a", 1)


@NATIVE
class TestTextHitsArguments:
    """text_hits refuses an owner it cannot read, and any start, length, back or fit length outside
    [0, 2**40], with an exception, never a read outside the data."""

    @staticmethod
    def call(owners: object, max_hits: int = 10, left: float = -1.0) -> object:
        return Automaton.MODULE.text_hits(b"abcabc", owners, b"abc", 1, 1 | 2, max_hits, -1, left)

    @pytest.mark.parametrize(
        ("owners", "error"),
        [
            ([([0], 3, 3, 0, -1)], ValueError), ([([0], -1, 3, 0, 3)], ValueError),
            ([([0], 3, -9, 0, 3)], ValueError), ([([-1], 3, 3, 0, 3)], ValueError),
            ([([1 << 62], 3, 3, 0, 3)], ValueError), ([([0], 1 << 62, 0, 0, 3)], ValueError),
            ([([0], 3, 3, 0, 1 << 62)], ValueError), ([([0], 3, 3, 0, 1 << 70)], OverflowError),
            ([([0.0], 3, 3, 0, 3)], TypeError), ([((0,), 3, 3, 0, 3)], TypeError),
            ([([0], 3, 3, 0)], TypeError), (5, TypeError),
        ],
    )  # fmt: skip
    def test_bad_owners_are_refused(self, owners: object, error: type[Exception]) -> None:
        with pytest.raises(error):
            self.call(owners)

    def test_bad_max_hits_is_refused(self) -> None:
        with pytest.raises(ValueError, match="max_hits"):
            self.call([([0], 3, 3, 0, 3)], max_hits=-1)

    def test_a_fit_past_the_end_reads_nothing_outside(self) -> None:
        starts, lengths = self.call([([3, 0], 3, 3, 0, 1 << 40)])  # type: ignore[misc]
        # fullword: the start at 3 follows "c", so only 0 is kept, with the fit length as given
        assert bytes(starts) == (0).to_bytes(8, "little")
        assert bytes(lengths) == (1 << 40).to_bytes(8, "little")

    def test_no_time_left_is_a_timeout(self) -> None:
        with pytest.raises(TimeoutError):
            self.call([([0, 3], 3, 3, 0, 3)], left=0.0)


@NATIVE
class TestHexHitsArguments:
    """hex_hits (and text_hits) take only exact ints in an owner, so no Python code runs between
    counting the occurrences and writing them; the start table is sized by what is found; and
    the time allowed is read inside one event's lanes (review findings 1-3)."""

    BYTE, SKIP, DONE = 1, 13, 18

    @staticmethod
    def layout(*ops: tuple[int, int, int]) -> bytes:
        return b"".join(int(v).to_bytes(8, "little", signed=True) for op in ops for v in op)

    def plain(self) -> tuple[bytes, bytes]:
        return self.layout((self.BYTE, 0x61, 0), (self.DONE, 0, 0)), self.layout((self.DONE, 0, 0))

    def test_an_index_that_grows_the_starts_is_refused(self) -> None:
        starts: list[int] = [0]

        class Grows:
            def __index__(self) -> int:
                starts.extend(range(1, 100_000))  # past what was counted, were it run
                return 1

        forward, backward = self.plain()
        with pytest.raises(TypeError, match="not an int"):
            Automaton.MODULE.hex_hits(
                b"a" * 10, [(starts, Grows(), 1, 0, 0, 0)], forward, backward, 4096, 0, 10, -1
            )
        with pytest.raises(TypeError, match="not an int"):
            Automaton.MODULE.text_hits(b"a" * 10, [(starts, 1, Grows(), 0, 1)], b"a", 1, 0, 10, -1)

    def test_one_occurrence_costs_no_table_of_max_hits(self) -> None:
        import tracemalloc

        forward, backward = self.plain()
        tracemalloc.start()
        try:
            got = Automaton.MODULE.hex_hits(
                b"xa", [([1], 1, 1, 0, 0, 0)], forward, backward, 4096, 0, 1_000_000, -1
            )
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert bytes(got[0]) == (1).to_bytes(8, "little")
        assert peak < 1 << 20  # a table sized by max_hits was about 48 MB

    def test_one_event_of_many_lanes_runs_out_of_time(self) -> None:
        import time

        from cordon_scanner.detect.binary.rule_engine.pattern import Op
        from cordon_scanner.detect.binary.rule_engine.threads import Lanes

        data = b"a" + b"b" * 70_000
        # every position after the skip reads "b", so each becomes a lane, each insert a move
        forward = self.layout(
            (self.BYTE, 0x61, 0), (self.SKIP, 0, 65_000), (self.BYTE, 0x62, 0), (self.BYTE, 0x63, 0),
            (self.DONE, 0, 0),
        )  # fmt: skip
        began = time.monotonic()
        with pytest.raises(TimeoutError):
            Automaton.MODULE.hex_hits(
                data,
                [([0], 1, 1, 0, 0, -1)],
                forward,
                self.layout((self.DONE, 0, 0)),
                1 << 17,
                0,
                10,
                -1,
                0.05,
            )
        assert time.monotonic() - began < 5
        ops = [(Op.BYTE, 0x61), (Op.SKIP, 0, 65_000), (Op.BYTE, 0x62), (Op.BYTE, 0x63), (Op.DONE,)]
        began = time.monotonic()
        with pytest.raises(TimeoutError):
            # REACH bounds the Python twin's lanes to 4,096; a time already past is read at the
            # 4,096th step, inside this one run (Lanes has no reading between runs of its own)
            Lanes(ops).run(0, data, 0, deadline=time.monotonic() - 1)
        assert time.monotonic() - began < 5
