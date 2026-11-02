"""rule_engine.anchoring.stream: the streamed hunt gives the matches the whole-list hunt gives.

Both hunts match the same rules over the same data, and every match -- each string's offsets and
lengths, so every count and position a condition reads -- must be the same. The cases attack the
argument the stream rests on as well as random ones:

- chains (counted class repeats of at least `Chain.HEAVY`, open-ended ones read up to the reach),
  over runs of exactly REACH - 1, REACH and REACH + 1 bytes, and chains asking for more than a run
  can read (which match nothing);
- the window smaller than REACH, so anchors fall on, before and after window boundaries;
- multi-part strings with jumps up to the widest (`[n-]`, open-ended) across REACH-sized gaps;
- overlapping strings, one chain given twice, folded (`nocase`) chains;
- MAX_HITS lowered so the hunt stops mid-window.

The number of random cases is CORDON_STREAM_EXAMPLES (300 by default); the proof runs 100,000."""

from __future__ import annotations

import os

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cordon_scanner.detect.binary.rule_engine import scan
from cordon_scanner.detect.binary.rule_engine.anchoring.stream import Streams
from cordon_scanner.detect.binary.rule_engine.lang import RuleError, Rules
from cordon_scanner.detect.binary.rule_engine.threads import REACH

EXAMPLES = int(os.environ.get("CORDON_STREAM_EXAMPLES", "300"))
CHAINS = [
    "/ +\\\\s{40,}/", "/a+[ab]{64,}/", "/a{64,}/", "/[ab]{4000,}/", "/a{4095,}/", "/ {4096,}/",
    "/a+[^a]{16}/", "/[^a]{167,}[0-9]*.{513}[0-9]{1,6}/", "/a{2,}[^a]{4097}/", "/b+a{16,}b/",
]  # fmt: skip
"""Chains of byte-class repeats (each takes the chain matcher), up to and past what a run reads."""
OTHERS = [
    "{ 61 [4095-4097] 62 }", "{ 61 [4096-] 62 }", "{ 61 [0-] 62 }", "{ 61 [1-4094] 62 }", "/ab+/",
    '"ab"', '"aA" nocase', '"ab" wide', "{ 61 ?? 62 }", "/a[b\\\\x00]{1,3}/", '"a" fullword',
]  # fmt: skip
"""Other strings: jumps up to the widest, text, hex, regular expressions."""
LENGTHS = st.sampled_from([1, 2, 15, 16, 17, 64, REACH - 1, REACH, REACH + 1, 2 * REACH])
DATA = st.lists(
    st.tuples(st.sampled_from(list(b"ab \t1\x00A")), LENGTHS), min_size=1, max_size=12
).map(lambda runs: b"".join(bytes([b]) * n for b, n in runs))
WINDOWS = st.sampled_from([1, 97, REACH - 1, REACH, REACH + 1, 3 * REACH])


class Both:
    @staticmethod
    def matches(
        source: str, data: bytes, streamed: bool, window: int, monkeypatch: pytest.MonkeyPatch
    ) -> object:
        monkeypatch.setattr(Streams, "ABOVE", -1 if streamed else 1 << 40)
        monkeypatch.setattr(Streams, "WINDOW", window)
        try:
            rules = Rules.compile(source)
        except RuleError:
            return "does not compile"
        try:
            return sorted((m.rule, sorted(m.strings)) for m in rules.match(data))
        except RuleError as exc:
            return f"refused: {exc}"

    @staticmethod
    def agree(
        strings: list[str], data: bytes, window: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        body = " ".join(f"$s{i} = {s}" for i, s in enumerate(strings))
        source = f"rule r {{ strings: {body} condition: any of them }}"
        whole = Both.matches(source, data, False, window, monkeypatch)
        assert Both.matches(source, data, True, window, monkeypatch) == whole


class TestTheSameMatches:
    @settings(max_examples=EXAMPLES, deadline=None, suppress_health_check=list(HealthCheck))
    @given(
        strings=st.lists(
            st.one_of(st.sampled_from(CHAINS), st.sampled_from(OTHERS)), min_size=1, max_size=3
        ),
        twice=st.booleans(),
        folded=st.booleans(),
        data=DATA,
        window=WINDOWS,
        hits=st.sampled_from([None, 1, 7, 100, 1000]),
    )
    def test_streamed_and_whole_agree(
        self, strings: list[str], twice: bool, folded: bool, data: bytes, window: int,
        hits: int | None, monkeypatch: pytest.MonkeyPatch,
    ) -> None:  # fmt: skip
        if folded:
            strings = [s + " nocase" if s.startswith("/") else s for s in strings]
        if twice:
            strings = [*strings, strings[0]]
        if hits is not None:
            monkeypatch.setattr(scan, "MAX_HITS", hits)
        Both.agree(strings, data, window, monkeypatch)


class TestTheEdges:
    """Each chain over runs of REACH - 1, REACH and REACH + 1 bytes, at window sizes around REACH."""

    @pytest.mark.parametrize("chain", CHAINS)
    @pytest.mark.parametrize("run", [REACH - 1, REACH, REACH + 1])
    @pytest.mark.parametrize("window", [97, REACH - 1, REACH + 1])
    def test_a_chain_at_the_reach(
        self, chain: str, run: int, window: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data = (b"b" + b"a" * run + b" " * run + b"\t" * 3 + b"1" * 7) * 5
        Both.agree([chain], data, window, monkeypatch)

    def test_the_hit_limit_stops_mid_window(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(scan, "MAX_HITS", 50)
        Both.agree(
            ["/a{64,}/", "{ 00 00 }", '"a" nocase'],
            (b"a" * 5000 + b"\x00" * 300) * 6,
            97,
            monkeypatch,
        )
