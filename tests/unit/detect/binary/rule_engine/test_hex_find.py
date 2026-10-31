"""anchoring.automaton.HexFind: a plain hex string's find in one native call gives the matches
the hunt gives (its twin). Random plain hex patterns (bytes, masked nibbles, ??, ~ negations,
jumps short and wide, repeated bytes where an anchor may sit at several places), random data
dense in their bytes, MAX_HITS lowered and a fixed offset by `at`; both ways, every match the
same. Cases: CORDON_HEXFIND_EXAMPLES (500 by default; the proof runs 100,000)."""

from __future__ import annotations

import os

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cordon_scanner.detect.binary.rule_engine import scan
from cordon_scanner.detect.binary.rule_engine.anchoring.automaton import Automaton, HexFind
from cordon_scanner.detect.binary.rule_engine.lang import RuleError, Rules

EXAMPLES = int(os.environ.get("CORDON_HEXFIND_EXAMPLES", "500"))
NATIVE = pytest.mark.skipif(not Automaton.NATIVE, reason=str(Automaton.WHY))
TOKEN = st.sampled_from(["61", "62", "00", "41", "??", "6?", "?1", "~61", "~?2", "4?"])
JUMP = st.sampled_from(
    [
        "[1]",
        "[2]",
        "[0-2]",
        "[1-3]",
        "[0-5]",
        "[4-9]",
        "[2-15]",
        "[3-40]",
        "[16-60]",
        "[0-300]",
        "[20]",
    ]
)
PIECE = st.lists(TOKEN, min_size=1, max_size=4).map(" ".join)
HEX = st.lists(st.tuples(PIECE, JUMP), min_size=1, max_size=3).flatmap(
    lambda pieces: st.just(" ".join(f"{p} {j}" for p, j in pieces[:-1]) + " " + pieces[-1][0])
)
DATA = st.one_of(
    st.lists(
        st.sampled_from(
            [b"a", b"b", b"A", b"\x00", b"aa", b"ab", b"a\x00b", b"1", b"\x61\x62\x61"]
        ),
        max_size=200,
    ).map(b"".join),
    # past the hunt's BUSY (64) occurrences of an anchor, where a heavy part's runs are first
    # tested for a factor near them (_factor_near): the C runs every event, so the two agree
    # only if that test never turns away a match
    st.tuples(st.integers(80, 600), st.sampled_from([b"a", b"ab", b"aab", b"a\x00"])).map(
        lambda t: t[1] * t[0]
    ),
)


class Both:
    @staticmethod
    def matches(source: str, data: bytes, native: bool, monkeypatch: pytest.MonkeyPatch) -> object:
        if not native:
            monkeypatch.setattr(HexFind, "layouts", staticmethod(lambda search: None))
        try:
            rules = Rules.compile(source)
        except RuleError:
            return "does not compile"
        try:
            return sorted((m.rule, sorted(m.strings)) for m in rules.match(data))
        finally:
            monkeypatch.undo()


@NATIVE
class TestTheSameMatches:
    @settings(max_examples=EXAMPLES, deadline=None, suppress_health_check=list(HealthCheck))
    @given(
        hexes=st.lists(st.tuples(HEX, st.sampled_from(["", " private"])), min_size=1, max_size=3),
        data=DATA,
        hits=st.sampled_from([None, 1, 3, 50]),
        at=st.sampled_from([None, 0, 1, 5]),
    )
    def test_native_and_hunt_agree(
        self,
        hexes: list[tuple[str, str]],
        data: bytes,
        hits: int | None,
        at: int | None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        body = " ".join(f"$h{i} = {{ {h} }}{m}" for i, (h, m) in enumerate(hexes))
        condition = f"$h0 at {at}" if at is not None else "any of them"
        source = f"rule r {{ strings: {body} condition: {condition} or #h0 >= 0 }}"
        with monkeypatch.context() as m:
            if hits is not None:
                m.setattr(scan, "MAX_HITS", hits)
            native = Both.matches(source, data, True, monkeypatch)
            m.setattr(scan, "MAX_HITS", hits if hits is not None else scan.MAX_HITS)
            python = Both.matches(source, data, False, monkeypatch)
        assert native == python


@NATIVE
class TestItIsUsed:
    def test_a_masked_pattern_with_repeated_bytes_is_found_natively(self) -> None:
        rules = Rules.compile("rule r { strings: $h = { 61 ?? 61 [0-2] 6? } condition: $h }")
        search = rules.rules[0].strings[0].search
        data = b"xxaaaaab a1ab"
        got = sorted(m.strings for m in rules.match(data))
        assert HexFind.layouts(search) is not None
        # the shortest match at each start: "a?a" then "6?" at once, so 4 bytes each
        assert got == [
            [(2, "$h", b"aaaa"), (3, "$h", b"aaaa"), (4, "$h", b"aaab"), (9, "$h", b"a1ab")]
        ]
