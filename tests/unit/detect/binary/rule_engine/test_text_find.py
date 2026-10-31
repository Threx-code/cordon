"""anchoring.automaton.TextFind: a text string's find in one native call gives the matches the hunt
gives (its twin). Random text strings (ascii, wide, xor, fullword, greedy-making alternatives of
one text, a fixed offset by `at`), random data dense in their bytes, and MAX_HITS lowered; both ways,
every match the same. Cases: CORDON_TEXTFIND_EXAMPLES (500 by default; the proof runs 100,000)."""

from __future__ import annotations

import os

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cordon_scanner.detect.binary.rule_engine import scan
from cordon_scanner.detect.binary.rule_engine.anchoring.automaton import Automaton, TextFind
from cordon_scanner.detect.binary.rule_engine.lang import RuleError, Rules

EXAMPLES = int(os.environ.get("CORDON_TEXTFIND_EXAMPLES", "500"))
NATIVE = pytest.mark.skipif(not Automaton.NATIVE, reason=str(Automaton.WHY))
TEXT = st.text(alphabet="abA1 ", min_size=1, max_size=8).filter(
    lambda t: t.strip() != "" and '"' not in t
)
MODS = st.sampled_from(
    [
        "",
        " wide",
        " ascii wide",
        " xor",
        " xor wide",
        " fullword",
        " wide fullword",
        " xor fullword",
        " private",
        " nocase",
        " nocase wide",
        " nocase fullword",
        " nocase ascii wide",
    ]
)
DATA = st.lists(
    st.sampled_from([b"a", b"b", b"A", b"1", b" ", b"\x00", b"ab", b"a\x00b\x00", b"ba"]),
    max_size=200,
).map(b"".join)


class Both:
    @staticmethod
    def matches(source: str, data: bytes, native: bool, monkeypatch: pytest.MonkeyPatch) -> object:
        if not native:
            monkeypatch.setattr(TextFind, "usable", staticmethod(lambda search: False))
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
        texts=st.lists(st.tuples(TEXT, MODS), min_size=1, max_size=3),
        data=DATA,
        hits=st.sampled_from([None, 1, 3, 50]),
        at=st.sampled_from([None, 0, 1, 5]),
    )
    def test_native_and_hunt_agree(
        self,
        texts: list[tuple[str, str]],
        data: bytes,
        hits: int | None,
        at: int | None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        body = " ".join(f'$s{i} = "{t}"{m}' for i, (t, m) in enumerate(texts))
        condition = f"$s0 at {at}" if at is not None else "any of them"
        source = f"rule r {{ strings: {body} condition: {condition} or #s0 >= 0 }}"
        with monkeypatch.context() as m:
            if hits is not None:
                m.setattr(scan, "MAX_HITS", hits)
            native = Both.matches(source, data, True, monkeypatch)
            m.setattr(scan, "MAX_HITS", hits if hits is not None else scan.MAX_HITS)
            python = Both.matches(source, data, False, monkeypatch)
        assert native == python
