"""anchoring.program.PatternFind: a regular expression's or a hex string with alternatives' find in
one native call gives the matches the hunt gives with threads.Threads (its twin). Random patterns
from a regular-expression grammar (bytes, classes, \\w \\d \\s, ., \\b, alternatives, greedy and lazy
repeats, counted ones nested), hex strings with alternatives and jumps, every modifier, random
data dense in their bytes, MAX_HITS lowered and a fixed offset by `at`; both ways the same
matches, or the same refusal (too many threads). Cases: CORDON_PATTERNFIND_EXAMPLES (500 by
default; the proof runs 100,000). The program encoding is held separately: depth, classes."""

from __future__ import annotations

import os

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cordon_scanner.detect.binary.rule_engine import scan
from cordon_scanner.detect.binary.rule_engine.anchoring.automaton import Automaton
from cordon_scanner.detect.binary.rule_engine.anchoring.program import Encoded, PatternFind
from cordon_scanner.detect.binary.rule_engine.lang import RuleError, Rules
from cordon_scanner.detect.binary.rule_engine.pattern import Op

EXAMPLES = int(os.environ.get("CORDON_PATTERNFIND_EXAMPLES", "500"))
NATIVE = pytest.mark.skipif(not Automaton.NATIVE, reason=str(Automaton.WHY))

ATOM = st.sampled_from(["a", "b", "ab", "[ab]", "[^a]", ".", r"\w", r"\d", r"\s", "x", "1", r"\b"])
QUANT = st.sampled_from(["", "", "*", "+", "?", "*?", "+?", "{2}", "{1,3}", "{0,2}?", "{2,}"])
REGEX = st.recursive(
    st.tuples(ATOM, QUANT).map("".join),
    lambda inner: st.one_of(
        st.lists(inner, min_size=1, max_size=3).map("".join),
        st.tuples(st.lists(inner, min_size=2, max_size=3).map("|".join), QUANT).map(
            lambda t: f"({t[0]}){t[1]}"
        ),
    ),
    max_leaves=6,
)
HEXTOK = st.sampled_from(
    ["61", "62", "78", "?1", "6?", "??", "( 61 | 62 63 )", "( 62 | 78 )", "[1-2]"]
)
HEX = st.lists(HEXTOK, min_size=2, max_size=6).map(lambda ts: "61 " + " ".join(ts) + " 62")
MODS = st.sampled_from(
    ["", " wide", " ascii wide", " nocase", " fullword", " private", " nocase wide"]
)
DATA = st.lists(
    st.sampled_from(
        [b"a", b"b", b"x", b"1", b" ", b"\n", b"ab", b"aab", b"A", b"a\x00b\x00", b"bx1"]
    ),
    max_size=150,
).map(b"".join)


class Both:
    @staticmethod
    def matches(source: str, data: bytes, native: bool, monkeypatch: pytest.MonkeyPatch) -> object:
        if not native:
            monkeypatch.setattr(PatternFind, "programs", staticmethod(lambda search: None))
        try:
            rules = Rules.compile(source)
        except RuleError:
            return "does not compile"
        try:
            return sorted((m.rule, sorted(m.strings)) for m in rules.match(data))
        except RuleError as exc:
            return f"refused: {exc}"
        finally:
            monkeypatch.undo()


@NATIVE
class TestTheSameMatches:
    @settings(max_examples=EXAMPLES, deadline=None, suppress_health_check=list(HealthCheck))
    @given(
        pattern=st.one_of(REGEX.map(lambda r: f"/a{r}/"), HEX.map(lambda h: f"{{ {h} }}")),
        mods=MODS,
        data=DATA,
        hits=st.sampled_from([None, 1, 3, 50]),
        at=st.sampled_from([None, 0, 1, 5]),
    )
    def test_native_and_hunt_agree(
        self,
        pattern: str,
        mods: str,
        data: bytes,
        hits: int | None,
        at: int | None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mods = "" if pattern.startswith("{") and "nocase" in mods else mods
        condition = f"$p at {at}" if at is not None else "$p"
        source = f"rule r {{ strings: $p = {pattern}{mods} condition: {condition} or #p >= 0 }}"
        with monkeypatch.context() as m:
            if hits is not None:
                m.setattr(scan, "MAX_HITS", hits)
            native = Both.matches(source, data, True, monkeypatch)
            m.setattr(scan, "MAX_HITS", hits if hits is not None else scan.MAX_HITS)
            python = Both.matches(source, data, False, monkeypatch)
        assert native == python


class TestTheEncoding:
    @staticmethod
    def nesting(ops: list[tuple[int, ...]]) -> int:
        """The depth another way: ENTER and AGAIN pairs nest in pc order (the body is laid between
        them), so a stack over the layout gives the deepest."""
        depth = deepest = 0
        for op in ops:
            if op[0] == Op.ENTER:
                depth += 1
                deepest = max(deepest, depth)
            elif op[0] == Op.AGAIN:
                depth -= 1
        return deepest

    @pytest.mark.parametrize(
        "pattern",
        [
            r"/a((b{2,3}c){2,4}){1,2}x(d{2}){2}/",
            r"/a(b{1,3}){2,5}/",
            r"/ab*c+/",
            r"/a(((b){2,3}c){2,3}d){2,3}/",
        ],
    )
    def test_the_depth_is_the_nesting_not_the_count(self, pattern: str) -> None:
        rules = Rules.compile(f"rule r {{ strings: $p = {pattern} condition: $p }}")
        for ops in (
            rules.rules[0].strings[0].search.parts[0].forward,
            rules.rules[0].strings[0].search.parts[0].backward,
        ):
            assert Encoded.depth(ops) == TestTheEncoding.nesting(ops)
            assert Encoded.depth(ops) <= sum(1 for op in ops if op[0] == Op.ENTER)

    def test_each_class_is_its_bits(self) -> None:
        import struct

        rules = Rules.compile(r"rule r { strings: $p = /a[b-d][^\n]x/ condition: $p }")
        program = Encoded.of(rules.rules[0].strings[0].search.parts[0].forward)
        assert program is not None
        words = struct.unpack(f"<{len(program) // 8}q", program)
        nops, nclasses = words[2], words[3]
        assert words[:2] == (Encoded.MAGIC, Encoded.VERSION) and nclasses >= 1
        bits = words[7 + 6 * nops : 7 + 6 * nops + 4]

        def has(c: int) -> bool:  # bit c in word c >> 6
            return bool(bits[c >> 6] >> (c & 63) & 1)

        assert has(ord("b")) and has(ord("d")) and not has(ord("a")) and not has(ord("e"))

    @pytest.mark.skipif(not Automaton.NATIVE, reason=str(Automaton.WHY))
    def test_the_native_find_is_used(self) -> None:
        rules = Rules.compile("rule r { strings: $p = /a(b|cd)+e/ condition: $p }")
        search = rules.rules[0].strings[0].search
        found = sorted(m.strings for m in rules.match(b"xx abcdbe abe ae"))
        assert PatternFind.programs(search) is not None
        assert found == [[(3, "$p", b"abcdbe"), (10, "$p", b"abe")]]
