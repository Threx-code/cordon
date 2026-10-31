"""rule_engine.stream: the streamed hunt gives the matches the whole-list hunt gives. Random strings
(text with and without nocase, wide, fullword; hex with wildcards and jumps; regular expressions,
anchored and not) over random data with long runs of a few bytes are matched both ways, and every
match -- each string's offsets and lengths, so every count and position a condition reads -- must be
the same; the number of cases is CORDON_STREAM_EXAMPLES (500 by default). A MAX_HITS stop is held
too, with the limit lowered."""

from __future__ import annotations

import os

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cordon_scanner.detect.binary.rule_engine import scan
from cordon_scanner.detect.binary.rule_engine.lang import RuleError, Rules
from cordon_scanner.detect.binary.rule_engine.stream import Streams

EXAMPLES = int(os.environ.get("CORDON_STREAM_EXAMPLES", "500"))
ALPHABET = b"ab\\x00A"
TEXT = st.text(alphabet="abA", min_size=1, max_size=4)
HEX_BYTE = st.sampled_from(["61", "62", "00", "41", "??", "6?"])
STRING = st.one_of(
    st.tuples(TEXT, st.sampled_from(["", " nocase", " wide", " fullword", " ascii wide", " nocase wide"])).map(
        lambda t: f'"{t[0]}"{t[1]}'
    ),
    st.lists(HEX_BYTE, min_size=1, max_size=4).filter(lambda bs: any("?" not in b for b in bs)).map(
        lambda bs: "{ " + " ".join(bs) + " }"
    ),
    st.tuples(st.lists(st.sampled_from(["61", "62", "00"]), min_size=1, max_size=2), st.integers(0, 3),
              st.lists(st.sampled_from(["61", "62", "00"]), min_size=1, max_size=2)).map(
        lambda t: "{ " + " ".join(t[0]) + f" [0-{t[1]}] " + " ".join(t[2]) + " }"
    ),
    st.sampled_from(["/ab+/", "/a[b\\\\x00]{1,3}/", "/b.?a/", "/^ab/", "/(a|b)b/", "/a\\\\x00*b/", "/[ab]{2}/"]),
)  # fmt: skip
DATA = st.lists(st.tuples(st.sampled_from(list(ALPHABET)), st.integers(1, 40)), max_size=60).map(
    lambda runs: b"".join(bytes([b]) * n for b, n in runs)
)


class Both:
    @staticmethod
    def matches(
        source: str, data: bytes, streamed: bool, monkeypatch: pytest.MonkeyPatch
    ) -> object:
        monkeypatch.setattr(Streams, "ABOVE", -1 if streamed else 1 << 40)
        try:
            rules = Rules.compile(source)
        except RuleError:
            return "does not compile"
        return sorted((m.rule, sorted(m.strings)) for m in rules.match(data))


class TestTheSameMatches:
    @settings(max_examples=EXAMPLES, deadline=None, suppress_health_check=list(HealthCheck))
    @given(strings=st.lists(STRING, min_size=1, max_size=4), data=DATA)
    def test_streamed_and_whole_agree(
        self, strings: list[str], data: bytes, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        body = " ".join(f"$s{i} = {s}" for i, s in enumerate(strings))
        source = f"rule r {{ strings: {body} condition: any of them }}"
        assert Both.matches(source, data, True, monkeypatch) == Both.matches(
            source, data, False, monkeypatch
        )

    def test_the_hit_limit_stops_both_at_the_same_matches(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(scan, "MAX_HITS", 50)
        source = 'rule r { strings: $a = { 00 00 } $b = "a" nocase condition: #a >= 0 and #b >= 0 and any of them }'
        data = (b"\\x00" * 300 + b"aA") * 20
        assert Both.matches(source, data, True, monkeypatch) == Both.matches(
            source, data, False, monkeypatch
        )
