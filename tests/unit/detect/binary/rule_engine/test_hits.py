"""rule_engine.hits: a string's matches kept as int64 arrays (Hits) and a match's instances built from
them when read (Match.strings): the same values every condition and caller read, in a fraction of
the memory, and the file refused past Hits.MOST matches in all."""

from __future__ import annotations

import pytest

from cordon_scanner.detect.binary.rule_engine import scan
from cordon_scanner.detect.binary.rule_engine.hits import Hits, Match
from cordon_scanner.detect.binary.rule_engine.lang import RuleError, Rules
from cordon_scanner.detect.binary.rule_engine.pattern import TooManyMatches
from support import PeakMemory


class Peak:
    @staticmethod
    def mb() -> int:
        return PeakMemory.mib()


class TestHits:
    def test_reads_as_the_list_of_pairs(self) -> None:
        pairs = [(0, 3), (5, 2), (9, 4)]
        hits = Hits(pairs)
        assert len(hits) == 3 and list(hits) == pairs and hits == pairs and hits[1] == (5, 2)
        assert hits[-1] == (9, 4) and hits[0:2] == pairs[:2] and bool(hits) and not Hits()
        assert Hits.of({9: 4, 0: 3, 5: 2}) == hits
        with pytest.raises(IndexError):
            hits[3]

    def test_a_match_reads_as_before(self) -> None:
        eager = Match("r", ["t"], {"k": 1}, [(0, "$a", b"ab"), (4, "$b", b"c")])
        lazy = Match(
            "r",
            ["t"],
            {"k": 1},
            data=b"ab  c",
            hits=[("$a", Hits([(0, 2)])), ("$b", Hits([(4, 1)]))],
        )
        assert lazy == eager and lazy.strings == eager.strings and repr(lazy) == repr(eager)
        assert Match(rule="r", tags=[], meta={}, strings=[]).strings == []

    def test_conditions_read_the_same_counts_offsets_and_lengths(self) -> None:
        rules = Rules.compile(
            'rule r { strings: $a = "ab" condition: #a == 3 and @a[2] == 4 and !a[3] == 2 and $a at 8 }'
        )
        found = rules.match(b"ab  ab  ab")
        assert [m.rule for m in found] == ["r"]
        assert found[0].strings == [(0, "$a", b"ab"), (4, "$a", b"ab"), (8, "$a", b"ab")]


class TestTheBound:
    def test_more_matches_than_the_file_may_hold_refuses_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(Hits, "MOST", 1_000)
        rules = Rules.compile('rule r { strings: $a = "a" $b = "b" condition: any of them }')
        with pytest.raises(RuleError) as caught:
            rules.match(b"ab" * 600)
        assert isinstance(caught.value.__cause__, TooManyMatches)

    def test_twenty_hot_strings_hold_their_matches_compactly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """2,000,000 matches (twenty strings at a lowered MAX_HITS of 100,000 each, on 8 MB of
        zeros): as tuples with data slices they held about 440 MB; as arrays, 32 MB."""
        monkeypatch.setattr(scan, "MAX_HITS", 100_000)
        strings = " ".join(f"$h{i} = {{ {' '.join(['00'] * (3 + i))} }}" for i in range(20))
        rules = Rules.compile(f"rule r {{ strings: {strings} condition: all of them }}")
        before = Peak.mb()
        found = rules.match(bytes(8 << 20))
        assert [m.rule for m in found] == ["r"]
        assert Peak.mb() - before < 200
