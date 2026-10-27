"""The chain matcher (`detect/binary/rule_chain`): patterns that are a chain of byte-class repeats,
matched from class-run lengths instead of thread by thread.

It must give exactly the matches running the threads gives, and finish where running them would
take minutes or give up at the thread bound.
"""

from __future__ import annotations

import random
import time
from typing import Any, ClassVar

import pytest

from cordon_scanner.detect.binary import rule_scan
from cordon_scanner.detect.binary.rule_chain import Chain
from cordon_scanner.detect.binary.rule_lang import RuleError, Rules


class Runs:
    """A rule's matches with the chain matcher forced on, and with it off."""

    @staticmethod
    def rules(pattern: str) -> Rules:
        return Rules.compile("rule r { strings: $a = " + pattern + " condition: $a or true }")

    @staticmethod
    def matches(rules: Rules, data: bytes, *, chain: bool) -> Any:
        busy, chained = rule_scan._Hunt.BUSY, rule_scan._Hunt._chained
        try:
            rule_scan._Hunt.BUSY = -1
            if not chain:
                rule_scan._Hunt._chained = lambda self, events: None  # type: ignore[method-assign]
            return [(m.rule, m.strings) for m in rules.match(data, timeout=60)]
        except RuleError as exc:
            return ("refused", str(exc))
        finally:
            rule_scan._Hunt.BUSY, rule_scan._Hunt._chained = busy, chained  # type: ignore[method-assign]

    @staticmethod
    def brute(pattern: list[tuple[bytes, int, int | None]], data: bytes) -> list[tuple[int, int]]:
        """Every start's first match, by backtracking with greedy repeats longest first."""
        n = len(data)
        runs = []
        for cls, _, _ in pattern:
            r = [0] * (n + 1)
            for i in range(n - 1, -1, -1):
                r[i] = r[i + 1] + 1 if data[i] in cls else 0
            runs.append(r)
        memo: dict[tuple[int, int], int | None] = {}

        def go(i: int, p: int) -> int | None:
            if i == len(pattern):
                return p
            if (i, p) not in memo:
                _, lo, hi = pattern[i]
                top = runs[i][p] if hi is None else min(hi, runs[i][p])
                memo[(i, p)] = next(
                    (e for k in range(top, lo - 1, -1) if (e := go(i + 1, p + k)) is not None),
                    None,
                )
            return memo[(i, p)]

        return [(s, e - s) for s in range(n) if (e := go(0, s)) is not None and e > s]


class TestWhatIsAChain:
    @pytest.mark.parametrize(
        ("pattern", "chain"),
        [
            (r"/ +\s{475}\s{402,}/", True),
            (r"/[^a]{167,}[0-9]*.{513}[0-9]{1,6}/s", True),
            (r"/[ ]{400,}\S/", True),
            (r"/[0-9]?ab/", False),  # a first term that may read nothing
            (r"/a+?b/", False),  # a lazy repeat
            (r"/(ab)+/", False),  # a repeat of more than one byte
            (r"/a|b/", False),
        ],
    )
    def test_chains_are_recognised(self, pattern: str, chain: bool) -> None:
        part = Runs.rules(pattern).rules[0].strings[0].search.parts[0]
        assert (part.chain is not None) is chain
        if chain:
            assert isinstance(part.chain, Chain)


class TestSameMatchesAsTheRuns:
    CLASSES: ClassVar[list[str]] = ["a", " ", "[ab]", "\\s", "[^a]", "[0-9]", ".", "\\w", "B"]

    @pytest.mark.parametrize("seed", range(4))
    def test_random_chains_over_long_runs(self, seed: int) -> None:
        r = random.Random(seed)  # noqa: S311 -- a fixture, not key material
        for _ in range(12):
            terms = []
            for i in range(r.randint(1, 4)):
                reps = ["", "+", f"{{{r.randint(1, 60)}}}", f"{{{r.randint(1, 40)},}}"]
                reps += ["*", "?", f"{{0,{r.randint(1, 9)}}}"] if i else []
                terms.append(r.choice(self.CLASSES) + r.choice(reps))
            pattern = "/" + "".join(terms) + "/" + r.choice(["", "i", "s"])
            rules = Runs.rules(pattern)
            pieces = [b" " * r.randint(1, 300), b"ab1", b"\n", b"aB" * r.randint(1, 40), b"7" * 90]
            data = b"".join(r.choice(pieces) for _ in range(40))[:3000]
            assert Runs.matches(rules, data, chain=True) == Runs.matches(
                rules, data, chain=False
            ), pattern

    @pytest.mark.parametrize(
        ("pattern", "data"),
        [
            (r"/ +/", b" " * 10000),  # anchors' backward and forward runs each read up to the reach
            (r"/ +b/", b" " * 5000 + b"b"),
            (r"/x {2,}/", b"x" + b" " * 5000),
            (r"/ {2,}x/", b" " * 4097 + b"x"),
        ],
    )
    def test_matches_as_long_as_the_reach(self, pattern: str, data: bytes) -> None:
        rules = Runs.rules(pattern)
        assert Runs.matches(rules, data, chain=True) == Runs.matches(rules, data, chain=False)


class TestWhereRunningThreadsIsDear:
    def test_long_counted_repeats_over_spaces_finish_at_once(self) -> None:
        data = (b" " * 1371 + b"\n" + b" " * 1108 + b"ab1" + b" " * 1018 + b"Z9+/") * 2
        rules = Runs.rules(r"/ +\s{475}\s{402,}/i")
        started = time.perf_counter()
        found = Runs.matches(rules, data, chain=True)
        assert time.perf_counter() - started < 5
        assert found[0][1]

    def test_a_pattern_the_runs_refuse_is_answered_correctly(self) -> None:
        r = random.Random(7)  # noqa: S311 -- a fixture, not key material
        data = bytes(r.choice(b"0123456789abcdef_ \n") for _ in range(4000))
        pattern = r"/[0-9]{2,50}\w{15,26}\w{575}/s"
        word = bytes(c for c in range(256) if chr(c).isascii() and (chr(c).isalnum() or c == 95))
        want = Runs.brute([(b"0123456789", 2, 50), (word, 15, 26), (word, 575, 575)], data)
        found = Runs.matches(Runs.rules(pattern), data, chain=True)
        got = [(o, len(t)) for o, _, t in found[0][1]] if found and found[0][1] else []
        assert sorted(got) == want
