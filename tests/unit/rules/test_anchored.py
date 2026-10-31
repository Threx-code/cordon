"""The anchored search finds exactly what finditer finds: the same matches, in the same order."""

from __future__ import annotations

import random
import re

import pytest

from cordon_scanner.rules.anchored import AnchoredSearch


class AnchorKit:
    @staticmethod
    def both(pattern: bytes, data: bytes, flags: int = 0) -> list[tuple[tuple[int, int], bytes]]:
        compiled = re.compile(pattern, flags)
        want = [(m.span(), m.group(0)) for m in compiled.finditer(data)]
        plan = AnchoredSearch.plan(compiled)
        got = [
            (m.span(), m.group(0))
            for m in AnchoredSearch.matches(compiled, plan, data, data.lower())
        ]
        assert got == want, (pattern, plan)
        return got


class TestExact:
    @pytest.mark.parametrize(
        "pattern",
        [
            rb"\bfetch\s*\(",
            rb"(?:\bfetch\s*\()|(?:\baxios\s*\.\s*get\s*\()",
            rb"ab(?:cde|cd)",  # the first alternative that matches wins, not the longest
            rb"(?:xx)?token[0-9]{1,3}",  # an optional prefix before the anchor
            rb"(?<=key=)secret\w+",  # lookbehind sees the bytes before the candidate
            rb"(?:\$\(\w+)|(?:\bcurl\b.{0,40}\|\s*sh)",  # one alternative has no anchor
            rb"(?:`[a-z]+`)|(?:\beval\s*\()",
        ],
    )
    def test_same_matches_as_finditer(self, pattern: bytes) -> None:
        text = (
            b"x fetch( axios . get( abcde abcd xxtoken12 token999 key=secretABC "
            b"$(whoami) curl http://h | sh `id` eval ( fetchfetch( afetch( "
        )
        AnchorKit.both(pattern, text * 3)

    def test_case_folded_anchors(self) -> None:
        got = AnchorKit.both(rb"\bFETCH\s*\(", b"Fetch( FETCH( fetch( xfetch(", re.IGNORECASE)
        assert len(got) == 3

    def test_matches_resume_where_the_last_ended(self) -> None:
        # Overlapping candidates: finditer takes "aaab" once, never the "aab" inside it.
        AnchorKit.both(rb"a{1,3}b", b"aaab aab ab b aaaab")

    def test_random_inputs(self) -> None:
        rng = random.Random(20261030)  # noqa: S311 - seeded test inputs, not a secret
        alphabet = b"fetch(axios.get) $`|\n \t\\eval"
        patterns = [rb"\bfetch\s*\(", rb"(?:\$\(\w*)|(?:\beval\b)", rb"(?:axi|get)os?\s*\."]
        for _ in range(300):
            data = bytes(rng.choice(alphabet) for _ in range(rng.randint(0, 400)))
            for pattern in patterns:
                AnchorKit.both(pattern, data)


class TestThePlan:
    def test_an_anchored_pattern_is_planned(self) -> None:
        plan = AnchoredSearch.plan(re.compile(rb"\bfetch\s*\("))
        assert plan is not None and plan.rest is None
        assert [a.literal for a in plan.anchors] == [b"fetch"]

    def test_unanchored_alternatives_are_searched_apart(self) -> None:
        plan = AnchoredSearch.plan(re.compile(rb"(?:\bfetch\s*\()|(?:\$\(\w+)"))
        assert plan is not None and plan.rest is not None

    def test_nothing_to_anchor_on_is_no_plan(self) -> None:
        assert AnchoredSearch.plan(re.compile(rb"[a-z]+\d")) is None
        assert AnchoredSearch.plan(re.compile(rb"x*")) is None  # can match empty

    def test_too_many_candidates_falls_back_to_finditer(self) -> None:
        compiled = re.compile(rb"abc\d")
        data = b"abc" * 100_000 + b"abc1"
        plan = AnchoredSearch.plan(compiled)
        assert plan is not None
        assert AnchoredSearch._starts(plan.anchors, data, None) is None
        AnchorKit.both(rb"abc\d", data)


PERSIST = rb">>(?>\s*\n)?[^\n]*\.(?:bashrc|bash_profile|zshrc|profile)\b"


class TestLineMonotone:
    """An alternative shaped `literal [^\\n]* tail` is tried once a line: exactly finditer's matches,
    in linear time on a line of many literals (CAP.SH.PERSIST.001, review 98, R6)."""

    def test_the_persist_branch_is_planned_line_wise(self) -> None:
        plan = AnchoredSearch.plan(re.compile(PERSIST))
        assert plan is not None and plan.rest is None and plan.anchors == ()
        [line_wise] = plan.monotone
        assert line_wise.literal == b">>" and line_wise.continuation

    @pytest.mark.parametrize(
        "data",
        [
            b"echo x >> a >> b >> ~/.bashrc\n",  # the first `>>` on the line matches, to the end
            b">> a\n>> b .zshrc\n",  # a line that fails, then one that matches
            b"a >> b >> c >> d\n",  # a line of failures only
            b"cat >> x >>  \n  y .profile\n",  # the last `>>`, blanks only after it: the line after
            b"cat >>  \n\n   \n z .bash_profile\n",  # several blank lines between
            b">> .bashrc >> .zshrc >> .profile\n",  # three matches on one line, each after the last
            b">> \n>> .bashrc",  # continuation fails (next line's `>>` is the real start)
            b"x >> y.bashrc.zshrc >> .profile",  # no newline at the end
            b">>\r\n .bashrc\r\n",  # carriage returns are blanks and not line ends
        ],
    )
    def test_same_matches_as_finditer_on_lines(self, data: bytes) -> None:
        AnchorKit.both(PERSIST, data)
        AnchorKit.both(PERSIST, data * 4)

    def test_a_folded_and_a_lazy_form(self) -> None:
        AnchorKit.both(rb">>[^\n]*?\.BASHRC\b", b">> a .bashrc >> b .BASHRC\n>> c", re.IGNORECASE)
        AnchorKit.both(
            rb"(?:>>[^\n]*\.rc\b)|(?:\bsource\s+\S+)", b">> x .rc source a\n>> source b .rc"
        )

    def test_random_inputs(self) -> None:
        rng = random.Random(20261031)  # noqa: S311 - seeded test inputs, not a secret
        pieces = [
            b">>",
            b"\n",
            b" ",
            b"\t",
            b".bashrc",
            b".zshrc",
            b".profile",
            b"x",
            b"a.b",
            b"\r\n",
        ]
        for _ in range(500):
            data = b"".join(rng.choice(pieces) for _ in range(rng.randint(0, 60)))
            AnchorKit.both(PERSIST, data)
            AnchorKit.both(rb">>[^\n]*\.profile\b", data)

    def test_its_time_grows_with_the_line_not_faster(self) -> None:
        import time

        compiled = re.compile(PERSIST)
        plan = AnchoredSearch.plan(compiled)

        def cpu(data: bytes) -> float:
            best = float("inf")
            for _ in range(3):
                started = time.process_time()
                assert list(AnchoredSearch.matches(compiled, plan, data, None)) == []
                best = min(best, time.process_time() - started)
            return best

        small, large = b"x >> " * 2_000, b"x >> " * 8_000
        # Four times the line: about four times the time. finditer takes sixteen (quadratic).
        assert cpu(large) < 7 * max(cpu(small), 1e-3)

    def test_too_many_anchored_candidates_keeps_the_line_wise_search(self) -> None:
        # A file full of the anchored alternative's literal: trying each candidate would cost more
        # than searching, so the anchored alternatives are searched for directly -- never the raw
        # pattern whole, whose line-monotone alternative would then scan a long line of `>>`
        # from every one of them.
        pattern = rb"(?:>>[^\n]*\.bashrc\b)|(?:\bcrontab\s+-)"
        compiled = re.compile(pattern)
        plan = AnchoredSearch.plan(compiled)
        assert plan is not None and plan.monotone and plan.anchored is not None
        data = b"crontab " * 50_000 + b"\n" + b"x >> " * 20_000 + b"\ncrontab -\n>> .bashrc\n"
        assert AnchoredSearch._starts(plan.anchors, data, None) is None
        AnchorKit.both(pattern, data)
