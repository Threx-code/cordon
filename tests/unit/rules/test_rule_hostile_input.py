"""S7's pathological-input suite: every bundled rule's regex, on hostile input built from its own
pattern, runs in time linear in the input and far under its CPU budget
(reviews/release-080/S7-RULE-BUDGET.md).

The static validator (test_pattern_safety.py) refuses nested unbounded quantifiers and
backreferences. It accepts `a[a-z]*b`, which is quadratic on a run of `a`, so this suite times what
the validator cannot see. A rule found here is fixed by rewriting its pattern, never by raising the
budget.
"""

from __future__ import annotations

import re
import time
from typing import Any, ClassVar

import pytest

from cordon_scanner.rules.loader import RuleLoader
from cordon_scanner.rules.pack import CompiledMatch

try:  # Python 3.11+: the parser moved under `re`
    from re import _parser as sre_parse  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover
    import sre_parse  # type: ignore[no-redef]


class HostileKit:
    #: Bytes every rule gets a run of, whatever its pattern: the shapes text formats repeat.
    GENERIC: tuple[bytes, ...] = (
        b"a",
        b"0",
        b" ",
        b"\t",
        b"\n",
        b"\\",
        b'"',
        b"'",
        b"<",
        b"{",
        b"/",
        b"=",
        b"%",
        b".",
    )
    SMALL, LARGE = 16 << 10, 64 << 10
    #: A linear search grows 4x from SMALL to LARGE, a quadratic one 16x. Above this ratio, and
    #: above the noise floor (each time the best of two runs), the rule is super-linear on that
    #: input.
    #: The floor is 5% of the smallest budget: under parallel test load, linear rules at 30-50 ms
    #: showed 10-26x ratios; every quadratic rule found took 0.5-2 s here.
    RATIO, NOISE = 9.0, 0.1
    #: The most CPU any rule may spend on LARGE: a quarter of the smallest budget.
    CEILING = CompiledMatch.BUDGET_FLOOR / 4

    #: The machine's speed, from a fixed linear workload timed in the same run: what `REFERENCE`
    #: takes here against what it took where CEILING and NOISE were set (a 2026-11-12 container,
    #: Python 3.11-3.13: 0.17-0.19 s, every bundled rule under CEILING). On PR #71's Windows
    #: runners linear rules measured 0.547-0.578 s, three times this machine's 0.15-0.20 s: the
    #: runner was slower, not the rule. Both are scaled by it, never below 1 -- the budget, the
    #: inputs and the ratio a super-linear rule fails on are unchanged.
    REFERENCE_SECONDS = 0.18
    _speed: ClassVar[float | None] = None

    @staticmethod
    def reference() -> float:
        """The least CPU time of five runs of the reference workload: a 48-word alternation behind
        a lookbehind, the shape of the bundled rules, over 8 MB of calls."""
        words = b"|".join(f"name{i:02d}x".encode() for i in range(48))
        regex = re.compile(rb"(?<![\w$.])(?:" + words + rb")\s{0,4}\(\s{0,4}[\w$]{1,40}")
        data = (b"call(name07, value) { x = name1(y); } " * 220000)[: 8 << 20]
        best = float("inf")
        for _ in range(5):
            started = time.thread_time()
            for _ in regex.finditer(data):
                pass
            best = min(best, time.thread_time() - started)
        return best

    @classmethod
    def speed(cls) -> float:
        """How much slower than the reference machine this one is, at least 1; measured once."""
        if cls._speed is None:
            cls._speed = max(1.0, cls.reference() / cls.REFERENCE_SECONDS)
        return cls._speed

    @classmethod
    def ceiling(cls) -> float:
        return cls.CEILING * cls.speed()

    @classmethod
    def noise(cls) -> float:
        return cls.NOISE * cls.speed()

    @staticmethod
    def rules() -> list[tuple[str, re.Pattern[bytes]]]:
        out: list[tuple[str, re.Pattern[bytes]]] = []
        seen: set[bytes] = set()
        for pack in RuleLoader.load_builtin():
            for compiled in pack.rules:
                regex = compiled.match.regex
                if regex is None or regex.pattern in seen:
                    continue
                seen.add(regex.pattern)
                out.append((compiled.rule.id, regex))
        return out

    @staticmethod
    def pieces(regex: re.Pattern[bytes]) -> list[bytes]:
        """The bytes and literal runs the pattern itself names: what it repeats is what to repeat."""
        found: list[bytes] = []
        run: list[int] = []

        def close() -> None:
            if len(run) > 1:
                found.append(bytes(run))
            run.clear()

        def walk(items: Any) -> None:
            for op, av in items:
                name = str(op)
                if name == "LITERAL":
                    if av < 256:
                        found.append(bytes([av]))
                        run.append(av)
                    continue
                close()
                if name == "IN":
                    for kind, value in av:
                        if str(kind) == "LITERAL" and value < 256:
                            found.append(bytes([value]))
                        elif str(kind) == "RANGE" and value[0] < 256:
                            found.append(bytes([value[0]]))
                elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
                    walk(av[2])
                elif name == "SUBPATTERN":
                    walk(av[-1])
                elif name == "BRANCH":
                    for branch in av[1]:
                        walk(branch)
                elif name in ("ASSERT", "ASSERT_NOT"):
                    walk(av[1])
                elif name == "ATOMIC_GROUP":
                    walk(av)
            close()

        # Not guarded: the pattern compiled, so it parses; a failure here is a defect to see.
        walk(sre_parse.parse(regex.pattern.decode("latin-1"), regex.flags & ~re.DEBUG))
        unique = list(dict.fromkeys(found))
        return unique[:40]

    #: Runs of one input, the best kept: CPU time on a shared runner (CI, a loaded machine) is the
    #: work plus whatever else stole the core, so the least of several runs is the work. Measured
    #: against the same CEILING; a pattern that is slow, or super-linear, is slow on every run.
    REPEATS = 5

    @staticmethod
    def cpu(regex: re.Pattern[bytes], data: bytes) -> float:
        """The least CPU time of up to `REPEATS` runs of `regex` over `data`: at least two, so the
        small input of a ratio is as well measured as the large, and no more once one is
        comfortably under the ceiling. A single run over it is not taken as the answer: on PR #71's
        runners two linear rules measured 0.502-0.512 s once against 0.5 s."""
        best = float("inf")
        for run in range(HostileKit.REPEATS):
            started = time.thread_time()
            for _ in regex.finditer(data):
                pass
            best = min(best, time.thread_time() - started)
            if run >= 1 and best < HostileKit.ceiling() / 2:
                break
        return best

    @staticmethod
    def worst(regex: re.Pattern[bytes]) -> tuple[float, float, bytes]:
        """The worst LARGE time and SMALL->LARGE ratio over every hostile input, and its piece."""
        worst = (0.0, 0.0, b"")
        for piece in dict.fromkeys(HostileKit.pieces(regex) + list(HostileKit.GENERIC)):
            small = (piece * (HostileKit.SMALL // len(piece) + 1))[: HostileKit.SMALL]
            large = (piece * (HostileKit.LARGE // len(piece) + 1))[: HostileKit.LARGE]
            t_small = HostileKit.cpu(regex, small + b"\x01")
            t_large = HostileKit.cpu(regex, large + b"\x01")
            ratio = t_large / t_small if t_small > 0 else 0.0
            if t_large > worst[0] or (t_large > HostileKit.noise() and ratio > worst[1]):
                worst = (t_large, ratio, piece)
        return worst


RULES = HostileKit.rules()


class TestEveryRuleOnHostileInput:
    def test_the_suite_reaches_the_bundled_rules(self) -> None:
        assert len(RULES) >= 200, len(RULES)

    @pytest.mark.parametrize(("rule_id", "regex"), RULES, ids=[r for r, _ in RULES])
    def test_linear_and_under_budget(self, rule_id: str, regex: re.Pattern[bytes]) -> None:
        large, ratio, piece = HostileKit.worst(regex)
        ceiling = HostileKit.ceiling()
        assert large < ceiling, (
            f"{rule_id}: {large:.3f}s on {piece[:12]!r} runs (ceiling {ceiling:.3f}s: "
            f"{HostileKit.CEILING}s at {HostileKit.speed():.2f}x the reference machine)"
        )
        assert large < HostileKit.noise() or ratio < HostileKit.RATIO, (
            f"{rule_id}: super-linear on {piece[:12]!r} runs ({ratio:.1f}x for 4x the input)"
        )
