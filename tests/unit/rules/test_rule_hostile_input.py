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
from typing import Any

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

    @staticmethod
    def cpu(regex: re.Pattern[bytes], data: bytes) -> float:
        best = float("inf")
        for _ in range(2):
            started = time.thread_time()
            for _ in regex.finditer(data):
                pass
            best = min(best, time.thread_time() - started)
            if best > HostileKit.CEILING:
                break  # already over: a second run only costs time
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
            if t_large > worst[0] or (t_large > HostileKit.NOISE and ratio > worst[1]):
                worst = (t_large, ratio, piece)
        return worst


RULES = HostileKit.rules()


class TestEveryRuleOnHostileInput:
    def test_the_suite_reaches_the_bundled_rules(self) -> None:
        assert len(RULES) >= 200, len(RULES)

    @pytest.mark.parametrize(("rule_id", "regex"), RULES, ids=[r for r, _ in RULES])
    def test_linear_and_under_budget(self, rule_id: str, regex: re.Pattern[bytes]) -> None:
        large, ratio, piece = HostileKit.worst(regex)
        assert large < HostileKit.CEILING, f"{rule_id}: {large:.3f}s on {piece[:12]!r} runs"
        assert large < HostileKit.NOISE or ratio < HostileKit.RATIO, (
            f"{rule_id}: super-linear on {piece[:12]!r} runs ({ratio:.1f}x for 4x the input)"
        )
