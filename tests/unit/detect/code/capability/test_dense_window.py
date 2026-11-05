"""The sliding dense window finds what the per-window search finds, hit for hit.

Past `MAX_PROXIMITY_HITS`, a composite with a proximity is searched one window per hit. Each window
used to be built and counted afresh (`_dense_window_each`), quadratic in the hits; `_dense_window`
slides two ends that only move forward and keeps the counts as hits enter and leave (review 98,
27-PERFORMANCE, 7). Both are asked here, on seeded lists of hits whose lines follow their offsets,
for every builtin composite rule with a proximity: windows bounded by lines and by bytes, hits a
fixed argv excuses, unresolved hits with no variants, deferred ranges. A window that differs by one
hit -- an end off by one at either bound -- fails.
"""

from __future__ import annotations

import random

from cordon_scanner.detect.code.capability.composites import CompositeEvaluator
from cordon_scanner.detect.code.capability.hits import CapabilityHit
from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.rules.loader import RuleLoader


class Hits:
    """Seeded hit lists for the composite rules that name a capability."""

    RULE_IDS = (
        "CAP.PY.SPAWN.001",
        "CAP.SH.FETCH.001",
        "AST.PY.SPAWN",
        "CAP.JS.EGRESS.001",
        "CAP.PY.DECODE.001",
        "CAP.PY.CREDENTIAL.001",
    )

    @staticmethod
    def rules() -> list:
        packs = RuleLoader.load_builtin()
        return [
            c
            for p in packs
            for c in p.rules
            if (c.match.all_of or c.match.any_of) and c.match.proximity > 0
        ]

    @staticmethod
    def capabilities(rules: list) -> list[Capability]:
        named = {cap for c in rules for cap in Capability if cap.value in repr(c.match)}
        return sorted(named, key=lambda c: c.value)

    @staticmethod
    def make(rnd: random.Random, named: list[Capability]) -> list[CapabilityHit]:
        """More hits than the pairwise search affords, in offset order, lines never falling."""
        n = rnd.randint(CompositeEvaluator.MAX_PROXIMITY_HITS + 1, 520)
        # Spacing in lines straddles the 200-line proximity; bytes per line straddle the byte bound.
        step = rnd.choice([(0, 1), (0, 1, 2), (0, 1, 199, 200, 201), (0, 3, 30, 120)])
        width = rnd.choice([20, 60, 199, 200, 201, 600])
        hits, line, byte = [], 1, 0
        for _ in range(n):
            line += rnd.choice(step)
            byte = max(byte + 1, line * width + rnd.randint(0, width - 1))
            hits.append(
                CapabilityHit(
                    capability=rnd.choice(named),
                    rule_id=rnd.choice(Hits.RULE_IDS),
                    byte_start=byte,
                    byte_end=byte + 5,
                    line=line,
                    fixed=rnd.random() < 0.15,
                    variants=rnd.choice([0, 1, 1, 2, 3]),
                    resolved=rnd.random() < 0.3,
                )
            )
        return hits

    @staticmethod
    def key(window: list[CapabilityHit] | None) -> list[tuple[str, int, int]] | None:
        return None if window is None else [(h.rule_id, h.line, h.byte_start) for h in window]


class TestDenseWindow:
    def test_the_sliding_window_finds_what_each_window_finds(self) -> None:
        rules = Hits.rules()
        named = Hits.capabilities(rules)
        assert len(rules) >= 40, "the builtin composite rules with a proximity"
        rnd = random.Random(20261029)  # noqa: S311 - a seeded generator for test inputs
        found = 0
        for round_ in range(3):
            for compiled in rules:
                hits = sorted(Hits.make(rnd, named), key=lambda h: h.byte_start)
                last = hits[-1].line
                deferred = (
                    frozenset()
                    if round_ == 0
                    else frozenset(
                        (a, a + rnd.randint(0, 300)) for a in rnd.sample(range(1, last + 1), 3)
                    )
                )
                evaluator = CompositeEvaluator(
                    in_entry=rnd.random() < 0.3, in_import_entry=rnd.random() < 0.3
                )
                fixed = CompositeEvaluator.fixed_lines(hits)
                where = (
                    rnd.choice(["setup.py", "index.js", "scripts/install.sh"]),
                    rnd.random() < 0.5,
                )
                args = (where[0], where[1], rnd.random() < 0.2, rnd.random() < 0.2, deferred)
                sliding = evaluator._dense_window(
                    compiled, hits, *args, compiled.match.proximity, fixed
                )
                each = evaluator._dense_window_each(
                    compiled, hits, *args, compiled.match.proximity, fixed
                )
                assert Hits.key(sliding) == Hits.key(each), (compiled.rule.id, round_)
                found += each is not None
        assert found >= 20, "dense windows were found, so the comparison is not vacuous"
