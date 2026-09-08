"""M-16: `baseline_hits` must be measured, not declared.

`Confidence.HIGH` carries a documented, supposedly enforced meaning:

    the rule was evaluated against the benign corpus and matched nothing. A rule
    with a non-zero baseline cannot declare it, and the rule loader refuses the
    pack if one tries. This turns false-positive control from a review-time
    judgement into a load-time invariant.

What the loader checks is `int(raw.get("baseline_hits", 0)) > 0`, comparing a
self-declared integer in the rule's own YAML against zero. Nothing runs the rule
against the corpus. An author writes `baseline_hits: 0` -- the default -- and
declares `confidence: high` with no evidence whatsoever. It is a load-time
invariant over an assertion, not over a measurement.

This module supplies the measurement.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon.core.models import Confidence, MatchKind
from cordon.rules.loader import RuleLoader, RuleTester
from support import requires_corpus

pytestmark = requires_corpus

BENIGN = Path(__file__).resolve().parents[2] / "corpus" / "benign"


def benign_files() -> list[Path]:
    return sorted(p for p in BENIGN.rglob("*") if p.is_file())


def measure(compiled) -> int:
    """How many benign files this rule matches, through the detector's path."""
    hits = 0
    for path in benign_files():
        try:
            sample = path.read_text(encoding="utf-8", errors="replace")
        except OSError:  # pragma: no cover
            continue
        if RuleTester._sample_matches(compiled, sample):
            hits += 1
    return hits


ALL_RULES = [
    compiled
    for pack in RuleLoader.load_builtin()
    for compiled in pack.rules
    if compiled.match.kind in {MatchKind.REGEX, MatchKind.LITERAL}
]


@pytest.mark.corpus
class TestDeclaredBaselines:
    def test_the_corpus_is_not_empty(self) -> None:
        """A measurement over nothing measures nothing, and would let every
        declaration pass."""
        assert len(benign_files()) >= 5

    def test_there_are_rules_to_measure(self) -> None:
        assert len(ALL_RULES) > 20

    @pytest.mark.parametrize("compiled", ALL_RULES, ids=lambda c: c.rule.id)
    def test_a_high_confidence_rule_matches_no_benign_file(self, compiled) -> None:
        """The claim, measured. A rule declaring `confidence: high` must match
        nothing in the benign corpus -- not because its YAML says so, but
        because it was run."""
        if compiled.rule.capability is not None:
            pytest.skip(
                "capability primitives are labels, not findings: they never reach a "
                "report on their own, and benign code decodes and spawns constantly"
            )
        if compiled.rule.confidence < Confidence.HIGH:
            pytest.skip("only high-confidence rules carry the zero-baseline claim")
        hits = measure(compiled)
        assert hits == 0, (
            f"{compiled.rule.id} declares confidence: high, which asserts a zero "
            f"baseline over the benign corpus, and it matches {hits} benign file(s). "
            f"Lower the confidence or narrow the rule."
        )

    @pytest.mark.parametrize("compiled", ALL_RULES, ids=lambda c: c.rule.id)
    def test_a_declared_baseline_matches_the_measured_one(self, compiled) -> None:
        """A declared count that disagrees with the measured one is worse than
        no declaration: it looks like evidence."""
        declared = compiled.rule.baseline_hits
        measured = measure(compiled)
        assert declared == measured, (
            f"{compiled.rule.id} declares baseline_hits: {declared} and measures "
            f"{measured} over the benign corpus."
        )
