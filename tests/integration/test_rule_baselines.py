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

from cordon_scanner.core.models import MatchKind
from cordon_scanner.rules.loader import RuleLoader, RuleTester
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

    def test_every_pattern_rule_is_a_capability_primitive(self) -> None:
        """Which is why the zero-baseline claim is not asserted here.

        There used to be a test running over these rules asserting that a
        high-confidence rule matches nothing in the benign corpus. It skipped
        capability primitives, on the correct reasoning that a primitive labels
        what a file *can do* and benign code decodes and spawns constantly.

        Every regex and literal rule in the bundled packs is a capability
        primitive, so that test skipped all forty-two of its own cases and
        asserted nothing, in every run, for the life of the suite -- while
        printing forty-two skips that read like forty-two things checked and
        found inapplicable. Selecting at collection instead of skipping turned
        it into "empty parameter set", which is what it had always been.

        This asserts the property that made it vacuous, so a non-capability
        pattern rule added to a pack fails here and is told where the claim is
        measured, rather than going unmeasured.
        """
        stray = [c.rule.id for c in ALL_RULES if c.rule.capability is None]
        assert not stray, (
            f"{stray} are pattern rules that are not capability primitives, so they "
            f"carry the zero-baseline claim and nothing measures it. Measure it here, "
            f"or in tests/integration/test_corpus.py where the composites are."
        )

    def test_the_zero_baseline_claim_is_measured_somewhere(self) -> None:
        """A signpost, asserted rather than left in a comment.

        The rules that do make the claim -- the composites and the
        detector-declared rules -- are measured by
        `test_benign_corpus_produces_nothing_significant`, which scans the whole
        benign corpus and requires nothing above `low`.
        """
        corpus = (Path(__file__).parent / "test_corpus.py").read_text(encoding="utf-8")
        assert "test_benign_corpus_produces_nothing_significant" in corpus

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
