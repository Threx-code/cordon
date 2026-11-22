"""Pack probing: a learned rule is public, an attacker rewrites the behaviour so the rule no longer sees it, and the next window's
candidate catches the rewrite. On fact vectors only: no package and no sample is read."""

from __future__ import annotations

import sys
from typing import Any

from support import ROOT as REPO

sys.path.insert(0, str(REPO))

from bench.cdi.distill import Distiller, Terms, Unit
from test_distill import FactsKit


class Helpers:
    @staticmethod
    def fires(candidate: dict[str, Any], facts: dict[str, Any]) -> bool:
        """Whether a candidate's predicate (every term of it) holds for a facts record."""
        held = Terms.of(facts)
        return all(tuple(term) in held for term in candidate["predicate"])




class Evasion:
    @staticmethod
    def evaders(families: int, per: int, *, split: str = "train") -> list[Unit]:
        """The planted behaviour, rewritten: the same spawn and the same egress, kept in two files nothing reaches, so that no one
        file has both (the learned rule asks for both in one file)."""
        return [
            Unit(
                f"{split}-evader-{f}-{j}",
                "mal",
                f"evader{f}",
                "npm",
                "s0",
                split,
                FactsKit.facts(
                    [
                        (True, ["install_entry"], ["read_file"]),
                        (False, [], ["spawn"]),
                        (False, [], ["egress"]),
                    ]
                ),
            )
            for f in range(families)
            for j in range(per)
        ]

    @classmethod
    def first_window(cls) -> list[Unit]:
        return (
            FactsKit.planted(4, 5)
            + FactsKit.legit(12_000)
            + FactsKit.planted(2, 3, split="confirm")
            + FactsKit.legit(9_000, split="confirm", seed=11)
        )

    @classmethod
    def next_window(cls) -> list[Unit]:
        return (
            cls.evaders(4, 5)
            + FactsKit.legit(12_000, seed=21)
            + cls.evaders(2, 3, split="confirm")
            + FactsKit.legit(9_000, split="confirm", seed=23)
        )


class TestAnEvasionOfALearnedRuleIsCaughtByTheNextWindowsCandidate:
    def test_the_learned_rule_misses_the_rewrite_and_the_next_candidate_catches_it(self) -> None:
        learned = Distiller().distill(Evasion.first_window()).candidate
        assert learned is not None and Helpers.fires(learned, FactsKit.planted(1, 1)[0].facts)
        evader = Evasion.evaders(1, 1)[0].facts
        assert not Helpers.fires(learned, evader)  # the evasion works against the public rule

        next_candidate = Distiller().distill(Evasion.next_window()).candidate
        assert next_candidate is not None
        assert Helpers.fires(next_candidate, evader)  # the next window's candidate catches it
        assert next_candidate["predicate_digest"] != learned["predicate_digest"]

    def test_the_new_candidate_is_not_the_old_rule_loosened_onto_legit_releases(self) -> None:
        candidate = Distiller().distill(Evasion.next_window()).candidate
        assert candidate is not None
        legit_fires = sum(1 for u in FactsKit.legit(2_000, seed=31) if Helpers.fires(candidate, u.facts))
        assert legit_fires == 0

    def test_it_is_learned_from_several_families_so_one_probing_family_alone_teaches_nothing(self) -> None:
        one_family = Evasion.evaders(1, 8) + FactsKit.legit(12_000, seed=21) + Evasion.evaders(1, 3, split="confirm")
        one_family += FactsKit.legit(9_000, split="confirm", seed=23)
        assert Distiller().distill(one_family).candidate is None

    def test_time_to_catch_on_the_evading_family_is_one_window(self) -> None:
        windows_with_a_rule_that_catches_it = []
        learned = Distiller().distill(Evasion.first_window()).candidate
        evader = Evasion.evaders(1, 1)[0].facts
        for window in (Evasion.first_window, Evasion.next_window):
            candidate = Distiller().distill(window()).candidate
            windows_with_a_rule_that_catches_it.append(candidate is not None and Helpers.fires(candidate, evader))
        assert learned is not None
        assert windows_with_a_rule_that_catches_it == [False, True]
        assert windows_with_a_rule_that_catches_it.index(True) == 1
