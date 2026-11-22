"""The gate re-scores a candidate from the rows (learning loop row LL-52), on fact vectors only: no package and no sample is read;
every unit below is a hand-made `facts`-shaped record."""

from __future__ import annotations

import functools
import random
import sys
from dataclasses import replace

import pytest

from support import ROOT as REPO

sys.path.insert(0, str(REPO))

from bench.cdi.distill import Distiller, Unit
from bench.cdi.rescore import ClaimMismatch, Rescore

CAPS = ("spawn", "egress", "read_file", "write_file", "decode", "env")


class RowsKit:
    @staticmethod
    def facts(files):
        return {
            "facts_version": "3",
            "files": [
                {"key": f"{i:016x}", "reached": reached, "places": places, "capabilities": caps}
                for i, (reached, places, caps) in enumerate(files)
            ],
            "package": {"rules": {}, "hooks": []},
        }

    @staticmethod
    def legit(n, split="train", seed=7):
        rng = random.Random(seed)  # noqa: S311 - fixture data, not a secret
        out = []
        for i in range(n):
            files = [(True, ["import_entry"], rng.sample(CAPS, 2))]
            if rng.random() < 0.3:
                files.append((False, [], [rng.choice(("spawn", "egress", "read_file"))]))
            out.append(
                Unit(
                    f"{split}-legit-{i}",
                    "legit",
                    "",
                    "npm",
                    f"s{i % 3}",
                    split,
                    RowsKit.facts(files),
                )
            )
        return out

    @staticmethod
    def planted(families, per, split="train"):
        shape = [(True, ["install_entry"], ["read_file"]), (False, [], ["spawn", "egress"])]
        return [
            Unit(f"{split}-mal-{f}-{j}", "mal", f"fam{f}", "npm", "s0", split, RowsKit.facts(shape))
            for f in range(families)
            for j in range(per)
        ]

    @staticmethod
    @functools.cache
    def made():
        """The rows and the distillation made from them, once for the module (a run over 21,000 units is the slow part)."""
        rows = tuple(RowsKit.rows())
        return rows, Distiller().distill(list(rows))

    @classmethod
    def rows(cls):
        return (
            cls.planted(4, 5)
            + cls.legit(12_000)
            + cls.planted(2, 3, split="confirm")
            + cls.legit(9_000, split="confirm", seed=11)
        )


class TestTheGateRescoresTheClaim:
    """LL-52: a candidate whose claim differs from the re-score is rejected."""

    def test_an_honest_candidate_passes(self) -> None:
        rows, run = RowsKit.made()
        Rescore.check(run.candidate, run.search, rows)

    def test_the_recomputed_numbers_are_the_stated_ones(self) -> None:
        rows, run = RowsKit.made()
        recomputed = Rescore.claims(run.candidate, run.search, rows)
        assert recomputed["train"] == run.candidate["train"]
        assert recomputed["confirm"] == run.candidate["confirm"]

    @pytest.mark.parametrize(
        ("part", "name", "value"),
        [
            ("train", "families", 9),
            ("train", "legit_upper", 0.0),
            ("train", "worst_stratum_upper", "s9"),
            ("confirm", "families", 7),
            ("confirm", "legit_upper", 0.0001),
        ],
    )
    def test_a_stated_number_the_rows_do_not_give_is_rejected_by_name(
        self, part, name, value
    ) -> None:
        rows, run = RowsKit.made()
        lie = {**run.candidate, part: {**run.candidate[part], name: value}}
        with pytest.raises(ClaimMismatch) as refusal:
            Rescore.check(lie, run.search, rows)
        assert refusal.value.fields == (f"{part}.{name}",)

    @pytest.mark.parametrize(
        ("name", "value"), [("size", 2), ("predicate_digest", "0" * 64), ("generator", "G9")]
    )
    def test_a_wrong_identity_is_rejected_by_name(self, name, value) -> None:
        rows, run = RowsKit.made()
        with pytest.raises(ClaimMismatch) as refusal:
            Rescore.check({**run.candidate, name: value}, run.search, rows)
        assert name in refusal.value.fields

    def test_a_predicate_the_rows_do_not_support_is_rejected(self) -> None:
        rows, run = RowsKit.made()
        other = {**run.candidate, "predicate": [["file", "any", "decode", "env"]]}
        with pytest.raises(ClaimMismatch) as refusal:
            Rescore.check(other, run.search, rows)
        assert "predicate_digest" in refusal.value.fields
        assert "train.families" in refusal.value.fields

    def test_other_rows_give_other_numbers(self) -> None:
        rows, run = RowsKit.made()
        fewer = [u for u in rows if not u.key.startswith("train-mal-3-")]
        with pytest.raises(ClaimMismatch, match=r"train\.families"):
            Rescore.check(run.candidate, run.search, fewer)

    def test_the_message_is_in_plain_words(self) -> None:
        rows, run = RowsKit.made()
        lie = {**run.candidate, "train": {**run.candidate["train"], "families": 9}}
        with pytest.raises(
            ClaimMismatch,
            match=r"the candidate's claim differs from the re-score in: train\.families",
        ):
            Rescore.check(lie, run.search, rows)

    def test_rows_a_generator_may_not_read_are_not_scored_either(self) -> None:
        rows, run = RowsKit.made()
        held = [replace(u, split="held") for u in RowsKit.planted(3, 4)]
        Rescore.check(run.candidate, run.search, [*rows, *held])


class TestTheRunCanBeReplayed:
    def test_the_search_record_states_every_threshold(self) -> None:
        _rows, run = RowsKit.made()
        assert run.search["params"] == {
            "generator": "G2",
            "min_families": 3,
            "confirm_min_families": 1,
            "budget": 0.005,
            "alpha": 0.05,
            "max_size": 3,
            "max_terms": 40,
            "max_candidates": 20_000,
            "lofo": True,
            "refused_families": 0,
            "refused_families_digest": run.search["params"]["refused_families_digest"],
        }

    def test_the_same_rows_and_thresholds_give_the_same_candidate_and_record(self) -> None:
        rows, run = RowsKit.made()
        again = Rescore.replay(run.search, rows)
        assert again.candidate == run.candidate
        assert again.search == run.search

    def test_a_different_threshold_is_replayed_as_recorded(self) -> None:
        rows = RowsKit.rows()
        run = Distiller(min_families=2, budget=0.01).distill(rows)
        again = Rescore.replay(run.search, rows)
        assert (again.candidate, again.search) == (run.candidate, run.search)

    def test_the_refused_families_must_be_the_ones_the_run_was_made_with(self) -> None:
        rows = RowsKit.rows()
        run = Distiller(refused_families=frozenset({"fam0"})).distill(rows)
        assert Rescore.replay(run.search, rows, frozenset({"fam0"})).candidate == run.candidate
        with pytest.raises(ValueError, match="not the ones this candidate was made with"):
            Rescore.replay(run.search, rows)

    def test_a_record_with_no_thresholds_cannot_be_replayed(self) -> None:
        rows, run = RowsKit.made()
        old = {k: v for k, v in run.search.items() if k != "params"}
        with pytest.raises(ValueError, match="cannot be replayed"):
            Rescore.replay(old, rows)
        with pytest.raises(ValueError, match="cannot be replayed"):
            Rescore.check(run.candidate, old, rows)
