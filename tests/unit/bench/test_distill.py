"""G2, the distiller (learning loop LL-16 to LL-19, LL-63, LL-66, LL-90, LL-101), on fact vectors only: no package and
no sample is read; every unit below is a hand-made `facts/v1`-shaped record."""

from __future__ import annotations

import random
import sys
from dataclasses import replace

import pytest

from support import ROOT as REPO

sys.path.insert(0, str(REPO))

from bench.cdi.distill import Distiller, Terms, Unit
from bench.cdi.leakage import Leakage, LeakageRefused

CAPS = ("spawn", "egress", "read_file", "write_file", "decode", "env")


class FactsKit:
    @staticmethod
    def facts(files: list[tuple[bool, list[str], list[str]]], hooks: tuple[str, ...] = ()) -> dict:
        return {
            "files": [
                {"key": f"{i:016x}", "reached": reached, "places": places, "capabilities": caps}
                for i, (reached, places, caps) in enumerate(files)
            ],
            "package": {"rules": {}, "hooks": [{"kind": k, "programs": []} for k in hooks]},
        }

    @staticmethod
    def legit(n: int, *, strata: int = 3, split: str = "train", seed: int = 7) -> list[Unit]:
        """Ordinary packages: spawn and egress are common, but never together in a file nothing reaches."""
        rng = random.Random(seed)  # noqa: S311 - fixture data, not a secret
        out = []
        for i in range(n):
            files = [(True, ["import_entry"], rng.sample(CAPS, 2))]
            if rng.random() < 0.3:
                files.append((False, [], [rng.choice(("spawn", "egress", "read_file"))]))
            if rng.random() < 0.3:
                files.append((True, ["install_entry"], ["read_file"]))
            out.append(
                Unit(
                    f"{split}-legit-{i}",
                    "legit",
                    "",
                    "npm",
                    f"s{i % strata}",
                    split,
                    FactsKit.facts(files),
                )
            )
        return out

    @staticmethod
    def planted(
        families: int, per: int, *, split: str = "train", ecosystem: str = "npm"
    ) -> list[Unit]:
        """Missed malicious units whose shipped code nothing reaches spawns AND egresses in one file."""
        out = []
        for f in range(families):
            for j in range(per):
                files = [(True, ["install_entry"], ["read_file"]), (False, [], ["spawn", "egress"])]
                out.append(
                    Unit(
                        f"{split}-mal-{f}-{j}",
                        "mal",
                        f"fam{f}",
                        ecosystem,
                        "s0",
                        split,
                        FactsKit.facts(files),
                    )
                )
        return out

    @staticmethod
    def decoy(per: int, *, split: str = "train") -> list[Unit]:
        """One family with a shape nothing legitimate has: a single family must never make a detector."""
        return [
            Unit(
                f"{split}-decoy-{j}",
                "mal",
                "decoyfam",
                "npm",
                "s0",
                split,
                FactsKit.facts([(False, [], ["decode", "env"])]),
            )
            for j in range(per)
        ]


class TestADetectorIsLearnedOnlyFromSeveralFamilies:
    def test_the_planted_shape_is_emitted_and_the_single_family_decoy_is_not(self) -> None:
        units = (
            FactsKit.planted(4, 5)
            + FactsKit.decoy(8)
            + FactsKit.legit(12_000)
            + FactsKit.planted(2, 3, split="confirm")
            + FactsKit.legit(9_000, split="confirm", seed=11)
        )
        run = Distiller().distill(units)
        assert run.candidate is not None
        assert ["file", "unreached", "egress", "spawn"] in run.candidate["predicate"]
        assert run.candidate["train"]["families"] == 4
        assert all("decode" not in term for term in run.candidate["predicate"])
        assert run.refused.get("single_or_few_families", 0) > 0

    def test_the_same_input_gives_the_same_candidate_and_search_record(self) -> None:
        units = (
            FactsKit.planted(3, 4)
            + FactsKit.legit(9_000)
            + FactsKit.planted(1, 2, split="confirm")
            + FactsKit.legit(6_000, split="confirm", seed=3)
        )
        a, b = Distiller().distill(units), Distiller().distill(list(reversed(units)))
        assert a.candidate == b.candidate and a.search == b.search
        assert a.candidate is not None and len(a.candidate["predicate_digest"]) == 64


class TestNothingIsLearnedFromNoise:
    @pytest.mark.parametrize("seed", range(100))
    def test_random_labels_promote_nothing(self, seed: int) -> None:
        rng = random.Random(seed)  # noqa: S311 - fixture data, not a secret
        units = []
        for i in range(3_300):
            files = [
                (
                    rng.random() < 0.7,
                    rng.choice([["import_entry"], []]),
                    rng.sample(CAPS, rng.randint(1, 3)),
                )
            ]
            if i < 300:
                units.append(
                    Unit(
                        f"m{i}", "mal", f"fam{i % 10}", "npm", "s0", "train", FactsKit.facts(files)
                    )
                )
            else:
                units.append(
                    Unit(f"l{i}", "legit", "", "npm", "s0", "train", FactsKit.facts(files))
                )
        assert Distiller().distill(units).candidate is None


class TestLeakageAndRefusedTerms:
    def test_a_family_with_a_sealed_member_is_refused_whole(self) -> None:
        units = (
            FactsKit.planted(3, 5)
            + FactsKit.legit(12_000)
            + FactsKit.planted(2, 2, split="confirm")
            + FactsKit.legit(9_000, split="confirm", seed=5)
        )
        run = Distiller(refused_families=frozenset({"fam0"})).distill(units)
        assert run.candidate is None
        assert run.refused["unit_in_refused_family"] == 5 + 2

    def test_an_age_name_host_or_publisher_term_is_refused(self) -> None:
        for kind in ("age", "name", "host", "publisher", "program"):
            with pytest.raises(ValueError, match="refused term kind"):
                Terms.check((kind, "younger-than-30-days"))

    def test_a_metadata_term_from_one_ecosystem_is_refused(self) -> None:
        units = [
            Unit(
                f"h{f}-{j}",
                "mal",
                f"hf{f}",
                "npm",
                "s0",
                "train",
                FactsKit.facts([(True, [], ["read_file"])], hooks=("preinstall",)),
            )
            for f in range(4)
            for j in range(4)
        ] + FactsKit.legit(12_000)
        run = Distiller().distill(units)
        assert run.refused.get("metadata_one_ecosystem", 0) >= 1
        assert run.candidate is None or all(t[0] != "hook" for t in run.candidate["predicate"])


class TestAChoiceIsConfirmedOnRowsNeverUsedToMakeIt:
    def test_a_predicate_that_fires_on_the_confirm_legit_rows_is_not_a_candidate(self) -> None:
        confirm_legit = [
            Unit(
                f"cl{i}",
                "legit",
                "",
                "npm",
                "s0",
                "confirm",
                FactsKit.facts(
                    [(True, ["install_entry"], ["read_file"]), (False, [], ["spawn", "egress"])]
                ),
            )
            for i in range(200)
        ] + FactsKit.legit(2_000, split="confirm", seed=9)
        units = (
            FactsKit.planted(4, 5)
            + FactsKit.legit(12_000)
            + FactsKit.planted(2, 2, split="confirm")
            + confirm_legit
        )
        run = Distiller().distill(units)
        assert run.candidate is None
        assert run.refused.get("failed_confirm", 0) >= 1

    def test_no_legit_rows_is_no_evidence_and_never_a_pass(self) -> None:
        assert Distiller().distill(FactsKit.planted(4, 5)).candidate is None


class TestACandidateShipsAsAnOrdinaryRule:
    def test_the_rendered_pack_loads_as_a_package_scope_composite_with_the_same_terms(
        self, tmp_path
    ) -> None:
        from bench.cdi.distill import PackRenderer

        from cordon_scanner.rules.fact_terms import FactTerms
        from cordon_scanner.rules.loader import RuleLoader

        units = (
            FactsKit.planted(4, 5)
            + FactsKit.legit(12_000)
            + FactsKit.planted(2, 3, split="confirm")
            + FactsKit.legit(9_000, split="confirm", seed=11)
        )
        candidate = Distiller().distill(units).candidate
        assert candidate is not None
        pack = tmp_path / "learned.yaml"
        pack.write_text(PackRenderer.render(candidate, "LEARNED.MCP.001"), encoding="utf-8")
        loaded = RuleLoader(require_tests=False).load_file(pack)
        (rule,) = loaded.rules
        assert rule.id == "LEARNED.MCP.001" and rule.match.scope == "package"
        assert sorted(FactTerms.of_spec(t) for t in rule.match.all_of) == sorted(
            tuple(t) for t in candidate["predicate"]
        )

    def test_a_rule_id_outside_the_learned_namespace_is_refused(self) -> None:
        from bench.cdi.distill import PackRenderer

        candidate = {
            "predicate": [["file", "unreached", "egress", "spawn"]],
            "predicate_digest": "0" * 64,
            "train": {"families": 3, "legit_upper": 0.001},
            "confirm": {"families": 1, "legit_upper": 0.002},
        }
        with pytest.raises(ValueError, match="LEARNED"):
            PackRenderer.render(candidate, "SUSPECT.MCP.001")


class TestOneDistillationReadsOneFactsVersion:
    def test_facts_of_two_versions_are_refused(self) -> None:
        units = FactsKit.planted(3, 2) + FactsKit.legit(50)
        old = Unit(
            "old",
            "legit",
            "",
            "npm",
            "s0",
            "train",
            {**FactsKit.facts([(True, [], ["spawn"])]), "facts_version": "1"},
        )
        new = Unit(
            "new",
            "legit",
            "",
            "npm",
            "s0",
            "train",
            {**FactsKit.facts([(True, [], ["spawn"])]), "facts_version": "2"},
        )
        with pytest.raises(ValueError, match="versions"):
            Distiller().distill([*units, old, new])


class TestAReleaseThatMayNotInformAGeneratorIsRefusedWithItsReason:
    """LL-43 (SI-Q8, SI-Q9): val, held, fresh, sealed and excluded releases, and malicious ones without a confirmed or corroborated
    label, are counted with the reason and never read; none is dropped silently."""

    @pytest.mark.parametrize("split", ["val", "held", "fresh", "sealed", "excluded"])
    def test_a_split_a_generator_may_not_read_is_refused_by_name(self, split: str) -> None:
        units = FactsKit.planted(3, 5, split=split) + FactsKit.legit(300)
        run = Distiller().distill(units)
        assert run.refused[f"split_{split}"] == 15
        assert run.candidate is None
        assert run.search["train_units"] == 300  # the planted families never reached the count

    def test_a_sealed_legit_unit_is_refused_too(self) -> None:
        run = Distiller().distill(FactsKit.legit(40, split="sealed") + FactsKit.legit(10))
        assert run.refused["split_sealed"] == 40
        assert run.search["train_units"] == 10

    def test_a_silver_labelled_malicious_unit_in_train_is_refused_for_its_tier(self) -> None:
        silver = [replace(u, label_tier="silver") for u in FactsKit.planted(4, 5)]
        run = Distiller().distill(silver + FactsKit.legit(300))
        assert run.refused["label_tier_silver"] == 20
        assert run.candidate is None

    def test_a_legit_unit_has_no_tier_to_fail(self) -> None:
        legit = [replace(u, label_tier="silver") for u in FactsKit.legit(30)]
        run = Distiller().distill(legit)
        assert "label_tier_silver" not in run.refused
        assert run.search["train_units"] == 30

    def test_train_dev_and_confirm_units_are_all_read(self) -> None:
        units = (
            FactsKit.planted(4, 5)
            + FactsKit.legit(12_000)
            + FactsKit.planted(2, 3, split="confirm")
            + FactsKit.legit(9_000, split="confirm", seed=11)
        )
        run = Distiller().distill(units)
        assert run.candidate is not None
        assert not [k for k in run.refused if k.startswith(("split_", "label_tier_"))]

    def test_one_offered_at_a_time_raises_with_the_reasons(self) -> None:
        Leakage.require("train", "confirmed")
        Leakage.require("dev", "corroborated")
        Leakage.require("confirm")
        with pytest.raises(LeakageRefused) as refusal:
            Leakage.require("held", "silver")
        assert refusal.value.reasons == ("label_tier_silver", "split_held")
