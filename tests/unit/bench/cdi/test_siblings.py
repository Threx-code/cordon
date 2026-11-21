"""G5, structural siblings (learning loop row LL-22), on fact vectors only: no package and no sample is read; every record below is
hand-made."""

from __future__ import annotations

import sys
from dataclasses import replace
from typing import Any

import pytest

from support import ROOT as REPO

sys.path.insert(0, str(REPO))

from bench.cdi.distill import Unit
from bench.cdi.siblings import KIND, Siblings

from cordon_scanner.report.facts import FACTS_VERSION


class SiblingKit:
    @staticmethod
    def facts(files: list[tuple[bool, tuple[str, ...], tuple[str, ...]]]) -> dict[str, Any]:
        return {
            "facts_version": FACTS_VERSION,
            "package": {"rules": {}, "hooks": []},
            "files": [
                {
                    "key": f"{i:016x}",
                    "reached": reached,
                    "places": list(places),
                    "capabilities": list(caps),
                }
                for i, (reached, places, caps) in enumerate(files)
            ],
        }

    @staticmethod
    def loader(extra: tuple[str, ...] = ()) -> dict[str, Any]:
        """The family's shape: an import entry that decodes and egresses, an install entry that spawns, and a file nothing reaches."""
        files = [
            (True, ("import_entry",), ("decode", "egress")),
            (True, ("install_entry",), ("spawn",)),
            (False, (), ("spawn", "egress")),
        ]
        if extra:
            files.append((True, ("import_entry",), extra))
        return SiblingKit.facts(files)

    @staticmethod
    def family(
        name: str,
        members: int,
        *,
        extras: tuple[tuple[str, ...], ...] = ((),),
        split: str = "train",
    ) -> list[Unit]:
        out = []
        for i in range(members):
            extra = extras[i % len(extras)]
            out.append(
                Unit(f"{name}-{i}", "mal", name, "npm", "s0", split, SiblingKit.loader(extra))
            )
        return out

    @staticmethod
    def legit(n: int, *, decoding_share: int = 0) -> list[Unit]:
        """Ordinary packages: an import entry that egresses; every `decoding_share`-th one also decodes (0: none)."""
        out = []
        for i in range(n):
            caps = (
                ("decode", "egress") if decoding_share and i % decoding_share == 0 else ("egress",)
            )
            out.append(
                Unit(
                    f"legit-{i}",
                    "legit",
                    "",
                    "npm",
                    f"s{i % 3}",
                    "train",
                    SiblingKit.facts([(True, ("import_entry",), caps)]),
                )
            )
        return out


class TestAReleaseWithAFamilysShapeIsFlaggedAndNeverLabelled:
    """LL-22: a fixture release with a confirmed family's signature is flagged and its label stays null."""

    def cores(self):
        cores, _ = Siblings().families(SiblingKit.family("fam-a", 4) + SiblingKit.legit(1_000))
        return cores

    def test_the_sibling_is_flagged_with_no_label(self) -> None:
        (hit,) = Siblings.find(self.cores(), [("fresh-1", SiblingKit.loader())])
        assert hit["kind"] == KIND
        assert hit["release"] == "fresh-1"
        assert hit["family"] == "fam-a"
        assert hit["label"] is None

    def test_no_hit_ever_carries_a_label(self) -> None:
        releases = [(f"fresh-{i}", SiblingKit.loader(("env",) * (i % 2))) for i in range(6)]
        hits = Siblings.find(self.cores(), releases)
        assert len(hits) == 6
        assert all(
            h["label"] is None and "verdict" not in h and "malicious" not in str(h) for h in hits
        )

    def test_a_release_with_more_than_the_shape_is_still_a_sibling_with_a_lower_similarity(
        self,
    ) -> None:
        plain, bigger = Siblings.find(
            self.cores(),
            [("a", SiblingKit.loader()), ("b", SiblingKit.loader(("env", "read_file")))],
        )
        assert plain["similarity"] > bigger["similarity"]
        assert plain["similarity"] == 1.0

    def test_a_release_missing_one_part_of_the_shape_is_not(self) -> None:
        partial = SiblingKit.facts(
            [
                (True, ("import_entry",), ("decode", "egress")),
                (True, ("install_entry",), ("spawn",)),
            ]
        )  # no file nothing reaches
        assert Siblings.find(self.cores(), [("fresh-2", partial)]) == []

    def test_an_ordinary_package_is_not(self) -> None:
        ordinary = SiblingKit.facts([(True, ("import_entry",), ("egress",))])
        assert Siblings.find(self.cores(), [("fresh-3", ordinary)]) == []

    def test_the_familys_own_members_are_not_reported_as_their_siblings(self) -> None:
        assert (
            Siblings.find(
                self.cores(), [("fam-a-0", SiblingKit.loader()), ("fam-a-2", SiblingKit.loader())]
            )
            == []
        )

    def test_the_hits_come_in_a_fixed_order(self) -> None:
        releases = [
            ("z", SiblingKit.loader()),
            ("a", SiblingKit.loader()),
            ("m", SiblingKit.loader()),
        ]
        assert [h["release"] for h in Siblings.find(self.cores(), releases)] == ["a", "m", "z"]

    def test_a_release_in_two_families_is_a_hit_for_each(self) -> None:
        units = (
            SiblingKit.family("fam-a", 4) + SiblingKit.family("fam-b", 4) + SiblingKit.legit(1_000)
        )
        cores, _ = Siblings().families(units)
        hits = Siblings.find(cores, [("fresh-4", SiblingKit.loader())])
        assert sorted(h["family"] for h in hits) == ["fam-a", "fam-b"]


class TestWhatTheFamilyKeeps:
    def test_the_core_is_what_every_member_shares(self) -> None:
        extras = (("env",), ("read_file",), ("write_file",), ("env", "read_file"))
        cores, _ = Siblings().families(
            SiblingKit.family("fam-a", 4, extras=extras) + SiblingKit.legit(1_000)
        )
        (core,) = cores
        assert ("file", "install_entry", "spawn") in core.core
        assert not any("env" in term or "read_file" in term for term in core.core)

    def test_a_term_most_but_not_all_members_share_is_in_a_core_made_with_lower_support(
        self,
    ) -> None:
        extras = (("env",), ("env",), ("env",), ())
        strict, _ = Siblings(support=1.0).families(
            SiblingKit.family("fam-a", 4, extras=extras) + SiblingKit.legit(1_000)
        )
        loose, _ = Siblings(support=0.7).families(
            SiblingKit.family("fam-a", 4, extras=extras) + SiblingKit.legit(1_000)
        )
        assert ("file", "import_entry", "env") not in strict[0].core
        assert ("file", "import_entry", "env") in loose[0].core

    def test_support_must_be_a_majority(self) -> None:
        with pytest.raises(ValueError, match="above one half"):
            Siblings(support=0.5)

    def test_a_single_confirmed_release_is_a_family(self) -> None:
        cores, _ = Siblings().families(SiblingKit.family("lone", 1) + SiblingKit.legit(1_000))
        assert [c.family for c in cores] == ["lone"]


class TestACoreThatOrdinaryPackagesAlsoHoldIsNotUsed:
    def test_a_core_that_only_partly_overlaps_ordinary_packages_is_used(self) -> None:
        # Legit packages that decode and egress from an import entry are a tenth of the set: the family's import-entry
        # shape alone would be theirs; its core also has the install-entry spawn, which no legit package has, so it is used.
        units = SiblingKit.family("fam-a", 4) + SiblingKit.legit(1_000, decoding_share=10)
        cores, refused = Siblings().families(units)
        assert [c.family for c in cores] == ["fam-a"]
        assert cores[0].legit_fires == 0
        assert "over_legit_budget" not in refused

    def test_a_family_whose_whole_shape_is_the_legit_shape_is_refused_and_counted(self) -> None:
        shape = [(True, ("import_entry",), ("decode", "egress"))]
        family = [
            Unit(f"fam-c-{i}", "mal", "fam-c", "npm", "s0", "train", SiblingKit.facts(shape))
            for i in range(4)
        ]
        cores, refused = Siblings().families(family + SiblingKit.legit(1_000, decoding_share=10))
        assert cores == []
        assert refused == {"over_legit_budget": 1}

    def test_a_family_of_one_plain_file_has_no_shape_to_match(self) -> None:
        plain = [(True, ("import_entry",), ("egress",))]
        family = [Unit("fam-d-0", "mal", "fam-d", "npm", "s0", "train", SiblingKit.facts(plain))]
        cores, refused = Siblings(min_core=3).families(family + SiblingKit.legit(1_000))
        assert cores == []
        assert refused == {"core_too_small": 1}

    def test_without_legit_releases_nothing_is_evidence(self) -> None:
        cores, refused = Siblings().families(SiblingKit.family("fam-a", 4))
        assert cores == []
        assert refused == {"over_legit_budget": 1}


class TestOnlyAdmittedReleasesFormAFamily:
    """The leakage gates (SI-Q8, SI-Q9): a held, fresh or sealed release, or one without a confirmed or corroborated label, never forms a
    family; it is counted with its reason."""

    @pytest.mark.parametrize("split", ["val", "held", "fresh", "sealed", "excluded"])
    def test_a_family_in_a_split_a_generator_may_not_read_forms_no_core(self, split: str) -> None:
        cores, refused = Siblings().families(
            SiblingKit.family("fam-a", 4, split=split) + SiblingKit.legit(1_000)
        )
        assert cores == []
        assert refused[f"split_{split}"] == 4

    def test_a_silver_labelled_family_forms_no_core(self) -> None:
        silver = [replace(u, label_tier="silver") for u in SiblingKit.family("fam-a", 4)]
        cores, refused = Siblings().families(silver + SiblingKit.legit(1_000))
        assert cores == []
        assert refused["label_tier_silver"] == 4

    def test_a_sealed_legit_set_does_not_tune_the_legit_rate(self) -> None:
        sealed = [replace(u, split="sealed") for u in SiblingKit.legit(1_000)]
        cores, refused = Siblings().families(SiblingKit.family("fam-a", 4) + sealed)
        assert cores == []
        assert refused["split_sealed"] == 1_000
