"""A family is keyed by content and campaign fingerprints; families of one publisher count as one."""

from __future__ import annotations

from typing import Any

from bench.cdi.families import RULE_VERSION, Families


class Kit:
    @staticmethod
    def unit(
        digest: str, content: str = "", campaign: str = "", publisher: str = ""
    ) -> dict[str, Any]:
        return {"digest": digest, "content": content, "campaign": campaign, "publisher": publisher}


class TestHowAFamilyIsKeyed:
    def test_units_sharing_a_content_fingerprint_are_one_family(self) -> None:
        units = [Kit.unit("a", "c1"), Kit.unit("b", "c1"), Kit.unit("c", "c2")]
        assert sorted(sorted(m["digest"] for m in f) for f in Families.keyed(units).values()) == [
            ["a", "b"],
            ["c"],
        ]

    def test_units_sharing_a_campaign_fingerprint_are_one_family_though_their_content_differs(
        self,
    ) -> None:
        units = [Kit.unit("a", "c1", "k1"), Kit.unit("b", "c2", "k1")]
        assert len(Families.keyed(units)) == 1

    def test_a_chain_of_shared_fingerprints_joins_the_whole_chain(self) -> None:
        units = [
            Kit.unit("a", "c1", "k1"),
            Kit.unit("b", "c1", "k2"),
            Kit.unit("c", "c3", "k2"),
            Kit.unit("d", "c9", "k9"),
        ]
        assert sorted(len(f) for f in Families.keyed(units).values()) == [1, 3]

    def test_a_unit_with_no_fingerprint_is_a_family_of_its_own_and_not_joined_by_the_empty_one(
        self,
    ) -> None:
        units = [Kit.unit("a"), Kit.unit("b"), Kit.unit("c", "c1")]
        assert len(Families.keyed(units)) == 3


class TestHowManyFamiliesCount:
    def test_three_families_from_one_publisher_count_as_one(self) -> None:
        units = [Kit.unit(d, c, "", "mallory") for d, c in (("a", "c1"), ("b", "c2"), ("c", "c3"))]
        assert len(Families.keyed(units)) == 3
        assert len(Families.independent(units)) == 1
        assert not Families.meets_claim(units)

    def test_three_families_from_three_publishers_count_as_three_and_meet_the_claim(self) -> None:
        units = [
            Kit.unit("a", "c1", "", "p1"),
            Kit.unit("b", "c2", "", "p2"),
            Kit.unit("c", "c3", "", "p3"),
        ]
        assert len(Families.independent(units)) == 3 and Families.meets_claim(units)

    def test_three_independent_families_behind_two_publishers_do_not_meet_it(self) -> None:
        units = [
            Kit.unit("a", "c1", "", "p1"),
            Kit.unit("b", "c2", "", "p2"),
            Kit.unit("c", "c3", "", "p2"),
        ]
        assert len(Families.independent(units)) == 2 and not Families.meets_claim(units)

    def test_a_publisher_shared_by_two_families_merges_them_and_a_third_stays_apart(self) -> None:
        units = [
            Kit.unit("a", "c1", "", "p1"),
            Kit.unit("b", "c2", "", "p1"),
            Kit.unit("c", "c3", "", "p3"),
        ]
        assert Families.independent(units) == [["a", "b"], ["c"]]

    def test_units_with_no_publisher_known_never_merge_families(self) -> None:
        units = [Kit.unit("a", "c1"), Kit.unit("b", "c2"), Kit.unit("c", "c3")]
        assert len(Families.independent(units)) == 3
        assert not Families.meets_claim(units), (
            "three families, but no publisher is known, so none is distinct"
        )


class TestTheFoldRecordsTheRule:
    def test_the_counts_carry_the_rules_version_and_what_was_counted(self) -> None:
        units = [
            Kit.unit("a", "c1", "", "p1"),
            Kit.unit("b", "c1", "", "p2"),
            Kit.unit("c", "c3", "", "p1"),
        ]
        assert Families.counts(units) == {
            "family_rule": RULE_VERSION,
            "families": 2,
            "independent_families": 1,
            "publishers": 2,
        }
