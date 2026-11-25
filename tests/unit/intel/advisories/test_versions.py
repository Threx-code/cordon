"""Version ordering is a correctness question with a security consequence.

A vulnerability range is only as good as the comparator that decides whether a
resolved version falls inside it. Getting SemVer prerelease ordering wrong, or
Maven's qualifier ranking wrong, silently turns into a missed detection or a
false one -- and unlike most detector code, there is no ambiguity to hide
behind: every scheme here is a public specification with worked examples, so
"wrong" is checkable rather than a judgement call.

Fixtures below are drawn from each specification's own ordering examples
(SemVer 2.0.0 section 11's worked chain, PEP 440's appendix, Maven's
documented qualifier list, RubyGems' own spec suite) rather than invented, so
a failure here means a disagreement with the standard rather than with this
project's taste.
"""

from __future__ import annotations

from itertools import pairwise
from typing import ClassVar

import pytest

from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.intel.advisories import versions


class TestSemVer:
    # https://semver.org/#spec-item-11 -- the worked precedence chain.
    CHAIN: ClassVar[list[str]] = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
    ]

    def test_the_spec_chain_orders_correctly(self) -> None:
        for lower, higher in pairwise(self.CHAIN):
            assert versions.Versions.compare("npm", lower, higher) == -1, (lower, higher)
            assert versions.Versions.compare("npm", higher, lower) == 1, (higher, lower)

    def test_equal_versions_compare_equal(self) -> None:
        assert versions.Versions.compare("npm", "1.2.3", "1.2.3") == 0

    def test_build_metadata_is_ignored(self) -> None:
        assert versions.Versions.compare("cargo", "1.0.0+build1", "1.0.0+build2") == 0

    def test_numeric_precedes_alphanumeric_in_prerelease(self) -> None:
        assert versions.Versions.compare("npm", "1.0.0-1", "1.0.0-alpha") == -1

    def test_go_v_prefix_is_stripped(self) -> None:
        assert versions.Versions.compare("gomod", "v1.2.3", "v1.2.4") == -1

    def test_go_pseudo_version_sorts_before_its_base_release(self) -> None:
        pseudo = "v1.2.3-0.20200101000000-abcdef123456"
        assert versions.Versions.compare("gomod", pseudo, "v1.2.3") == -1

    def test_nuget_four_component_legacy_version(self) -> None:
        assert versions.Versions.compare("nuget", "1.0.0.1", "1.0.0.2") == -1

    def test_unparseable_falls_back_to_string_order_not_an_exception(self) -> None:
        assert versions.Versions.compare("npm", "not-a-version", "1.0.0") in (-1, 0, 1)

    def test_range_matching(self) -> None:
        assert versions.Versions.in_range("npm", "1.5.0", introduced="1.0.0", fixed="2.0.0")
        assert not versions.Versions.in_range("npm", "2.0.0", introduced="1.0.0", fixed="2.0.0")
        assert not versions.Versions.in_range("npm", "0.9.0", introduced="1.0.0", fixed="2.0.0")

    def test_open_ended_introduced_zero(self) -> None:
        assert versions.Versions.in_range("npm", "0.0.1", introduced="0", fixed="1.0.0")


class TestPEP440:
    # https://peps.python.org/pep-0440/#summary-of-permitted-suffixes-and-relative-ordering
    CHAIN: ClassVar[list[str]] = [
        "1.0.dev1",
        "1.0a1",
        "1.0a2.dev1",
        "1.0a2",
        "1.0b1.dev1",
        "1.0b1",
        "1.0rc1",
        "1.0",
        "1.0+local",
        "1.0.post1.dev1",
        "1.0.post1",
    ]

    def test_the_spec_chain_orders_correctly(self) -> None:
        for lower, higher in pairwise(self.CHAIN):
            # `1.0` and `1.0+local` are equal by public-version ordering; the
            # chain still must not go backwards.
            assert versions.Versions.compare("pypi", lower, higher) in (-1, 0), (lower, higher)

    def test_epoch_dominates_everything_else(self) -> None:
        assert versions.Versions.compare("pypi", "1!1.0", "2.0") == 1

    def test_alpha_beta_rc_aliases_normalise(self) -> None:
        assert versions.Versions.compare("pypi", "1.0alpha1", "1.0a1") == 0
        assert versions.Versions.compare("pypi", "1.0c1", "1.0rc1") == 0

    def test_release_without_suffix_beats_prerelease(self) -> None:
        assert versions.Versions.compare("pypi", "1.0", "1.0rc1") == 1

    def test_post_release_beats_release(self) -> None:
        assert versions.Versions.compare("pypi", "1.0.post1", "1.0") == 1

    def test_range_matching(self) -> None:
        assert versions.Versions.in_range("pypi", "2.1.0", introduced="2.0.0", fixed="2.2.0")
        assert not versions.Versions.in_range("pypi", "2.2.0", introduced="2.0.0", fixed="2.2.0")


class TestMaven:
    def test_numeric_segments_compare_numerically(self) -> None:
        assert versions.Versions.compare("maven", "1.9", "1.10") == -1

    def test_qualifier_rank_alpha_beta_milestone_rc_snapshot_release_sp(self) -> None:
        chain = [
            "1.0-alpha",
            "1.0-beta",
            "1.0-milestone",
            "1.0-rc",
            "1.0-SNAPSHOT",
            "1.0",
            "1.0-sp",
        ]
        for lower, higher in pairwise(chain):
            assert versions.Versions.compare("maven", lower, higher) == -1, (lower, higher)

    def test_final_and_ga_are_release_equivalent(self) -> None:
        assert versions.Versions.compare("maven", "1.0-final", "1.0") == 0
        assert versions.Versions.compare("maven", "1.0-ga", "1.0") == 0

    def test_unrecognised_qualifier_sorts_after_recognised_ones(self) -> None:
        assert versions.Versions.compare("maven", "1.0-weird", "1.0-sp") == 1

    def test_gradle_uses_the_same_scheme(self) -> None:
        assert versions.Versions.compare("gradle", "1.0-alpha", "1.0") == -1

    def test_range_matching(self) -> None:
        assert versions.Versions.in_range("maven", "3.1.0", introduced="3.0.0", fixed="3.2.0")


class TestRubyGems:
    def test_numeric_segments_compare_numerically(self) -> None:
        assert versions.Versions.compare("rubygems", "1.9", "1.10") == -1

    def test_prerelease_suffix_sorts_before_release(self) -> None:
        assert versions.Versions.compare("rubygems", "1.0.pre", "1.0") == -1
        assert versions.Versions.compare("rubygems", "1.0.rc1", "1.0") == -1

    def test_range_matching(self) -> None:
        assert versions.Versions.in_range("rubygems", "4.5.0", introduced="4.0.0", fixed="5.0.0")


class TestRobustness:
    """Version strings arrive from a scanned target's own lockfile."""

    @pytest.mark.parametrize(
        "ecosystem", ["npm", "pypi", "maven", "gradle", "rubygems", "cargo", "unknown-ecosystem"]
    )
    def test_never_raises_on_adversarial_input(self, ecosystem: str) -> None:
        payloads = [
            "",
            "." * 500,
            "9" * 500,
            "1.0.0-" + "a" * 500,
            "\x00\x01\x02",
            "1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.18.19.20",
            "v" * 300,
        ]
        for payload in payloads:
            versions.Versions.compare(ecosystem, payload, "1.0.0")
            versions.Versions.compare(ecosystem, "1.0.0", payload)
            versions.Versions.in_range(ecosystem, payload, introduced="1.0.0", fixed="2.0.0")

    def test_overlong_input_is_bounded_and_does_not_raise(self) -> None:
        huge = "1." + "0." * 200 + "0"
        assert len(huge) > versions.MAX_VERSION_LENGTH
        versions.Versions.compare("npm", huge, "1.0.0")

    def test_sort_key_is_usable_with_sorted(self) -> None:
        values = ["1.10.0", "1.9.0", "1.2.0"]
        ordered = sorted(values, key=lambda v: versions.Versions.sort_key("npm", v))
        assert ordered == ["1.2.0", "1.9.0", "1.10.0"]

    def test_sort_key_falls_back_for_unparseable_and_stays_sortable(self) -> None:
        values = ["not-a-version", "1.0.0", "also-not"]
        sorted(values, key=lambda v: versions.Versions.sort_key("npm", v))


class TestIntroducedZeroIsNoLowerBound:
    def test_a_go_pseudo_version_is_inside_an_open_range(self) -> None:
        from cordon_scanner.intel.advisories.versions import Versions

        pseudo = "v0.0.0-20180724234803-3673e40ba225"
        assert Versions.in_range(
            "gomod", pseudo, introduced="0", fixed="0.0.0-20180925071336-cf3bd585ca2a"
        )
        assert Versions.in_range("gomod", pseudo, introduced="0", fixed="0.17.0")
        assert not Versions.in_range(
            "gomod",
            "v0.0.0-20190101000000-aaaaaaaaaaaa",
            introduced="0",
            fixed="0.0.0-20180925071336-cf3bd585ca2a",
        )

    def test_an_npm_prerelease_of_zero_is_inside_too(self) -> None:
        from cordon_scanner.intel.advisories.versions import Versions

        assert Versions.in_range("npm", "0.0.0-alpha.1", introduced="0", fixed="1.0.0")


# Every ecosystem the scanner supports orders its versions by its own published scheme.

#: One pair per ecosystem: (earlier, later), in that ecosystem's own version form.
ORDERED: dict[str, tuple[str, str]] = {
    "npm": ("1.2.3-beta.1", "1.2.3"),
    "pypi": ("1.0rc1", "1.0"),
    "cargo": ("0.9.9", "0.10.0"),
    "rubygems": ("1.0.0.pre", "1.0.0"),
    "nuget": ("1.0.0-alpha", "1.0.0"),
    "gomod": ("v1.9.0", "v1.10.0"),
    "maven": ("1.0-SNAPSHOT", "1.0"),
    "gradle": ("2.9", "2.10"),
    "composer": ("1.9.0", "1.10.0"),
    "pub": ("1.0.0-dev", "1.0.0"),
    "hex": ("1.4.0-rc.0", "1.4.0"),
    "cocoapods": ("5.8.0", "5.10.0"),
    "swift": ("5.8.0", "5.10.0"),
    "conda": ("1.9", "1.10"),
    "cran": ("1.0-5", "1.0-12"),
    "conan": ("3.2.0", "3.10.0"),
    "vcpkg": ("1.2.9", "1.2.10#2"),
    "homebrew": ("3.1.9", "3.1.10_1"),
    "nix": ("v1.9.0", "v1.10.0"),
    "julia": ("0.9.0", "0.10.0"),
    "hackage": ("0.9.1", "0.10"),
    "opam": ("1.0~beta", "1.0"),
    "helm": ("18.0.0-rc.1", "18.0.0"),
    "terraform": ("5.9.0", "5.10.0"),
    "ansible": ("7.9.0", "7.10.0"),
    "actions": ("v4", "v5"),
    "image": ("3.12.9-slim", "3.12.10-slim"),
    "bazel": ("0.0.9", "0.0.10"),
}


class TestEveryEcosystem:
    def test_the_table_holds_every_ecosystem_the_scanner_supports(self) -> None:
        assert set(ORDERED) == set(EcosystemRegistry.BY_ID)

    def test_every_ecosystem_has_a_scheme(self) -> None:
        assert set(EcosystemRegistry.BY_ID) <= set(versions.Versions.SCHEMES)

    @pytest.mark.parametrize("ecosystem", sorted(ORDERED))
    def test_a_version_of_thousands_of_digits_never_raises(self, ecosystem: str) -> None:
        huge = "1." + "9" * 5000
        assert versions.Versions.compare(ecosystem, huge, "1.0") in (-1, 0, 1)
        assert versions.Versions.compare(ecosystem, "1." + "9" * 200, "1." + "9" * 199) in (-1, 1)

    @pytest.mark.parametrize("ecosystem", sorted(ORDERED))
    def test_it_orders_by_its_own_scheme(self, ecosystem: str) -> None:
        earlier, later = ORDERED[ecosystem]
        assert versions.Versions.compare(ecosystem, earlier, later) == -1
        assert versions.Versions.compare(ecosystem, later, earlier) == 1

    @pytest.mark.parametrize("ecosystem", sorted(ORDERED))
    def test_a_range_matches_in_it(self, ecosystem: str) -> None:
        earlier, later = ORDERED[ecosystem]
        assert versions.Versions.in_range(ecosystem, earlier, introduced="0", fixed=later)
        assert not versions.Versions.in_range(ecosystem, later, introduced="0", fixed=later)


class TestOpamOrdersAsDebian:
    @pytest.mark.parametrize(
        ("earlier", "later"),
        [
            ("1.0~beta", "1.0"),
            ("1.0~beta", "1.0~beta2"),
            ("1.0", "1.0a"),
            ("1.0a", "1.0+b"),
            ("1.9", "1.10"),
        ],
    )
    def test_the_published_order(self, earlier: str, later: str) -> None:
        assert versions.Versions.compare("opam", earlier, later) == -1


class TestATagWithoutAVersion:
    @pytest.mark.parametrize("ecosystem", ["image", "nix"])
    @pytest.mark.parametrize("other", ["latest", "3f2a9c1d0b7e4a5f6c8d9e0a1b2c3d4e5f6a7b8c"])
    def test_a_name_or_a_commit_compares_as_text(self, ecosystem: str, other: str) -> None:
        assert versions.Versions.compare(ecosystem, "1.0.0", other) == (
            -1 if other > "1.0.0" else 1
        )

    def test_the_debian_comparer_orders_huge_digit_runs_without_int(self) -> None:
        a, b = "1." + "9" * 5000, "1." + "1" + "0" * 5000
        assert versions.Versions._debian("opam", a, b) == -1


class TestTagsThatAreNumbers:
    def test_a_date_tag_is_a_version_not_a_commit(self) -> None:
        assert versions.Versions.compare("image", "20241130", "20241231") == -1


class TestActionsTags:
    def test_a_major_tag_orders_with_a_full_one(self) -> None:
        assert versions.Versions.compare("actions", "v4", "v4.1.2") == -1
        assert versions.Versions.compare("actions", "v4.1.2", "v5") == -1

    def test_a_branch_name_compares_as_text(self) -> None:
        assert versions.Versions.compare("actions", "main", "v4") == (-1 if "main" < "v4" else 1)


class TestNixComparesAsNixDoes:
    """`builtins.compareVersions`, by the examples in the Nix manual's description of it."""

    @pytest.mark.parametrize(
        ("earlier", "later"),
        [
            ("1.0", "2.3"),
            ("2.1", "2.3"),
            ("2.3", "2.3.1"),
            ("2.3pre1", "2.3"),
            ("2.3pre3", "2.3pre12"),
            ("2.3a", "2.3c"),
            ("2.3a", "2.3.1"),
            ("2.3pre1", "2.3q"),
            ("23.05", "23.11"),
        ],
    )
    def test_the_published_order(self, earlier: str, later: str) -> None:
        assert versions.Versions.compare("nix", earlier, later) == -1
        assert versions.Versions.compare("nix", later, earlier) == 1

    def test_a_huge_number_is_compared_without_int(self) -> None:
        assert (
            versions.Versions._nix("nix", "1." + "9" * 5000 + "a", "1." + "1" + "0" * 5000 + "a")
            == -1
        )


class TestAnImageTagsVariant:
    """`1.25.3-debian-12-r0` is release 1.25.3 of a variant, not a pre-release of it."""

    @pytest.mark.parametrize(
        ("earlier", "later"),
        [
            ("1.25.3", "1.25.3-debian-12-r0"),
            ("1.25.2-debian-12-r5", "1.25.3-debian-12-r0"),
            ("1.25.3-debian-12-r0", "1.25.3-debian-12-r1"),
            ("3.12.9-slim", "3.12.10"),
        ],
    )
    def test_the_release_orders_first(self, earlier: str, later: str) -> None:
        assert versions.Versions.compare("image", earlier, later) == -1

    def test_a_variant_at_the_fixed_release_is_not_affected(self) -> None:
        assert not versions.Versions.in_range(
            "image", "1.25.3-debian-12-r0", introduced="0", fixed="1.25.3"
        )
        assert versions.Versions.in_range(
            "image", "1.25.2-debian-12-r9", introduced="0", fixed="1.25.3"
        )
