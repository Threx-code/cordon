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

from cordon_scanner.intel import versions


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
            assert versions.compare("npm", lower, higher) == -1, (lower, higher)
            assert versions.compare("npm", higher, lower) == 1, (higher, lower)

    def test_equal_versions_compare_equal(self) -> None:
        assert versions.compare("npm", "1.2.3", "1.2.3") == 0

    def test_build_metadata_is_ignored(self) -> None:
        assert versions.compare("cargo", "1.0.0+build1", "1.0.0+build2") == 0

    def test_numeric_precedes_alphanumeric_in_prerelease(self) -> None:
        assert versions.compare("npm", "1.0.0-1", "1.0.0-alpha") == -1

    def test_go_v_prefix_is_stripped(self) -> None:
        assert versions.compare("gomod", "v1.2.3", "v1.2.4") == -1

    def test_go_pseudo_version_sorts_before_its_base_release(self) -> None:
        pseudo = "v1.2.3-0.20200101000000-abcdef123456"
        assert versions.compare("gomod", pseudo, "v1.2.3") == -1

    def test_nuget_four_component_legacy_version(self) -> None:
        assert versions.compare("nuget", "1.0.0.1", "1.0.0.2") == -1

    def test_unparseable_falls_back_to_string_order_not_an_exception(self) -> None:
        assert versions.compare("npm", "not-a-version", "1.0.0") in (-1, 0, 1)

    def test_range_matching(self) -> None:
        assert versions.in_range("npm", "1.5.0", introduced="1.0.0", fixed="2.0.0")
        assert not versions.in_range("npm", "2.0.0", introduced="1.0.0", fixed="2.0.0")
        assert not versions.in_range("npm", "0.9.0", introduced="1.0.0", fixed="2.0.0")

    def test_open_ended_introduced_zero(self) -> None:
        assert versions.in_range("npm", "0.0.1", introduced="0", fixed="1.0.0")


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
            assert versions.compare("pypi", lower, higher) in (-1, 0), (lower, higher)

    def test_epoch_dominates_everything_else(self) -> None:
        assert versions.compare("pypi", "1!1.0", "2.0") == 1

    def test_alpha_beta_rc_aliases_normalise(self) -> None:
        assert versions.compare("pypi", "1.0alpha1", "1.0a1") == 0
        assert versions.compare("pypi", "1.0c1", "1.0rc1") == 0

    def test_release_without_suffix_beats_prerelease(self) -> None:
        assert versions.compare("pypi", "1.0", "1.0rc1") == 1

    def test_post_release_beats_release(self) -> None:
        assert versions.compare("pypi", "1.0.post1", "1.0") == 1

    def test_range_matching(self) -> None:
        assert versions.in_range("pypi", "2.1.0", introduced="2.0.0", fixed="2.2.0")
        assert not versions.in_range("pypi", "2.2.0", introduced="2.0.0", fixed="2.2.0")


class TestMaven:
    def test_numeric_segments_compare_numerically(self) -> None:
        assert versions.compare("maven", "1.9", "1.10") == -1

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
            assert versions.compare("maven", lower, higher) == -1, (lower, higher)

    def test_final_and_ga_are_release_equivalent(self) -> None:
        assert versions.compare("maven", "1.0-final", "1.0") == 0
        assert versions.compare("maven", "1.0-ga", "1.0") == 0

    def test_unrecognised_qualifier_sorts_after_recognised_ones(self) -> None:
        assert versions.compare("maven", "1.0-weird", "1.0-sp") == 1

    def test_gradle_uses_the_same_scheme(self) -> None:
        assert versions.compare("gradle", "1.0-alpha", "1.0") == -1

    def test_range_matching(self) -> None:
        assert versions.in_range("maven", "3.1.0", introduced="3.0.0", fixed="3.2.0")


class TestRubyGems:
    def test_numeric_segments_compare_numerically(self) -> None:
        assert versions.compare("rubygems", "1.9", "1.10") == -1

    def test_prerelease_suffix_sorts_before_release(self) -> None:
        assert versions.compare("rubygems", "1.0.pre", "1.0") == -1
        assert versions.compare("rubygems", "1.0.rc1", "1.0") == -1

    def test_range_matching(self) -> None:
        assert versions.in_range("rubygems", "4.5.0", introduced="4.0.0", fixed="5.0.0")


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
            versions.compare(ecosystem, payload, "1.0.0")
            versions.compare(ecosystem, "1.0.0", payload)
            versions.in_range(ecosystem, payload, introduced="1.0.0", fixed="2.0.0")

    def test_overlong_input_is_bounded_and_does_not_raise(self) -> None:
        huge = "1." + "0." * 200 + "0"
        assert len(huge) > versions.MAX_VERSION_LENGTH
        versions.compare("npm", huge, "1.0.0")

    def test_sort_key_is_usable_with_sorted(self) -> None:
        values = ["1.10.0", "1.9.0", "1.2.0"]
        ordered = sorted(values, key=lambda v: versions.sort_key("npm", v))
        assert ordered == ["1.2.0", "1.9.0", "1.10.0"]

    def test_sort_key_falls_back_for_unparseable_and_stays_sortable(self) -> None:
        values = ["not-a-version", "1.0.0", "also-not"]
        sorted(values, key=lambda v: versions.sort_key("npm", v))
