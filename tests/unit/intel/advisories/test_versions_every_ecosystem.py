"""Every ecosystem the scanner supports orders its versions by its own published scheme, so an advisory's affected
range matches in every ecosystem, not only the ones first built."""

from __future__ import annotations

import pytest

from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.intel.advisories.versions import Versions

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
        assert set(EcosystemRegistry.BY_ID) <= set(Versions.SCHEMES)

    @pytest.mark.parametrize("ecosystem", sorted(ORDERED))
    def test_a_version_of_thousands_of_digits_never_raises(self, ecosystem: str) -> None:
        huge = "1." + "9" * 5000
        assert Versions.compare(ecosystem, huge, "1.0") in (-1, 0, 1)
        assert Versions.compare(ecosystem, "1." + "9" * 200, "1." + "9" * 199) in (-1, 1)

    @pytest.mark.parametrize("ecosystem", sorted(ORDERED))
    def test_it_orders_by_its_own_scheme(self, ecosystem: str) -> None:
        earlier, later = ORDERED[ecosystem]
        assert Versions.compare(ecosystem, earlier, later) == -1
        assert Versions.compare(ecosystem, later, earlier) == 1

    @pytest.mark.parametrize("ecosystem", sorted(ORDERED))
    def test_a_range_matches_in_it(self, ecosystem: str) -> None:
        earlier, later = ORDERED[ecosystem]
        assert Versions.in_range(ecosystem, earlier, introduced="0", fixed=later)
        assert not Versions.in_range(ecosystem, later, introduced="0", fixed=later)


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
        assert Versions.compare("opam", earlier, later) == -1


class TestATagWithoutAVersion:
    @pytest.mark.parametrize("ecosystem", ["image", "nix"])
    @pytest.mark.parametrize("other", ["latest", "3f2a9c1d0b7e4a5f6c8d9e0a1b2c3d4e5f6a7b8c"])
    def test_a_name_or_a_commit_compares_as_text(self, ecosystem: str, other: str) -> None:
        assert Versions.compare(ecosystem, "1.0.0", other) == (-1 if other > "1.0.0" else 1)

    def test_the_debian_comparer_orders_huge_digit_runs_without_int(self) -> None:
        a, b = "1." + "9" * 5000, "1." + "1" + "0" * 5000
        assert Versions._debian("opam", a, b) == -1


class TestTagsThatAreNumbers:
    def test_a_date_tag_is_a_version_not_a_commit(self) -> None:
        assert Versions.compare("image", "20241130", "20241231") == -1


class TestActionsTags:
    def test_a_major_tag_orders_with_a_full_one(self) -> None:
        assert Versions.compare("actions", "v4", "v4.1.2") == -1
        assert Versions.compare("actions", "v4.1.2", "v5") == -1

    def test_a_branch_name_compares_as_text(self) -> None:
        assert Versions.compare("actions", "main", "v4") == (-1 if "main" < "v4" else 1)
