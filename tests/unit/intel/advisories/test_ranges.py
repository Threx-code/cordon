"""Whether a declared range admits a release: npm semver ranges and PEP 440 specifiers."""

from __future__ import annotations

import pytest

from cordon_scanner.intel.advisories.ranges import VersionRanges


class TestRanges:
    """The tests of test_ranges.py that stood alone."""

    @pytest.mark.parametrize(
        ("spec", "version", "expected"),
        [
            ("^1.11.21", "1.11.22", True),
            ("^1.11.21", "2.0.0", False),
            ("^1.11.21", "1.11.20", False),
            ("^0.2.3", "0.2.9", True),
            ("^0.2.3", "0.3.0", False),
            ("^0.0.3", "0.0.4", False),
            ("~1.2.3", "1.2.9", True),
            ("~1.2.3", "1.3.0", False),
            ("1.2.x", "1.2.7", True),
            ("1.2", "1.3.0", False),
            ("*", "9.9.9", True),
            ("", "1.0.0", True),
            (">=1.2.0 <1.4.0", "1.3.5", True),
            (">= 1.2.0 < 1.4.0", "1.4.0", False),
            ("1.0.0 - 1.2.0", "1.2.0", True),
            ("1.0.0 - 1.2", "1.2.9", True),
            ("^1.0.0 || ^3.0.0", "3.1.0", True),
            ("^1.0.0 || ^3.0.0", "2.1.0", False),
            ("1.2.3", "1.2.3", True),
            ("=1.2.3", "1.2.4", False),
            ("^1.2.3", "1.3.0-beta.1", False),
            ("^1.2.3-beta.1", "1.2.3-beta.2", True),
            (">1.2", "1.2.9", False),
            (">1.2", "1.3.0", True),
            ("file:../local", "1.0.0", False),
            ("workspace:*", "1.0.0", False),
            ("git+https://github.com/a/b", "1.0.0", False),
        ],
    )
    def test_npm(self, spec: str, version: str, expected: bool) -> None:
        assert VersionRanges.admits("npm", spec, version) is expected

    @pytest.mark.parametrize(
        ("spec", "version", "expected"),
        [
            (">=1.0,<2.0", "1.5.0", True),
            (">=1.0,<2.0", "2.0", False),
            ("==1.4.*", "1.4.9", True),
            ("==1.4.*", "1.5.0", False),
            ("!=1.4.2", "1.4.2", False),
            ("~=2.2", "2.9", True),
            ("~=2.2", "3.0", False),
            ("~=1.4.5", "1.4.9", True),
            ("~=1.4.5", "1.5.0", False),
            ("==2.0.0", "2.0.0", True),
            (">=1.0; python_version >= '3.8'", "1.2", True),
            ("garbage", "1.0", False),
        ],
    )
    def test_pep440(self, spec: str, version: str, expected: bool) -> None:
        assert VersionRanges.admits("pypi", spec, version) is expected

    def test_an_unknown_ecosystem_answers_no(self) -> None:
        assert VersionRanges.admits("not-an-ecosystem", "^1.0", "1.0.1") is False


class TestEveryEcosystemIsReadOrSaysWhy:
    def test_each_registered_ecosystem_has_a_syntax_or_a_reason(self) -> None:
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        read, why = set(VersionRanges.SYNTAX), set(VersionRanges.NO_RANGES)
        assert not read & why, "an ecosystem is both read and said to have no ranges"
        assert set(EcosystemRegistry.BY_ID) == read | why
        for ecosystem, reason in VersionRanges.NO_RANGES.items():
            assert len(reason) >= 40, ecosystem

    def test_an_ecosystem_with_no_ranges_admits_nothing(self) -> None:
        for ecosystem in VersionRanges.NO_RANGES:
            assert not VersionRanges.admits(ecosystem, ">= 1.0", "1.5.0"), ecosystem


class TestEachEcosystemsOwnSyntax:
    """Each case is the ecosystem's own documented form, as a manifest writes it."""

    @pytest.mark.parametrize(
        ("ecosystem", "spec", "version", "expected"),
        [
            # Cargo: a bare version is a caret requirement; commas join.
            ("cargo", "1.2", "1.9.0", True),
            ("cargo", "1.2", "2.0.0", False),
            ("cargo", "0.2.3", "0.2.9", True),
            ("cargo", "0.2.3", "0.3.0", False),
            ("cargo", "~1.2.3", "1.2.9", True),
            ("cargo", "~1.2.3", "1.3.0", False),
            ("cargo", "=1.2.3", "1.2.4", False),
            ("cargo", ">=1.2, <1.5", "1.4.0", True),
            ("cargo", ">=1.2, <1.5", "1.5.0", False),
            # Julia [compat]: a comma means any of them.
            ("julia", "0.7, 1", "1.4.0", True),
            ("julia", "0.7, 1", "0.8.0", False),
            ("julia", "1.2", "1.9.1", True),
            ("julia", "~1.2", "1.3.0", False),
            ("julia", "≥ 1.6", "1.10.0", True),
            # pub
            ("pub", "^1.2.3", "1.5.0", True),
            ("pub", ">=1.0.0 <2.0.0", "2.0.0", False),
            ("pub", "any", "9.9.9", True),
            ("pub", "1.2.3", "1.2.4", False),
            # Helm (Masterminds semver)
            ("helm", "~1.2.0", "1.2.7", True),
            ("helm", ">=1.2.0, <1.3.0", "1.3.0", False),
            ("helm", "1.2.x", "1.2.5", True),
            # Composer: `~1.2` lets only the last stated part grow.
            ("composer", "~1.2", "1.9.0", True),
            ("composer", "~1.2", "2.0.0", False),
            ("composer", "~1.2.3", "1.2.9", True),
            ("composer", "~1.2.3", "1.3.0", False),
            ("composer", "^2.0 || ^3.0", "3.4.0", True),
            ("composer", ">=1.0 <1.1 | >=1.3", "1.5.0", True),
            ("composer", "1.0.*", "1.0.4", True),
            ("composer", "dev-main", "1.0.0", False),
            # Conan
            ("conan", ">=1.2 <2", "1.8.0", True),
            ("conan", ">=1.2 <2", "2.0.0", False),
            ("conan", "~1.2, include_prerelease", "1.2.5", True),
            # RubyGems, Hex, CocoaPods, Terraform: `~>`
            ("rubygems", "~> 3.0", "3.9", True),
            ("rubygems", "~> 3.0", "4.0", False),
            ("rubygems", "~> 3.0.1", "3.0.9", True),
            ("rubygems", "~> 3.0.1", "3.1.0", False),
            ("rubygems", ">= 1.0, < 2.0", "1.5", True),
            ("rubygems", "!= 1.5", "1.5", False),
            ("rubygems", "1.5", "1.5", True),
            ("hex", "~> 1.2", "1.9.0", True),
            ("hex", "~> 1.2.3", "1.3.0", False),
            ("hex", ">= 1.0.0 and < 2.0.0", "1.4.0", True),
            ("hex", "~> 1.0 or ~> 2.0", "2.3.0", True),
            ("hex", "== 1.0.0", "1.0.1", False),
            ("cocoapods", "~> 5.0", "5.9.0", True),
            ("cocoapods", "~> 5.0", "6.0.0", False),
            ("terraform", "~> 5.0", "5.31.0", True),
            ("terraform", "~> 5.0.1", "5.1.0", False),
            ("terraform", ">= 4.0, < 6.0", "5.2.0", True),
            ("terraform", "!= 5.2.0", "5.2.0", False),
            # Ansible collections and R packages
            ("ansible", ">=1.0.0,<2.0.0", "1.9.0", True),
            ("ansible", ">=1.0.0,<2.0.0", "2.0.0", False),
            ("ansible", "*", "3.1.0", True),
            ("cran", "(>= 1.2)", "1.10", True),
            ("cran", "(>= 1.2)", "1.1", False),
            # conda
            ("conda", ">=1.2,<2", "1.8", True),
            ("conda", "1.2", "1.2.5", True),
            ("conda", "1.2", "1.3", False),
            ("conda", "1.2.*|>=3", "3.1", True),
            ("conda", "==1.2", "1.2.1", False),
            # Cabal
            ("hackage", ">=1.2 && <2", "1.9", True),
            ("hackage", ">=1.2 && <2", "2.0", False),
            ("hackage", "^>=1.2.3", "1.2.9", True),
            ("hackage", "^>=1.2.3", "1.3", False),
            ("hackage", "==1.2.*", "1.2.0.1", True),
            ("hackage", "-any", "0.1", True),
            # opam
            ("opam", '>= "1.2" & < "2.0"', "1.5", True),
            ("opam", '>= "1.2" & < "2.0"', "2.0", False),
            ("opam", '< "1.0" | >= "2.0"', "2.1", True),
            # SwiftPM, as the manifest reader states the requirement
            ("swift", ">= 1.2.3, < next major", "1.9.0", True),
            ("swift", ">= 1.2.3, < next major", "2.0.0", False),
            ("swift", ">= 1.2.3, < next minor", "1.3.0", False),
            ("swift", ">= 1.0.0, < 2.0.0", "1.5.0", True),
            ("swift", "1.2.3", "1.2.4", False),
        ],
    )
    def test_the_ecosystems_own_form(
        self, ecosystem: str, spec: str, version: str, expected: bool
    ) -> None:
        assert VersionRanges.admits(ecosystem, spec, version) is expected

    @pytest.mark.parametrize("ecosystem", sorted(VersionRanges.SYNTAX))
    def test_unreadable_or_oversized_admits_nothing(self, ecosystem: str) -> None:
        assert not VersionRanges.admits(ecosystem, "~~ nonsense ((", "1.0.0")
        assert not VersionRanges.admits(ecosystem, ">=" + "1." * 400 + "0", "1.0.0")
