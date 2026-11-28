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


class TestEveryEdgeIsPinned:
    """Each comparison at its own boundary, each limit at exactly its size, each form both ways: a
    one-character change to any reader fails one of these (the mutation gate's survivors, killed)."""

    @pytest.mark.parametrize(
        ("spec", "version", "expected"),
        [
            ("[1.0,2.0)", "1.0", True),
            ("[1.0,2.0)", "2.0", False),
            ("(1.0,2.0]", "1.0", False),
            ("(1.0,2.0]", "2.0", True),
            ("(1.0,2.0]", "1.5", True),
            ("[1.0,2.0]", "2.1", False),
            ("[1.0,2.0]", "0.9", False),
            ("(,1.5]", "0.1", True),
            ("(,1.5]", "1.6", False),
            ("[1.5,)", "9.0", True),
            ("[1.5,)", "1.4", False),
            ("[2.0]", "2.0", True),
            ("[2.0]", "2.1", False),
            ("(2.0)", "2.0", False),
            ("[1.0,1.2),[1.5,)", "1.6", True),
            ("[1.0,1.2),[1.5,)", "1.3", False),
            ("[1.0,1.2),[1.5,)", "1.1", True),
            ("1.0", "1.0", True),
            ("1.0", "1.1", False),
            ("", "1.0", False),
            ("[", "1.0", False),
            ("[1.0,2.0)", "", False),
        ],
    )
    def test_maven_intervals(self, spec: str, version: str, expected: bool) -> None:
        assert VersionRanges.admits("maven", spec, version) is expected

    @pytest.mark.parametrize("ecosystem", ["maven", "npm", "pypi", "rubygems", "composer"])
    def test_a_spec_is_read_up_to_256_characters_and_no_further(self, ecosystem: str) -> None:
        wide = {
            "maven": "[1.0,2.0)",
            "npm": ">=1.0.0",
            "pypi": ">=1.0",
            "rubygems": ">= 1.0",
            "composer": ">=1.0",
        }
        spec = wide[ecosystem]
        padded = spec + " " * (256 - len(spec))
        assert len(padded) == 256
        version = "1.5.0" if ecosystem in ("npm", "composer") else "1.5"
        assert VersionRanges.admits(
            ecosystem, padded.strip() if ecosystem == "maven" else padded, version
        )
        assert not VersionRanges.admits(ecosystem, spec + " " * (257 - len(spec)) + "x", version)

    def test_maven_at_exactly_256_and_257(self) -> None:
        at = "[1.0,2.0)" + "," * (256 - len("[1.0,2.0)"))
        assert len(at) == 256 and VersionRanges.admits("maven", at, "1.5")
        assert not VersionRanges.admits("maven", at + ",", "1.5")

    @pytest.mark.parametrize(
        ("spec", "version", "expected"),
        [
            ("1.2.3 - 2.3.4", "2.3.4", True),
            ("1.2.3 - 2.3.4", "2.3.5", False),
            ("1.2.3 - 2.3.4", "1.2.2", False),
            ("1.2.3 - 2.3", "2.3.9", True),
            ("1.2.3 - 2.3", "2.4.0", False),
            ("1.2.3 - x", "9.0.0", True),
            ("1.2.3 - x", "1.2.2", False),
            (">1.2", "1.3.0", True),
            (">1.2", "1.2.9", False),
            (">1.2.3", "1.2.3", False),
            (">1.2.3", "1.2.4", True),
            ("<=1.2", "1.2.9", True),
            ("<=1.2", "1.3.0", False),
            ("<=1.2.3", "1.2.3", True),
            ("<=1.2.3", "1.2.4", False),
            (">=1.2.3", "1.2.3", True),
            ("<1.2.3", "1.2.3", False),
            ("=1.2.3", "1.2.3", True),
            ("x", "1.0.0", True),
            ("x", "1.0.0-beta", False),
            ("*", "2.0.0-rc.1", False),
            ("latest", "3.0.0", True),
            ("^1.2.3-beta.2", "1.2.3-beta.4", True),
            ("^1.2.3-beta.2", "1.2.4-beta.1", False),
            (">=1.0.0", "2.0.0-beta", False),
            ("file:../x", "1.0.0", False),
            ("git+https://h/x.git", "1.0.0", False),
            ("npm:other@1", "1.0.0", False),
            ("workspace:*", "1.0.0", False),
            ("^1.0.0", "v1.2.0", True),
            ("^1.0.0", "1.x", False),
            ("@@", "1.0.0", False),
            ("~> 1.2", "1.2.9", True),
            ("~> 1.2", "1.3.0", False),
            ("x.1.2", "5.0.0", True),
            ("<x", "1.0.0", False),
        ],
    )
    def test_npm_edges(self, spec: str, version: str, expected: bool) -> None:
        assert VersionRanges.admits("npm", spec, version) is expected

    @pytest.mark.parametrize(
        ("spec", "version", "expected"),
        [
            ("===1.0", "1.0", True),
            ("===1.0", "1.0.0", False),
            ("==1.0.*", "1.0.5", True),
            ("==1.0.*", "1.1", False),
            ("!=1.0.*", "1.0.5", False),
            ("!=1.0.*", "1.1", True),
            (">=1.0.*", "1.0", False),
            ("~=1.4.5", "1.4.9", True),
            ("~=1.4.5", "1.5.0", False),
            ("~=1.4.5", "1.4.4", False),
            ("~=1", "1.0", False),
            ("==1.0", "1.0.0", True),
            ("!=1.0", "1.0", False),
            (">=1.0", "1.0", True),
            ("<=1.0", "1.0", True),
            ("<=1.0", "1.1", False),
            (">1.0", "1.0", False),
            ("<1.0", "1.0", False),
            (">=1.0, <2.0", "2.0", False),
            (">=1.0; python_version < '3'", "1.5", True),
            ("", "1.0", False),
            ("bogus", "1.0", False),
        ],
    )
    def test_pep440_edges(self, spec: str, version: str, expected: bool) -> None:
        assert VersionRanges.admits("pypi", spec, version) is expected

    @pytest.mark.parametrize(
        ("ecosystem", "spec", "version", "expected"),
        [
            ("terraform", "= 1.2", "1.2.0", True),
            ("terraform", "1.2", "1.2.0", True),
            ("terraform", "> 1.2", "1.2.0", False),
            ("terraform", ">= 1.2", "1.2.0", True),
            ("terraform", "< 1.2", "1.2.0", False),
            ("terraform", "<= 1.2", "1.2.0", True),
            ("terraform", "!= 1.2", "1.2.0", False),
            ("terraform", "~> 1.2", "1.2.0", True),
            ("terraform", "~> 1.2", "1.1.9", False),
            ("terraform", "v1.2", "1.2.0", True),
            ("rubygems", "~> 1", "1.9", True),
            ("rubygems", "~> 1", "2.0", False),
            ("rubygems", "> 1.0", "1.0", False),
            ("rubygems", "> 1.0", "1.0.1", True),
            ("rubygems", "= 1.0", "1.0.1", False),
            ("rubygems", "~> x", "1.0", False),
            ("rubygems", "", "1.0", False),
            ("rubygems", ">= 1.0", "", False),
            ("hex", "~> 1.2.3", "1.2.3", True),
            ("conda", "~=1.2.3", "1.2.9", True),
            ("conda", "~=1.2.3", "1.3", False),
            ("conda", "!=1.2", "1.2", False),
            ("conda", "!=1.2", "1.3", True),
            ("conda", "=1.2", "1.2.7", True),
            ("conda", "*", "4.0", True),
            ("conda", "<*", "4.0", False),
            ("conda", "===1.2", "1.2", True),
            ("conda", "===1.2", "1.2.0", False),
            ("hackage", "^>=1", "1.0.5", True),
            ("hackage", "^>=1", "1.1", False),
            ("hackage", "any", "0.0.1", True),
            ("opam", '(>= "1.0")', "1.5", False),
            ("opam", '! "1.0"', "1.5", False),
            ("opam", '!= "1.0"', "1.5", True),
            ("opam", '{= "1.0"}', "1.0", True),
            ("julia", "≤ 1.6", "1.6.0", True),
            ("julia", "≤ 1.6", "1.7.0", False),
            ("composer", "~1.2 @stable", "1.5.0", True),
            ("composer", "~1.2 @stable", "2.0.0", False),
            ("composer", "^1.0@dev", "1.3.0", True),
            ("composer", "~v1.2", "1.9.0", True),
            ("composer", "~>1.2", "1.2.5", True),
            ("composer", "1.0", "v1.0.0", True),
            ("composer", "^1.0, <1.5", "1.5.0", False),
            ("composer", "x" * 257, "1.0.0", False),
            ("helm", ">=1.0.0,<1.5.0", "1.4.9", True),
            ("helm", ">=1.0.0,<1.5.0", "1.5.0", False),
            ("conan", "[>=1.0 <2.0]", "1.0", False),
            ("cargo", "1.2, <1.4", "1.4.0", False),
            ("cargo", "1.2, <1.4", "1.3.9", True),
            ("swift", "*", "9.9.9", True),
            ("swift", ">= 1.0.0, <= 1.0.0", "1.0.0", True),
        ],
    )
    def test_comparator_edges(
        self, ecosystem: str, spec: str, version: str, expected: bool
    ) -> None:
        assert VersionRanges.admits(ecosystem, spec, version) is expected

    def test_the_comparator_list_is_bounded_at_256_characters_in_total(self) -> None:
        from cordon_scanner.intel.advisories.ranges import ComparatorRanges

        # The clauses' own length: 6 + 250 is 256, read; one more is past the limit.
        assert ComparatorRanges._all_hold("rubygems", [">= 1.0", " " * 250], "1.5")
        assert not ComparatorRanges._all_hold("rubygems", [">= 1.0", " " * 251], "1.5")


class TestTheLastEdges:
    """The survivors of the second mutation run, each pinned: limits measured inside the spec (the
    reader trims its ends first), the exact upper bound of each npm form, and short versions padded."""

    @staticmethod
    def wide(head: str, tail: str, size: int) -> str:
        return head + " " * (size - len(head) - len(tail)) + tail

    @pytest.mark.parametrize(
        ("ecosystem", "head", "tail", "version"),
        [
            ("npm", ">=1.0.0", "<2.0.0", "1.5.0"),
            ("pypi", ">=1.0,", "<2.0", "1.5"),
            ("composer", ">=1.0", "<2.0", "1.5.0"),
        ],
    )
    def test_256_characters_inside_the_spec_are_read_and_257_are_not(
        self, ecosystem: str, head: str, tail: str, version: str
    ) -> None:
        assert VersionRanges.admits(ecosystem, self.wide(head, tail, 256), version)
        assert not VersionRanges.admits(ecosystem, self.wide(head, tail, 257), version)

    @pytest.mark.parametrize(
        ("spec", "version", "expected"),
        [
            ("1.x", "1.99.0", True),
            ("1.x", "2.0.0", False),
            ("1.x", "0.9.0", False),
            ("1.2.x", "1.2.99", True),
            ("1.2.x", "1.3.0", False),
            ("1.2.x", "1.1.9", False),
            ("<=1.x", "1.9.9", True),
            ("<=1.x", "2.0.0", False),
            (">1.x", "2.0.0", True),
            (">1.x", "1.9.9", False),
            ("^0.0.3", "0.0.3", True),
            ("^0.0.3", "0.0.4", False),
            ("^0.2", "0.2.9", True),
            ("^0.2", "0.3.0", False),
            ("^0.x", "0.9.0", True),
            ("^0.x", "1.0.0", False),
            ("^1.x", "1.9.0", True),
            ("~1", "1.9.0", True),
            ("~1", "2.0.0", False),
            ("~1.2", "1.2.9", True),
            ("~1.2", "1.3.0", False),
            ("1.0.0 - 1.2", "1.2.99", True),
            ("1.0.0 - 1.2", "1.3.0", False),
            ("1.0.0 - 2", "2.9.9", True),
            ("1.0.0 - 2", "3.0.0", False),
            ("1.0.0 - nope", "1.0.0", False),
            (">=1.2.3-alpha.1 <1.2.3", "1.2.3-alpha.5", True),
            (">=1.2.3-alpha.1 <1.2.3", "1.2.4-alpha.1", False),
            ("1.2.3-alpha.1 - 1.2.3", "1.2.3-alpha.3", True),
            ("<1.0.0", "v0.9.0", True),
        ],
    )
    def test_npm_upper_bounds(self, spec: str, version: str, expected: bool) -> None:
        assert VersionRanges.admits("npm", spec, version) is expected

    @pytest.mark.parametrize(
        ("ecosystem", "spec", "version", "expected"),
        [
            ("pypi", "~=1.4.5", "1.4.5", True),
            ("pypi", "~=1.4.5", "1.4", False),
            ("pypi", ">1.0", "1.0.1", True),
            ("pypi", ">=1.0 ; os_name == 'nt'; extra", "1.0", True),
            ("terraform", "= 1", "1.0.0", True),
            ("terraform", "= 1", "1.0.1", False),
            ("terraform", "<= 1.2", "1.2.1", False),
            ("terraform", "~> 1.2", "1.2", True),
            ("cocoapods", "~> 1.2", "1.2", True),
            ("hackage", "^>=1.2.3", "1.2.2", False),
            ("hackage", "^>=1.2", "1.2", True),
            ("conda", "!=1.2.*", "1.2.3", False),
            ("conda", "!=1.2.*", "1.3", True),
            ("julia", "≥ 1.6", "1.6.0", True),
            ("julia", "≥ 1.6", "1.5.9", False),
            ("conan", "^1.2, include_prerelease, other", "1.9.0", True),
            ("composer", ">= 1.0 <= 1.4", "1.4.0", True),
            ("composer", ">= 1.0 <= 1.4", "1.4.1", False),
            ("composer", "^1.0", "v1.2.0", True),
            # Composer reads a short version exactly (1.2 is 1.2.0), unlike npm's 1.2.x...
            ("composer", ">1.2", "1.2.1", True),
            ("composer", "1.2", "1.2.5", False),
            ("composer", "1.2", "1.2.0", True),
            ("composer", "<1.2", "1.1.9", True),
            ("composer", "<1.2", "1.2.0", False),
            # ...but a hyphen range's short upper end is a wildcard, in Composer as in npm.
            ("composer", "1.0 - 2.0", "2.0.5", True),
            ("composer", "1.0 - 2.0", "2.1.0", False),
            ("maven", "[1.0]", "1.0", True),
            ("maven", "[1.0,]", "1.0", True),
            ("maven", "[1.0,]", "0.9", False),
            ("maven", "[,1.0)", "0.5", True),
        ],
    )
    def test_short_versions_and_remaining_forms(
        self, ecosystem: str, spec: str, version: str, expected: bool
    ) -> None:
        assert VersionRanges.admits(ecosystem, spec, version) is expected
