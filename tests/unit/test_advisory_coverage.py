"""What the shipped advisory database actually covers.

Every other advisory test asks whether a record, once loaded, matches the right
versions. None of them asked the question a user cares about: given a package
with a well-known vulnerability, does a scan report it?

That gap was not theoretical. The OSV importer read only `ECOSYSTEM`-typed
ranges while npm, crates.io and Go publish almost entirely as `SEMVER`, so those
three ecosystems shipped almost no vulnerability records -- npm had 397 beside
23,550 malicious ones, cargo had 37, gomod had 112. Every unit test passed,
because each one tested a record that had already been loaded. A lockfile
pinning `lodash@4.17.15` reported nothing, and the scan said it was complete.

These tests are deliberately coarse. They assert that a handful of famous,
long-published, high-severity advisories are present, and that no ecosystem's
record count collapses. A precise assertion about which advisories exist would
have to be rewritten every time the database is refreshed, and would then be
rewritten to match whatever the refresh produced -- which is how a test comes to
agree with a regression instead of catching it.
"""

from __future__ import annotations

import pytest

from cordon_scanner.intel.advisories import AdvisoryDatabase

#: Pins whose vulnerability has been public for years, one per ecosystem whose
#: data this project ships. Chosen for longevity rather than severity: each is
#: named by several advisories from several sources, so no single upstream
#: withdrawal can empty the expectation.
KNOWN_VULNERABLE = (
    ("npm", "lodash", "4.17.15"),
    ("npm", "minimist", "1.2.0"),
    ("npm", "axios", "0.21.0"),
    ("pypi", "django", "1.2.1"),
    ("pypi", "pyyaml", "5.1"),
    ("cargo", "smallvec", "0.6.13"),
    ("gomod", "github.com/gogo/protobuf", "v1.3.1"),
    ("maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
    ("maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.8"),
)

#: The floor each ecosystem's *vulnerability* count must clear. An order of
#: magnitude below what the database holds today, because the point is to catch
#: a collapse rather than to track the upstream feed: cargo sat at 37 and gomod
#: at 112 while this was read as healthy coverage.
MINIMUM_VULNERABILITIES = {
    "npm": 2_000,
    "pypi": 2_000,
    "cargo": 300,
    "gomod": 1_000,
    "maven": 2_000,
    "nuget": 500,
    "composer": 1_000,
    "rubygems": 300,
}


@pytest.fixture(scope="module")
def database() -> AdvisoryDatabase:
    return AdvisoryDatabase.bundled()


class TestKnownVulnerabilitiesAreFound:
    @pytest.mark.parametrize(
        ("ecosystem", "name", "version"),
        KNOWN_VULNERABLE,
        ids=[f"{e}:{n}@{v}" for e, n, v in KNOWN_VULNERABLE],
    )
    def test_a_famously_vulnerable_pin_matches(
        self, database: AdvisoryDatabase, ecosystem: str, name: str, version: str
    ) -> None:
        matched = database.matching(ecosystem, name, version)
        assert matched, (
            f"{ecosystem}:{name}@{version} matched no advisory. Either the database "
            f"lost this ecosystem's coverage or the version comparison for it broke; "
            f"both look identical from a scan, which reports nothing and says it is "
            f"complete."
        )

    def test_a_package_nobody_published_matches_nothing(self, database: AdvisoryDatabase) -> None:
        """The other half of the claim. A database that matched everything would
        satisfy every assertion above and be worthless.

        A package that does not exist, rather than a package believed to be
        fixed: `lodash@4.17.21` was the obvious choice for this and is wrong --
        GHSA-r5fr-rjxr-66jc names `[4.0.0, 4.18.0)` for code injection through
        `_.template`. A negative control has to be one the upstream feed cannot
        turn positive.
        """
        assert not database.matching("npm", "cordon-no-such-package-exists", "1.0.0")
        assert not database.matching("pypi", "cordon-no-such-package-exists", "1.0.0")

    def test_a_version_that_is_not_known_matches_no_exact_advisory(
        self, database: AdvisoryDatabase
    ) -> None:
        """A version of `None` cannot fall in a range or equal a listed version,
        so it must match nothing rather than everything."""
        assert not database.matching("npm", "lodash", None)


class TestNoEcosystemHasCollapsed:
    @pytest.mark.parametrize(
        ("ecosystem", "floor"),
        sorted(MINIMUM_VULNERABILITIES.items()),
    )
    def test_the_vulnerability_count_clears_its_floor(self, ecosystem: str, floor: int) -> None:
        from cordon_scanner.intel.advisories import _shipped

        records = _shipped(ecosystem)
        vulnerabilities = sum(1 for r in records if not r.malicious)
        assert vulnerabilities >= floor, (
            f"{ecosystem} ships {vulnerabilities} vulnerability record(s), below the "
            f"{floor} floor. A count this low is what an importer silently dropping a "
            f"range type looks like."
        )

    def test_the_ranged_records_survived_the_import(self) -> None:
        """Range-based records are the ones a type filter removes first.

        An ecosystem whose records are all exact version lists has lost its
        `SEMVER` ranges: `MAL-` entries carry exact lists and CVEs mostly do not,
        so 'plenty of records, none of them ranged' is precisely the shape the
        npm data had while its CVE coverage was missing.
        """
        from cordon_scanner.intel.advisories import _shipped

        for ecosystem in ("npm", "cargo", "gomod"):
            ranged = sum(1 for r in _shipped(ecosystem) if r.is_range)
            assert ranged > 100, f"{ecosystem} has only {ranged} range-based advisor(y/ies)"
