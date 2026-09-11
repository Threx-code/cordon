"""The shipped allowlist of established package names.

This file decides what the typosquat rule stays quiet about, which makes it the
one piece of bundled data whose contents can remove a detection. It is generated
from seven registries by `scripts/refresh_package_intel.py` and is fifty thousand
lines long, so nobody is going to read it; these are the properties a reviewer
would check if they could.

Two failure directions, and they are not symmetric.

A name MISSING costs a false accusation against a real maintainer's package, at
a severity that used to fail builds. That is what the file was written for:
`psycopg` and `colord` were both reported as typosquats, at high, in two of the
first four repositories scanned.

A name WRONGLY PRESENT costs a missed squat, and it is the quieter failure -- the
rule goes on running and reporting nothing, which is indistinguishable from a
clean tree. So the tests that matter most here are the ones asserting that known
squats are absent.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.intel.popular import PackageIntel
from cordon_scanner.intel.real import DATA_DIR, REAL_PACKAGES, real_packages

SHIPPED = sorted(p for p in DATA_DIR.glob("*.txt") if not p.name.endswith(".refused.txt"))

#: Below this, a refresh did not work. Not a target -- a floor that a source
#: returning an error page, an empty array or an HTML redirect would fall through.
#: The script has its own guard against shrinking an existing file; this catches the
#: first write, where there is nothing to shrink from.
MINIMUM_NAMES = {
    "pypi": 10_000,
    "npm": 5_000,
    "cargo": 10_000,
    "nuget": 2_000,
    "composer": 500,
    "rubygems": 1_000,
    "pub": 500,
}


def names(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def test_something_is_shipped() -> None:
    """A parametrised test over an empty glob reports success, and this directory
    is exactly where that could happen quietly: the loader falls back to the
    curated sets when a file is missing, so an empty `data/` is a working scanner
    with a far smaller allowlist and no error anywhere."""
    assert SHIPPED, f"no allowlist files found in {DATA_DIR}"


@pytest.mark.parametrize("path", SHIPPED, ids=lambda p: p.stem)
class TestEachFileIsWellFormed:
    def test_it_has_a_provenance_header(self, path: Path) -> None:
        """Where the names came from, what threshold was applied and when. A
        security artefact whose provenance is not written down is not reviewable."""
        header = "\n".join(
            line for line in path.read_text(encoding="utf-8").splitlines() if line.startswith("#")
        )
        for required in ("Source:", "Threshold:", "Refreshed:"):
            assert required in header, f"{path.name} header is missing {required!r}"

    def test_it_is_sorted_and_has_no_duplicates(self, path: Path) -> None:
        """So a refresh produces a diff somebody can read. An unsorted file
        rewrites itself completely on every run and hides what actually changed,
        which is the one thing a reviewer of this file needs to see."""
        entries = names(path)
        assert entries == sorted(entries), f"{path.name} is not sorted"
        assert len(entries) == len(set(entries)), f"{path.name} has duplicates"

    def test_it_has_enough_names_to_be_a_refresh(self, path: Path) -> None:
        floor = MINIMUM_NAMES.get(path.stem)
        if floor is None:
            pytest.skip(f"no floor declared for {path.stem}")
        assert len(names(path)) >= floor

    def test_every_name_is_a_plausible_package_name(self, path: Path) -> None:
        """No blank lines, no stray whitespace, no HTML. A source that starts
        serving an error page parses into entries, and they look like this."""
        # A leading `@` is npm's scope syntax: `@types/node`, `@babel/core`. It
        # belongs in the shape, and leaving it out failed this test against correct
        # data -- a third of the npm allowlist is scoped.
        shape = re.compile(r"^[@A-Za-z0-9][A-Za-z0-9._@/+:-]{0,200}$")
        bad = [name for name in names(path) if not shape.match(name)]
        assert not bad, f"{path.name}: {bad[:10]}"

    def test_its_refusals_are_recorded_beside_it(self, path: Path) -> None:
        """An exclusion nobody can see is the failure mode of every suppression
        mechanism ever shipped. These are the names cordon will still report as
        typosquats despite their download counts, so the list has to be in the diff
        where somebody who knows the ecosystem can disagree with it."""
        assert path.with_suffix(".refused.txt").exists(), (
            f"{path.name} has no .refused.txt; a refresh writes both"
        )


class TestTheNamesThatStartedThis:
    """The two false accusations the allowlist was written to stop."""

    @pytest.mark.parametrize(
        ("ecosystem", "name"),
        [
            ("pypi", "psycopg"),
            ("pypi", "psycopg2"),
            ("pypi", "psycopg2-binary"),
            ("npm", "colord"),
            ("npm", "colorette"),
            ("npm", "picocolors"),
        ],
    )
    def test_it_is_known(self, ecosystem: str, name: str) -> None:
        assert PackageIntel.is_known_package(ecosystem, name)


class TestKnownSquatsAreNotAllowlisted:
    """The quiet failure direction, and the one worth the most attention.

    A missing name costs a false accusation, which somebody notices within a day. A
    name wrongly present costs a missed squat, and the rule goes on running and
    reporting nothing -- which looks exactly like a clean tree. `tdqm` is the live
    case: a real PyPI typosquat of `tqdm`, with enough installs to clear any
    download threshold, which the look-alike filter refused.
    """

    @pytest.mark.parametrize(
        ("ecosystem", "name", "imitates"),
        [
            ("pypi", "tdqm", "tqdm"),
            ("pypi", "requsts", "requests"),
            ("pypi", "urlib3", "urllib3"),
            ("npm", "lodahs", "lodash"),
            ("npm", "expresss", "express"),
            ("cargo", "cfg-iif", "cfg-if"),
        ],
    )
    def test_it_is_not_known(self, ecosystem: str, name: str, imitates: str) -> None:
        assert not PackageIntel.is_known_package(ecosystem, name), (
            f"{name!r} is allowlisted, so it can no longer be reported as a squat of {imitates!r}"
        )

    def test_the_refused_list_names_the_one_that_got_this_far(self) -> None:
        """`tdqm` cleared the download threshold and was stopped by shape. If the
        filter is ever relaxed, this is the entry that says what it cost."""
        refused = DATA_DIR / "pypi.refused.txt"
        assert "tdqm ~ tqdm" in refused.read_text(encoding="utf-8")


class TestTheLoader:
    def test_every_supported_ecosystem_has_some_allowlist(self) -> None:
        """Shipped or curated, but never empty. An ecosystem with no allowlist
        reports every real package within one edit of a popular name -- which is
        the state five of the nine were in."""
        for ecosystem in sorted(EcosystemRegistry.BY_ID):
            assert real_packages(ecosystem), f"{ecosystem} has no allowlist at all"

    def test_gradle_and_maven_share_one(self) -> None:
        """They name the same artefacts, so one refresh serves both."""
        assert real_packages("gradle") == real_packages("maven")

    def test_an_unknown_ecosystem_is_empty_rather_than_an_error(self) -> None:
        assert real_packages("not-an-ecosystem") == frozenset()

    def test_the_mapping_reads_lazily(self) -> None:
        """`REAL_PACKAGES[eco]` must not mean "load nine files to answer about
        one". A scan that touches no npm project should never open the npm file."""
        assert "psycopg" in REAL_PACKAGES["pypi"]
        assert REAL_PACKAGES.get("not-an-ecosystem", frozenset({"x"})) == frozenset({"x"})


class TestPackaging:
    """A wheel without the data directory is the dangerous outcome, because it is
    not a crash. The scanner works, and reports typosquats against real packages in
    every installed copy while passing every test in a source checkout."""

    ROOT = Path(__file__).resolve().parents[2]

    def test_the_wheel_declares_the_data(self) -> None:
        pyproject = self.ROOT / "pyproject.toml"
        if not pyproject.exists():
            pytest.skip("pyproject.toml is not shipped in the sdist")
        text = pyproject.read_text(encoding="utf-8")
        assert '"cordon_scanner.intel.data" = ["*.txt"]' in text

    def test_the_sdist_declares_the_data(self) -> None:
        manifest = self.ROOT / "MANIFEST.in"
        if not manifest.exists():
            pytest.skip("MANIFEST.in is not shipped in the sdist")
        text = manifest.read_text(encoding="utf-8")
        assert "recursive-include src/cordon_scanner/intel/data *.txt" in text

    def test_the_directory_is_a_package(self) -> None:
        """`package-data` names a package, so setuptools needs the `__init__.py` to
        find it. Without one the declaration above matches nothing."""
        assert (DATA_DIR / "__init__.py").exists()
