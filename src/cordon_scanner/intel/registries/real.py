"""Package names that are known to exist, per ecosystem.

The allowlist a typosquat accusation has to clear, and it is separate from
`popular.py` because the two sets behave in opposite directions and were being
grown as if they were the same thing.

`POPULAR_PACKAGES` is what distance is measured *from*. Adding a name there adds
a target, and every target is another string some legitimate package may sit one
edit away from, so that set has to stay focused on names popular enough that a
mistyped install actually happens.

This set is the opposite. It is the answer to "is the name in front of me real",
and every name added to it can only remove a false accusation -- it can never
create one, because a name that is known to exist is never reported as a squat of
anything. Growing it is monotonically good, and the only cost is bytes on disk.

`popular.py` used to argue for short lists in general, and that reasoning
produced the defect this module exists to fix. Two of the first four real
repositories scanned were accused at HIGH severity of shipping typosquats:

* `psycopg` reported as a typing slip for `psycopg2`. `psycopg` is psycopg 3.
  It is one of the most installed packages on PyPI.
* `colord` reported as a typing slip for `colors`. `colord` is a widely used npm
  colour library.

Both accusations came with the sentence "and is not itself a known package",
which is a claim a forty-name hand-curated list cannot support. Five of the nine
ecosystems had no entries here at all, so in those every real package within one
edit of a popular name was reported at high severity. A scanner that calls
psycopg malware does not get a second look, and no amount of correct detection
elsewhere earns that back.

Bundled as code rather than fetched, like the rest of the intel: a scan works
offline, and a security tool that asks a registry about the code it is scanning
is doing a version of the thing it warns about.

Necessarily still incomplete. No bundled list is a registry, which is why the
detector treats name distance as evidence that something is worth confirming
rather than as a finding it can stand behind on its own -- see the severity and
the wording of SUSPECT.DEPENDENCY.TYPOSQUAT.001, both of which changed with this.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Final

from cordon_scanner.foundation.once import OneOff
from cordon_scanner.foundation.paths import PackagePaths
from cordon_scanner.intel.registries.known.actions import NAMES as _ACTIONS
from cordon_scanner.intel.registries.known.cargo import NAMES as _CARGO
from cordon_scanner.intel.registries.known.cocoapods import NAMES as _COCOAPODS
from cordon_scanner.intel.registries.known.composer import NAMES as _COMPOSER
from cordon_scanner.intel.registries.known.conan import NAMES as _CONAN
from cordon_scanner.intel.registries.known.conda import NAMES as _CONDA
from cordon_scanner.intel.registries.known.cran import NAMES as _CRAN
from cordon_scanner.intel.registries.known.go import NAMES as _GO
from cordon_scanner.intel.registries.known.hex import NAMES as _HEX
from cordon_scanner.intel.registries.known.maven import NAMES as _MAVEN
from cordon_scanner.intel.registries.known.npm import NAMES as _NPM
from cordon_scanner.intel.registries.known.nuget import NAMES as _NUGET
from cordon_scanner.intel.registries.known.others import ANSIBLE as _ANSIBLE
from cordon_scanner.intel.registries.known.others import BAZEL as _BAZEL
from cordon_scanner.intel.registries.known.others import HACKAGE as _HACKAGE
from cordon_scanner.intel.registries.known.others import HELM as _HELM
from cordon_scanner.intel.registries.known.others import HOMEBREW as _HOMEBREW
from cordon_scanner.intel.registries.known.others import IMAGE as _IMAGE
from cordon_scanner.intel.registries.known.others import JULIA as _JULIA
from cordon_scanner.intel.registries.known.others import OPAM as _OPAM
from cordon_scanner.intel.registries.known.others import SWIFT as _SWIFT
from cordon_scanner.intel.registries.known.others import TERRAFORM as _TERRAFORM
from cordon_scanner.intel.registries.known.others import VCPKG as _VCPKG
from cordon_scanner.intel.registries.known.pypi import NAMES as _PYPI
from cordon_scanner.intel.registries.known.rubygems import NAMES as _RUBYGEMS

_NIX: Final = frozenset(
    {
        "numtide/flake-utils-plus",
        "cachix/git-hooks.nix",
        "cachix/pre-commit-hooks.nix",
        "edolstra/flake-compat",
        "hercules-ci/flake-parts",
        "hercules-ci/gitignore.nix",
        "ipetkov/crane",
        "lnl7/nix-darwin",
        "mic92/sops-nix",
        "nix-community/disko",
        "nix-community/fenix",
        "nix-community/home-manager",
        "nix-community/naersk",
        "nix-community/nixvim",
        "nix-community/poetry2nix",
        "nix-systems/default",
        "nixos/nixpkgs",
        "numtide/flake-utils",
        "numtide/treefmt-nix",
        "oxalica/rust-overlay",
        "pyproject-nix/pyproject.nix",
        "pyproject-nix/uv2nix",
        "ryantm/agenix",
    }
)


_CURATED: Final[dict[str, frozenset[str]]] = {
    "npm": _NPM,
    "pypi": _PYPI,
    "cargo": _CARGO,
    "gomod": _GO,
    "rubygems": _RUBYGEMS,
    "composer": _COMPOSER,
    "maven": _MAVEN,
    "gradle": _MAVEN,
    "nuget": _NUGET,
    # Curated only. The CocoaPods Specs repository is the whole registry with no
    # download statistics and no popularity ordering, so there is nothing for
    # `scripts/refresh/refresh_package_intel.py` to rank by. It was the last supported
    # ecosystem with no allowlist of any kind, which meant every real pod within one
    # edit of a popular name was reportable as a squat of it.
    "cocoapods": _COCOAPODS,
    # Curated for the same reason CocoaPods is: none of these registries
    # publishes a ranked export for `scripts/refresh/refresh_package_intel.py` to read.
    # An ecosystem with no allowlist reports every real package within a
    # plausible keyboard slip of a popular name as a squat of it, so every
    # ecosystem the registry knows has one.
    "hex": _HEX,
    "cran": _CRAN,
    "swift": _SWIFT,
    "conan": _CONAN,
    "conda": _CONDA,
    "bazel": _BAZEL,
    "actions": _ACTIONS,
    "terraform": _TERRAFORM,
    "helm": _HELM,
    "ansible": _ANSIBLE,
    "nix": _NIX,
    "vcpkg": _VCPKG,
    "homebrew": _HOMEBREW,
    "image": _IMAGE,
    "hackage": _HACKAGE,
    "julia": _JULIA,
    "opam": _OPAM,
}

DATA_DIR: Final = PackagePaths.data("intel")

#: Ecosystems whose allowlist file is shared. Gradle and Maven name the same
#: artefacts, so one refresh serves both.
_SHARED_DATA: Final[dict[str, str]] = {"gradle": "maven"}


class RealPackages:
    """Names known to be established packages in an ecosystem."""

    @staticmethod
    @OneOff.cache
    def _shipped(ecosystem: str) -> frozenset[str]:
        """The generated allowlist for one ecosystem, or an empty set.

        Plain newline-delimited text, not JSON and not compressed. This file decides
        what a security tool stays quiet about, so it has to be reviewable: a reviewer
        reading a pull request needs to see `tdqm` being added as a line they can
        object to, and neither a blob nor a re-serialised JSON array gives them that.
        Forty thousand names cost about half a megabyte, which is the cheapest part of
        the trade.

        Read once per ecosystem per process, lazily. A scan that touches no npm
        project never opens the npm file.

        Missing is normal and is not an error: `scripts/refresh/refresh_package_intel.py` has
        not been run in this checkout, or the sdist did not ship the directory. The
        curated set below carries it.
        """
        path = DATA_DIR / f"{_SHARED_DATA.get(ecosystem, ecosystem)}.txt"
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return frozenset()
        return frozenset(
            line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")
        )

    @staticmethod
    def real_packages(ecosystem: str) -> frozenset[str]:
        """Every name known to be an established package in this ecosystem."""
        return RealPackages._shipped(ecosystem) | _CURATED.get(ecosystem, frozenset())


class _Mapping:
    """`REAL_PACKAGES[eco]` without loading nine files to answer about one.

    A mapping rather than a dict because the whole point is that the files are
    opened on demand. Kept as the name the rest of the code already uses, so the
    change from a literal dict to a lazy read is invisible to callers.
    """

    def __getitem__(self, ecosystem: str) -> frozenset[str]:
        return RealPackages.real_packages(ecosystem)

    def get(self, ecosystem: str, default: frozenset[str] = frozenset()) -> frozenset[str]:
        found = RealPackages.real_packages(ecosystem)
        return found or default

    def __contains__(self, ecosystem: str) -> bool:
        return bool(RealPackages.real_packages(ecosystem))

    def __iter__(self) -> Iterator[str]:
        return iter({*_CURATED, *_SHARED_DATA})


REAL_PACKAGES: Final = _Mapping()

__all__ = ["DATA_DIR", "REAL_PACKAGES", "RealPackages"]
