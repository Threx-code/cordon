"""The package-name lists' ports (`intel.base.PopularNames`, `EstablishedNames`, `RemovedNameList`), as
the registry's roles, answer from the same tables the detectors read directly before: every answer
equal, for every ecosystem they know."""

from __future__ import annotations

from cordon_scanner.intel import registry
from cordon_scanner.intel.registries.popular import PackageIntel
from cordon_scanner.intel.registries.real import RealPackages
from cordon_scanner.intel.registries.removed import RemovedNames


class NamesKit:
    @staticmethod
    def ecosystems() -> list[str]:
        known = {*PackageIntel.POPULAR_PACKAGES, *PackageIntel._KNOWN_NEIGHBOURS, "npm", "pypi"}
        return sorted(known | {"cargo", "rubygems", "gomod", "nuget", "maven", "composer", "none"})


class TestThePort:
    def test_they_are_the_registrys_roles(self) -> None:
        assert registry.PopularPackageNames.popular("npm") == PackageIntel.POPULAR_PACKAGES["npm"]
        assert registry.RemovedPackageNames is RemovedNames

    def test_every_answer_is_the_tables(self) -> None:
        popular = registry.PopularPackageNames
        established = registry.EstablishedPackageNames
        removed = registry.RemovedPackageNames
        for eco in NamesKit.ecosystems():
            assert popular.popular(eco) == PackageIntel.POPULAR_PACKAGES.get(eco, frozenset())
            assert popular.neighbours(eco) == PackageIntel._KNOWN_NEIGHBOURS.get(eco, frozenset())
            assert established.established(eco) == RealPackages.real_packages(eco)
            assert removed.removed(eco) == RemovedNames.removed(eco)
            assert removed.checked(eco) == RemovedNames.checked(eco)
            names = [*sorted(popular.popular(eco) | popular.neighbours(eco))[:50], "not-a-pkg-x"]
            for name in names:
                assert popular.is_known(eco, name) == PackageIntel.is_known_package(eco, name)
