"""The package-name lists' port (`intel.base.PackageNames`), answered by `BuiltinPackageNames` from the
same tables the detectors read directly before: every answer equal, for every ecosystem they know."""

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
    def test_it_is_the_registrys_role(self) -> None:
        assert registry.BuiltinPackageNames.popular("npm") == PackageIntel.POPULAR_PACKAGES["npm"]

    def test_every_answer_is_the_tables(self) -> None:
        names = registry.BuiltinPackageNames
        for eco in NamesKit.ecosystems():
            assert names.popular(eco) == PackageIntel.POPULAR_PACKAGES.get(eco, frozenset())
            assert names.neighbours(eco) == PackageIntel._KNOWN_NEIGHBOURS.get(eco, frozenset())
            assert names.established(eco) == RealPackages.real_packages(eco)
            assert names.removed(eco) == RemovedNames.removed(eco)
            assert names.removed_checked(eco) == RemovedNames.checked(eco)
            for name in [*sorted(names.popular(eco) | names.neighbours(eco))[:50], "not-a-pkg-x"]:
                assert names.is_known(eco, name) == PackageIntel.is_known_package(eco, name)
