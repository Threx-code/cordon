"""The package-name lists behind their ports (`intel.base`): the popular names and their curated
neighbours (`popular`), the shipped established names (`real`) and, through its own class,
the registry-removed names (`removed`), each answered from the same tables as before, unchanged."""

from __future__ import annotations

from cordon_scanner.intel.registries.popular import PackageIntel
from cordon_scanner.intel.registries.real import RealPackages


class PopularPackageNames:
    """`PopularNames`, as the class itself (`intel.registry` hands it over typed by the protocol)."""

    @staticmethod
    def popular(ecosystem: str) -> frozenset[str]:
        return PackageIntel.POPULAR_PACKAGES.get(ecosystem, frozenset())

    @staticmethod
    def neighbours(ecosystem: str) -> frozenset[str]:
        return PackageIntel._KNOWN_NEIGHBOURS.get(ecosystem, frozenset())

    @staticmethod
    def is_known(ecosystem: str, normalized_name: str) -> bool:
        return PackageIntel.is_known_package(ecosystem, normalized_name)


class EstablishedPackageNames:
    """`EstablishedNames`."""

    @staticmethod
    def established(ecosystem: str) -> frozenset[str]:
        return RealPackages.real_packages(ecosystem)


__all__ = ["EstablishedPackageNames", "PopularPackageNames"]
