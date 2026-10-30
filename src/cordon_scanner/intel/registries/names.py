"""The package-name lists as one `PackageNames` (`intel.base`): the popular names and their curated
neighbours (`popular`), the shipped established names (`real`) and the registry-removed names
(`removed`), answered from the same tables as before, unchanged."""

from __future__ import annotations

from cordon_scanner.intel.registries.popular import PackageIntel
from cordon_scanner.intel.registries.real import RealPackages
from cordon_scanner.intel.registries.removed import RemovedNames


class BuiltinPackageNames:
    """The shipped name lists, as the class itself (`intel.registry` hands it over typed by the
    protocol, as its other roles are)."""

    @staticmethod
    def popular(ecosystem: str) -> frozenset[str]:
        return PackageIntel.POPULAR_PACKAGES.get(ecosystem, frozenset())

    @staticmethod
    def neighbours(ecosystem: str) -> frozenset[str]:
        return PackageIntel._KNOWN_NEIGHBOURS.get(ecosystem, frozenset())

    @staticmethod
    def is_known(ecosystem: str, normalized_name: str) -> bool:
        return PackageIntel.is_known_package(ecosystem, normalized_name)

    @staticmethod
    def established(ecosystem: str) -> frozenset[str]:
        return RealPackages.real_packages(ecosystem)

    @staticmethod
    def removed(ecosystem: str) -> frozenset[str]:
        return RemovedNames.removed(ecosystem)

    @staticmethod
    def removed_checked(ecosystem: str) -> str:
        return RemovedNames.checked(ecosystem)


__all__ = ["BuiltinPackageNames"]
