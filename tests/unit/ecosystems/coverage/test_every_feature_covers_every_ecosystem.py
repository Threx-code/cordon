"""Every feature that applies across ecosystems covers every ecosystem the scanner supports, or names, per ecosystem, why
the thing itself does not exist there (a registry that publishes no signatures). Only the detection bar is measured
ecosystem by ecosystem, and it is not a feature here.

The structural guard (`test_ecosystem_literals_cover_all.py`) catches a new partial list anywhere in the source; this
test holds each feature to the whole set by the table that decides it. A new cross-ecosystem feature is added to
`Features.TABLE` when it is built. A feature still being built is listed in `Features.BUILDING`, whose tests are
expected to fail and fail the run the moment they pass, so the entry is taken off then: the list only shrinks."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import ClassVar

import pytest

from cordon_scanner.ecosystems.registry import EcosystemRegistry


class Coverage:
    """Where each feature's coverage is decided: the one table it reads."""

    @staticmethod
    def registry_record() -> frozenset[str]:
        from cordon_scanner.intel.registries.registry_record import ECOSYSTEMS

        return frozenset(ECOSYSTEMS)

    @staticmethod
    def provenance() -> frozenset[str]:
        from cordon_scanner.foundation.dependencies import PROVENANCE_ECOSYSTEMS

        return frozenset(PROVENANCE_ECOSYSTEMS)

    @staticmethod
    def provenance_reasons() -> Mapping[str, str]:
        from cordon_scanner.foundation.dependencies import PROVENANCE_NOT_PUBLISHED

        return PROVENANCE_NOT_PUBLISHED

    @staticmethod
    def version_order() -> frozenset[str]:
        from cordon_scanner.intel.advisories.versions import Versions

        return frozenset(Versions.SCHEMES)

    @staticmethod
    def advisory_sources() -> frozenset[str]:
        from cordon_scanner.intel.advisories.osv_import import ECOSYSTEM_OSV_NAMES
        from cordon_scanner.intel.advisories.upstream_advisories import SUPPORTED

        # Gradle's artefacts are Maven's: the same records, read once (`_SHARED_DATA`).
        return frozenset(ECOSYSTEM_OSV_NAMES) | SUPPORTED | {"gradle"}

    @staticmethod
    def campaign_fingerprints() -> frozenset[str]:
        """Every ecosystem whose own manifest parser the fingerprint reads (`CampaignFingerprint.of_manifest`)."""
        return frozenset(e for e in EcosystemRegistry.BY_ID if EcosystemRegistry.get(e) is not None)

    @staticmethod
    def previous_release() -> frozenset[str]:
        from cordon_scanner.sources.previous import PreviousRelease

        return PreviousRelease.supported()

    @staticmethod
    def confusable_names() -> frozenset[str]:
        from cordon_scanner.detect.supply.registries.detector import CONFUSABLE_ECOSYSTEMS

        return frozenset(CONFUSABLE_ECOSYSTEMS)

    @staticmethod
    def private_registries() -> frozenset[str]:
        from cordon_scanner.intel.registries.private_registries import PrivateRegistries

        return PrivateRegistries.supported()

    @staticmethod
    def confusable_reasons() -> Mapping[str, str]:
        from cordon_scanner.detect.supply.registries.detector import NOT_CONFUSABLE

        return NOT_CONFUSABLE

    @staticmethod
    def release_compare() -> frozenset[str]:
        from cordon_scanner.cli.commands.review import COMPARABLE

        return frozenset(COMPARABLE)


class More:
    """The rest of the inventory's features (reviews/platform/61-ECOSYSTEM-INVENTORY-AND-PLAN.md section 1), each by
    the table it decides by. Where a feature decides by a chain of branches rather than a table, its coverage is
    read from those branches in its own source, so the row follows the code; building it replaces the chain with a
    table and the row reads that."""

    #: The extension ecosystem goes by one id; a feature that names it `openvsx` covers `vscode`.
    SAME: ClassVar[dict[str, str]] = {"openvsx": "vscode"}

    @classmethod
    def ids(cls, names: object) -> frozenset[str]:
        return frozenset(cls.SAME.get(str(n), str(n)) for n in names)  # type: ignore[attr-defined]

    @staticmethod
    def compared(module: str, function: str) -> frozenset[str]:
        """The ecosystem ids a function names, read from its source: what a chain of branches covers."""
        import ast
        import importlib
        import inspect

        source = inspect.getsource(importlib.import_module(module))
        found: set[str] = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.FunctionDef) and node.name == function:
                for leaf in ast.walk(node):
                    if isinstance(leaf, ast.Constant) and isinstance(leaf.value, str):
                        found.add(leaf.value)
        return frozenset(found & (frozenset(EcosystemRegistry.BY_ID) | {"vscode", "openvsx"}))

    @classmethod
    def archive_fetch(cls) -> frozenset[str]:
        from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources

        return cls.ids(ArchiveSources.fetchable())

    @classmethod
    def release_history(cls) -> frozenset[str]:
        from cordon_scanner.intel.registries.release_history import ReleaseHistory

        return cls.ids(ReleaseHistory.covered())

    @classmethod
    def registry_facts(cls) -> frozenset[str]:
        from cordon_scanner.intel.registries.registry_hosts import HOSTS

        return cls.ids(HOSTS)

    @classmethod
    def package_url_targets(cls) -> frozenset[str]:
        from cordon_scanner.sources.package import PackageTarget

        return cls.ids(PackageTarget.TYPES.values())

    @staticmethod
    def package_url_reasons() -> Mapping[str, str]:
        from cordon_scanner.sources.package import PackageTarget

        return PackageTarget.NOT_PURL_TYPES

    @classmethod
    def advisory_text(cls) -> frozenset[str]:
        from cordon_scanner.intel.advisories.advisory_text import AdvisoryTextSymbols

        return cls.ids(AdvisoryTextSymbols.APPLIES_TO)

    @classmethod
    def malware_dataset(cls) -> frozenset[str]:
        from cordon_scanner.intel.malware.datadog_malware import DIRECTORIES

        return cls.ids(DIRECTORIES)

    @staticmethod
    def malware_dataset_reasons() -> dict[str, str]:
        """DataDog's dataset publishes samples for npm, PyPI and editor extensions only: for every other ecosystem
        the dataset itself does not exist (its known malware comes from OSV's MAL- records, the advisory sources)."""
        from cordon_scanner.intel.malware.datadog_malware import DIRECTORIES

        return dict.fromkeys(
            ALL - More.ids(DIRECTORIES),
            "DataDog's malicious-packages dataset publishes no samples for this ecosystem; its known malware "
            "comes from OSV's MAL- records through the advisory sources",
        )

    @classmethod
    def sbom_ingest(cls) -> frozenset[str]:
        from cordon_scanner.engine.sbom_ingest import PackageUrl

        return cls.ids(PackageUrl.ECOSYSTEMS.values())

    @classmethod
    def mcp_packages(cls) -> frozenset[str]:
        from cordon_scanner.mcp.packages import ECOSYSTEMS

        return cls.ids(ECOSYSTEMS)

    @classmethod
    def name_signals(cls) -> frozenset[str]:
        from cordon_scanner.detect.supply.name_risk import PackageIdentities

        return cls.ids(PackageIdentities.READERS)

    @classmethod
    def fixer(cls) -> frozenset[str]:
        from cordon_scanner.cloud.fixer import FixSpec

        return cls.ids(FixSpec.FIXABLE)

    @classmethod
    def device_attestation(cls) -> frozenset[str]:
        from cordon_scanner.cloud.device_attestation import DeviceAttestation

        return cls.ids(DeviceAttestation.SPLITTERS)

    @classmethod
    def subjects(cls) -> frozenset[str]:
        from cordon_scanner.contracts.subjects import SubjectParts

        return cls.ids([*SubjectParts.PURL_TYPES, *SubjectParts.PURL_TYPES.values()]) & (
            ALL | {"vscode"}
        )

    @classmethod
    def own_name_findings(cls) -> frozenset[str]:
        from cordon_scanner.detect.supply.manifests.identity_findings import IdentityFindings

        return cls.ids(IdentityFindings.OWN_NAME_MEASURED_ON)

    @classmethod
    def package_format(cls) -> frozenset[str]:
        return cls.ids(More.compared("cordon_scanner.engine.package_format", "of"))

    @classmethod
    def agent_hook(cls) -> frozenset[str]:
        return cls.ids(More.compared("cordon_scanner.cloud.agent.agent_hook", "of"))


class Features:
    #: feature -> (its coverage, the ecosystems it cannot apply to with the reason why).
    TABLE: ClassVar[
        dict[str, tuple[Callable[[], frozenset[str]], Callable[[], Mapping[str, str]]]]
    ] = {
        "registry record (publisher, history, withdrawals)": (Coverage.registry_record, dict),
        "provenance (signed build attestations)": (
            Coverage.provenance,
            Coverage.provenance_reasons,
        ),
        "version ordering for advisory ranges": (Coverage.version_order, dict),
        "advisory sources (OSV or the upstream project)": (Coverage.advisory_sources, dict),
        "campaign fingerprints": (Coverage.campaign_fingerprints, dict),
        "the previous release from the registry archive": (Coverage.previous_release, dict),
        "look-alike names": (Coverage.confusable_names, Coverage.confusable_reasons),
        "old-versus-new release compare in the pre-merge gate": (Coverage.release_compare, dict),
        "archive fetch (digest verified)": (More.archive_fetch, dict),
        "release history (when each release was published)": (More.release_history, dict),
        "registry facts client": (More.registry_facts, dict),
        "package-URL scan targets": (More.package_url_targets, More.package_url_reasons),
        "advisory-text symbols": (More.advisory_text, dict),
        "malware dataset": (More.malware_dataset, More.malware_dataset_reasons),
        "SBOM package-URL ingest": (More.sbom_ingest, dict),
        "MCP package check": (More.mcp_packages, dict),
        "name-signal readers": (More.name_signals, dict),
        "private registries": (Coverage.private_registries, dict),
        "agent hook install recognition": (More.agent_hook, dict),
        "fixer (lockfile fix)": (More.fixer, dict),
        "device attestation splitters": (More.device_attestation, dict),
        "subject canonicalisation": (More.subjects, dict),
        "manifest findings (own name)": (More.own_name_findings, dict),
        "package format sniffing": (More.package_format, dict),
    }
    #: Features being built now: expected to fail until they cover every ecosystem; the entry comes off when they do.
    BUILDING: ClassVar[frozenset[str]] = frozenset(
        {
            # Not yet built for every ecosystem:
            "registry facts client",
            "advisory-text symbols",
            "SBOM package-URL ingest",
            "MCP package check",
            "name-signal readers",
            "agent hook install recognition",
            "fixer (lockfile fix)",
            "device attestation splitters",
            "subject canonicalisation",
            "manifest findings (own name)",
            "package format sniffing",
        }
    )

    @staticmethod
    def params() -> list[object]:
        """Each feature, marked to fail strictly while it is being built."""
        return [
            pytest.param(f, marks=[pytest.mark.xfail(strict=True, reason="being built")])
            if f in Features.BUILDING
            else pytest.param(f)
            for f in sorted(Features.TABLE)
        ]


#: Every ecosystem the product supports: the 28 registered package ecosystems and editor extensions (VS Code
#: Marketplace and Open VSX, `vscode`), which are published to registries of their own like any package.
ALL = frozenset(EcosystemRegistry.BY_ID) | {"vscode"}


class TestEveryFeatureCoversEveryEcosystem:
    @pytest.mark.parametrize("feature", Features.params())
    def test_it_covers_every_ecosystem_it_can_apply_to(self, feature: str) -> None:
        covered_by, reasons = Features.TABLE[feature]
        missing = ALL - (covered_by() & ALL) - set(reasons())
        assert not missing, (
            f"{feature}: not built for {len(missing)} of {len(ALL)} ecosystems: {sorted(missing)}"
        )

    @pytest.mark.parametrize("feature", sorted(Features.TABLE))
    def test_a_reason_names_a_real_ecosystem_and_says_why(self, feature: str) -> None:
        covered_by, reasons = Features.TABLE[feature]
        given = reasons()
        assert set(given) <= ALL
        assert not (set(given) & covered_by()), "an ecosystem the feature covers needs no reason"
        assert all(len(why) >= 40 for why in given.values())

    def test_only_a_listed_feature_is_being_built(self) -> None:
        assert set(Features.TABLE) >= Features.BUILDING

    def test_the_ecosystems_checked_are_the_scanners_own(self) -> None:
        assert (
            len(ALL) == 29
            and {"npm", "pypi", "cargo", "maven", "actions", "image", "vscode"} <= ALL
        )
