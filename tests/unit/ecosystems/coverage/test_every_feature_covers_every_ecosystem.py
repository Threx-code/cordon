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

        return frozenset(PreviousRelease.FROM_ARCHIVE)

    @staticmethod
    def confusable_names() -> frozenset[str]:
        from cordon_scanner.detect.supply.registries.detector import CONFUSABLE_ECOSYSTEMS

        return frozenset(CONFUSABLE_ECOSYSTEMS)

    @staticmethod
    def release_compare() -> frozenset[str]:
        from cordon_scanner.cli.commands.review import COMPARABLE

        return frozenset(COMPARABLE)


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
        "look-alike names": (Coverage.confusable_names, dict),
        "old-versus-new release compare in the pre-merge gate": (Coverage.release_compare, dict),
    }
    #: Features being built now: expected to fail until they cover every ecosystem; the entry comes off when they do.
    BUILDING: ClassVar[frozenset[str]] = frozenset(
        {
            "provenance (signed build attestations)",
            "the previous release from the registry archive",
            "look-alike names",
            "old-versus-new release compare in the pre-merge gate",
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


ALL = frozenset(EcosystemRegistry.BY_ID)


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
        assert len(ALL) >= 28 and {"npm", "pypi", "cargo", "maven", "actions", "image"} <= ALL
