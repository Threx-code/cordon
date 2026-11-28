"""A days-old release of an established package that changed who publishes it, or how, is held.

A maintainer account taken over publishes under the real name, from the real registry: no look-alike
check sees it, and its code may read like any other release. What it cannot hide is how it was
published. A release by an account that did not publish the one before it, or one that stops carrying
the build provenance its earlier releases carry, is the first visible trace of most takeovers, and
such releases are usually found and pulled within days. So such a release of an established name is
held while it is younger than `HOLD_DAYS`; past the hold, or published as before, it is judged on its
content like any other.

The registry's own publish times and publisher names decide; nothing in the package does. Only a
release whose newest version is inside the hold costs a request for its history.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.detect.base import ScanContext
    from cordon_scanner.foundation.models import Finding
    from cordon_scanner.foundation.results import Dependency
    from cordon_scanner.intel.base import PackageFacts, PublishedRelease

HOLD_DAYS: Final = 7
"""How long a changed-publisher or lost-provenance release of an established package is held."""

RULE: Final = "SUSPECT.RELEASE.TAKEOVER_HOLD.001"


class TakeoverHold:
    """The hold on a fresh release of an established package that changed who publishes it, or how."""

    @staticmethod
    def established(ecosystem: str, name: str) -> bool:
        """Whether the name is one many projects depend on: popular or established for its ecosystem."""
        from cordon_scanner.ecosystems.registry import EcosystemRegistry
        from cordon_scanner.intel.registry import EstablishedPackageNames, PopularPackageNames

        adapter = EcosystemRegistry.BY_ID.get(ecosystem)
        normalized = adapter.normalize_name(name) if adapter else name.lower()
        return PopularPackageNames.is_known(ecosystem, normalized) or (
            normalized in EstablishedPackageNames.established(ecosystem)
        )

    @classmethod
    def findings(
        cls,
        ctx: ScanContext,
        dependency: Dependency,
        observed: PackageFacts,
        *,
        min_attested: int,
        now: datetime | None = None,
    ) -> Iterator[Finding]:
        from cordon_scanner.detect.supply.registries.findings import RegistryFinding
        from cordon_scanner.intel.registry import RegistryError, ReleaseLedger, YoungReleases

        version = dependency.version
        if not version or not cls.established(dependency.ecosystem, dependency.name):
            return
        # The newest release is at least as young as any other: outside the hold, none can be inside it.
        if not YoungReleases.younger_than(observed.last_published, HOLD_DAYS):
            return
        try:
            listed = ReleaseLedger.releases(dependency.ecosystem, dependency.name, version)
            before = ReleaseLedger.previous_release(dependency.ecosystem, dependency.name, version)
        except (RegistryError, OSError, ValueError):
            # S2: the history could not be read; the registry checks already recorded what they asked.
            ctx.checks.record(dependency.purl, "takeover-hold", "history unavailable")
            return
        this = next((r for r in listed if r.version in (version, f"v{version}")), None)
        if this is None or not cls._inside(this, now):
            return
        reasons = cls.reasons(this, before, observed, min_attested=min_attested)
        if reasons:
            yield RegistryFinding.finding(
                RULE,
                ctx,
                dependency=dependency,
                detail=(
                    f"{dependency.name}@{version} was published {this.published:%Y-%m-%d}, inside the "
                    f"{HOLD_DAYS}-day hold, and " + "; and ".join(reasons)
                ),
            )

    @staticmethod
    def reasons(
        this: PublishedRelease,
        before: PublishedRelease | None,
        observed: PackageFacts,
        *,
        min_attested: int,
    ) -> list[str]:
        """What changed in how this release was published, compared with the release before it."""
        found = []
        if (
            before is not None
            and before.publisher
            and this.publisher
            and before.publisher != this.publisher
        ):
            found.append(
                f"it was published by `{this.publisher}` where {before.version} was published by `{before.publisher}`"
            )
        if observed.attested_versions >= min_attested and not observed.attested:
            found.append(
                f"it carries no build provenance where {observed.attested_versions} earlier releases do"
            )
        return found

    @staticmethod
    def _inside(release: PublishedRelease, now: datetime | None) -> bool:
        published = release.published
        if published.tzinfo is None:
            published = published.replace(tzinfo=UTC)
        return (now or datetime.now(UTC)) - published < timedelta(days=HOLD_DAYS)


__all__ = ["HOLD_DAYS", "RULE", "TakeoverHold"]
