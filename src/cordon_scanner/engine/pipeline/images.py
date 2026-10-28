"""A container image's contents as the scan reports them: the packages its package databases install,
the dependencies each declares, and the files the image carries that no package installed.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from cordon_scanner.engine.pipeline.accumulator import Accumulator
from cordon_scanner.engine.pipeline.constants import REPOSITORY_SCOPE
from cordon_scanner.foundation.results import Dependency, OperationalFinding


class Images:
    """What a container image contains."""

    @staticmethod
    def report_image_contents(inventory: Any, acc: Accumulator) -> None:
        """Say what of the image was content-scanned and what was not, and why."""
        from cordon_scanner.images.oci import OVERSIZE, OVERSIZE_STRINGS

        skipped = ", ".join(
            f"{count} ({reason})" for reason, count in sorted(inventory.skipped.items())
        )
        acc.append(
            OperationalFinding.build(
                path=REPOSITORY_SCOPE,
                rule_id="OPERATIONAL.IMAGE.CONTENTS",
                message=(
                    f"{inventory.added_files} files the image adds beyond its distribution's packages were "
                    f"scanned"
                    + (
                        f" (and {inventory.binaries_as_strings} past the per-file limit as their "
                        f"printable strings and build metadata)"
                        if inventory.binaries_as_strings
                        else ""
                    )
                    + (
                        f", {inventory.removed_files} file(s) a later layer removed were scanned in "
                        f"the layer that holds them"
                        if inventory.removed_files
                        else ""
                    )
                    + f", and {len(inventory.language_packages)} installed language packages were "
                    f"inventoried. Not content-scanned: {skipped or 'nothing'}."
                    + (
                        f" A multi-platform image: the operating-system packages of all "
                        f"{1 + len(inventory.other_platforms)} platforms were inventoried, and the "
                        f"files content-scanned on {inventory.platform}."
                        if getattr(inventory, "other_platforms", None)
                        else ""
                    )
                ),
                remediation="None needed; the counts say what this scan covered.",
            )
        )
        oversize = inventory.skipped.get(OVERSIZE, 0) + inventory.skipped.get(OVERSIZE_STRINGS, 0)
        if oversize:
            acc.complete = False
            acc.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.IMAGE.PARTIAL",
                    message=(
                        "Part of the image was not fully examined: "
                        + "; ".join(
                            f"{inventory.skipped[reason]} file(s) {reason}"
                            for reason in (OVERSIZE, OVERSIZE_STRINGS)
                            if inventory.skipped.get(reason)
                        )
                        + "."
                    ),
                    remediation="Raise limits.max_file_bytes to read them.",
                )
            )

    @staticmethod
    def image_dependencies(inventory: Any) -> tuple[Dependency, ...]:
        """An image's installed dependencies; for a multi-platform image, every platform's.

        An operating-system package installed on every platform is listed once, unlabelled; one
        installed on some is labelled with exactly those. Language packages come from the files,
        content-scanned on the first platform, and are not labelled: they would read as present on
        that platform alone."""
        primary = Images._image_dependencies_of(inventory)
        others = getattr(inventory, "other_platforms", None) or []
        if not others:
            return primary
        from cordon_scanner.images.packages import OsPackage

        system = set(OsPackage.PURL_TYPE.values())
        merged: dict[tuple[str, str, str | None], Dependency] = {}
        seen_on: dict[tuple[str, str, str | None], list[str]] = {}
        for platform_inventory, dependencies in (
            (inventory, primary),
            *((other, Images._image_dependencies_of(other)) for other in others),
        ):
            for dependency in dependencies:
                key = (dependency.ecosystem, dependency.name, dependency.version)
                merged.setdefault(key, dependency)
                seen_on.setdefault(key, []).append(platform_inventory.platform)
        everywhere = 1 + len(others)
        return tuple(
            replace(
                dependency,
                platform=(
                    *dependency.platform,
                    *(f"platform {label}" for label in seen_on[key] if label),
                ),
            )
            if dependency.ecosystem in system and len(seen_on[key]) < everywhere
            else dependency
            for key, dependency in merged.items()
        )

    @staticmethod
    def _image_dependencies_of(inventory: Any) -> tuple[Dependency, ...]:
        from cordon_scanner.foundation.dependencies import NAMED_BY_FILE
        from cordon_scanner.images.packages import OsPackage

        where = OsPackage.DATABASE
        languages = tuple(
            Dependency(
                purl=package.purl,
                ecosystem=package.ecosystem,
                name=package.name,
                version=package.version,
                direct=True,
                declared_in=package.path,
                # The checksum the build recorded where it recorded one (Go). Otherwise these are
                # bytes already installed in the image, not something still to be fetched whose
                # hash could be missing -- and never `local`, which would hide their advisories.
                integrity=package.integrity or "installed-in-image",
                # A binary's architecture and whether it is signed, where it came from one.
                platform=package.platform,
                resolved_from=NAMED_BY_FILE if package.named_by_file else None,
            )
            for package in inventory.language_packages
        )
        from cordon_scanner.images.packages import PackageGraph

        # The installed graph: what each package requires, from the asked-for ones down. Each
        # manager's packages are their own graph -- an image holds one, but nothing assumes it.
        operating_system: list[Dependency] = []
        for manager in OsPackage.MANAGERS:
            packages = [p for p in inventory.packages if p.manager == manager]
            if not packages:
                continue
            edges = PackageGraph.edges(packages)
            direct = PackageGraph.direct(packages, edges)
            depth = {index: 0 for index, asked in enumerate(direct) if asked}
            parents: dict[int, set[str]] = {index: set() for index in range(len(packages))}
            frontier = list(depth)
            while frontier:
                following: list[int] = []
                for index in frontier:
                    for child in edges[index]:
                        parents[child].add(packages[index].name)
                        if child not in depth:
                            depth[child] = depth[index] + 1
                            following.append(child)
                frontier = following
            for index, package in enumerate(packages):
                operating_system.append(
                    Dependency(
                        purl=package.purl(inventory.release),
                        ecosystem=OsPackage.PURL_TYPE[manager],
                        name=package.name,
                        version=package.version,
                        direct=direct[index],
                        # Installed automatically and required by nothing now (what `apt
                        # autoremove` would take): a dependency of nothing in the graph.
                        depth=depth.get(index, 1),
                        parents=tuple(sorted(parents[index])),
                        declared_in=where[manager],
                    )
                )
        identity = inventory.identity
        base: tuple[Dependency, ...] = ()
        if identity.base_name:
            from cordon_scanner.ecosystems.registry import ImageReference

            reference = ImageReference.parse(identity.base_name)
            if reference is not None:
                version = reference.tag
                digest = identity.base_digest or reference.digest
                base = (
                    Dependency(
                        purl=f"pkg:docker/{reference.familiar}"
                        + (f"@{version}" if version else ""),
                        ecosystem="image",
                        name=reference.familiar,
                        version=version,
                        direct=True,
                        integrity=digest,
                        resolved_from=f"registry:{reference.registry}"
                        if reference.registry
                        else None,
                        declared_in="image-config/labels",
                        declared_spec=version or "",
                    ),
                )
        return base + languages + tuple(operating_system)


__all__ = ["Images"]
