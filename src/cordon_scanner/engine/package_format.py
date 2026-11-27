"""Which published-package format an archive is, from the metadata its packaging tool writes.

Moved out of engine/engine.py (review 98 #18), where it was `Engine._distribution_format`, which
now delegates here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon_scanner.ecosystems.registry import RegistryFacts

if TYPE_CHECKING:
    from cordon_scanner.detect.base import FileUnit
    from cordon_scanner.foundation.models import Finding


class PackageFormat:
    @staticmethod
    def of(units: list[FileUnit]) -> str:
        """Which published-package format the archive is, or "" when it is not one.

        Recognised by the shape each ecosystem declares for its own packages (`published_archive`, asked in
        `precedence` order), at the archive's first level only. That level matters: a repository snapshot that
        vendors a package tarball is still a repository, and its own lockfiles are still the project's. An
        ecosystem declares why it has none where it has no archive of its own. A Composer dist and an action
        download are the git host's own archive of a repository at a ref, so an archive of that shape is rightly read
        as the published package, and a plain checked-out folder never is (it has no archive members): do not "fix" this.
        """
        return RegistryFacts.published_format(units)

    @staticmethod
    def renamed_npm(units: list[FileUnit]) -> bool:
        """Whether the archive is npm only by `npm_under_another_root`. A repository snapshot of a
        project with a package.json at its root has the same shape (GitHub's codeload tarballs:
        23 gradle, nix, opam and swift repositories in the #18 A/B), so it is read both ways
        (`union`)."""
        manifest = RegistryFacts.archive_manifest(PackageFormat.of(units))
        return manifest is not None and manifest not in (RegistryFacts.top_level_members(units))

    @staticmethod
    def union(package: list[Finding], repository: list[Finding]) -> list[Finding]:
        """Both readings of an archive that may be either (`renamed_npm`): every finding either
        reading reports, each at the higher of its two grades. A repository snapshot then loses
        nothing to npm's install-time reading of it, and renaming a package's folder gains an
        attacker nothing either way. Findings are paired by rule and location, which the
        ceilings never change."""
        if not repository:
            return package
        graded: dict[tuple[str, object], list[Finding]] = {}
        for finding in repository:
            graded.setdefault((finding.rule_id, finding.location), []).append(finding)
        out: list[Finding] = []
        for finding in package:
            same = graded.get((finding.rule_id, finding.location))
            other = same.pop(0) if same else None
            out.append(
                other if other is not None and other.severity > finding.severity else finding
            )
        out.extend(f for rest in graded.values() for f in rest)
        return out


__all__ = ["PackageFormat"]
