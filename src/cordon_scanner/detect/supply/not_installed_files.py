"""A file detector's findings about one dependency's record, split by the inventory's install scope.

The manifest and lockfile detectors read every manifest and lockfile in a target, nested and vendored
ones included, while the inventory reads only what installing the target reads (`DependencyScope`)
and keeps the rest as not-installed records. A finding about what one record or declaration says
-- a source outside the registry, a hash that is not a hash -- on a file whose records are all not
installed gets its rule's twin instead: info, or high where the rule is malicious, added after the
verdict and never gating. Which files those are is read from the records' own `installed` flag, so
the finding and the inventory cannot disagree. Rules about a file as a whole are not in any map.
"""

from __future__ import annotations

import posixpath
from dataclasses import replace
from typing import TYPE_CHECKING

from cordon_scanner.foundation.models import Category, Severity

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from cordon_scanner.detect.base import ScanContext
    from cordon_scanner.detect.catalogue import DeclaredRule
    from cordon_scanner.foundation.models import Finding
    from cordon_scanner.foundation.results import Dependency


class NotInstalledFiles:
    """The split and the twins' declarations, for a detector's map of rule to twin."""

    @staticmethod
    def severity(category: Category) -> Severity:
        return Severity.HIGH if category is Category.MALICIOUS else Severity.INFO

    @staticmethod
    def declared(rule: DeclaredRule, twins: Mapping[str, str]) -> DeclaredRule:
        """`rule`'s twin, declared from the rule itself so the two cannot drift."""
        return replace(
            rule,
            id=twins[rule.id],
            severity=NotInstalledFiles.severity(rule.category),
            title=f"{rule.title}, in a file installing the package does not read",
            message=(
                "Only a nested or vendored file in this package records it: installing the "
                "package does not read that file, building the subdirectory that holds it does. "
                + rule.message
            ),
        )

    @staticmethod
    def split(
        findings: list[Finding],
        twins: Mapping[str, str],
        installed: Iterable[Dependency],
        not_installed: Iterable[Dependency],
        ctx: ScanContext,
    ) -> tuple[list[Finding], list[Finding]]:
        """The findings kept, and the twins of those in `twins` on a file whose directory's
        records are all not installed, which the engine adds after the verdict."""
        inside = {posixpath.dirname(d.declared_in) for d in installed if d.declared_in}
        outside = {
            posixpath.dirname(d.declared_in) for d in not_installed if d.declared_in
        } - inside
        kept: list[Finding] = []
        held: list[Finding] = []
        for finding in findings:
            twin = twins.get(finding.rule_id)
            if twin is None or posixpath.dirname(finding.location.path) not in outside:
                kept.append(finding)
                continue
            severity = NotInstalledFiles.severity(finding.category)
            held.append(
                replace(
                    finding,
                    rule_id=twin,
                    severity=severity,
                    message=f"Not installed with this package. {finding.message}",
                    explanation=replace(finding.explanation, matched_rule=twin),
                    risk=ctx.scorer.score(severity, finding.confidence),
                )
            )
        return kept, held


__all__ = ["NotInstalledFiles"]
