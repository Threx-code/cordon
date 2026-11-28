"""The fast loop's pre-test, past the rules: a candidate's findings run through the scanner's own package composites over a unit's cached findings (LL-147).

The pre-test used to count a unit as newly blocked only when the idea's own predicate said so, so a candidate whose finding does not block by itself
but completes a composite (the third part of the worm, the injection phrase beside the learned reading) was never counted. `PipelineReplay.blocks`
takes a unit's cached findings and the findings a candidate would add, runs `PackageComposites` over all of them (the scanner's code, not a copy), and
applies the content rule to the result, as the scan's exit status does.

A finding is `[rule, severity, confidence, category, detector]`, the cache's own shape (no path, no text). What the replay does NOT do is recorded in
`GAPS`: each is a stage the cache has no input for, and a report must carry them.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import replace
from typing import Any, ClassVar

from cordon_scanner.contracts.content_rule import Content
from cordon_scanner.decide.composites import PackageComposites
from cordon_scanner.foundation.models import Category, Confidence, Finding, Severity
from cordon_scanner.foundation.results import OperationalFinding

Row = Sequence[str]


class PipelineReplay:
    GAPS: ClassVar[dict[str, str]] = {
        "ceilings": "the cache holds no path or place, and its findings are already graded by the ceilings: a candidate's finding is taken at the grade its rule declares",
        "verdict_model": "the verdict model reads the package's paths, sizes, manifests and sources, which the cache does not hold: its lowering or adding of a block is not replayed",
        "injection_basis": "the cache holds no suppression and no match shape: the injection composite counts when both of its rules are present at the grade it was measured at",
    }

    @staticmethod
    def finding(row: Row) -> Finding:
        """A scanner `Finding` for a cached row, carrying what the composites read: rule, grade, category, detector."""
        rule, severity, confidence, category, detector = (*row, "", "", "", "", "")[:5]
        built = OperationalFinding.build(
            path=".",
            rule_id=rule,
            message="",
            remediation="",
            category=Category(category),
            severity=Severity[severity.upper()],
        )
        return replace(built, confidence=Confidence[confidence.upper()], detector=detector)

    @staticmethod
    def row(found: Finding) -> list[str]:
        """The cache row of a finding the replay made."""
        return [
            found.rule_id,
            found.severity.name.lower(),
            found.confidence.name.lower(),
            found.category.value,
            found.detector,
        ]

    @classmethod
    def composites(cls, rows: Iterable[Row]) -> list[list[str]]:
        """The rows of the findings the package composites add to `rows`: the scanner's `PackageComposites`, run over them."""
        findings = [cls.finding(r) for r in rows]
        added = (
            PackageComposites.worm(findings),
            PackageComposites.corroborated_injection(findings),
        )
        return [cls.row(f) for f in added if f is not None]

    @staticmethod
    def blocks_by_content(rows: Iterable[Row]) -> bool:
        """The default gate over content findings, one by one (what the cache's `blk` is)."""
        return any(
            Content.fails(r[0], r[1], r[2], r[3]) and Content.is_content(r[0], r[4]) for r in rows
        )

    @classmethod
    def blocks(cls, cached: Iterable[Row], added: Iterable[Row] = ()) -> bool:
        """Whether the unit is blocked once the candidate's findings are added and the composites have run over the whole."""
        rows = [*cached, *added]
        return cls.blocks_by_content([*rows, *cls.composites(rows)])

    @classmethod
    def through_a_composite(cls, cached: Iterable[Row], added: Iterable[Row] = ()) -> bool:
        """Whether the unit is blocked only because a composite fired: not by the cached findings, not by the candidate's, but by what they make together."""
        rows = [*cached, *added]
        return cls.blocks(cached, added) and not cls.blocks_by_content(rows)

    @classmethod
    def flags(
        cls,
        units: Iterable[Mapping[str, Any]],
        add: Callable[[Mapping[str, Any]], Iterable[Row]],
    ) -> dict[str, bool]:
        """For each unit (`u`, `f` as in the cache): whether the candidate's added findings make it blocked after the replay."""
        return {str(u["u"]): cls.blocks(u.get("f") or (), add(u)) for u in units}


__all__ = ["PipelineReplay"]
