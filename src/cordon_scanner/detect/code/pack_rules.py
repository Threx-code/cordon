"""Text rules that report on their own: the rules a `--rules` pack or the signed feed delivers.

Every rule Cordon bundles is a capability primitive or a composite over them: a primitive is a label
that only a composite turns into a finding (`CapabilityDetector`). A pack rule with no `capability`
is the other kind the loader accepts -- a rule that "can produce a finding" on its own, the shape of
an indicator pack promoted for a live campaign (CDI §5). Nothing ran those, so such a pack loaded,
passed its own samples, and reported nothing: the failure the samples exist to prevent, one layer
down. This detector runs them: one finding per rule per file, at the first match.

The same restraint as the bundled rules applies: rule material and binary files are not read, a
non-malicious rule is ceilinged in test material, and evidence follows the rule's policy.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from cordon_scanner.analysis.shared.source_paths import SourcePaths
from cordon_scanner.detect.base import (
    BaseDetector,
    DetectorRequirements,
    FileUnit,
    RuleSelector,
    Unit,
)
from cordon_scanner.foundation.capabilities import MatchKind
from cordon_scanner.foundation.models import Category, Explanation, Finding, Location, Severity
from cordon_scanner.foundation.text.redact import Redactor

if TYPE_CHECKING:
    from cordon_scanner.detect.base import ScanContext
    from cordon_scanner.rules.loader import CompiledRule


class PackRuleDetector(BaseDetector):
    """Reports pack rules that declare no capability, wherever their pattern matches."""

    id = "pack-rules"
    version = "0.1.0"
    categories = frozenset(Category)
    requires = DetectorRequirements(content=True)

    @staticmethod
    def reporting(compiled: CompiledRule) -> bool:
        return (
            compiled.rule.capability is None
            and compiled.match.kind is MatchKind.REGEX
            and compiled.match.regex is not None
        )

    def applicable(self, ctx: ScanContext) -> bool:
        return any(self.reporting(r) for r in ctx.rules.rules)

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()
        content = unit.content
        if content.is_binary or content.is_rule_material:
            return ()
        findings: list[Finding] = []
        for compiled in RuleSelector.select_rules(
            ctx.rules, language=unit.language, path=content.path
        ):
            if not self.reporting(compiled):
                continue
            regex = compiled.match.regex_for(content.raw, None)
            match = regex.search(content.raw) if regex is not None else None
            if match is None:
                continue
            rule = compiled.rule
            severity = ctx.scorer.apply_category_floor(rule.category, rule.severity)
            if rule.category is not Category.MALICIOUS and SourcePaths.is_test_material(
                content.path
            ):
                severity = min(severity, Severity.LOW)
            mode = Redactor.effective_mode(rule.evidence_policy, ctx.config.evidence)
            findings.append(
                Finding(
                    rule_id=rule.id,
                    category=rule.category,
                    severity=severity,
                    confidence=rule.confidence,
                    message=rule.message,
                    remediation=rule.remediation,
                    location=Location(
                        path=content.path,
                        line=content.line_of(match.start()),
                        project=unit.project,
                    ),
                    evidence=Redactor.build_evidence(content, match.start(), match.end(), mode),
                    explanation=Explanation(summary=rule.title, matched_rule=rule.id),
                    risk=ctx.scorer.score(severity, rule.confidence),
                    detector=self.id,
                    # Which pack and version: a delivered shadow pack is `shadow:<id>`, how the
                    # analyser fleet tells what it would block from what it decides.
                    rule_version=rule.version,
                    rulepack=rule.rulepack,
                    references=rule.references,
                )
            )
        return findings


__all__ = ["PackRuleDetector"]
