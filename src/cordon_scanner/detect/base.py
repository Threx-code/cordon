"""The detector contract.

This module defines the port that every detector plugs into. The engine depends
on this protocol and never on a concrete detector, which is what allows a new
detector -- ours or a third party's -- to be added without touching the core.

Two properties of the contract exist for reasons beyond tidiness.

**Detectors are pure.** ``inspect`` takes a unit and returns findings, with no
I/O outside the unit and no shared state. That is what makes them safe to run in
a worker process, and therefore what makes horizontal scaling a deployment
decision rather than a rewrite. It is also what makes them testable without a
filesystem.

**Applicability is cheap.** ``applicable`` answers from the inventory alone,
performing no reads. A repository with no Python must not pay to discover that
the Python detector has nothing to do.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from cordon_scanner.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    RiskScore,
    Severity,
)
from cordon_scanner.core.scoring import RiskScorer, ScoringContext

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from cordon_scanner.core.config import Config
    from cordon_scanner.core.content import FileContent
    from cordon_scanner.core.models import Capability, Dependency, Repository, Rule
    from cordon_scanner.rules.loader import CompiledRule, RuleSet


@dataclass(frozen=True, slots=True)
class DetectorRequirements:
    """What a detector needs in order to run.

    Declared rather than discovered, so the engine can plan the work before
    doing any of it: which layers to run, whether an AST is needed, whether a
    dependency graph must be built first.
    """

    content: bool = True
    """Needs file bytes."""

    ast: bool = False
    """Needs a parsed syntax tree. Detectors declaring this degrade with an
    OPERATIONAL note when the optional grammar extra is not installed, rather
    than failing the scan."""

    dependencies: bool = False
    repository: bool = False
    network: bool = False
    """Needs network access. Such a detector is skipped entirely when the scan is
    offline, which is the default."""


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Everything a detector may consult that is not the unit itself.

    Immutable and shared. Passing one object rather than a long parameter list
    means a new piece of context does not change every detector's signature.
    """

    config: Config
    rules: RuleSet
    repository: Repository | None = None
    dependencies: tuple[Dependency, ...] = ()
    install_hook_paths: frozenset[str] = frozenset()
    """Paths that execute during install or build.

    Precomputed because it is consulted for every finding and is the largest
    single input to the risk score. The same capability pair is moderate in
    application code and critical here, since install-time code runs unprompted,
    as the developer, before any other control applies.
    """

    scorer: RiskScorer = field(default_factory=RiskScorer)
    offline: bool = True

    def in_install_hook(self, path: str) -> bool:
        return path in self.install_hook_paths


@dataclass(frozen=True, slots=True)
class FileUnit:
    """One file, presented to a content detector."""

    content: FileContent
    language: str | None = None
    project: str | None = None

    @property
    def path(self) -> str:
        return self.content.path


@dataclass(frozen=True, slots=True)
class GraphUnit:
    """The resolved dependency graph, presented to a graph detector."""

    dependencies: tuple[Dependency, ...]
    project: str | None = None


@dataclass(frozen=True, slots=True)
class RepositoryUnit:
    """The repository inventory, presented to a repository detector."""

    repository: Repository


Unit = FileUnit | GraphUnit | RepositoryUnit


@runtime_checkable
class Detector(Protocol):
    """A source of findings.

    Implemented structurally, so a third-party detector satisfies this without
    importing anything from Cordon and is therefore not coupled to our release
    cycle.
    """

    id: str
    version: str
    categories: frozenset[Category]
    requires: DetectorRequirements

    def applicable(self, ctx: ScanContext) -> bool:
        """Cheap check against the inventory. Must not read files."""
        ...

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        """Examine one unit.

        Pure: no I/O outside ``unit``, no global state, safe to call from a
        worker process. Must return findings located within the unit it was
        given; the engine asserts this.
        """
        ...


class BaseDetector:
    """Optional base class providing finding construction.

    Detectors are not required to inherit from it -- the protocol is structural
    -- but building a well-formed :class:`Finding` involves redaction, scoring,
    the category severity floor and explanation assembly, and every detector
    getting that subtly different would be a bug factory.
    """

    id: str = "base"
    version: str = "0.0.0"
    categories: frozenset[Category] = frozenset()
    requires: DetectorRequirements = DetectorRequirements()

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        raise NotImplementedError

    # -- Finding construction -------------------------------------------

    def build_finding(
        self,
        *,
        rule: Rule,
        location: Location,
        evidence: Evidence,
        ctx: ScanContext,
        capabilities: Sequence[Capability] = (),
        is_obfuscated: bool = False,
        extra_escalations: Sequence[str] = (),
        message: str | None = None,
    ) -> Finding:
        """Assemble a finding from a rule match.

        Applies, in order: the category severity floor, context-based scoring,
        and explanation assembly. Centralised so that a rule's declared severity
        and the score it produces can never disagree about the same context.
        """
        in_hook = ctx.in_install_hook(location.path)

        severity = RiskScorer.apply_category_floor(rule.category, rule.severity)

        escalations: list[str] = list(extra_escalations)
        if in_hook:
            escalations.append(
                "executes during install or build, as the user, before other controls"
            )
            # An install hook is where a capability stops being a capability and
            # becomes a mechanism. Escalating severity here rather than writing a
            # second rule keeps the rule set small enough to audit.
            if rule.category in {Category.SUSPICIOUS, Category.MALICIOUS}:
                severity = max(severity, Severity.HIGH)

        risk = ctx.scorer.score(
            severity,
            rule.confidence,
            ScoringContext(
                in_install_hook=in_hook,
                capabilities=frozenset(capabilities),
                is_obfuscated=is_obfuscated,
            ),
        )

        return Finding(
            rule_id=rule.id,
            category=rule.category,
            severity=severity,
            confidence=rule.confidence,
            message=message or rule.message,
            location=location,
            evidence=evidence,
            remediation=rule.remediation,
            explanation=Explanation(
                summary=rule.title,
                matched_rule=rule.id,
                escalations=tuple(escalations),
            ),
            risk=risk,
            detector=self.id,
            rule_version=rule.version,
            rulepack=rule.rulepack,
            references=rule.references,
            capabilities=tuple(capabilities),
        )

    def operational(
        self,
        *,
        path: str,
        message: str,
        detail: str = "",
        rule_id: str = "OPERATIONAL.SCAN.DEGRADED",
    ) -> Finding:
        """Report that the scan itself was degraded.

        Never silent. A file that was not examined is indistinguishable in the
        output from one that was examined and found clean, and a scanner whose
        coverage quietly shrinks is the most dangerous failure available to one.
        """
        return Finding(
            rule_id=rule_id,
            category=Category.OPERATIONAL,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            message=message,
            location=Location(path=path),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(f"{rule_id}:{path}:{detail}".encode()),
                redaction=RedactionMode.NONE,
                metadata=(("detail", detail),) if detail else (),
            ),
            remediation=(
                "Raise the relevant limit, or exclude the path deliberately, so that "
                "coverage is a decision rather than an accident."
            ),
            explanation=Explanation(
                summary="Part of the scan did not complete.",
                matched_rule=rule_id,
            ),
            risk=NO_RISK,
            detector=self.id,
        )


NO_RISK = RiskScore(value=0, base=0, confidence_multiplier=1.0)
"""Score for an operational finding.

Operational findings carry no security risk, so the value is zero. It is still a
real score object rather than None, because every consumer of a finding reads
one, and a special case here would become a null check in every reporter.
"""


class RuleSelector:
    """Chooses which rules can apply to one file.

    Separate from matching because it runs first and decides how much matching
    happens at all. Filtering here rather than inside the match loop means a
    rule that cannot apply to a file never costs a regex execution, which is
    most of what keeps a full scan affordable at commit time.
    """

    @staticmethod
    def rule_applies_to_path(rule: Rule, path: str) -> bool:
        """Whether a rule's path filters admit this file.

        Include is checked before exclude, and an empty include means every path.
        """
        from cordon_scanner.core.walker import PathGlob

        if rule.paths_include and not any(PathGlob.matches(path, p) for p in rule.paths_include):
            return False
        return not any(PathGlob.matches(path, p) for p in rule.paths_exclude)

    @staticmethod
    def select_rules(
        rules: RuleSet, *, language: str | None, path: str
    ) -> tuple[CompiledRule, ...]:
        """Rules that could apply to one file.

        Filtering here rather than inside the match loop means a rule that cannot
        apply never costs a regex execution.
        """
        return tuple(
            compiled
            for compiled in rules.for_language(language)
            if RuleSelector.rule_applies_to_path(compiled.rule, path)
        )


__all__ = [
    "BaseDetector",
    "Detector",
    "DetectorRequirements",
    "FileUnit",
    "GraphUnit",
    "RepositoryUnit",
    "RuleSelector",
    "ScanContext",
    "Unit",
]
