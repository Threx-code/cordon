"""Explainable risk scoring.

A risk score exists to answer one question a severity label cannot: *of the
forty findings in front of me, which do I look at first?* Severity alone cannot
answer it, because a high-severity finding in a test-only dependency and a
high-severity finding in an install hook are not the same problem.

The design constraint is that the score must be **reconstructible by hand**.
This is not a transparency nicety. A score nobody can derive is a score nobody
trusts, and a score nobody trusts is one that gets configured away or ignored --
at which point the ranking it was meant to provide is worse than useless,
because it is still present and still being read.

So the implementation is deliberately not a model. It is:

    score = clamp(base(severity) * weight(confidence) + sum(context factors))

Every factor is an integer, declared in one table, carrying the reason it
applied. Nothing is learned, nothing is tuned per-run, and nothing depends on
the order findings were produced in.

Determinism (constraint C5) is why the arithmetic is integer. A float
accumulated across parallel workers is not reproducible, and baselines,
incremental caching and reproducible CI gates all require that identical inputs
produce identical scores.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar

from cordon.core.models import (
    Capability,
    Category,
    Confidence,
    RiskFactor,
    RiskScore,
    Scope,
    Severity,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

# ---------------------------------------------------------------------------
# The weight table
# ---------------------------------------------------------------------------

SEVERITY_BASE: Mapping[Severity, int] = {
    Severity.INFO: 10,
    Severity.LOW: 25,
    Severity.MEDIUM: 45,
    Severity.HIGH: 70,
    Severity.CRITICAL: 90,
}
"""Base points per severity.

The gaps widen deliberately at the top. The distance between medium and high
should be larger than between low and medium, because that is where the
triage decision actually changes.
"""

CONFIDENCE_WEIGHT: Mapping[Confidence, float] = {
    Confidence.LOW: 0.50,
    Confidence.MEDIUM: 0.75,
    Confidence.HIGH: 1.00,
    Confidence.CONFIRMED: 1.10,
}
"""Confidence scales impact rather than adding to it.

Multiplicative because confidence is a probability: a critical finding that is
probably wrong should rank below a medium finding that is certainly right, and
only scaling produces that ordering. An additive term would preserve the
severity ranking regardless of how doubtful the evidence was.

CONFIRMED exceeds 1.0 so that cryptographic identity -- a known-bad artefact
hash, an exact malicious package version -- outranks everything heuristic at the
same severity. There is no triage judgement to make about a confirmed match.
"""


@dataclass(frozen=True, slots=True)
class ScoringWeights:
    """Context factors, in points.

    Versioned and shipped in policy so that changing them is a reviewable diff
    rather than a silent behavioural change. Two scans of the same code with
    different weights should be explainable by pointing at the policy commit.
    """

    install_time: int = 15
    """Code that executes during install or build.

    The largest positive factor, and the reason is structural rather than
    statistical. Install-time code runs unprompted, as the developer, with the
    developer's full environment, before any test, review, container boundary or
    network policy applies. The same behaviour in application code has to get
    past all of those first.
    """

    credential_access: int = 12
    network_egress: int = 10
    obfuscated: int = 10
    """Encoding is not itself malicious, but it has no defensive purpose in
    source code. Its presence means the author wanted the content unreadable to
    a reviewer, which is information regardless of intent."""

    binary_payload: int = 8
    reachable: int = 8
    direct_dependency: int = 5
    no_fix_available: int = 5

    transitive_penalty_per_hop: int = -2
    transitive_penalty_floor: int = -6
    """Depth reduces the score because a deep transitive dependency is less
    directly controllable, not because it is less dangerous. The floor stops
    depth from burying a genuine finding: a malicious package eight levels down
    still executes with the same privileges as one at the top."""

    dev_only: int = -8
    """Development-only scope reduces but never eliminates. A build-time
    dependency still runs on developer machines and CI runners, which is
    precisely where the credentials are."""

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


DEFAULT_WEIGHTS = ScoringWeights()


# ---------------------------------------------------------------------------
# Scoring context
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScoringContext:
    """Facts about where a finding is, which the scorer turns into factors.

    Assembled by the engine from the inventory and the dependency graph. Keeping
    it a separate value object means the scorer is a pure function and can be
    unit-tested without a scan, a filesystem or a repository.
    """

    in_install_hook: bool = False
    capabilities: frozenset[Capability] = frozenset()
    is_obfuscated: bool = False
    has_binary_payload: bool = False
    is_reachable: bool | None = None
    """None means reachability was not analysed. Distinguished from False so an
    un-analysed finding is not scored as though it were proven unreachable."""

    dependency_depth: int | None = None
    is_direct_dependency: bool = False
    scope: Scope = Scope.RUNTIME
    fix_available: bool | None = None


# ---------------------------------------------------------------------------
# The scorer
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RiskScorer:
    """Computes explainable scores. Stateless and reusable."""

    weights: ScoringWeights = field(default_factory=lambda: DEFAULT_WEIGHTS)

    CATEGORY_SEVERITY_FLOOR: ClassVar[Mapping[Category, Severity]] = {
        Category.MALICIOUS: Severity.HIGH,
    }
    """Minimum severity a category may be reported at.

    Malicious findings cannot be filed below high regardless of what a rule
    declares. A rule author can be wrong about severity; the category assertion
    "this is evidence of intent to harm" is not something a threshold should be
    able to hide.
    """

    @classmethod
    def apply_category_floor(cls, category: Category, severity: Severity) -> Severity:
        floor = cls.CATEGORY_SEVERITY_FLOOR.get(category)
        return max(severity, floor) if floor else severity

    @staticmethod
    def security_severity(score: RiskScore) -> str:
        """Render a score as a SARIF ``security-severity`` string.

        This single property carries disproportionate weight in practice. Code
        scanning platforms sort, filter and threshold on it, and a SARIF file
        that omits it renders every finding as equally important -- which
        discards the entire ranking the scorer exists to produce.

        The scale is 0.0 to 10.0, so the score is divided by ten and rendered to
        one decimal. Formatted from an integer to keep output byte-identical
        across platforms; float repr is not something to rely on for
        reproducibility.
        """
        return f"{score.value // 10}.{score.value % 10}"

    def score(
        self,
        severity: Severity,
        confidence: Confidence,
        context: ScoringContext | None = None,
    ) -> RiskScore:
        ctx = context or ScoringContext()
        w = self.weights

        base = SEVERITY_BASE[severity]
        multiplier = CONFIDENCE_WEIGHT[confidence]
        total = int(base * multiplier)
        factors: list[RiskFactor] = []

        def add(name: str, points: int, reason: str) -> None:
            nonlocal total
            if points:
                factors.append(RiskFactor(name, points, reason))
                total += points

        if ctx.in_install_hook:
            add(
                "install_time",
                w.install_time,
                "executes during install or build, as the user, before other controls",
            )

        if Capability.CREDENTIAL in ctx.capabilities:
            add("credential_access", w.credential_access, "reads environment or key material")

        if Capability.EGRESS in ctx.capabilities:
            add("network_egress", w.network_egress, "opens an outbound connection")

        if ctx.is_obfuscated:
            add("obfuscated", w.obfuscated, "content is encoded, packed or escaped")

        if ctx.has_binary_payload:
            add("binary_payload", w.binary_payload, "unexpected binary or executable content")

        if ctx.is_reachable is True:
            add("reachable", w.reachable, "the affected code path is used")

        if ctx.is_direct_dependency:
            add("direct_dependency", w.direct_dependency, "declared in this project's manifest")

        if ctx.fix_available is False:
            add("no_fix_available", w.no_fix_available, "no patched version is published")

        if ctx.dependency_depth and ctx.dependency_depth > 0:
            penalty = max(
                w.transitive_penalty_per_hop * ctx.dependency_depth,
                w.transitive_penalty_floor,
            )
            add(
                "transitive_depth",
                penalty,
                f"{ctx.dependency_depth} hops from a direct dependency",
            )

        if ctx.scope in {Scope.DEV, Scope.TEST}:
            add("dev_only", w.dev_only, f"{ctx.scope} scope only")

        clamped = max(0, min(100, total))
        if clamped != total:
            factors.append(
                RiskFactor("clamped", clamped - total, f"raw score {total} clamped into 0-100")
            )

        return RiskScore(
            value=clamped,
            base=base,
            confidence_multiplier=multiplier,
            factors=tuple(factors),
        )


# ---------------------------------------------------------------------------
# SARIF interoperability
__all__ = [
    "CONFIDENCE_WEIGHT",
    "DEFAULT_WEIGHTS",
    "SEVERITY_BASE",
    "RiskScorer",
    "ScoringContext",
    "ScoringWeights",
]
