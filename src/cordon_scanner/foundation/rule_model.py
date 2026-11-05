"""A detection rule as Cordon holds it: its id, what it matches, where it came from and under what
licence, and the tests that pin what it must and must not match.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

from cordon_scanner.foundation.capabilities import Capability, MatchKind
from cordon_scanner.foundation.models import Category, Confidence, RedactionMode, Severity


@dataclass(frozen=True, slots=True)
class RuleProvenance:
    """Where a rule came from, and how protected it is.

    Mandatory for ``category: malicious``.

    Rules derived from a real incident are qualitatively different from rules
    derived from reasoning: they are the only ones known to have matched
    something that actually arrived. They are also the easiest to lose, because
    they often look arbitrary out of context -- an opaque string constant with no
    obvious meaning is exactly what a well-intentioned cleanup deletes, and a
    refactor that reorganises a rule set can drop one while the diff appears to
    show nothing but an improvement.

    Marking provenance as ``incident`` makes such a rule structurally protected:
    ``cordon rules diff`` fails when one is removed or weakened without an
    explicit review trailer on the commit.
    """

    kind: str
    """incident | research | advisory | community | synthetic"""
    reference: str = ""
    note: str = ""

    @property
    def protected(self) -> bool:
        return self.kind == "incident"

    def to_dict(self) -> dict[str, Any]:
        out = {"kind": self.kind}
        if self.reference:
            out["reference"] = self.reference
        if self.note:
            out["note"] = self.note
        return out


@dataclass(frozen=True, slots=True)
class RuleTests:
    """Samples proving a rule fires, and samples proving it does not overfire.

    Mandatory. A pack containing a rule without at least one positive and one
    negative case fails to load.

    This is not process ceremony. Detection rules fail silently by nature: a path
    filter that no longer matches, a pattern invalidated by a syntax change, an
    escaping error introduced during a refactor. The rule stops matching
    anything, the scan still exits successfully, and nothing anywhere reports a
    problem. The gate looks green precisely because the check is broken.

    Executable samples turn that silent failure into a load-time error.
    """

    positive: tuple[str, ...] = ()
    negative: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Rule:
    """A loaded, validated detection rule.

    Rules are data, not code. They are authored in YAML, versioned independently
    of the engine, signed as a pack, and reviewable by a security team without
    reading Python. That separation is what lets detection content ship on its
    own cadence and be approved by the people qualified to approve it.
    """

    id: str
    category: Category
    severity: Severity
    confidence: Confidence
    title: str
    message: str
    remediation: str
    match_kind: MatchKind
    version: str = "0.0.0"
    rulepack: str = "cordon-builtin"
    languages: tuple[str, ...] = ()
    ecosystems: tuple[str, ...] = ()
    paths_include: tuple[str, ...] = ()
    paths_exclude: tuple[str, ...] = ()
    evidence_policy: RedactionMode = RedactionMode.MASKED
    capability: Capability | None = None
    provenance: RuleProvenance | None = None
    tests: RuleTests = field(default_factory=RuleTests)
    references: tuple[str, ...] = ()
    enabled: bool = True
    baseline_hits: int = 0
    """Matches recorded against the benign corpus. A rule with a non-zero
    baseline may not declare ``confidence: high``; the loader enforces it."""

    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)
    """The rule's source mapping, retained for pattern compilation and for
    ``cordon rules show``."""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "version": self.version,
            "rulepack": self.rulepack,
            "category": str(self.category),
            "severity": str(self.severity),
            "confidence": str(self.confidence),
            "title": self.title,
            "message": self.message,
            "remediation": self.remediation,
            "match_kind": str(self.match_kind),
        }
        if self.languages:
            out["languages"] = list(self.languages)
        if self.ecosystems:
            out["ecosystems"] = list(self.ecosystems)
        if self.capability:
            out["capability"] = str(self.capability)
        if self.provenance:
            out["provenance"] = self.provenance.to_dict()
        if self.references:
            out["references"] = list(self.references)
        return out


__all__ = ["Rule", "RuleProvenance", "RuleTests"]
