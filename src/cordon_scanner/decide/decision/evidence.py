"""What `decide()` is given: the artifact, the context it arrives in, and the evidence about it (spec 5.1, 5.2).

All plain data. Nothing here reads a file, the clock or the network; a consumer builds these from its own
store (the backend from `scan/v1` predicates, the CLI from a `ScanResult`) and the function is the same.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.contracts.subjects import SubjectKind
from cordon_scanner.decide.decision.records import Checks, DecisionError, Instants, JsonRecord


@dataclass(frozen=True, slots=True)
class ArtifactRef(JsonRecord):
    """What is being decided on: the subject (a canonical id), the exact bytes (a digest) and the facts a policy rule reads."""

    kind: str
    subject_id: str
    digest: str | None = None
    version: str | None = None
    ecosystem: str | None = None
    namespace: str | None = None
    tags: tuple[str, ...] = ()
    released_at: str | None = None
    registry: str | None = None
    """The host the artifact was served from (`registry.npmjs.org`), when known: what `registry.host` reads (R505)."""

    def __post_init__(self) -> None:
        Checks.one_of("ArtifactRef", "kind", self.kind, tuple(kind.value for kind in SubjectKind))
        Checks.text("ArtifactRef", "subject_id", self.subject_id)
        Checks.strings("ArtifactRef", "tags", self.tags)
        if self.digest is not None and not ArtifactDigests.is_digest(self.digest):
            raise DecisionError(f"ArtifactRef.digest: {self.digest!r} is not a sha256 digest")
        if self.released_at is not None:
            Instants.parse(self.released_at)
        if self.registry is not None:
            Checks.text("ArtifactRef", "registry", self.registry)

    def age_days(self, clock: datetime) -> int | None:
        """Whole days since the release at `clock`, or `None` when the release time is not known."""
        if self.released_at is None:
            return None
        return max(0, (clock - Instants.parse(self.released_at)).days)


@dataclass(frozen=True, slots=True)
class Context(JsonRecord):
    """Where and how the artifact arrives (spec 5.2)."""

    POINTS: ClassVar[tuple[str, ...]] = (
        "cli",
        "ide",
        "agent_hook",
        "firewall",
        "ci_gate",
        "deploy_admission",
        "inventory_sweep",
    )
    RELATIONS: ClassVar[tuple[str, ...]] = ("direct", "transitive", "bundled", "runtime", "tool")

    point: str
    environment: str
    scope_path: tuple[str, ...] = ()
    actor: str = "human"
    relation: str = "direct"
    online: bool = True
    bundle_age_s: int | None = None
    intel_age_s: int | None = None

    def __post_init__(self) -> None:
        Checks.one_of("Context", "point", self.point, self.POINTS)
        Checks.one_of("Context", "relation", self.relation, self.RELATIONS)
        Checks.text("Context", "environment", self.environment)
        Checks.strings("Context", "scope_path", self.scope_path)
        for name in ("bundle_age_s", "intel_age_s"):
            if getattr(self, name) is not None:
                Checks.whole("Context", name, getattr(self, name))


@dataclass(frozen=True, slots=True)
class FindingFact(JsonRecord):
    """One active finding as a policy sees it: suppressed and baselined findings are removed before."""

    SEVERITIES: ClassVar[tuple[str, ...]] = ("info", "low", "medium", "high", "critical")
    CONFIDENCES: ClassVar[tuple[str, ...]] = ("low", "medium", "high", "confirmed")
    CATEGORIES: ClassVar[tuple[str, ...]] = (
        "malicious",
        "suspicious",
        "vulnerable",
        "policy",
        "operational",
    )

    rule_id: str
    severity: str
    confidence: str
    category: str
    domain: str = "unspecified"
    path: str = ""
    line: int | None = None
    evidence_hash: str | None = None

    def __post_init__(self) -> None:
        Checks.text("FindingFact", "rule_id", self.rule_id)
        Checks.one_of("FindingFact", "severity", self.severity, self.SEVERITIES)
        Checks.one_of("FindingFact", "confidence", self.confidence, self.CONFIDENCES)
        Checks.one_of("FindingFact", "category", self.category, self.CATEGORIES)
        if self.line is not None:
            Checks.whole("FindingFact", "line", self.line)

    @property
    def severity_rank(self) -> int:
        return self.SEVERITIES.index(self.severity)

    @property
    def confidence_rank(self) -> int:
        return self.CONFIDENCES.index(self.confidence)

    def sort_key(self) -> tuple[str, str, int, str, str, str, str]:
        """A total order, so evidence assembled in any order is one evidence."""
        return (
            self.rule_id,
            self.path,
            -1 if self.line is None else self.line,
            self.evidence_hash or "",
            self.category,
            self.severity,
            self.confidence,
        )


@dataclass(frozen=True, slots=True)
class GapFact(JsonRecord):
    """A part of the content left unread because of the content itself (an unparseable running file, an archive refused)."""

    rule_id: str
    path: str = ""

    def __post_init__(self) -> None:
        Checks.text("GapFact", "rule_id", self.rule_id)


@dataclass(frozen=True, slots=True)
class IntelMatch(JsonRecord):
    """Intelligence about this digest: a known-malware match or an advisory."""

    kind: str
    id: str
    source: str
    first_seen: str
    withdrawn: bool = False

    def __post_init__(self) -> None:
        Checks.one_of("IntelMatch", "kind", self.kind, ("known_malware", "advisory"))
        Checks.text("IntelMatch", "id", self.id)
        Instants.parse(self.first_seen)


@dataclass(frozen=True, slots=True)
class Provenance(JsonRecord):
    """How the artifact was built and signed, after the verification ladder (spec 7.3)."""

    slsa_level: int = 0
    signer: str | None = None
    verified: bool = True
    publisher_first_seen: str | None = None
    """When the publisher account first published this subject's namespace (ISO 8601), from the registry: what `publisher.age_days` reads (R502)."""

    def __post_init__(self) -> None:
        Checks.whole("Provenance", "slsa_level", self.slsa_level, high=4)
        if self.publisher_first_seen is not None:
            Instants.parse(self.publisher_first_seen)


@dataclass(frozen=True, slots=True)
class Approval(JsonRecord):
    """An approval or an exception, bound to digests and an expiry (spec 5.3 step 5, I2)."""

    KINDS: ClassVar[tuple[str, ...]] = ("approve", "approve_with_conditions", "exception")

    id: str
    kind: str
    expires_at: str
    digests: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] | None = None
    scope_path: tuple[str, ...] = ()
    conditions: tuple[str, ...] = ()
    revoked: bool = False
    #: For an exception: what the rule's outcome becomes, REVIEW or ALLOW (ALLOW when not stated), set by
    #: the approver within what the policy permits (`defaults.exceptions`).
    outcome: str | None = None
    #: The reason codes an exception speaks for; `None` is every code its rules give. Never a hard stop.
    reason_codes: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        Checks.text("Approval", "id", self.id)
        Checks.one_of("Approval", "kind", self.kind, self.KINDS)
        Instants.parse(self.expires_at)
        Checks.strings("Approval", "digests", self.digests)
        Checks.strings("Approval", "scope_path", self.scope_path)
        Checks.strings("Approval", "conditions", self.conditions)
        if self.rule_ids is not None:
            Checks.strings("Approval", "rule_ids", self.rule_ids)
        if any(not ArtifactDigests.is_digest(item) for item in self.digests):
            raise DecisionError("Approval.digests: every entry is a sha256 digest")
        if self.outcome is not None:
            Checks.one_of("Approval", "outcome", self.outcome, ("REVIEW", "ALLOW"))
            if self.kind != "exception":
                raise DecisionError("Approval.outcome: only an exception names an outcome")
        if self.reason_codes is not None:
            Checks.strings("Approval", "reason_codes", self.reason_codes)

    def active(self, clock: datetime) -> bool:
        """Not revoked and not expired at `clock`."""
        return not self.revoked and Instants.parse(self.expires_at) > clock

    HARD_STOPS: ClassVar[tuple[str, ...]] = ("R100", "R101", "R102", "R103")

    def names_a_hard_stop(self) -> bool:
        """Whether it claims to speak for a hard stop (R100 to R103), which nothing lifts."""
        return any(code in self.HARD_STOPS for code in self.reason_codes or ())

    def covers(self, digest: str | None, scope_path: tuple[str, ...]) -> bool:
        """Whether it speaks for this digest in this scope: the digest is listed (an approval by subject
        covers only the digests it lists) and the approval's scope is the context's scope or an ancestor of it."""
        if digest is None or digest not in self.digests:
            return False
        return scope_path[: len(self.scope_path)] == self.scope_path


@dataclass(frozen=True, slots=True)
class EvidenceSet(JsonRecord):
    """Everything known about the artifact, fetched before the call (spec 5.1)."""

    NESTED: ClassVar[dict[str, type[JsonRecord]]] = {
        "findings": FindingFact,
        "gaps": GapFact,
        "intel": IntelMatch,
        "provenance": Provenance,
        "approvals": Approval,
    }

    findings: tuple[FindingFact, ...] = ()
    gaps: tuple[GapFact, ...] = ()
    complete: bool = True
    intel: tuple[IntelMatch, ...] = ()
    provenance: Provenance | None = None
    approvals: tuple[Approval, ...] = ()
    revoked: bool = False
    kill_listed: bool = False
    integrity_ok: bool | None = None
    unresolved: bool = False
    required_missing: tuple[str, ...] = ()
    lookalike_of: str | None = None
    """The popular name this subject's name resembles, from the name analysis: what `name.lookalike` reads (R504)."""

    def __post_init__(self) -> None:
        Checks.strings("EvidenceSet", "required_missing", self.required_missing)

    def canonical(self) -> dict[str, Any]:
        """The evidence with every collection in a fixed order: the same evidence is one document."""
        document = self.to_json()
        document["findings"] = [
            item.to_json() for item in sorted(self.findings, key=FindingFact.sort_key)
        ]
        document["gaps"] = sorted(
            (item.to_json() for item in self.gaps),
            key=lambda item: (item["rule_id"], item.get("path", "")),
        )
        document["intel"] = sorted(
            (item.to_json() for item in self.intel), key=lambda item: (item["kind"], item["id"])
        )
        document["approvals"] = sorted(
            (item.to_json() for item in self.approvals), key=lambda item: item["id"]
        )
        document["required_missing"] = sorted(self.required_missing)
        return document

    def sha256(self) -> str:
        """The digest of the canonical evidence (`sha256:<hex>`), a part of the decision's `inputs_digest`."""
        return ArtifactDigests.of_bytes(ArtifactDigests.canonical_json(self.canonical()))

    #: The fields that are facts about the artifact's own bytes. Everything else in the set is what one
    #: tenant adds (approvals, a revocation, a kill list, a required-evidence list).
    ANALYSIS_FIELDS: ClassVar[tuple[str, ...]] = (
        "findings",
        "gaps",
        "complete",
        "intel",
        "provenance",
    )

    def analysis_sha256(self) -> str:
        """The digest of what is known about the artifact itself: its findings, gaps, completeness,
        intelligence matches and provenance, and nothing a tenant decides. Two tenants with different
        approvals or kill lists share this key for a public digest, so the analysis is stored once;
        the decision key (`Decision.inputs_digest`) still differs, because it covers the whole set."""
        document = self.canonical()
        shared = {name: document[name] for name in self.ANALYSIS_FIELDS if name in document}
        return ArtifactDigests.of_bytes(ArtifactDigests.canonical_json(shared))

    def request_problems(self) -> list[str]:
        """What is wrong with this evidence as a request: an exception that names a hard stop."""
        return [
            f"Approval {item.id}: an exception cannot cover a hard stop ({', '.join(item.reason_codes or ())})"
            for item in self.approvals
            if item.names_a_hard_stop()
        ]

    def known_malware(self) -> tuple[IntelMatch, ...]:
        return tuple(
            item for item in self.intel if item.kind == "known_malware" and not item.withdrawn
        )


__all__ = [
    "Approval",
    "ArtifactRef",
    "Context",
    "EvidenceSet",
    "FindingFact",
    "GapFact",
    "IntelMatch",
    "Provenance",
]
