"""What `decide()` returns (spec 5.1, 5.6): a state, stable reason codes, an explanation a person can read, obligations.

`Decision.to_json()` is the `decision/v1` predicate (`contracts/schemas/decision-v1.json`): the same bytes a
signed envelope carries, so the console, the audit log and a customer's pipeline read one shape.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.contracts.reason_codes import ReasonCodes
from cordon_scanner.decide.decision.records import Checks, DecisionError, Instants, JsonRecord


class States:
    """The four states of a decision and how strict each is."""

    ALLOW = "ALLOW"
    ALLOW_WITH_CONDITIONS = "ALLOW_WITH_CONDITIONS"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"
    ORDER: ClassVar[tuple[str, ...]] = (ALLOW, ALLOW_WITH_CONDITIONS, REVIEW, BLOCK)

    @classmethod
    def rank(cls, state: str) -> int:
        """0 (ALLOW) to 3 (BLOCK): the larger is the stricter."""
        return cls.ORDER.index(state)

    @classmethod
    def stricter(cls, left: str, right: str) -> str:
        return left if cls.rank(left) >= cls.rank(right) else right


@dataclass(frozen=True, slots=True)
class Reason(JsonRecord):
    """One reason: a registered code, a sentence, and where it came from."""

    code: str
    text: str
    rule_id: str | None = None
    path: str | None = None
    line: int | None = None
    evidence_hash: str | None = None

    def __post_init__(self) -> None:
        if not ReasonCodes.is_registered(self.code):
            raise DecisionError(f"Reason.code: {self.code!r} is not a registered reason code")
        Checks.text("Reason", "text", self.text)

    def sort_key(self) -> tuple[str, str, str, int, str]:
        return (
            self.code,
            self.rule_id or "",
            self.path or "",
            -1 if self.line is None else self.line,
            self.text,
        )


@dataclass(frozen=True, slots=True)
class Explanation(JsonRecord):
    NESTED: ClassVar[dict[str, type[JsonRecord]]] = {"reasons": Reason}

    summary: str
    reasons: tuple[Reason, ...] = ()

    def __post_init__(self) -> None:
        Checks.text("Explanation", "summary", self.summary)


@dataclass(frozen=True, slots=True)
class PolicyRef(JsonRecord):
    """The policy a decision was made under: its id, version and the digest of its compiled table."""

    id: str
    version: int
    sha256: str

    def __post_init__(self) -> None:
        Checks.text("PolicyRef", "id", self.id)
        Checks.whole("PolicyRef", "version", self.version, low=1)
        if not ArtifactDigests.is_digest(self.sha256):
            raise DecisionError("PolicyRef.sha256: not a sha256 digest")


@dataclass(frozen=True, slots=True)
class DecisionContext(JsonRecord):
    """The part of the context a decision records."""

    point: str
    environment: str
    relation: str


@dataclass(frozen=True, slots=True)
class Relaxation(JsonRecord):
    """A fail-closed default the policy relaxed for this call's environment (invariant I4): the shortfall that was
    found (`code`), the policy setting that decided it (`setting`), the level it was let through at (`level`: a warning
    or a review, never a block) and the environment the policy relaxes it for."""

    SETTINGS: ClassVar[tuple[str, ...]] = ("on_incomplete", "unresolved", "on_gaps")
    LEVELS: ClassVar[tuple[str, ...]] = ("warn", "review")

    code: str
    setting: str
    level: str
    environment: str

    def __post_init__(self) -> None:
        if not ReasonCodes.is_registered(self.code):
            raise DecisionError(f"Relaxation.code: {self.code!r} is not a registered reason code")
        Checks.one_of("Relaxation", "setting", self.setting, self.SETTINGS)
        Checks.one_of("Relaxation", "level", self.level, self.LEVELS)
        Checks.text("Relaxation", "environment", self.environment)

    def sort_key(self) -> tuple[str, str, str, str]:
        return (self.code, self.setting, self.level, self.environment)


@dataclass(frozen=True, slots=True)
class Decision(JsonRecord):
    """The outcome for one artifact in one context under one policy."""

    NESTED: ClassVar[dict[str, type[JsonRecord]]] = {
        "explanation": Explanation,
        "policy": PolicyRef,
        "context": DecisionContext,
        "relaxations": Relaxation,
    }

    state: str
    reason_codes: tuple[str, ...]
    explanation: Explanation
    obligations: tuple[str, ...]
    inputs_digest: str
    policy: PolicyRef
    context: DecisionContext | None = None
    clock_bucket: str | None = None
    relaxations: tuple[Relaxation, ...] | None = None
    """The fail-closed defaults the policy relaxed for this environment that this call used; absent when none was."""

    def __post_init__(self) -> None:
        Checks.one_of("Decision", "state", self.state, States.ORDER)
        Checks.strings("Decision", "reason_codes", self.reason_codes)
        Checks.strings("Decision", "obligations", self.obligations)
        if not self.reason_codes:
            raise DecisionError("Decision.reason_codes: a decision has at least one reason")
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise DecisionError("Decision.reason_codes: a code is listed once")
        if self.clock_bucket is not None:
            Instants.parse(self.clock_bucket)
        if self.relaxations is not None and not self.relaxations:
            raise DecisionError("Decision.relaxations: absent when there is none, never empty")

    @property
    def blocked(self) -> bool:
        return self.state == States.BLOCK

    def canonical_bytes(self) -> bytes:
        """The decision as the bytes every digest and signature of it is taken over."""
        return ArtifactDigests.canonical_json(self.to_json())


__all__ = [
    "Decision",
    "DecisionContext",
    "Explanation",
    "PolicyRef",
    "Reason",
    "Relaxation",
    "States",
]
