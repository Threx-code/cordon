"""The compiled policy: a decision table `decide()` evaluates, and the digest that pins it (design spec 6.3).

A `CompiledPolicy` is self-contained: every list reference is resolved, inheritance is merged, the rules are
in their evaluation order. Its `sha256` covers all of that, and `decide()` refuses a policy whose digest does
not match what it holds, so an edited table cannot be decided on.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, ClassVar

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.decision.outcome import PolicyRef
from cordon_scanner.decide.decision.predicates import Condition
from cordon_scanner.decide.decision.records import Checks, JsonRecord, PolicyError


@dataclass(frozen=True, slots=True)
class Defaults(JsonRecord):
    """The merged defaults. `on_incomplete` maps an environment (or `*`) to block, review or warn."""

    STRICTNESS: ClassVar[tuple[str, ...]] = ("warn", "review", "block")
    OUTCOMES: ClassVar[tuple[str, ...]] = ("allow", "allow_with_conditions", "review", "block")
    #: What exceptions may do, from the most they may lift to nothing: a larger index is stricter.
    EXCEPTIONS: ClassVar[tuple[str, ...]] = ("allow", "review", "none")

    on_incomplete: dict[str, str]
    unresolved: str = "block"
    on_gaps: str = "block"
    exceptions: str = "allow"
    default: str = "allow"
    max_intel_age_s: int | None = None
    bundle_max_age_s: int | None = None
    warn_until_measured: tuple[str, ...] = ()
    clock_bucket_s: int = 60
    serve_last_allow_s: int | None = None
    """How long an earlier ALLOW may stand in for a decision held back by facts that cannot be had; None is the library's 24 hours."""

    def __post_init__(self) -> None:
        if "*" not in self.on_incomplete:
            raise PolicyError("defaults.on_incomplete: needs a `*` entry")
        for environment, level in self.on_incomplete.items():
            Checks.one_of("Defaults", f"on_incomplete.{environment}", level, self.STRICTNESS)
        Checks.one_of("Defaults", "unresolved", self.unresolved, self.STRICTNESS)
        Checks.one_of("Defaults", "on_gaps", self.on_gaps, self.STRICTNESS)
        Checks.one_of("Defaults", "exceptions", self.exceptions, self.EXCEPTIONS)
        Checks.one_of("Defaults", "default", self.default, self.OUTCOMES)
        Checks.whole("Defaults", "clock_bucket_s", self.clock_bucket_s, low=1)
        if self.serve_last_allow_s is not None:
            Checks.whole(
                "Defaults",
                "serve_last_allow_s",
                self.serve_last_allow_s,
                high=self.SERVE_LAST_ALLOW_MAX_S,
            )

    SERVE_LAST_ALLOW_DEFAULT_S: ClassVar[int] = 86_400
    SERVE_LAST_ALLOW_MAX_S: ClassVar[int] = 604_800

    def serve_last_allow_seconds(self) -> int:
        return (
            self.SERVE_LAST_ALLOW_DEFAULT_S
            if self.serve_last_allow_s is None
            else self.serve_last_allow_s
        )

    def incomplete_for(self, environment: str) -> str:
        """What an incomplete scan does in this environment."""
        return self.on_incomplete.get(environment, self.on_incomplete["*"])


@dataclass(frozen=True, slots=True)
class CompiledRule(JsonRecord):
    NESTED: ClassVar[dict[str, type[JsonRecord]]] = {
        "applies_to": Condition,
        "when": Condition,
        "require": Condition,
    }

    id: str
    tier: str
    then: str
    origin: str
    mandatory: bool = False
    applies_to: tuple[Condition, ...] = ()
    when: tuple[Condition, ...] = ()
    require: tuple[Condition, ...] = ()
    reason: str | None = None
    obligations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CompiledPolicy(JsonRecord):
    NESTED: ClassVar[dict[str, type[JsonRecord]]] = {"defaults": Defaults, "rules": CompiledRule}

    id: str
    version: int
    sha256: str
    defaults: Defaults
    scope: tuple[str, ...] = ()
    chain: tuple[str, ...] = ()
    locked_by: tuple[str, ...] = ()
    mandatory: bool = False
    rules: tuple[CompiledRule, ...] = ()
    lists: dict[str, Any] | None = None
    expires_at: str | None = None
    prev_sha: str | None = None

    def computed_sha256(self) -> str:
        """The digest of everything but `sha256` itself, in canonical JSON."""
        body = replace(self, sha256="sha256:" + "0" * 64).to_json()
        body.pop("sha256")
        return ArtifactDigests.of_bytes(ArtifactDigests.canonical_json(body))

    def sealed(self) -> CompiledPolicy:
        """This policy with its digest filled in."""
        return replace(self, sha256=self.computed_sha256())

    def verify(self) -> None:
        """Refuse a policy whose digest is not the digest of what it holds."""
        if self.sha256 != self.computed_sha256():
            raise PolicyError(
                f"policy {self.id} v{self.version}: the digest does not match the table"
            )

    def ref(self) -> PolicyRef:
        return PolicyRef(self.id, self.version, self.sha256)


__all__ = ["CompiledPolicy", "CompiledRule", "Defaults"]
