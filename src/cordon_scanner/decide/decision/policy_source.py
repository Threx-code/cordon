"""Policy v2 as written: the JSON surface a tenant, the console or a repository states (design spec 6.1).

Source is data, checked strictly: a key the type does not have is an error, and `policy_schema` must be 2 so
a v2 source is never read as today's settings file (version 1). `PolicyCompiler` turns a source into a
`CompiledPolicy`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar

from cordon_scanner.decide.decision.records import Checks, JsonRecord, PolicyError


class Durations:
    """`7d`, `72h`, `30m`, `90s` or a whole number of seconds."""

    UNITS: ClassVar[dict[str, int]] = {"d": 86_400, "h": 3_600, "m": 60, "s": 1}

    @classmethod
    def seconds(cls, value: Any, path: str) -> int:
        if isinstance(value, bool):
            raise PolicyError(f"{path}: expected a duration such as 7d or 72h")
        if isinstance(value, int) and value >= 0:
            return value
        text = str(value).strip()
        unit = text[-1:] if text[-1:] in cls.UNITS else "s"
        digits = text[:-1] if text[-1:] in cls.UNITS else text
        if not digits.isdigit():
            raise PolicyError(f"{path}: {value!r} is not a duration such as 7d or 72h")
        return int(digits) * cls.UNITS[unit]


@dataclass(frozen=True, slots=True)
class RuleSource(JsonRecord):
    """One rule as written. A rule fires when `applies_to` holds, `when` holds (or is empty) and `require`
    is unmet (or is empty); what it does is `then`."""

    TIERS: ClassVar[tuple[str, ...]] = ("deny", "require", "allow")
    THENS: ClassVar[tuple[str, ...]] = ("block", "review", "allow_with_conditions", "allow")

    id: str
    tier: str
    then: str
    applies_to: dict[str, Any] | None = None
    when: dict[str, Any] | None = None
    require: dict[str, Any] | None = None
    reason: str | None = None
    obligations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        Checks.text("RuleSource", "id", self.id)
        Checks.one_of("RuleSource", "tier", self.tier, self.TIERS)
        Checks.one_of("RuleSource", "then", self.then, self.THENS)
        Checks.strings("RuleSource", "obligations", self.obligations)


@dataclass(frozen=True, slots=True)
class DegradeSource(JsonRecord):
    """What a point may do when the facts that would refresh a decision cannot be had (spec 8.4)."""

    MAX_SERVE_HOURS: ClassVar[int] = 168

    serve_last_allow_hours: int | None = None
    """How long an earlier ALLOW for the same digest, policy, environment and scope may stand in for a decision that is held back
    only by required evidence that cannot be fetched or intelligence older than the policy allows. Default 24, at most 168, 0 turns it off."""

    def __post_init__(self) -> None:
        if self.serve_last_allow_hours is not None:
            Checks.whole(
                "DegradeSource",
                "serve_last_allow_hours",
                self.serve_last_allow_hours,
                high=self.MAX_SERVE_HOURS,
            )


@dataclass(frozen=True, slots=True)
class DefaultsSource(JsonRecord):
    """The policy's defaults as written; what is not stated is inherited, or the library's default."""

    NESTED: ClassVar[dict[str, type[JsonRecord]]] = {"degrade": DegradeSource}

    on_incomplete: dict[str, str] | str | None = None
    unresolved: str | None = None
    on_gaps: str | None = None
    exceptions: str | None = None
    default: str | None = None
    max_intel_age: str | int | None = None
    bundle_max_age: str | int | None = None
    warn_until_measured: tuple[str, ...] | None = None
    clock_bucket_s: int | None = None
    degrade: DegradeSource | None = None


@dataclass(frozen=True, slots=True)
class PolicySource(JsonRecord):
    NESTED: ClassVar[dict[str, type[JsonRecord]]] = {
        "defaults": DefaultsSource,
        "rules": RuleSource,
    }

    policy_schema: int
    id: str
    version: int
    scope: tuple[str, ...] = ()
    extends: tuple[str, ...] = ()
    mandatory: bool = False
    defaults: DefaultsSource | None = None
    rules: tuple[RuleSource, ...] = ()
    lists: dict[str, Any] | None = None
    disable: tuple[str, ...] = ()
    expires_at: str | None = None
    prev_sha: str | None = None

    def __post_init__(self) -> None:
        if self.policy_schema != 2:
            raise PolicyError("policy_schema: this reads policy v2 sources (policy_schema: 2)")
        Checks.text("PolicySource", "id", self.id)
        Checks.whole("PolicySource", "version", self.version, low=1)
        Checks.strings("PolicySource", "scope", self.scope)
        Checks.strings("PolicySource", "extends", self.extends)
        Checks.strings("PolicySource", "disable", self.disable)


__all__ = ["DefaultsSource", "Durations", "PolicySource", "RuleSource"]
