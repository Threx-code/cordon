"""The part of a compiled policy that can be exported to another engine, and what cannot (row BP-6-5).

A customer who enforces in OPA or Cedar gets the policy as that engine's own language and the facts of a call as a JSON document
(`ExportFacts`); the engine answers with the state `decide()` gives. What is exported is the decision table: the hard stops, the
shortfalls of evidence and the level the policy sets for each, the rules (`applies_to`, `when`, `require`, `then`) and the default
outcome. The facts are worked out by this library's own code (`ExportFacts`), so the age of a release or whether a provenance is
verified is never re-derived in another language.

What is NOT exported, and is refused rather than approximated (`ExportUnsupported`, naming each):

* approvals and exceptions: a rule on the `approval` field, and any call whose evidence carries an approval;
* `warn_until_measured` (the quality guard of invariant I10): it needs to know which blocks a content rule asked for;
* a `glob` pattern an engine cannot express (Cedar's `like` knows only `*`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from cordon_scanner.decide.decision.predicates import Condition, Fields
from cordon_scanner.decide.decision.table import CompiledPolicy


class ExportUnsupported(ValueError):
    """The policy or the call uses something the export does not carry; the message names each."""


@dataclass(frozen=True, slots=True)
class ExportedRule:
    id: str
    tier: str
    then: str
    applies_to: tuple[Condition, ...]
    when: tuple[Condition, ...]
    require: tuple[Condition, ...]

    @property
    def asks_for_more(self) -> bool:
        """A deny or require rule: when it fires it holds the decision at its `then`, and nothing below it is consulted."""
        return self.tier != "allow"


@dataclass(frozen=True, slots=True)
class ExportTable:
    SHORTFALLS: ClassVar[tuple[str, ...]] = (
        "required_missing",
        "unresolved",
        "incomplete",
        "gaps",
        "bundle_expired",
        "intel_stale",
        "provenance_unverified",
    )
    #: The rank of each state, and of each level a shortfall may be set to (a `warn` raises nothing).
    STATE_RANK: ClassVar[dict[str, int]] = {
        "ALLOW": 0,
        "ALLOW_WITH_CONDITIONS": 1,
        "REVIEW": 2,
        "BLOCK": 3,
    }
    THEN_RANK: ClassVar[dict[str, int]] = {
        "allow": 0,
        "allow_with_conditions": 1,
        "review": 2,
        "block": 3,
    }
    LEVEL_RANK: ClassVar[dict[str, int]] = {"warn": 0, "review": 2, "block": 3}

    policy_id: str
    version: int
    sha256: str
    rules: tuple[ExportedRule, ...]
    on_incomplete: tuple[tuple[str, str], ...]
    unresolved: str
    on_gaps: str
    default: str

    @classmethod
    def of(cls, policy: CompiledPolicy) -> ExportTable:
        problems: list[str] = []
        if policy.defaults.warn_until_measured:
            problems.append("defaults.warn_until_measured (the quality guard)")
        for rule in policy.rules:
            for part, conditions in (
                ("applies_to", rule.applies_to),
                ("when", rule.when),
                ("require", rule.require),
            ):
                for item in conditions:
                    if item.field == "approval":
                        problems.append(f"rules.{rule.id}.{part}: a condition on `approval`")
        if problems:
            raise ExportUnsupported("not exportable: " + "; ".join(problems))
        return cls(
            policy_id=policy.id,
            version=policy.version,
            sha256=policy.sha256,
            rules=tuple(
                ExportedRule(
                    rule.id, rule.tier, rule.then, rule.applies_to, rule.when, rule.require
                )
                for rule in policy.rules
            ),
            on_incomplete=tuple(sorted(policy.defaults.on_incomplete.items())),
            unresolved=policy.defaults.unresolved,
            on_gaps=policy.defaults.on_gaps,
            default=policy.defaults.default,
        )

    def level_of(self, shortfall: str, environment: str) -> str:
        """The level the policy sets for a shortfall in an environment: `unresolved` and `gaps` have their own, the rest follow
        `on_incomplete`."""
        if shortfall == "unresolved":
            return self.unresolved
        if shortfall == "gaps":
            return self.on_gaps
        levels = dict(self.on_incomplete)
        return levels.get(environment, levels["*"])

    @staticmethod
    def is_finding(condition: Condition) -> bool:
        return Fields.TABLE[condition.field].is_finding


__all__ = ["ExportTable", "ExportUnsupported", "ExportedRule"]
