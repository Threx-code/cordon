"""The stages of `decide()` (design spec 5.3), each a pure step over the facts and the compiled policy.

```
  2 hard stops        known malware, revoked, kill-listed, integrity mismatch   -> BLOCK, nothing lifts them
  3 completeness      stale intelligence, expired bundle, unresolved, missing evidence, an incomplete scan,
                      content gaps, unverifiable provenance                      -> the policy's level for each
  4 rules             deny, require and allow rules in their compiled order      -> the strictest outcome that fired
  5 overrides         an active approval, or an exception, over a rule's outcome  (never over 2 or 3)
  6 quality guard     a BLOCK from content rules alone, in an ecosystem the policy marks warn-until-measured -> REVIEW
```
Nothing here keeps state between calls; a `Draft` lives for one call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from cordon_scanner.decide.decision.bounds import Bounds
from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.evidence import Approval, FindingFact
from cordon_scanner.decide.decision.facts import Facts, Matcher
from cordon_scanner.decide.decision.outcome import Reason, Relaxation, States
from cordon_scanner.decide.decision.reason_map import ReasonMap
from cordon_scanner.decide.decision.records import Instants
from cordon_scanner.decide.decision.table import CompiledPolicy, CompiledRule


@dataclass(frozen=True, slots=True)
class Fired:
    """A rule that fired: what it asks for, the reasons it gives and the findings behind them."""

    rule: CompiledRule
    state: str
    reasons: tuple[Reason, ...]
    findings: tuple[FindingFact, ...]

    @property
    def about_content(self) -> bool:
        """Whether the rule fired on findings of the scanned content (the measured-quality guard's concern)."""
        return bool(self.findings) and self.rule.tier == "deny"


@dataclass(slots=True)
class Draft:
    """What one call has decided so far."""

    state: str = States.ALLOW
    reasons: list[Reason] = field(default_factory=list)
    obligations: set[str] = field(default_factory=set)
    fired: list[Fired] = field(default_factory=list)
    stopped: bool = False  # a hard stop: nothing after it runs
    relaxations: set[Relaxation] = field(
        default_factory=set
    )  # fail-closed defaults the policy relaxed and the call used

    def raise_to(self, state: str) -> None:
        self.state = States.stricter(self.state, state)


class HardStops:
    @staticmethod
    def check(facts: Facts) -> list[Reason]:
        evidence = facts.evidence
        found: list[Reason] = []
        for match in evidence.known_malware():
            found.append(
                Reason("R100", f"known malware for this digest: {match.id} ({match.source})")
            )
        if evidence.revoked:
            found.append(Reason("R101", "the artifact was revoked"))
        if evidence.integrity_ok is False:
            found.append(Reason("R102", "the digest is not what the registry or the lock claims"))
        if evidence.kill_listed:
            found.append(Reason("R103", "the subject is on the tenant's kill list"))
        return found


class Completeness:
    """Step 3: what is missing, stale or unreadable, at the level the policy sets for it."""

    LEVEL_STATE: ClassVar[dict[str, str]] = {
        "warn": States.ALLOW,
        "review": States.REVIEW,
        "block": States.BLOCK,
    }

    @classmethod
    def check(cls, facts: Facts, policy: CompiledPolicy) -> list[tuple[str, Reason]]:
        """(level, reason) for each shortfall, in a fixed order."""
        context, evidence, defaults = facts.context, facts.evidence, policy.defaults
        incomplete = defaults.incomplete_for(context.environment)
        found: list[tuple[str, Reason]] = []
        expired = policy.expires_at is not None and Instants.parse(policy.expires_at) <= facts.clock
        if expired or cls._over(context.bundle_age_s, defaults.bundle_max_age_s):
            found.append((incomplete, Reason("R202", "the policy bundle has expired")))
        if cls._over(context.intel_age_s, defaults.max_intel_age_s):
            found.append(
                (incomplete, Reason("R201", "the intelligence is older than the policy allows"))
            )
        if evidence.unresolved:
            found.append(
                (
                    defaults.unresolved,
                    Reason("R203", "the subject or its version could not be resolved"),
                )
            )
        for name in sorted(evidence.required_missing):
            found.append((incomplete, Reason("R200", f"required evidence is missing: {name}")))
        if not evidence.complete:
            found.append((incomplete, Reason("R204", "the scan did not complete")))
        for gap in sorted(evidence.gaps, key=lambda item: (item.rule_id, item.path)):
            where = f" at {Bounds.path(gap.path)}" if gap.path else ""
            found.append(
                (
                    defaults.on_gaps,
                    Reason(
                        "R204",
                        f"part of the content was not examined ({gap.rule_id}{where})",
                        rule_id=gap.rule_id,
                        path=gap.path or None,
                    ),
                )
            )
        provenance = evidence.provenance
        if provenance is not None and not provenance.verified and cls.reads_provenance(policy):
            found.append(
                (incomplete, Reason("R205", "provenance is present but cannot be verified"))
            )
        return found

    @staticmethod
    def setting_of(reason: Reason) -> str:
        """The policy default that gave a shortfall its level: `unresolved` for R203, `on_gaps` for an unexamined
        part of the content, `on_incomplete` for everything else."""
        if reason.code == "R203":
            return "unresolved"
        if reason.code == "R204" and reason.rule_id is not None:
            return "on_gaps"
        return "on_incomplete"

    @staticmethod
    def _over(age: int | None, limit: int | None) -> bool:
        return age is not None and limit is not None and age > limit

    PROVENANCE_FIELDS: ClassVar[tuple[str, ...]] = (
        "provenance.slsa_level",
        "signature.signer",
        "publisher.age_days",
    )

    @classmethod
    def reads_provenance(cls, policy: CompiledPolicy) -> bool:
        """Whether any rule of the policy reads a fact that comes from verified provenance."""
        return any(
            item.field in cls.PROVENANCE_FIELDS
            for rule in policy.rules
            for item in (*rule.applies_to, *rule.when, *rule.require)
        )


class RuleStage:
    """Step 4."""

    @classmethod
    def run(cls, facts: Facts, policy: CompiledPolicy) -> list[Fired]:
        fired: list[Fired] = []
        for rule in policy.rules:
            if not Matcher.evaluate(rule.applies_to, facts).matched:
                continue
            when = Matcher.evaluate(rule.when, facts)
            if not when.matched:
                continue
            if rule.require and Matcher.evaluate(rule.require, facts).matched:
                continue  # the requirement is met
            findings = tuple(sorted(when.findings, key=FindingFact.sort_key))
            fired.append(
                Fired(
                    rule,
                    PolicyCompiler.states_of(rule.then),
                    tuple(cls._reasons(rule, findings)),
                    findings,
                )
            )
        return fired

    @classmethod
    def _reasons(cls, rule: CompiledRule, findings: tuple[FindingFact, ...]) -> list[Reason]:
        if findings:
            fallback = cls._code_of(findings)
            return [
                Reason(
                    rule.reason or ReasonMap.of(item.rule_id) or fallback,
                    f"policy rule {rule.id}: {item.rule_id} ({item.severity}, {item.confidence})",
                    rule_id=item.rule_id,
                    path=item.path or None,
                    line=item.line,
                    evidence_hash=item.evidence_hash,
                )
                for item in findings
            ]
        code = rule.reason or ("R900" if rule.tier == "allow" else "R700")
        return [Reason(code, f"policy rule {rule.id}")]

    @staticmethod
    def _code_of(findings: tuple[FindingFact, ...]) -> str:
        categories = {item.category for item in findings}
        if "malicious" in categories:
            return "R400"
        return "R404" if categories == {"vulnerable"} else "R401"


class Overrides:
    """Step 5: approvals and exceptions over what rules asked for. Only deny and require outcomes can be lifted."""

    @classmethod
    def apply(
        cls, facts: Facts, fired: list[Fired], permitted: str = "allow"
    ) -> tuple[list[Fired], list[Reason], str | None]:
        """(the rules that still stand, the reasons the overrides add, the state an override lifts the
        outcome to, or `None` when no override applies or a blocking rule still stands)."""
        blocking = [item for item in fired if cls.asks_for_more(item)]
        if not blocking:
            return fired, [], None
        approval = cls._approval(facts)
        names = ", ".join(sorted(item.rule.id for item in blocking))
        if approval is not None:
            conditions = approval.kind == "approve_with_conditions" or bool(approval.conditions)
            added = [Reason("R901", f"approved for this digest by {approval.id} (covers: {names})")]
            if conditions:
                added.append(
                    Reason(
                        "R703", "allowed with conditions: " + Bounds.conditions(approval.conditions)
                    )
                )
            kept = [item for item in fired if item not in blocking]
            return kept, added, States.ALLOW_WITH_CONDITIONS if conditions else States.ALLOW
        standing: list[Fired] = []
        added = cls._expired(facts)
        lifted: list[str] = []
        for item in fired:
            lowered = cls._exception(facts, item, permitted) if item in blocking else None
            if lowered is None:
                standing.append(item)
                continue
            added.append(Reason("R702", f"exception {lowered[0].id} covers rule {item.rule.id}"))
            if lowered[1] in (States.ALLOW, States.ALLOW_WITH_CONDITIONS):
                lifted.append(lowered[1])
            else:
                standing.append(Fired(item.rule, lowered[1], item.reasons, item.findings))
        if any(cls.asks_for_more(item) for item in standing) or not lifted:
            return standing, added, None
        return (
            standing,
            added,
            States.ALLOW_WITH_CONDITIONS
            if States.ALLOW_WITH_CONDITIONS in lifted
            else States.ALLOW,
        )

    @staticmethod
    def asks_for_more(item: Fired) -> bool:
        return item.rule.tier != "allow" and item.state != States.ALLOW

    @staticmethod
    def _approval(facts: Facts) -> Approval | None:
        for item in sorted(facts.evidence.approvals, key=lambda entry: entry.id):
            if (
                item.kind != "exception"
                and item.active(facts.clock)
                and item.covers(facts.artifact.digest, facts.context.scope_path)
            ):
                return item
        return None

    @staticmethod
    def _expired(facts: Facts) -> list[Reason]:
        """R701: an approval that speaks for this digest in this scope ran out (it was not revoked), and a rule still asks for more.
        It changes nothing in the outcome: it says why the approval that would have lifted it does not."""
        return [
            Reason("R701", f"approval {item.id} expired at {item.expires_at}")
            for item in sorted(facts.evidence.approvals, key=lambda entry: entry.id)
            if item.kind != "exception"
            and not item.revoked
            and not item.active(facts.clock)
            and item.covers(facts.artifact.digest, facts.context.scope_path)
        ]

    @staticmethod
    def _exception(facts: Facts, item: Fired, permitted: str) -> tuple[Approval, str] | None:
        """The exception that covers this rule's outcome, and the state it gives: the outcome the exception
        names (ALLOW when it names none), no more than the policy permits (`defaults.exceptions`); an ALLOW
        with conditions is ALLOW_WITH_CONDITIONS. A hard stop never reaches here."""
        if permitted == "none":
            return None
        codes = {reason.code for reason in item.reasons}
        for entry in sorted(facts.evidence.approvals, key=lambda each: each.id):
            if entry.kind != "exception" or not entry.active(facts.clock):
                continue
            if not entry.covers(facts.artifact.digest, facts.context.scope_path):
                continue
            if entry.rule_ids is not None and item.rule.id not in entry.rule_ids:
                continue
            if entry.reason_codes is not None and not codes & set(entry.reason_codes):
                continue
            named = entry.outcome or "ALLOW"
            if named == "ALLOW" and permitted == "allow":
                return entry, States.ALLOW_WITH_CONDITIONS if entry.conditions else States.ALLOW
            return entry, States.REVIEW
        return None


class QualityGuard:
    """Step 6 (invariant I10): a content rule in an ecosystem not yet measured reviews, it does not block."""

    ALIASES: ClassVar[dict[str, str]] = {"agent_skill": "skills", "mcp_server": "mcp"}

    @classmethod
    def applies(cls, facts: Facts, policy: CompiledPolicy, draft: Draft, other_block: bool) -> bool:
        if draft.state != States.BLOCK or other_block:
            return False
        names = {facts.artifact.ecosystem, cls.ALIASES.get(facts.artifact.kind)} - {None}
        return bool(names & set(policy.defaults.warn_until_measured))


__all__ = ["Completeness", "Draft", "Fired", "HardStops", "Overrides", "QualityGuard", "RuleStage"]
