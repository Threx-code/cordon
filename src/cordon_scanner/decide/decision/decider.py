"""`Decider.decide`: the one decision function (design spec 5.1). Pure: no I/O, no clock, no environment.

Every input is passed in and nothing is read from anywhere else, so the same call gives the same `Decision`
bytes in the CLI, a hook, the firewall, a gate and the cloud (invariant I3). `decide_json` is the same call
over JSON for a caller that is not Python.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime
from typing import Any

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.decision.evidence import ArtifactRef, Context, EvidenceSet
from cordon_scanner.decide.decision.facts import Facts
from cordon_scanner.decide.decision.outcome import (
    Decision,
    DecisionContext,
    Explanation,
    Reason,
    States,
)
from cordon_scanner.decide.decision.pipeline import (
    Completeness,
    Draft,
    Fired,
    HardStops,
    Overrides,
    QualityGuard,
    RuleStage,
)
from cordon_scanner.decide.decision.records import DecisionError, Instants
from cordon_scanner.decide.decision.table import CompiledPolicy


class Decider:
    @classmethod
    def decide(
        cls,
        artifact: ArtifactRef,
        context: Context,
        policy: CompiledPolicy,
        evidence: EvidenceSet,
        clock: datetime,
    ) -> Decision:
        """The decision for `artifact` in `context` under `policy`, given `evidence`, at `clock` (UTC, aware)."""
        if clock.tzinfo is None:
            raise DecisionError("clock: a time with a zone is required")
        policy.verify()
        evidence = replace(
            evidence, findings=tuple(sorted(evidence.findings, key=lambda item: item.sort_key()))
        )
        facts = Facts.of(artifact, context, evidence, clock)
        draft = Draft()
        stops = HardStops.check(facts)
        if stops:
            draft.reasons, draft.state, draft.stopped = stops, States.BLOCK, True
        else:
            cls._evaluate(facts, policy, draft)
        return cls._emit(facts, policy, draft)

    @classmethod
    def decide_json(cls, request: Mapping[str, Any]) -> dict[str, Any]:
        """`decide` over JSON: `{artifact, context, policy, evidence, clock}` in, a `decision/v1` predicate out."""
        known = {"artifact", "context", "policy", "evidence", "clock"}
        extra = sorted(set(request) - known)
        missing = sorted(known - set(request))
        if extra or missing:
            raise DecisionError(f"decide request: unexpected {extra} missing {missing}")
        decision = cls.decide(
            ArtifactRef.from_json(request["artifact"]),
            Context.from_json(request["context"]),
            CompiledPolicy.from_json(request["policy"]),
            EvidenceSet.from_json(request["evidence"]),
            Instants.parse(request["clock"]),
        )
        return decision.to_json()

    # -- steps 3 to 6 ----------------------------------------------------------------------------

    @classmethod
    def _evaluate(cls, facts: Facts, policy: CompiledPolicy, draft: Draft) -> None:
        other_block = False
        for level, reason in Completeness.check(facts, policy):
            draft.reasons.append(reason)
            draft.raise_to(Completeness.LEVEL_STATE[level])
            other_block = other_block or level == "block"
        fired = RuleStage.run(facts, policy)
        standing, added, lifted = Overrides.apply(facts, fired)
        asking = [item for item in standing if Overrides.asks_for_more(item)]
        if asking:
            cls._take(draft, asking)
            other_block = other_block or any(
                item.state == States.BLOCK and not item.about_content for item in asking
            )
        elif lifted is not None:
            draft.raise_to(lifted)
            if any(item.code == "R901" for item in added):
                draft.obligations.add("O001")
        else:
            other_block = cls._allow_or_default(draft, standing, policy) or other_block
        draft.reasons.extend(added)
        if QualityGuard.applies(facts, policy, draft, other_block):
            draft.state = States.REVIEW
            draft.reasons.append(
                Reason(
                    "R300",
                    "a content rule in an ecosystem the policy marks warn-until-measured: reviewed, not blocked",
                )
            )

    @staticmethod
    def _take(draft: Draft, asking: list[Fired]) -> None:
        for item in asking:
            draft.raise_to(item.state)
            draft.reasons.extend(item.reasons)
            draft.obligations.update(item.rule.obligations)
            draft.fired.append(item)

    @staticmethod
    def _allow_or_default(draft: Draft, standing: list[Fired], policy: CompiledPolicy) -> bool:
        """No deny or require rule stands: an allow rule decides, else the policy's default. True when the
        default is a BLOCK (a block no content rule asked for)."""
        allows = [item for item in standing if item.rule.tier == "allow"]
        if allows:
            for item in allows:
                draft.raise_to(item.state)
                draft.reasons.extend(item.reasons)
                draft.obligations.update(item.rule.obligations)
            return False
        outcome = policy.defaults.default
        draft.raise_to(
            {
                "allow": States.ALLOW,
                "allow_with_conditions": States.ALLOW_WITH_CONDITIONS,
                "review": States.REVIEW,
                "block": States.BLOCK,
            }[outcome]
        )
        code = {
            "allow": "R903",
            "allow_with_conditions": "R703",
            "review": "R700",
            "block": "R700",
        }[outcome]
        draft.reasons.append(Reason(code, f"no rule matched; the policy's default is {outcome}"))
        return outcome == "block"

    # -- step 7 ----------------------------------------------------------------------------------

    @classmethod
    def _emit(cls, facts: Facts, policy: CompiledPolicy, draft: Draft) -> Decision:
        bucket = Instants.bucket(facts.clock, policy.defaults.clock_bucket_s)
        bucket_text = Instants.text(bucket)
        inputs = ArtifactDigests.canonical_json(
            {
                "artifact": facts.artifact.to_json(),
                "context": facts.context.to_json(),
                "policy": policy.sha256,
                "evidence": facts.evidence.sha256(),
                "clock_bucket": bucket_text,
            }
        )
        reasons = tuple(draft.reasons)
        first = reasons[0]
        return Decision(
            state=draft.state,
            reason_codes=tuple(sorted({item.code for item in reasons})),
            explanation=Explanation(f"{draft.state}: {first.code} {first.text}", reasons),
            obligations=tuple(sorted(draft.obligations)),
            inputs_digest=ArtifactDigests.of_bytes(inputs),
            policy=policy.ref(),
            context=DecisionContext(
                facts.context.point, facts.context.environment, facts.context.relation
            ),
            clock_bucket=bucket_text,
        )


__all__ = ["Decider"]
