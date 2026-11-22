"""Where every enforcement point asks (invariant I1, row BP-0-2).

The CLI, the IDE extension, an agent's hook, the package firewall, a CI gate, a deploy admission check and an inventory
sweep each have to answer one question about one artifact: may it come in here. They all ask `PointRuntime.ask`, which names
the point the question comes from and hands everything else to `Decider.decide`, the one pure decision function the cloud
service shares. No point keeps a threshold, a severity comparison or a "block this" list of its own: a point that wants a
different answer than another point's for the same artifact in the same context says so in the POLICY (a rule that reads
`context.point`), never in code.

What a point may differ in is therefore exactly what a rule reads. `PointRuntime.content` is what a decision says apart from
where it was asked: the state, the reason codes, the obligations and the explanation. For the same artifact, evidence,
policy, clock and context, it is equal at every point whose policy has no rule that reads `context.point`
(`tests/unit/decide/decision/test_points_matrix.py` asks 1,000 cases at all seven points).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.decide.decision.decider import Decider
from cordon_scanner.decide.decision.evidence import Context

if TYPE_CHECKING:
    from datetime import datetime

    from cordon_scanner.decide.decision.evidence import ArtifactRef, EvidenceSet
    from cordon_scanner.decide.decision.outcome import Decision
    from cordon_scanner.decide.decision.table import CompiledPolicy


class PointRuntime:
    """The single entry the enforcement points ask through."""

    POINTS: ClassVar[tuple[str, ...]] = Context.POINTS

    @classmethod
    def ask(
        cls,
        point: str,
        artifact: ArtifactRef,
        evidence: EvidenceSet,
        policy: CompiledPolicy,
        clock: datetime,
        *,
        environment: str,
        scope_path: tuple[str, ...] = (),
        actor: str = "human",
        relation: str = "direct",
        online: bool = True,
        bundle_age_s: int | None = None,
        intel_age_s: int | None = None,
    ) -> Decision:
        """The decision for `artifact` as asked by `point` (one of `POINTS`; any other is a `DecisionError`)."""
        context = Context(
            point=point,
            environment=environment,
            scope_path=scope_path,
            actor=actor,
            relation=relation,
            online=online,
            bundle_age_s=bundle_age_s,
            intel_age_s=intel_age_s,
        )
        return Decider.decide(artifact, context, policy, evidence, clock)

    @staticmethod
    def content(decision: Decision) -> dict[str, Any]:
        """What the decision says apart from where it was asked: equal at every point unless a rule reads the point."""
        document = decision.to_json()
        for name in ("context", "inputs_digest", "clock_bucket"):
            document.pop(name, None)
        return document


__all__ = ["PointRuntime"]
