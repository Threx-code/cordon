"""The build gate and the release gate: every locked artifact is decided, and a release is decided on its provenance.

The build gate asks the one decision function at the `ci_gate` point about each artifact a lockfile lists, so no locked artifact
passes unasked: an artifact whose evidence cannot be had is decided with that evidence named as missing (the policy's own level
for incomplete evidence says what that means), never skipped. The release gate asks the same function about the artifact being
released with the provenance, the SBOM and the signature it carries; the policy's provenance rules (`provenance.slsa_level`,
`signature.signer`) refuse a release that is below the level the policy asks. The gates keep no threshold of their own.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import datetime

from cordon_scanner.decide.decision.evidence import ArtifactRef, EvidenceSet, Provenance
from cordon_scanner.decide.decision.outcome import Decision, States
from cordon_scanner.decide.decision.table import CompiledPolicy
from cordon_scanner.decide.points import PointRuntime


@dataclass(frozen=True, slots=True)
class GateVerdict:
    """What a gate decided: one decision per artifact asked about, in the order asked."""

    decisions: tuple[tuple[ArtifactRef, Decision], ...]

    @property
    def state(self) -> str:
        """The strictest state of any decision, ALLOW for none."""
        worst = max((States.ORDER.index(d.state) for _, d in self.decisions), default=0)
        return States.ORDER[worst]

    @property
    def passes(self) -> bool:
        return self.state in (States.ALLOW, States.ALLOW_WITH_CONDITIONS)


class BuildGate:
    """Decides every artifact of a lock, and a release."""

    POINT = "ci_gate"
    EVIDENCE_MISSING = "evidence"

    @classmethod
    def locked(
        cls,
        artifacts: Sequence[ArtifactRef],
        evidence_of: Callable[[ArtifactRef], EvidenceSet],
        policy: CompiledPolicy,
        clock: datetime,
        *,
        environment: str,
        scope_path: tuple[str, ...] = (),
    ) -> GateVerdict:
        """A decision for each locked artifact; one whose evidence cannot be fetched is decided with the evidence missing."""
        decided = []
        for artifact in artifacts:
            try:
                evidence = evidence_of(artifact)
            except Exception:  # noqa: BLE001
                evidence = EvidenceSet(complete=False, required_missing=(cls.EVIDENCE_MISSING,))
            decided.append(
                (
                    artifact,
                    PointRuntime.ask(
                        cls.POINT,
                        artifact,
                        evidence,
                        policy,
                        clock,
                        environment=environment,
                        scope_path=scope_path,
                    ),
                )
            )
        return GateVerdict(tuple(decided))

    @classmethod
    def release(
        cls,
        artifact: ArtifactRef,
        provenance: Provenance | None,
        policy: CompiledPolicy,
        clock: datetime,
        *,
        sbom: bool,
        environment: str,
        scope_path: tuple[str, ...] = (),
        evidence: EvidenceSet | None = None,
    ) -> GateVerdict:
        """The release decided on the provenance it carries; a release with no SBOM or no provenance names it as missing."""
        base = evidence or EvidenceSet()
        missing = (
            *(() if sbom else ("sbom",)),
            *(() if provenance is not None else ("provenance",)),
        )
        carried = replace(
            base,
            provenance=provenance,
            required_missing=(*base.required_missing, *missing),
            complete=base.complete and not missing,
        )
        decision = PointRuntime.ask(
            cls.POINT,
            artifact,
            carried,
            policy,
            clock,
            environment=environment,
            scope_path=scope_path,
        )
        return GateVerdict(((artifact, decision),))


__all__ = ["BuildGate", "GateVerdict"]
