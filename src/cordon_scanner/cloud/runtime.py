"""`cordon-runtime`: one stdlib library every execution point calls (spec 8.3).

```
  resolve(input) ---> ArtifactRef
  evidence.gather:  1 the local intelligence snapshot       (always; a known malware match ends the gathering: decide() blocks it)
                    2 a cloud decision for this digest      (when online; reused when it was made under the policy held here)
                    3 a scan of the bytes                   (when there is no cloud decision; its evidence is kept by digest)
                    4 provenance verification               (when a rule of the policy reads it)
  decide()  -> Decision        (`LocalRuntime.answer`: kept decisions first, then the decision function)
  act       -> the point's own adapter (print, exit code, deny, 403)
  cache.store, outbox.append   (the local store: what was decided is kept and queued for the control plane)
```

Every outside thing is an adapter handed in, so the same library runs in the CLI, a hook, the firewall and a test with nothing but the
standard library: a resolver per subject kind, the four evidence sources, and the act. An adapter that fails is a source that did not
answer: the gathering falls through to the next source and what is missing is named in the evidence (`required_missing`), so
`decide()` treats it as a shortfall at the level the policy sets, never as "nothing found".
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, NamedTuple

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.decision.evidence import (
    ArtifactRef,
    EvidenceSet,
    FindingFact,
    GapFact,
    IntelMatch,
    Provenance,
)
from cordon_scanner.decide.decision.pipeline import Completeness
from cordon_scanner.decide.resolve.resolution import Resolution

if TYPE_CHECKING:
    from datetime import datetime

    from cordon_scanner.cloud.local_runtime import LocalRuntime
    from cordon_scanner.decide.decision.outcome import Decision
    from cordon_scanner.decide.decision.table import CompiledPolicy


@dataclass(frozen=True, slots=True)
class ScanEvidence:
    """What a scan of the artifact's bytes found: the findings, the parts it could not read, and whether it finished."""

    findings: tuple[FindingFact, ...] = ()
    gaps: tuple[GapFact, ...] = ()
    complete: bool = True

    def to_json(self) -> dict[str, Any]:
        return {
            "findings": [item.to_json() for item in self.findings],
            "gaps": [item.to_json() for item in self.gaps],
            "complete": self.complete,
        }

    @classmethod
    def from_json(cls, document: Mapping[str, Any]) -> ScanEvidence:
        return cls(
            findings=tuple(FindingFact.from_json(item) for item in document.get("findings", [])),
            gaps=tuple(GapFact.from_json(item) for item in document.get("gaps", [])),
            complete=bool(document.get("complete", True)),
        )


@dataclass(frozen=True, slots=True)
class Sources:
    """The four places evidence comes from, each optional. An absent source is a source that is not there."""

    intel: Callable[[ArtifactRef], tuple[IntelMatch, ...]] | None = None
    cloud: Callable[[ArtifactRef], Decision | None] | None = None
    scan: Callable[[ArtifactRef], ScanEvidence | None] | None = None
    provenance: Callable[[ArtifactRef], Provenance | None] | None = None
    #: Whether the signed revocation list names this artifact. Asked before anything else, so a kept or reused ALLOW never stands in for a revoked digest.
    revoked: Callable[[ArtifactRef], bool] | None = None
    #: What identifies the rules a scan ran with, so evidence kept for a digest is not reused after the rules change.
    rules_version: str = "rules-unversioned"


class Gathered(NamedTuple):
    """What the gathering produced: the evidence, the sources that were asked in order (`ran`), and a reusable cloud decision."""

    evidence: EvidenceSet
    ran: tuple[str, ...]
    cloud_decision: Decision | None


class Outcome(NamedTuple):
    """One run of the runtime: the decision, where it came from, how the name resolved, and which sources were asked."""

    decision: Decision
    source: str
    resolution: Resolution
    ran: tuple[str, ...]


class Gatherer:
    """`evidence.gather`, in the order of the spec and with the fall-through each source has."""

    def __init__(self, sources: Sources, local: LocalRuntime) -> None:
        self._sources, self._local = sources, local

    def gather(self, artifact: ArtifactRef, *, online: bool) -> Gathered:
        sources, ran = self._sources, []
        evidence = EvidenceSet()
        if sources.revoked is not None:
            ran.append("revoked")
            answer = self._try(sources.revoked, artifact)
            if answer:
                return Gathered(replace(evidence, revoked=True), (*ran, "stopped:revoked"), None)
            if answer is None:
                evidence = self._missing(evidence, "revocation")
        if sources.intel is not None:
            ran.append("intel")
            evidence = replace(evidence, intel=self._try(sources.intel, artifact) or ())
            if evidence.known_malware():
                return Gathered(evidence, (*ran, "stopped:known_malware"), None)
        policy = self._local.policy
        if online and sources.cloud is not None:
            ran.append("cloud")
            reused = self._try(sources.cloud, artifact)
            if reused is not None and reused.policy.sha256 == policy.sha256:
                return Gathered(evidence, tuple(ran), reused)
        evidence = self._scanned(artifact, evidence, ran)
        if Completeness.reads_provenance(policy):
            evidence = self._verified(artifact, evidence, ran)
        return Gathered(evidence, tuple(ran), None)

    def _scanned(self, artifact: ArtifactRef, evidence: EvidenceSet, ran: list[str]) -> EvidenceSet:
        sources = self._sources
        if sources.scan is None or artifact.digest is None:
            return self._missing(evidence, "scan")
        key = ArtifactDigests.of_bytes(f"{artifact.digest}\0{sources.rules_version}".encode())
        kept = self._local.kept_scan(key)
        if kept is not None:
            found: ScanEvidence | None = ScanEvidence.from_json(kept)
            ran.append("scan:kept")
        else:
            ran.append("scan")
            found = self._try(sources.scan, artifact)
            if found is not None:
                self._local.keep_scan(key, found.to_json())
        if found is None:
            return self._missing(evidence, "scan")
        return replace(evidence, findings=found.findings, gaps=found.gaps, complete=found.complete)

    def _verified(
        self, artifact: ArtifactRef, evidence: EvidenceSet, ran: list[str]
    ) -> EvidenceSet:
        if self._sources.provenance is None:
            return self._missing(evidence, "provenance")
        ran.append("provenance")
        found = self._try(self._sources.provenance, artifact)
        return (
            self._missing(evidence, "provenance")
            if found is None
            else replace(evidence, provenance=found)
        )

    @staticmethod
    def _missing(evidence: EvidenceSet, name: str) -> EvidenceSet:
        return replace(evidence, required_missing=tuple(sorted({*evidence.required_missing, name})))

    @staticmethod
    def _try(source: Callable[[ArtifactRef], Any], artifact: ArtifactRef) -> Any:
        """The source's answer, or None when it could not answer (any failure is a source that is not there)."""
        try:
            return source(artifact)
        except Exception:  # noqa: BLE001 -- an adapter that fails has not answered
            return None


class CordonRuntime:
    """The runtime of spec 8.3 over a `LocalRuntime`: resolve, gather, decide, act."""

    def __init__(
        self,
        local: LocalRuntime,
        *,
        resolvers: Mapping[str, Callable[[str], Resolution]],
        sources: Sources,
        act: Callable[[Decision, str], None] | None = None,
    ) -> None:
        self._local, self._resolvers, self._act = local, dict(resolvers), act
        self._gatherer = Gatherer(sources, local)

    @property
    def policy(self) -> CompiledPolicy:
        return self._local.policy

    def run(
        self,
        kind: str,
        reference: str,
        point: str,
        clock: datetime,
        *,
        environment: str,
        scope_path: tuple[str, ...] = (),
        relation: str = "direct",
        online: bool = False,
        actor: str = "human",
    ) -> Outcome:
        resolver = self._resolvers.get(kind)
        resolution = (
            resolver(reference)
            if resolver is not None
            else Resolution.failed(kind, Resolution.stand_in(kind, reference), "unparseable")
        )
        artifact = resolution.artifact()
        gathered = self._gatherer.gather(artifact, online=online and resolution.resolved)
        if gathered.cloud_decision is not None:
            decision, source = gathered.cloud_decision, "cloud"
        else:
            answer = self._local.answer(
                point,
                artifact,
                resolution.evidence(gathered.evidence),
                clock,
                environment=environment,
                scope_path=scope_path,
                relation=relation,
                online=online,
                actor=actor,
            )
            decision, source = answer.decision, answer.source
        if self._act is not None:
            self._act(decision, point)
        return Outcome(decision, source, resolution, gathered.ran)


__all__ = ["CordonRuntime", "Gathered", "Gatherer", "Outcome", "ScanEvidence", "Sources"]
