"""The build gate decides every locked artifact; the release gate refuses a release below the policy's provenance level."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.build_gate import BuildGate
from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.evidence import ArtifactRef, EvidenceSet, Provenance
from cordon_scanner.decide.decision.policy_source import PolicySource

CLOCK = datetime(2026, 11, 24, 16, 0, tzinfo=UTC)


class Fixture:
    @staticmethod
    def policy(rules: list[dict[str, Any]], on_incomplete: str = "block"):
        return PolicyCompiler.compile(
            PolicySource.from_json(
                {
                    "policy_schema": 2,
                    "id": "acme/policy",
                    "version": 1,
                    "scope": ["acme"],
                    "rules": rules,
                    "defaults": {"default": "allow", "on_incomplete": {"*": on_incomplete}},
                }
            )
        )

    @staticmethod
    def artifact(name: str) -> ArtifactRef:
        return ArtifactRef(
            kind="package",
            subject_id=f"pkg:npm/{name}",
            digest=ArtifactDigests.of_bytes(name.encode()),
            ecosystem="npm",
            released_at="2026-06-01T00:00:00Z",
        )

    @staticmethod
    def lock() -> list[ArtifactRef]:
        return [Fixture.artifact(n) for n in ("a", "b", "c")]


LEVEL = {
    "id": "level",
    "tier": "require",
    "then": "block",
    "when": {"provenance.slsa_level": "<3"},
}


class TestTheBuildGate:
    def evidence(self, artifact: ArtifactRef) -> EvidenceSet:
        return EvidenceSet(revoked=artifact.subject_id.endswith("/b"))

    def test_every_locked_artifact_gets_a_decision_in_order(self) -> None:
        verdict = BuildGate.locked(
            Fixture.lock(), self.evidence, Fixture.policy([]), CLOCK, environment="ci"
        )
        assert [a.subject_id for a, _ in verdict.decisions] == [
            a.subject_id for a in Fixture.lock()
        ]

    def test_one_revoked_artifact_blocks_the_build(self) -> None:
        verdict = BuildGate.locked(
            Fixture.lock(), self.evidence, Fixture.policy([]), CLOCK, environment="ci"
        )
        states = [d.state for _, d in verdict.decisions]
        assert (
            states == ["ALLOW", "BLOCK", "ALLOW"]
            and verdict.state == "BLOCK"
            and not verdict.passes
        )

    def test_an_artifact_whose_evidence_cannot_be_fetched_is_decided_not_skipped(self) -> None:
        def broken(artifact: ArtifactRef) -> EvidenceSet:
            raise OSError("down")

        verdict = BuildGate.locked(
            Fixture.lock(), broken, Fixture.policy([]), CLOCK, environment="ci"
        )
        assert len(verdict.decisions) == 3 and verdict.state == "BLOCK"


class TestTheReleaseGate:
    def release(self, level: int | None, sbom: bool = True):
        provenance = None if level is None else Provenance(slsa_level=level)
        return BuildGate.release(
            Fixture.artifact("app"),
            provenance,
            Fixture.policy([LEVEL]),
            CLOCK,
            sbom=sbom,
            environment="ci",
        )

    def test_a_release_at_the_level_passes(self) -> None:
        assert self.release(3).passes

    def test_a_release_below_the_level_is_refused(self) -> None:
        verdict = self.release(2)
        assert not verdict.passes and "R500" in verdict.decisions[0][1].reason_codes

    def test_a_release_with_no_provenance_at_all_is_refused(self) -> None:
        assert not self.release(None).passes

    def test_a_release_without_an_sbom_is_not_complete(self) -> None:
        assert not self.release(3, sbom=False).passes
