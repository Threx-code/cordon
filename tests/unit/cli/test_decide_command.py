"""`decide` gives the decision function's answer: the IDE point and the CLI point agree on the 1,000-case matrix, and the gates run through it."""

from __future__ import annotations

import argparse
import io
import json
from typing import Any

from cordon_scanner.cli.commands.decision.decide import DecideCommand
from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.policy_source import PolicySource
from cordon_scanner.decide.points import PointRuntime
from unit.decide.decision.test_points_matrix import Matrix


class Ask:
    @staticmethod
    def question(index: int) -> dict[str, Any]:
        policy_i, evidence_i, artifact_i, context_i, clock_i = Matrix.inputs()["cases"][index]
        inputs = Matrix.inputs()
        return {
            "policy": Matrix.policies()[policy_i].to_json(),
            "artifact": inputs["artifacts"][artifact_i],
            "evidence": inputs["evidence"][evidence_i],
            "clock": inputs["clocks"][clock_i],
            "context": {k: v for k, v in inputs["contexts"][context_i].items() if k != "point"},
        }

    @staticmethod
    def run(question: dict[str, Any], point: str, **flags: bool) -> tuple[int, dict[str, Any]]:
        out = io.StringIO()
        args = argparse.Namespace(**{"point": point, "lock": False, "release": False, **flags})
        code = DecideCommand.run(args, io.StringIO(json.dumps(question)), out)
        return code, json.loads(out.getvalue())


class TestTheIdePointAndTheCliPointAgree:
    def test_on_the_thousand_case_matrix_through_the_command(self) -> None:
        differ = []
        for index in Matrix.indexes():
            question = Ask.question(index)
            _, ide = Ask.run(question, "ide")
            _, cli = Ask.run(question, "cli")
            _, direct = Ask.run(question, "ide")
            expected = Matrix.ask(index, "ide").to_json()
            if direct != expected:
                differ.append(index)
                continue
            for document in (ide, cli):
                for name in ("context", "inputs_digest", "clock_bucket"):
                    document.pop(name, None)
            if ide != cli:
                differ.append(index)
        assert len(Matrix.indexes()) == 1000 and differ == []

    def test_the_command_is_the_function_every_point_asks(self) -> None:
        question = Ask.question(0)
        _, document = Ask.run(question, "ci_gate")
        assert document == Matrix.ask(0, "ci_gate").to_json()
        assert PointRuntime.POINTS.count("ide") == 1


class GateFixture:
    @staticmethod
    def policy() -> dict[str, Any]:
        source = {
            "policy_schema": 2,
            "id": "acme/policy",
            "version": 1,
            "scope": ["acme"],
            "rules": [
                {
                    "id": "level",
                    "tier": "require",
                    "then": "block",
                    "when": {"provenance.slsa_level": "<3"},
                }
            ],
            "defaults": {"default": "allow", "on_incomplete": {"*": "block"}},
        }
        return PolicyCompiler.compile(PolicySource.from_json(source)).to_json()

    @staticmethod
    def artifact(name: str) -> dict[str, Any]:
        return {
            "kind": "package",
            "subject_id": f"pkg:npm/{name}",
            "digest": ArtifactDigests.of_bytes(name.encode()),
            "ecosystem": "npm",
            "released_at": "2026-06-01T00:00:00Z",
        }

    @classmethod
    def question(cls, **more: Any) -> dict[str, Any]:
        return {
            "policy": cls.policy(),
            "clock": "2026-11-24T16:00:00Z",
            "context": {"environment": "ci"},
            **more,
        }


class TestTheGatesThroughTheCommand:
    def test_every_artifact_of_the_lock_is_decided_and_a_revoked_one_blocks(self) -> None:
        names = ("a", "b", "c")
        evidence = {GateFixture.artifact(n)["subject_id"]: {"revoked": n == "b"} for n in names}
        document = GateFixture.question(
            artifacts=[GateFixture.artifact(n) for n in names], evidence=evidence
        )
        code, out = Ask.run(document, "ci_gate", lock=True)
        assert [d["subject"] for d in out["decisions"]] == [f"pkg:npm/{n}" for n in names]
        assert out["state"] == "BLOCK" and code == 1

    def test_a_lock_artifact_with_no_evidence_is_decided_not_skipped(self) -> None:
        document = GateFixture.question(artifacts=[GateFixture.artifact("a")], evidence={})
        code, out = Ask.run(document, "ci_gate", lock=True)
        assert len(out["decisions"]) == 1 and code == 1

    def test_a_release_at_the_level_passes_and_below_it_does_not(self) -> None:
        at = GateFixture.question(
            artifact=GateFixture.artifact("app"), provenance={"slsa_level": 3}, sbom=True
        )
        below = GateFixture.question(
            artifact=GateFixture.artifact("app"), provenance={"slsa_level": 2}, sbom=True
        )
        assert Ask.run(at, "ci_gate", release=True)[0] == 0
        assert Ask.run(below, "ci_gate", release=True)[0] == 1

    def test_a_release_with_no_provenance_or_no_sbom_does_not_pass(self) -> None:
        none = GateFixture.question(artifact=GateFixture.artifact("app"), sbom=True)
        no_sbom = GateFixture.question(
            artifact=GateFixture.artifact("app"), provenance={"slsa_level": 3}
        )
        assert Ask.run(none, "ci_gate", release=True)[0] == 1
        assert Ask.run(no_sbom, "ci_gate", release=True)[0] == 1
