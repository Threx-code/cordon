"""`decide` gives the decision function's answer: the IDE point and the CLI point agree on the 1,000-case matrix, and the gates run through it."""

from __future__ import annotations

import argparse
import io
import json
import subprocess
from pathlib import Path
from typing import Any

from cordon_scanner.cli.commands.decision.decide import DecideCommand
from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.policy_source import PolicySource
from cordon_scanner.decide.points import PointRuntime
from support import ROOT
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


class TestTheAdmissionAnswer:
    DIGEST = "sha256:" + "ab" * 32

    @classmethod
    def review(cls, spec: dict[str, Any], kind: str = "Pod") -> dict[str, Any]:
        return {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {"uid": "u-1", "object": {"kind": kind, "spec": spec}},
        }

    @classmethod
    def ask(cls, review: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
        document = GateFixture.question(review=review, evidence=evidence)
        code, out = Ask.run(document, "deploy_admission", admission=True)
        assert code == 0
        response: dict[str, Any] = out["response"]
        return response

    def test_a_pod_whose_images_pass_is_allowed(self) -> None:
        pod = self.review({"containers": [{"image": "registry.example/app:1"}]})
        response = self.ask(pod, {"registry.example/app:1": {}})
        assert response["allowed"] is True and response["uid"] == "u-1"

    def test_one_refused_image_refuses_the_pod_and_names_it(self) -> None:
        pod = self.review(
            {
                "initContainers": [{"image": "registry.example/init:1"}],
                "containers": [{"image": "registry.example/app:1"}],
            }
        )
        evidence = {"registry.example/init:1": {}, "registry.example/app:1": {"revoked": True}}
        response = self.ask(pod, evidence)
        assert response["allowed"] is False
        assert "registry.example/app:1" in response["status"]["message"]
        assert "init:1" not in response["status"]["message"]

    def test_the_images_of_a_deployment_template_are_decided_too(self) -> None:
        deployment = self.review(
            {"template": {"spec": {"containers": [{"image": f"r.example/app@{self.DIGEST}"}]}}},
            "Deployment",
        )
        assert DecideCommand.images(deployment["request"]["object"]) == [
            f"r.example/app@{self.DIGEST}"
        ]
        response = self.ask(deployment, {f"r.example/app@{self.DIGEST}": {"revoked": True}})
        assert response["allowed"] is False

    def test_an_image_with_no_evidence_is_not_let_through(self) -> None:
        pod = self.review({"containers": [{"image": "registry.example/app:1"}]})
        assert self.ask(pod, {})["allowed"] is False


class TestTheFourGatesAreInTheRepository:
    GATES = (
        "action/action.yml",
        "ci/gitlab/cordon.gitlab-ci.yml",
        "ci/jenkins/Jenkinsfile.snippet",
    )

    def test_the_github_action_the_gitlab_component_and_the_jenkins_step_run_the_scanner(
        self,
    ) -> None:
        for name in self.GATES:
            text = (ROOT / name).read_text(encoding="utf-8")
            assert "cordon-scanner" in text, name

    def test_the_fourth_gate_is_the_admission_answer_of_the_same_command(self) -> None:
        assert any(action.dest == "admission" for action in self.options())

    @staticmethod
    def options() -> list[argparse.Action]:
        parser = argparse.ArgumentParser()
        DecideCommand.add_parser(parser.add_subparsers())
        sub = parser._subparsers._group_actions[0].choices["decide"]  # type: ignore[union-attr,attr-defined]
        return list(sub._actions)


class Wrapper:
    """Runs the shell a wrapper hands the scanner in decide mode, with a stand-in scanner that records what it was given."""

    @staticmethod
    def block(path: str, marker: str, start: str) -> str:
        """The lines of a YAML block scalar that begin after `marker` and the line `start`, dedented."""
        lines = (ROOT / path).read_text(encoding="utf-8").splitlines()
        at = next(i for i, line in enumerate(lines) if marker in line)
        begin = next(i for i in range(at, len(lines)) if lines[i].strip() == start) + 1
        body: list[str] = []
        indent = len(lines[begin]) - len(lines[begin].lstrip())
        for line in lines[begin:]:
            if line.strip() and len(line) - len(line.lstrip()) < indent:
                break
            body.append(line[indent:] if line.strip() else "")
        return "\n".join(body)

    @staticmethod
    def run(
        tmp_path: Path, script: str, env: dict[str, str], exit_code: int = 0
    ) -> tuple[int, str, str]:
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        stand_in = bin_dir / "cordon-scanner"
        stand_in.write_text(
            f'#!/bin/sh\necho "$@" > "{tmp_path}/args"\ncat > "{tmp_path}/stdin"\necho \'{{"state":"ALLOW"}}\'\nexit {exit_code}\n',
            encoding="utf-8",
        )
        stand_in.chmod(0o755)
        (tmp_path / "question.json").write_text('{"q": 1}', encoding="utf-8")
        done = subprocess.run(
            ["sh", "-c", script],
            cwd=tmp_path,
            env={"PATH": f"{bin_dir}:/usr/bin:/bin", **env},
            capture_output=True,
            text=True,
            check=False,
        )
        args = (
            (tmp_path / "args").read_text(encoding="utf-8").strip()
            if (tmp_path / "args").exists()
            else ""
        )
        return (
            done.returncode,
            args,
            (tmp_path / "stdin").read_text(encoding="utf-8")
            if (tmp_path / "stdin").exists()
            else "",
        )


class TestEachWrapperHasADecideMode:
    DECIDE = "decide --lock --point ci_gate"

    def test_scan_stays_the_default_everywhere(self) -> None:
        action = (ROOT / "action/action.yml").read_text(encoding="utf-8")
        assert "mode:\n    description: >" in action and 'default: "scan"' in action
        assert 'CORDON_MODE: "scan"' in (ROOT / "ci/gitlab/cordon.gitlab-ci.yml").read_text(
            encoding="utf-8"
        )
        assert "env.CORDON_MODE ?: 'scan'" in (ROOT / "ci/jenkins/Jenkinsfile.snippet").read_text(
            encoding="utf-8"
        )

    def test_the_github_action_in_decide_mode_hands_the_question_to_the_scanner(
        self, tmp_path: Path
    ) -> None:
        script = Wrapper.block("action/action.yml", "- name: Decide", "run: |")
        code, args, stdin = Wrapper.run(
            tmp_path, script, {"CORDON_DECIDE_QUESTION": "question.json"}
        )
        assert (code, args, stdin) == (0, self.DECIDE, '{"q": 1}')

    def test_the_github_action_fails_the_job_when_the_gate_does_not_pass(
        self, tmp_path: Path
    ) -> None:
        script = Wrapper.block("action/action.yml", "- name: Decide", "run: |")
        assert (
            Wrapper.run(tmp_path, script, {"CORDON_DECIDE_QUESTION": "question.json"}, exit_code=1)[
                0
            ]
            == 1
        )

    def test_the_github_action_without_a_question_is_a_configuration_error(
        self, tmp_path: Path
    ) -> None:
        script = Wrapper.block("action/action.yml", "- name: Decide", "run: |")
        assert Wrapper.run(tmp_path, script, {"CORDON_DECIDE_QUESTION": ""})[0] == 3

    def test_the_gitlab_component_in_decide_mode_does_the_same(self, tmp_path: Path) -> None:
        script = Wrapper.block("ci/gitlab/cordon.gitlab-ci.yml", "cordon:scan:", "- |")
        env = {"CORDON_MODE": "decide", "CORDON_DECIDE_QUESTION": "question.json"}
        code, args, stdin = Wrapper.run(tmp_path, script, env)
        assert (code, args, stdin) == (0, self.DECIDE, '{"q": 1}')

    def test_the_gitlab_component_in_scan_mode_runs_the_scan_as_before(
        self, tmp_path: Path
    ) -> None:
        script = Wrapper.block("ci/gitlab/cordon.gitlab-ci.yml", "cordon:scan:", "- |")
        env = {
            "CORDON_MODE": "scan",
            "CORDON_SEVERITY": "low",
            "CORDON_FAIL_ON": "high",
            "CORDON_UPLOAD": "false",
        }
        _, args, _ = Wrapper.run(tmp_path, script, env)
        assert args.startswith("scan . --severity low --fail-on high")

    def test_the_jenkins_step_in_decide_mode_runs_the_same_command(self, tmp_path: Path) -> None:
        text = (ROOT / "ci/jenkins/Jenkinsfile.snippet").read_text(encoding="utf-8")
        script = text.split("script: decide ? '''", 1)[1].split("'''", 1)[0].replace("\\\n", " ")
        code, args, stdin = Wrapper.run(
            tmp_path, script, {"CORDON_DECIDE_QUESTION": "question.json"}
        )
        assert (code, args, stdin) == (0, self.DECIDE, '{"q": 1}')
