"""Row BP-6-5, the real engines: each export evaluated by its own engine over the 100 recorded cases gives the state `decide()` gave.

OPA (`opa eval`) and the Cedar CLI (`cedar authorize`) are run as processes. They are not part of the package or its dependencies and
are not in this repository: the test runs only where `CORDON_OPA` and `CORDON_CEDAR` name an engine binary (the container test that
mounts the engines read-only, no network), and is skipped elsewhere.

For each case the facts document goes to the engine, and the engine's state and the ids of the rules that decided it must equal both
`decide()`'s state (recorded) and the Python reference's. Each engine also has a control: the same export with one rule taken out must
be caught, so a pass is not a test that cannot fail.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
from test_exports import Recorded

from cordon_scanner.decide.export.cedar import CedarExporter
from cordon_scanner.decide.export.reference import ExportReference
from cordon_scanner.decide.export.rego import RegoExporter
from cordon_scanner.decide.export.table import ExportTable
from kits.export_cases import ExportCases

OPA = os.environ.get("CORDON_OPA", "")
CEDAR = os.environ.get("CORDON_CEDAR", "")


class Engines:
    @staticmethod
    def run(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)

    @classmethod
    def opa(cls, rego: Path, facts_file: Path) -> dict[str, Any]:
        done = cls.run(
            [
                OPA,
                "eval",
                "-f",
                "json",
                "-d",
                str(rego),
                "-i",
                str(facts_file),
                "data.cordon.export.decision",
            ]
        )
        assert done.returncode == 0, done.stderr[-600:]
        value: dict[str, Any] = json.loads(done.stdout)["result"][0]["expressions"][0]["value"]
        return value

    @classmethod
    def cedar(
        cls, policies: Path, entities: Path, scratch: Path, action: str, context: dict[str, Any]
    ) -> bool:
        context_file = scratch / "context.json"
        context_file.write_text(json.dumps(context), encoding="utf-8")
        done = cls.run(
            [
                CEDAR,
                "authorize",
                "--policies",
                str(policies),
                "--entities",
                str(entities),
                "--principal",
                'Principal::"cordon"',
                "--action",
                f"Action::{json.dumps(action)}",
                "--resource",
                'Artifact::"subject"',
                "--context",
                str(context_file),
            ]
        )
        answer = done.stdout.strip().split()[:1]
        assert answer in (["ALLOW"], ["DENY"]), (done.stdout[-300:], done.stderr[-300:])
        return answer == ["ALLOW"]


class Cases:
    """Each recorded case through an engine; the cases whose answer is not what decide() recorded."""

    @staticmethod
    def opa(rego_text: str, tmp_path: Path) -> list[tuple[int, str, str]]:
        table = ExportTable.of(ExportCases.policy())
        rego = tmp_path / "fixture.rego"
        rego.write_text(rego_text, encoding="utf-8")
        wrong = []
        for number, case in enumerate(Recorded.cases()):
            facts = Recorded.facts(case)
            facts_file = tmp_path / "facts.json"
            facts_file.write_text(json.dumps(facts), encoding="utf-8")
            answer = Engines.opa(rego, facts_file)
            reference = ExportReference.evaluate(table, facts)
            if (answer["state"], tuple(answer["fired"])) != reference or answer["state"] != case[
                "state"
            ]:
                wrong.append((number, answer["state"], case["state"]))
        return wrong

    @staticmethod
    def cedar(cedar_text: str, tmp_path: Path) -> list[tuple[int, str, str]]:
        table = ExportTable.of(ExportCases.policy())
        policies = tmp_path / "fixture.cedar"
        policies.write_text(cedar_text, encoding="utf-8")
        entities = tmp_path / "entities.json"
        entities.write_text("[]", encoding="utf-8")
        wrong = []
        for number, case in enumerate(Recorded.cases()):
            facts = Recorded.facts(case)
            state, decided = CedarExporter.evaluate(
                table,
                facts,
                lambda action, context: Engines.cedar(
                    policies, entities, tmp_path, action, context
                ),
            )
            if (state, decided) != ExportReference.evaluate(table, facts) or state != case["state"]:
                wrong.append((number, state, case["state"]))
        return wrong


@pytest.mark.skipif(
    not OPA, reason="CORDON_OPA is not set: the OPA engine is mounted only in the engines container"
)
class TestOpa:
    def test_the_engine_is_the_one_the_task_names(self) -> None:
        assert "Version: 1." in Engines.run([OPA, "version"]).stdout

    def test_it_gives_the_recorded_state_on_every_case(self, tmp_path: Path) -> None:
        assert Cases.opa(RegoExporter.render(ExportTable.of(ExportCases.policy())), tmp_path) == []

    def test_an_export_with_a_rule_taken_out_is_caught(self, tmp_path: Path) -> None:
        text = RegoExporter.render(ExportTable.of(ExportCases.policy()))
        broken = text.replace(
            'fired contains "block-malicious"', 'fired contains "x-block-malicious"'
        )
        assert broken != text and Cases.opa(broken, tmp_path)


@pytest.mark.skipif(
    not CEDAR,
    reason="CORDON_CEDAR is not set: the Cedar CLI is mounted only in the engines container",
)
class TestCedar:
    def test_the_engine_is_the_one_the_task_names(self) -> None:
        assert "4.15.0" in Engines.run([CEDAR, "--version"]).stdout

    def test_it_gives_the_recorded_state_on_every_case(self, tmp_path: Path) -> None:
        assert (
            Cases.cedar(CedarExporter.render(ExportTable.of(ExportCases.policy())), tmp_path) == []
        )

    def test_an_export_with_a_rule_taken_out_is_caught(self, tmp_path: Path) -> None:
        text = CedarExporter.render(ExportTable.of(ExportCases.policy()))
        kept = "\n".join(line for line in text.split("\n") if "match:block-malicious:" not in line)
        assert kept != text and Cases.cedar(kept, tmp_path)
