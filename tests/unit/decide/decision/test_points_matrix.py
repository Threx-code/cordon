"""The 1,000-case matrix of row BP-0-2: every enforcement point asks one function, and the answer does not depend on who asks.

The cases are every second case of the committed determinism goldens (`golden/cases.json`: 40 policies x 50 evidence sets with
their artifact, context and clock), so each has a recorded decision. Each is asked at all seven points through
`PointRuntime.ask`, the single entry the points use. Two things must hold:

* asked at its own recorded point, a case gives exactly the recorded decision (the facade changes nothing: this is the decision
  the cloud service gives for the same inputs, because both call the same library);
* asked at any other point, it gives the same decision content (state, reason codes, obligations, explanation), because none
  of these policies has a rule that reads `context.point`; and where a policy does have such a rule, the point is the only thing
  that can make two answers differ.
"""

from __future__ import annotations

import hashlib
import json
from functools import cache
from typing import Any

import pytest

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.evidence import ArtifactRef, Context, EvidenceSet
from cordon_scanner.decide.decision.outcome import Decision
from cordon_scanner.decide.decision.policy_source import PolicySource
from cordon_scanner.decide.decision.records import DecisionError, Instants
from cordon_scanner.decide.points import PointRuntime
from kits.decision_goldens import CASES_FILE, ENVELOPES_FILE, DecisionGoldens
from support import ROOT

GOLDEN = ROOT / "tests" / "unit" / "decide" / "decision" / "golden"
STRIDE = 2


class Matrix:
    @staticmethod
    @cache
    def inputs() -> dict[str, Any]:
        loaded: dict[str, Any] = json.loads((GOLDEN / CASES_FILE).read_bytes())
        return loaded

    @staticmethod
    @cache
    def recorded() -> list[str]:
        document: dict[str, Any] = json.loads((GOLDEN / ENVELOPES_FILE).read_text(encoding="utf-8"))
        envelopes: list[str] = document["envelopes"]
        return envelopes

    @classmethod
    @cache
    def policies(cls) -> list[Any]:
        return [DecisionGoldens.compile(item["chain"]) for item in cls.inputs()["policies"]]

    @classmethod
    def indexes(cls) -> list[int]:
        return list(range(0, len(cls.inputs()["cases"]), STRIDE))

    @classmethod
    def ask(cls, index: int, point: str | None = None) -> Decision:
        policy_i, evidence_i, artifact_i, context_i, clock_i = cls.inputs()["cases"][index]
        inputs = cls.inputs()
        context = Context.from_json(inputs["contexts"][context_i])
        return PointRuntime.ask(
            point or context.point,
            ArtifactRef.from_json(inputs["artifacts"][artifact_i]),
            EvidenceSet.from_json(inputs["evidence"][evidence_i]),
            cls.policies()[policy_i],
            Instants.parse(inputs["clocks"][clock_i]),
            environment=context.environment,
            scope_path=context.scope_path,
            actor=context.actor,
            relation=context.relation,
            online=context.online,
            bundle_age_s=context.bundle_age_s,
            intel_age_s=context.intel_age_s,
        )


class TestTheMatrix:
    def test_it_is_a_thousand_cases_over_seven_points(self) -> None:
        assert len(Matrix.indexes()) == 1000
        assert len(PointRuntime.POINTS) == 7

    def test_asked_at_its_own_point_every_case_gives_the_recorded_decision(self) -> None:
        wrong = [
            index
            for index in Matrix.indexes()
            if hashlib.sha256(
                ArtifactDigests.canonical_json(Matrix.ask(index).to_json())
            ).hexdigest()
            != Matrix.recorded()[index]
        ]
        assert wrong == []

    def test_asked_at_any_point_every_case_gives_the_same_content(self) -> None:
        different = []
        for index in Matrix.indexes():
            own = PointRuntime.content(Matrix.ask(index))
            for point in PointRuntime.POINTS:
                if PointRuntime.content(Matrix.ask(index, point)) != own:
                    different.append((index, point))
        assert different == []

    def test_the_point_shows_only_in_the_context_and_the_inputs_digest(self) -> None:
        for index in Matrix.indexes()[::50]:
            seen = {point: Matrix.ask(index, point) for point in PointRuntime.POINTS}
            assert {d.context.point for d in seen.values()} == set(PointRuntime.POINTS)  # type: ignore[union-attr]
            assert len({d.inputs_digest for d in seen.values()}) == len(PointRuntime.POINTS)
            assert {point: d.context.point for point, d in seen.items()} == {
                p: p for p in PointRuntime.POINTS
            }  # type: ignore[union-attr]

    def test_asking_twice_gives_the_same_bytes(self) -> None:
        for index in Matrix.indexes()[::100]:
            assert (
                Matrix.ask(index, "firewall").canonical_bytes()
                == Matrix.ask(index, "firewall").canonical_bytes()
            )


class TestAPolicyThatReadsThePoint:
    @staticmethod
    def policy() -> Any:
        return PolicyCompiler.compile(
            PolicySource.from_json(
                {
                    "policy_schema": 2,
                    "id": "acme/point-aware",
                    "version": 1,
                    "scope": ["acme"],
                    "rules": [
                        {
                            "id": "firewall-review",
                            "tier": "require",
                            "then": "review",
                            "when": {"context.point": "firewall"},
                            "reason": "R700",
                        }
                    ],
                    "defaults": {},
                }
            )
        )

    def test_only_the_named_point_gets_another_answer(self) -> None:
        artifact = Matrix.ask(
            0
        ).explanation  # a decision exists for the first case; the artifact below is its own
        assert artifact
        inputs = Matrix.inputs()
        subject = ArtifactRef.from_json(inputs["artifacts"][inputs["cases"][0][2]])
        states = {
            point: PointRuntime.ask(
                point,
                subject,
                EvidenceSet(),
                self.policy(),
                Instants.parse(inputs["clocks"][0]),
                environment="production",
            ).state
            for point in PointRuntime.POINTS
        }
        assert states["firewall"] == "REVIEW"
        assert {state for point, state in states.items() if point != "firewall"} == {"ALLOW"}


class TestTheEntry:
    def test_an_unknown_point_is_refused(self) -> None:
        with pytest.raises(DecisionError):
            Matrix.ask(0, "somewhere_else")

    def test_every_point_the_library_knows_is_asked_through_the_same_entry(self) -> None:
        assert PointRuntime.POINTS == Context.POINTS
