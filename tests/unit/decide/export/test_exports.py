"""Row BP-6-5, the fast half: what is exported, what is refused, and the exported semantics checked against `decide()` over 100 recorded cases.

The Python reference (`ExportReference`) runs the same semantics the Rego and Cedar exports carry over the same facts document. It must
give `decide()`'s state on every recorded case; `test_engines.py` runs the two real engines over the same cases in a container.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

import pytest

from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.evidence import Approval, ArtifactRef, Context, EvidenceSet
from cordon_scanner.decide.decision.policy_source import PolicySource
from cordon_scanner.decide.export.cedar import CedarExporter
from cordon_scanner.decide.export.facts import ExportFacts
from cordon_scanner.decide.export.reference import ExportReference
from cordon_scanner.decide.export.rego import RegoExporter
from cordon_scanner.decide.export.table import ExportTable, ExportUnsupported
from kits.export_cases import CLOCK, ExportCases
from support import ROOT

GOLDEN = ROOT / "tests" / "unit" / "decide" / "export" / "golden"


class Recorded:
    @staticmethod
    def cases() -> list[dict[str, Any]]:
        document = json.loads((GOLDEN / "cases.json").read_text(encoding="utf-8"))
        cases: list[dict[str, Any]] = document["cases"]
        return cases

    @staticmethod
    def facts(case: dict[str, Any]) -> dict[str, Any]:
        return ExportFacts.of(
            ArtifactRef.from_json(case["artifact"]),
            Context.from_json(case["context"]),
            EvidenceSet.from_json(case["evidence"]),
            CLOCK,
            ExportCases.policy(),
        )


class TestTheRecordedCases:
    def test_there_are_a_hundred_and_all_four_states_are_among_them(self) -> None:
        cases = Recorded.cases()
        assert len(cases) == 100
        counts = Counter(case["state"] for case in cases)
        assert set(counts) == set(ExportReference.STATES) and min(counts.values()) >= 5, counts

    def test_the_file_is_what_decide_gives_now(self) -> None:
        assert ExportCases.recorded() == Recorded.cases()

    def test_the_reference_gives_the_state_decide_gives_on_every_case(self) -> None:
        table = ExportTable.of(ExportCases.policy())
        wrong = [
            number
            for number, case in enumerate(Recorded.cases())
            if ExportReference.evaluate(table, Recorded.facts(case))[0] != case["state"]
        ]
        assert wrong == []

    def test_the_rules_that_decide_are_named(self) -> None:
        table = ExportTable.of(ExportCases.policy())
        seen = Counter()
        for case in Recorded.cases():
            _, decided = ExportReference.evaluate(table, Recorded.facts(case))
            seen.update(decided)
        assert {
            "block-malicious",
            "review-severe",
            "young-release",
            "our-namespace",
            "pinned-with-conditions",
        } <= set(seen)


class TestTheExportsAreGolden:
    def test_the_rego_is_what_the_exporter_writes(self) -> None:
        assert RegoExporter.render(ExportTable.of(ExportCases.policy())) == (
            GOLDEN / "fixture.rego"
        ).read_text(encoding="utf-8")

    def test_the_cedar_is_what_the_exporter_writes(self) -> None:
        assert CedarExporter.render(ExportTable.of(ExportCases.policy())) == (
            GOLDEN / "fixture.cedar"
        ).read_text(encoding="utf-8")

    def test_the_rego_names_the_policy_and_the_input_it_reads(self) -> None:
        text = RegoExporter.render(ExportTable.of(ExportCases.policy()))
        assert (
            "package cordon.export" in text
            and "acme/export-fixture" in text
            and "input.shortfalls.required_missing" in text
        )

    def test_the_cedar_has_the_match_and_the_state_actions(self) -> None:
        text = CedarExporter.render(ExportTable.of(ExportCases.policy()))
        for action in (
            "match:block-malicious:when",
            "state:block",
            "state:review",
            "state:allow_with_conditions",
        ):
            assert f'Action::"{action}"' in text


class TestWhatIsRefused:
    @staticmethod
    def policy(extra_defaults: dict[str, Any] | None = None, rule: dict[str, Any] | None = None):
        source: dict[str, Any] = {
            "policy_schema": 2,
            "id": "acme/p",
            "version": 1,
            "scope": ["acme"],
            "rules": [rule] if rule else [],
            "defaults": extra_defaults or {},
        }
        return PolicyCompiler.compile(PolicySource.from_json(source))

    def test_a_policy_that_warns_until_measured(self) -> None:
        with pytest.raises(ExportUnsupported, match="warn_until_measured"):
            ExportTable.of(self.policy({"warn_until_measured": ["npm"]}))

    def test_a_rule_on_approval(self) -> None:
        rule = {
            "id": "needs-approval",
            "tier": "require",
            "then": "review",
            "require": {"approval": "present"},
        }
        with pytest.raises(ExportUnsupported, match="approval"):
            ExportTable.of(self.policy(rule=rule))

    def test_a_call_whose_evidence_carries_an_approval(self) -> None:
        approval = Approval(
            id="A",
            kind="approve",
            expires_at="2026-12-31T00:00:00Z",
            digests=("sha256:" + "ab" * 32,),
        )
        artifact = ArtifactRef(kind="package", subject_id="pkg:npm/x", digest="sha256:" + "ab" * 32)
        with pytest.raises(ExportUnsupported, match="approval"):
            ExportFacts.of(
                artifact,
                Context(point="cli", environment="dev"),
                EvidenceSet(approvals=(approval,)),
                CLOCK,
                self.policy(),
            )

    @pytest.mark.parametrize("pattern", ["a?b", "a[bc]", "a\\*"])
    def test_a_glob_cedar_cannot_say(self, pattern: str) -> None:
        rule = {
            "id": "g",
            "tier": "require",
            "then": "review",
            "when": {"subject.namespace": {"glob": pattern}},
            "reason": "R700",
        }
        table = ExportTable.of(self.policy(rule=rule))
        assert RegoExporter.render(
            table
        )  # Rego carries any fnmatch pattern as a regular expression
        with pytest.raises(ExportUnsupported, match="Cedar"):
            CedarExporter.render(table)


class TestTheFactsDocument:
    def test_what_the_call_does_not_know_is_absent(self) -> None:
        artifact = ArtifactRef(kind="package", subject_id="pkg:npm/x", digest="sha256:" + "ab" * 32)
        facts = ExportFacts.of(
            artifact,
            Context(point="cli", environment="dev"),
            EvidenceSet(),
            CLOCK,
            ExportCases.policy(),
        )
        assert (
            "version.age_days" not in facts["values"]
            and "provenance.slsa_level" not in facts["values"]
        )
        assert facts["values"]["subject.kind"] == "package" and facts["findings"] == []
        assert not facts["hard_stop"] and not any(facts["shortfalls"].values())

    def test_a_finding_carries_its_ranks(self) -> None:
        case = next(item for item in Recorded.cases() if item["evidence"].get("findings"))
        finding = Recorded.facts(case)["findings"][0]
        assert {"severity_rank", "confidence_rank", "rule_id", "category", "domain"} <= set(finding)
