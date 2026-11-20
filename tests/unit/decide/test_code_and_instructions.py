"""Code and instructions agreeing in one package (`decide/code_and_instructions.py`).

```
  an agent-family finding in a code file, MEDIUM or stronger   ┐
  an instruction-file order of any class, any grade            ┴─ both in one package ──► SUSPECT.AGENT.CODE_AND_INSTRUCTIONS.001
  one of them alone, a code finding below MEDIUM or in a document, a suppressed finding  ──► nothing
```
Inert fixtures: findings built by the engine's own builder, with made-up paths; no code.
"""

from __future__ import annotations

import pytest

from cordon_scanner.decide.code_and_instructions import CodeAndInstructions
from cordon_scanner.foundation.models import Category, Finding, Severity, Suppression
from cordon_scanner.foundation.results import OperationalFinding

ORDER = "SUSPECT.AGENT.INSTRUCTION_PIPE_TO_SHELL.001"
CODE = "SUSPECT.AGENT.UNATTENDED.001"


class Findings:
    @staticmethod
    def of(rule: str, severity: Severity, path: str) -> Finding:
        return OperationalFinding.build(
            path=path,
            rule_id=rule,
            message="m",
            remediation="r",
            category=Category.SUSPICIOUS,
            severity=severity,
        )

    @staticmethod
    def order(severity: Severity = Severity.LOW, rule: str = ORDER) -> Finding:
        return Findings.of(rule, severity, "pkg/SKILL.md")

    @staticmethod
    def code(
        severity: Severity = Severity.MEDIUM, path: str = "pkg/server.js", rule: str = CODE
    ) -> Finding:
        return Findings.of(rule, severity, path)


class TestTheComposite:
    def test_an_order_and_a_code_finding_make_it(self) -> None:
        made = CodeAndInstructions.of([Findings.order(), Findings.code()])
        assert made is not None
        assert made.rule_id == "SUSPECT.AGENT.CODE_AND_INSTRUCTIONS.001"
        assert made.category is Category.SUSPICIOUS
        assert made.severity is Severity.HIGH
        assert set(made.related) == {ORDER, CODE}
        assert made.location.path == "pkg/SKILL.md"

    def test_an_order_alone_makes_nothing(self) -> None:
        assert CodeAndInstructions.of([Findings.order()]) is None

    def test_a_code_finding_alone_makes_nothing(self) -> None:
        assert CodeAndInstructions.of([Findings.code()]) is None

    def test_no_findings_make_nothing(self) -> None:
        assert CodeAndInstructions.of([]) is None

    @pytest.mark.parametrize("severity", [Severity.INFO, Severity.LOW])
    def test_a_code_finding_below_medium_does_not_count(self, severity: Severity) -> None:
        assert CodeAndInstructions.of([Findings.order(), Findings.code(severity)]) is None

    @pytest.mark.parametrize("severity", [Severity.LOW, Severity.MEDIUM, Severity.HIGH])
    def test_an_order_counts_at_any_grade(self, severity: Severity) -> None:
        assert CodeAndInstructions.of([Findings.order(severity), Findings.code()]) is not None

    @pytest.mark.parametrize(
        "path", ["pkg/README.md", "pkg/SKILL.md", "pkg/notes.txt", "pkg/a.json"]
    )
    def test_a_finding_in_a_document_is_not_code(self, path: str) -> None:
        assert CodeAndInstructions.of([Findings.order(), Findings.code(path=path)]) is None

    @pytest.mark.parametrize(
        "path", ["pkg/server.js", "pkg/a.mjs", "pkg/b.ts", "pkg/c.py", "pkg/d.sh"]
    )
    def test_a_finding_in_a_code_file_is_code(self, path: str) -> None:
        assert CodeAndInstructions.of([Findings.order(), Findings.code(path=path)]) is not None

    def test_an_agent_threat_rule_in_code_counts(self) -> None:
        code = Findings.code(rule="SUSPECT.AGENT.ATR.TOOL_POISONING.001")
        assert CodeAndInstructions.of([Findings.order(), code]) is not None

    def test_a_finding_of_another_family_in_code_does_not_count(self) -> None:
        other = Findings.code(rule="SUSPECT.DROPPER.001")
        assert CodeAndInstructions.of([Findings.order(), other]) is None

    def test_an_order_in_code_is_not_a_code_finding(self) -> None:
        order_in_code = Findings.of(ORDER, Severity.HIGH, "pkg/server.js")
        assert CodeAndInstructions.of([order_in_code]) is None

    def test_a_suppressed_finding_does_not_count(self) -> None:
        suppression = Suppression(
            rule=CODE, path="pkg/server.js", justification="accepted", expires="2999-01-01"
        )
        suppressed = Findings.code().with_suppression(suppression)
        assert CodeAndInstructions.of([Findings.order(), suppressed]) is None

    def test_the_composite_is_not_counted_as_its_own_part(self) -> None:
        made = CodeAndInstructions.of([Findings.order(), Findings.code()])
        assert made is not None
        assert CodeAndInstructions.of([made]) is None
        assert CodeAndInstructions.of([Findings.order(), made]) is None

    def test_it_adds_nothing_when_the_surface_found_no_order(self) -> None:
        findings = [
            Findings.code(),
            Findings.code(path="pkg/b.py", rule="SUSPECT.AGENT.FETCH_EXEC.001"),
        ]
        assert CodeAndInstructions.of(findings) is None
