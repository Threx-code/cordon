"""Code and instructions agreeing in one package: a block that is two readings of different files saying one thing.

An agent package has two places an attack can be: the instructions the agent reads (a skill's SKILL.md, an AGENTS.md,
a rules file) and the code that runs on the user's machine. Each reading alone is common in legitimate packages: an
agent tool's code runs commands without asking, a skill's instructions tell the agent to fetch a page. A package whose
code does an agent-directed thing (`SUSPECT.AGENT.*` in a code file, at MEDIUM or stronger) and whose instruction file
tells the agent to do one of the classes of order of the instruction surface (`SUSPECT.AGENT.INSTRUCTION_*`, at any
grade) is the two halves of one attack.

```
  an agent-family finding in a code file, MEDIUM or stronger   ┐
  an instruction-file order of any class, any grade            ┴─ both in one package ──► SUSPECT.AGENT.CODE_AND_INSTRUCTIONS.001
  one of them alone                                                                       nothing
```

It adds a finding and never lowers, holds or removes one. The classes are named by the prefix of their rule ids, so the
composite needs no list of them and does nothing in a package where the instruction surface found none.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.foundation.models import Category, Confidence, Finding, Severity
from cordon_scanner.foundation.results import OperationalFinding

if TYPE_CHECKING:
    from collections.abc import Sequence


class CodeAndInstructions:
    """`of(findings)`: the finding for a package whose code and instruction files agree, else None."""

    RULE: ClassVar[str] = "SUSPECT.AGENT.CODE_AND_INSTRUCTIONS.001"
    INSTRUCTION_ORDERS: ClassVar[str] = "SUSPECT.AGENT.INSTRUCTION_"
    """The rules of the instruction surface: one rule id per class of order, all with this prefix."""
    AGENT_FAMILIES: ClassVar[tuple[str, ...]] = ("SUSPECT.AGENT.", "MALWARE.AGENT.")
    CODE_SUFFIXES: ClassVar[tuple[str, ...]] = (
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".jsx",
        ".py",
        ".sh",
        ".bash",
        ".ps1",
        ".go",
        ".rs",
    )
    CODE_FLOOR: ClassVar[Severity] = Severity.MEDIUM
    """A code-side finding counts at this severity or stronger: the grade the rules and ceilings left it."""

    @staticmethod
    def _code(finding: Finding) -> bool:
        return (
            finding.suppressed is None
            and finding.rule_id.startswith(CodeAndInstructions.AGENT_FAMILIES)
            and not finding.rule_id.startswith(CodeAndInstructions.INSTRUCTION_ORDERS)
            and finding.rule_id != CodeAndInstructions.RULE
            and finding.severity >= CodeAndInstructions.CODE_FLOOR
            and finding.location.path.lower().endswith(CodeAndInstructions.CODE_SUFFIXES)
        )

    @staticmethod
    def _order(finding: Finding) -> bool:
        return finding.suppressed is None and finding.rule_id.startswith(
            CodeAndInstructions.INSTRUCTION_ORDERS
        )

    @staticmethod
    def of(findings: Sequence[Finding]) -> Finding | None:
        """The finding when `findings` hold an agent-family finding in code and an instruction-file order, else None."""
        code = [f for f in findings if CodeAndInstructions._code(f)]
        orders = [f for f in findings if CodeAndInstructions._order(f)]
        if not code or not orders:
            return None
        related = tuple(dict.fromkeys([*(f.rule_id for f in orders), *(f.rule_id for f in code)]))[
            :12
        ]
        return replace(
            OperationalFinding.build(
                path=orders[0].location.path,
                rule_id=CodeAndInstructions.RULE,
                message=(
                    "An instruction file of this package tells the agent to do something the rules treat as an "
                    f"attack on it (`{orders[0].rule_id}`), and the package's code does an agent-directed thing "
                    f"(`{code[0].rule_id}`). Each alone is common: an agent tool's code runs commands, a skill's "
                    "instructions say to fetch a page. The instructions and the code of one package agreeing "
                    "is the two halves of one attack."
                ),
                remediation=(
                    "Read the instruction file and the code file the findings name, together. Install the package "
                    "only from an author you trust."
                ),
                category=Category.SUSPICIOUS,
                severity=Severity.HIGH,
            ),
            confidence=Confidence.MEDIUM,
            always_report=False,
            detector="verdict",
            related=related,
        )


__all__ = ["CodeAndInstructions"]
