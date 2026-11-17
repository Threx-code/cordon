"""Package composites: a block that is the combination of findings the rules already made.

A finding is the reading of one place. Some behaviour is never in one place: a package that
decodes data and runs it, fetches code and runs it, and publishes itself to a registry is a worm,
however each part is written and wherever in the package it sits. Each part alone is common in
legitimate packages -- a release tool publishes, a loader decodes, an updater fetches -- and is graded
as such; all three in one package are the propagation itself.

```
  findings the rules made                          this layer (after the rules and the verdict)
    SUSPECT.REGISTRY.SELF_PUBLISH.001   ┐
    SUSPECT.DECODE_EXEC.001             ├─ all three, each at MEDIUM or stronger ──► MALWARE.WORM.SELF_PROPAGATION.001
    SUSPECT.DROPPER.REMOTE_CODE.001     ┘                                            (malicious, names the three)
```

It adds a finding and never lowers, holds or removes one. A part a ceiling has lowered below MEDIUM
(a tool a person runs by hand, build tooling) does not count: the ceilings' judgement of where the
code runs stands. Measured on the 350-unit malicious dev set and the legitimate dev, mcpc, other and
large-harvest sets (reviews/mcp-98/17): all three present in 7 malicious units and in none of 12,387
legitimate ones; any two in 12 legitimate units, which this does not touch. One campaign family in
dev: whether it generalises is for the sealed final to say.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.foundation.models import Category, Confidence, Finding, Severity
from cordon_scanner.foundation.results import OperationalFinding

if TYPE_CHECKING:
    from collections.abc import Sequence


class PackageComposites:
    """Blocks made of the package's own findings."""

    WORM_RULE: ClassVar[str] = "MALWARE.WORM.SELF_PROPAGATION.001"

    WORM_PARTS: ClassVar[tuple[str, ...]] = (
        "SUSPECT.REGISTRY.SELF_PUBLISH.001",
        "SUSPECT.DECODE_EXEC.001",
        "SUSPECT.DROPPER.REMOTE_CODE.001",
    )
    """The three behaviours a self-propagating package combines: publishing itself, decoding data
    to run it, and fetching code to run it."""

    PART_FLOOR: ClassVar[Severity] = Severity.MEDIUM
    """A part counts at this severity or stronger: the grade the rules and ceilings left it."""

    INJECTION_RULE: ClassVar[str] = "SUSPECT.AGENT.INJECTION_CORROBORATED.001"
    INJECTION_PHRASE: ClassVar[str] = "SUSPECT.AGENT.ATR.PROMPT_INJECTION.001"
    SKILL_READING: ClassVar[str] = "SUSPECT.AGENT.SKILL_INSTRUCTIONS.001"
    PHRASE_GRADE: ClassVar[tuple[Severity, Confidence]] = (Severity.MEDIUM, Confidence.LOW)
    """The grade of the injection phrase that counts: the one the composite was measured at (reviews/mcp-98/21,
    lever A(1)). The same rule at another grade is another reading and stays graded as it is."""

    @staticmethod
    def worm(findings: Sequence[Finding]) -> Finding | None:
        """The self-propagation finding when every part of the worm is among `findings`, else None."""
        counted = {
            f.rule_id
            for f in findings
            if f.rule_id in PackageComposites.WORM_PARTS
            and f.suppressed is None
            and f.severity >= PackageComposites.PART_FLOOR
        }
        if len(counted) != len(PackageComposites.WORM_PARTS):
            return None
        return replace(
            OperationalFinding.build(
                path=".",
                rule_id=PackageComposites.WORM_RULE,
                message=(
                    "This package publishes itself to a registry, decodes data and runs it, and "
                    "fetches code and runs it: "
                    f"{', '.join(PackageComposites.WORM_PARTS)} together are self-propagation. "
                    "Each alone is ordinary in a release tool, a loader or an updater; all three "
                    "in one package are the spread itself."
                ),
                remediation=(
                    "Do not install. Read the three findings it names; a package that republishes "
                    "itself from the machine that installs it carries its payload to the next one."
                ),
                category=Category.MALICIOUS,
                severity=Severity.CRITICAL,
            ),
            confidence=Confidence.HIGH,
            always_report=False,
            detector="verdict",
            related=PackageComposites.WORM_PARTS,
        )

    @staticmethod
    def corroborated_injection(findings: Sequence[Finding]) -> Finding | None:
        """The finding for an injection phrase and the learned reading of the skill's instructions agreeing, else None.

        Two independent weak readers, neither blocking alone: the agent-threat rules' injection phrase at MEDIUM
        and LOW confidence, and the learned reading of the instructions (`SKILL_INSTRUCTIONS`, at any grade).
        Out of fold by family on the skills dev half (3,475 malicious, 3,745 benign) the pair caught 49 of the
        misses of the constructed and wild sets together and newly blocked 11 legitimate units of 14,000
        (skills benign 10, MCP L1/L2 0, harvest 1). It adds a finding and never lowers, holds or removes one."""
        phrase_severity, phrase_confidence = PackageComposites.PHRASE_GRADE
        phrases = [
            f
            for f in findings
            if f.rule_id == PackageComposites.INJECTION_PHRASE
            and f.suppressed is None
            and f.severity is phrase_severity
            and f.confidence is phrase_confidence
        ]
        readings = [
            f
            for f in findings
            if f.rule_id == PackageComposites.SKILL_READING and f.suppressed is None
        ]
        if not phrases or not readings:
            return None
        parts = (PackageComposites.INJECTION_PHRASE, PackageComposites.SKILL_READING)
        return replace(
            OperationalFinding.build(
                path=phrases[0].location.path,
                rule_id=PackageComposites.INJECTION_RULE,
                message=(
                    "An instruction in this package reads as a prompt injection to the agent-threat rules "
                    "(`SUSPECT.AGENT.ATR.PROMPT_INJECTION.001`), and the learned reading of its skill "
                    "instructions scores them as written to steer the agent (`SUSPECT.AGENT.SKILL_INSTRUCTIONS.001`). "
                    "Neither blocks alone, as each is common on benign skills; the two agreeing is not."
                ),
                remediation=(
                    "Read the skill's instructions in full, and the files they tell the agent to run, before "
                    "installing it. Install it only from an author you trust."
                ),
                category=Category.SUSPICIOUS,
                severity=Severity.HIGH,
            ),
            confidence=Confidence.MEDIUM,
            always_report=False,
            detector="verdict",
            related=parts,
        )


__all__ = ["PackageComposites"]
