"""What agent-facing text says: the Agent Threat Rules it matches, and the intents it states.

An instruction file, a settings file's command, an MCP server's tool description: each is text an
agent reads and acts on. The Agent Threat Rules that match it give one finding per ATR category, and
the semantic layer (`agent_intent.py`) one per intent the text states, graded by the words that
state it. Every part of the agent chain that reads such text asks here."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Final

from cordon_scanner.detect.agents.defensive_doc import DefensiveDoc
from cordon_scanner.detect.agents.findings import AgentFinding
from cordon_scanner.detect.agents.rule_catalogue import INTENT_WORDS, RULES, AgentRules
from cordon_scanner.detect.base import FileUnit
from cordon_scanner.foundation.models import (
    Confidence,
    Finding,
    Severity,
)
from cordon_scanner.intel.malware import atr

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.detect.base import ScanContext

_MEDIUM_INTENTS: Final = frozenset({"markdown-exfil", "persist"})


class AgentTextFindings:
    """The agent-chain findings in what agent-facing text says."""

    @classmethod
    def intents(
        cls, unit: FileUnit, ctx: ScanContext, text: str, *, within: str | None = None
    ) -> Iterator[Finding]:
        """The semantic layer (`detect/agent_intent.py`): one finding per intent the text states,
        and, for an instruction file, the intent of a file it tells the agent to follow."""
        from cordon_scanner.detect.agents.agent_intent import InstructionIntent

        seen: set[str] = set()
        for intent in InstructionIntent.find(text):
            if intent.kind in seen:
                continue
            seen.add(intent.kind)
            message = (
                RULES["SUSPECT.AGENT.INTENT.001"].message
                + f' It asks the agent to {INTENT_WORDS[intent.kind]}: "{intent.sentence[:160]}"'
            )
            severity = Severity.MEDIUM if intent.kind in _MEDIUM_INTENTS else None
            if within is not None:
                yield AgentFinding.at_text(
                    "SUSPECT.AGENT.INTENT.001",
                    unit,
                    ctx,
                    within,
                    intent.sentence[:80],
                    message=message,
                    severity=severity,
                )
            else:
                start = len(text[: intent.start].encode("utf-8"))
                end = start + len(intent.sentence.encode("utf-8"))
                yield AgentFinding.finding(
                    "SUSPECT.AGENT.INTENT.001",
                    unit,
                    ctx,
                    start,
                    end,
                    message=message,
                    severity=severity,
                )
        if within is not None or ctx.repository is None:
            return
        root = Path(ctx.repository.root)
        base = (root / unit.content.path).parent
        for offset, referenced in InstructionIntent.chained_paths(text)[:5]:
            for candidate in (base / referenced, root / referenced):
                try:
                    resolved = candidate.resolve()
                    if (
                        not resolved.is_relative_to(root.resolve())
                        or not resolved.is_file()
                        or resolved.stat().st_size > 512 << 10
                    ):
                        continue
                    linked = resolved.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                found = InstructionIntent.find(linked)
                if found:
                    start = len(text[:offset].encode("utf-8"))
                    yield AgentFinding.finding(
                        "SUSPECT.AGENT.INTENT_CHAINED.001",
                        unit,
                        ctx,
                        start,
                        start + len(referenced.encode("utf-8")),
                        message=RULES["SUSPECT.AGENT.INTENT_CHAINED.001"].message
                        + f" {referenced} asks the agent to {INTENT_WORDS[found[0].kind]}.",
                    )
                    return
                break

    @classmethod
    def threat_rules(
        cls,
        unit: FileUnit,
        ctx: ScanContext,
        text: str,
        kinds: tuple[str, ...],
        *,
        within: str | None = None,
        instruction_file: bool = False,
        corroborated: bool = False,
        corroborated_code: bool = False,
        documentation: bool = False,
        local: bool = False,
        unconfirmed: bool = False,
    ) -> Iterator[Finding]:
        """The Agent Threat Rules that match `text`, one finding per ATR category.

        `unconfirmed`: a tool's text, or a skill, the learned model read as ordinary. An ATR match
        there is recorded at LOW; it warns and blocks only where the model agrees.

        `within` is the file's text when `text` is a piece of it -- a hook's command, a tool's
        description -- so the finding points at the piece; otherwise `text` is the file itself.
        """
        matches = atr.AtrEngine.evaluate(text, kinds)
        by_category: dict[str, list[atr.AtrMatch]] = {}
        for match in matches:
            by_category.setdefault(match.rule.category, []).append(match)
        defensive = DefensiveDoc.is_defensive(documentation, within or text)
        for category, found in by_category.items():
            yield from AgentTextFindings._category_finding(
                category,
                corroborated,
                corroborated_code,
                ctx,
                defensive,
                found,
                instruction_file,
                local,
                text,
                unconfirmed,
                unit,
                within,
            )

    @staticmethod
    def _category_finding(
        category: str,
        corroborated: bool,
        corroborated_code: bool,
        ctx: ScanContext,
        defensive: bool,
        found: list[atr.AtrMatch],
        instruction_file: bool,
        local: bool,
        text: str,
        unconfirmed: bool,
        unit: FileUnit,
        within: str | None,
    ) -> Iterator[Finding]:
        """The finding for one ATR category: the matches that count (stable ones first), named, graded, and placed at the first."""
        rule_id = AgentRules.atr_rule_id(category)

        # Graded by ATR's own quality standard, from each rule's measured benign match rate:
        # a production-grade rule (0.5% or less) that ATR marks stable at critical or high
        # blocks; any other production-grade rule warns; a rule above ATR's production line is
        # only ever an observation, never alone the reason a repository is flagged. An
        # instruction file is prose written to the agent, and ATR's 815 rules were written for
        # traffic, so there a rule counts only if it matched at most `atr.INSTRUCTION_TOLERANCE`
        # of its calibration instruction files. Whether a counted stable match then blocks is
        # `DefensiveDoc.stable_blocks`.
        def counts(m: atr.AtrMatch) -> bool:
            if m.rule.grade != "production" or m.rule.severity in ("low", "info"):
                return False
            return (
                not instruction_file
                or m.rule.instruction_hits is None
                or m.rule.instruction_hits <= atr.INSTRUCTION_TOLERANCE
            )

        counted = [m for m in found if counts(m)]
        stable = [
            m
            for m in counted
            if m.rule.status == "stable"
            and m.rule.severity in ("critical", "high")
            and DefensiveDoc.stable_blocks(
                corroborated_code, defensive, corroborated, instruction_file
            )
            and not local
            and not unconfirmed
        ]
        # A stable production-grade match blocks, as the grading above says -- and for that it
        # needs the gate's confidence, not the rule's declared LOW: at LOW the default gate
        # (`Policy.min_confidence_to_fail`, MEDIUM) never let one block (review 98, AG-1).
        confidence = Confidence.MEDIUM if stable else None
        if stable:
            severity = Severity.HIGH
        elif counted and not (unconfirmed or (instruction_file and not corroborated)):
            severity = Severity.MEDIUM
        else:
            # Recorded, not raised, where nothing backs the phrase: the learned reading
            # disagrees, or it is a project's own instruction file with none of Cordon's
            # evidence beside it. There ATR's phrases matched "re-read the article file",
            # "DREAD score: 8.6 -- critical" and a list of crate names: ATR categories warned
            # on 1,523 of the long tail's benign units, 726 of them for nothing else (review
            # 98).
            severity = Severity.LOW
        yield from AgentTextFindings._placed_finding(
            confidence, counted, ctx, found, rule_id, severity, stable, text, unit, within
        )

    @staticmethod
    def _placed_finding(
        confidence: Confidence | None,
        counted: list[atr.AtrMatch],
        ctx: ScanContext,
        found: list[atr.AtrMatch],
        rule_id: str,
        severity: Severity,
        stable: list[atr.AtrMatch],
        text: str,
        unit: FileUnit,
        within: str | None,
    ) -> Iterator[Finding]:
        """The category's finding, named for its matches and placed: at the first match's line in the file, or in the text it was found within."""
        found = stable or counted or found
        named = "; ".join(f"{m.rule.rule_id} ({m.rule.title.rstrip('.')})" for m in found[:4])
        more = len(found) - min(len(found), 4)
        message = (
            RULES[rule_id].message
            + f" Matched: {named}"
            + (f", and {more} more" if more > 0 else "")
            + f". Rules: {atr.RuleLinks.url(found[0].rule.rule_id)}"
        )
        first = found[0]
        if within is None:
            start = len(text[: first.start].encode("utf-8"))
            end = start + len(text[first.start : first.end].encode("utf-8"))
            yield AgentFinding.finding(
                rule_id,
                unit,
                ctx,
                start,
                end,
                message=message,
                severity=severity,
                confidence=confidence,
            )
        else:
            # The matched words are found inside the file's text; the whole piece is the
            # fallback when JSON escaping has changed how they are spelled there.
            needle = text[first.start : first.end]
            if within.find(needle) < 0 and within.find(json.dumps(needle)[1:-1]) < 0:
                needle = text
            yield AgentFinding.at_text(
                rule_id,
                unit,
                ctx,
                within,
                needle,
                message=message,
                severity=severity,
                confidence=confidence,
            )


__all__ = ["AgentTextFindings"]
