"""An agent-chain finding, built the one way every part of the family builds it.

The rule's own severity and message, lowered for a file under a test-material directory (an agent
reads its configuration by exact name, so only the directory says test); a masked snippet as
evidence, none for a secret or hidden text; the risk an install-time context scores; and the line a
match in a file's text points at."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.shared.source_paths import SourcePaths
from cordon_scanner.detect.agents.rule_catalogue import RULES
from cordon_scanner.detect.base import FileUnit
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Severity,
)
from cordon_scanner.foundation.paths import ContainerPaths
from cordon_scanner.foundation.scoring import ScoringContext
from cordon_scanner.foundation.text.redact import Redactor

if TYPE_CHECKING:
    from cordon_scanner.detect.base import ScanContext


class AgentFinding:
    """Building an agent-chain finding from a rule and a span of a file."""

    @classmethod
    def at_text(
        cls,
        rule_id: str,
        unit: FileUnit,
        ctx: ScanContext,
        text: str,
        needle: str,
        *,
        message: str | None = None,
        severity: Severity | None = None,
        secret: bool = False,
        confidence: Confidence | None = None,
    ) -> Finding:
        index = text.find(needle)
        if index < 0:
            index = text.find(json.dumps(needle)[1:-1])
        if index < 0:
            index = 0
        start = len(text[:index].encode("utf-8"))
        end = start + len(needle.encode("utf-8"))
        return cls.finding(
            rule_id,
            unit,
            ctx,
            start,
            end,
            message=message,
            severity=severity,
            secret=secret,
            confidence=confidence,
        )

    #: The id every agent-chain finding carries, wherever in the family it is built.
    DETECTOR: ClassVar[str] = "agents"

    @classmethod
    def finding(
        cls,
        rule_id: str,
        unit: FileUnit,
        ctx: ScanContext,
        start: int,
        end: int,
        *,
        message: str | None = None,
        severity: Severity | None = None,
        secret: bool = False,
        confidence: Confidence | None = None,
    ) -> Finding:
        rule = RULES[rule_id]
        content = unit.content
        line = content.line_of(start)
        chosen = severity or rule.severity
        text = message or rule.message
        # Only the directory says test here. An agent reads its configuration by exact name,
        # so `settings.local.json` -- `local` marks a key file as non-production -- is the file
        # Claude Code loads, not a fixture. And only a directory whose WHOLE name says so: a
        # word inside a name (`version-demo-helper`, `api-test-kit`) is chosen by whoever named
        # the skill, and the agent loads that skill all the same.
        if rule.category not in (Category.MALICIOUS, Category.OPERATIONAL) and (
            ContainerPaths.under_fixture_directory(content.path)
            or SourcePaths.test_material_glob(content.path)
        ):
            chosen = min(chosen, Severity.LOW)
            text += " It sits under a path that holds test material, so it is reported below its usual severity."
        snippet = content.line_text(line).strip()[:200]
        return Finding(
            rule_id=rule.rule_id,
            category=rule.category,
            severity=chosen,
            confidence=confidence or rule.confidence,
            message=text,
            location=Location(
                path=content.path,
                line=line,
                column=content.column_of(start),
                byte_start=start,
                byte_end=end,
                project=unit.project,
            ),
            evidence=Evidence(
                kind=EvidenceKind.SNIPPET,
                match_hash=Evidence.hash_bytes(content.raw[start:end] or rule.rule_id.encode()),
                redaction=RedactionMode.MASKED,
                snippet=None
                if secret or rule_id == "SUSPECT.AGENT.HIDDEN_TEXT.001"
                else Redactor.mask(snippet),
                span=(start, end),
            ),
            remediation=rule.remediation,
            explanation=Explanation(summary=rule.title, matched_rule=rule.rule_id),
            risk=ctx.scorer.score(chosen, rule.confidence, ScoringContext(in_install_hook=True)),
            detector=cls.DETECTOR,
            references=rule.references,
        )


__all__ = ["AgentFinding"]
