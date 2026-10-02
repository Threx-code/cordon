"""The operator's language model judges agent-facing text. Optional, off by default.

Runs only with `--judge`. Hands each instruction file, skill, slash command, MCP tool description
and agent hook command to the model `cordon_scanner.judge` names, and reports the passages it
judges to be subverting the agent. Says whether it ran (`OPERATIONAL.JUDGE.STATUS`); when it could
not, or when its call budget ran out, marks the scan incomplete -- a check the operator asked for
and did not get is coverage lost.

A judgement is reported only when the model quotes its evidence and the quote is in the text. A
malicious verdict warns; it blocks only when the operator says so with `--judge-blocks`, because a
model's reading is weaker evidence than a rule's match and the text it read was written by the
party being judged.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, ClassVar, Final

from cordon_scanner.core import references as ref
from cordon_scanner.core.models import (
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
from cordon_scanner.core.redact import Redactor
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, RepositoryUnit
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.judge import (
    DEFAULT_MAX_CALLS,
    BudgetExhausted,
    Chunker,
    Judge,
    JudgeError,
    ProviderFactory,
    Verdict,
    VerdictCache,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import ScanContext, Unit

JUDGED_RULE: Final = "SUSPECT.AGENT.JUDGED.001"
STATUS_RULE: Final = "OPERATIONAL.JUDGE.STATUS"
UNAVAILABLE_RULE: Final = "OPERATIONAL.JUDGE.UNAVAILABLE"
BUDGET_RULE: Final = "OPERATIONAL.JUDGE.BUDGET"


class AgentText:
    """The agent-facing text in a file, as (kind, text) pairs."""

    @staticmethod
    def of(unit: FileUnit) -> list[tuple[str, str]]:
        from cordon_scanner.detect import agents

        path = unit.content.path.rpartition("!")[2]
        text = unit.content.text
        if agents.AgentPaths._paths_match(
            path, agents.INSTRUCTION_PATHS
        ) or agents.AgentPaths._paths_match(path, agents.COMMAND_PATHS):
            return [("agent instruction file", text)]
        if agents.AgentPaths._paths_match(path, agents.AGENT_SETTINGS_PATHS):
            settings = agents.McpConfigs._json(unit.content)
            hooks = settings.get("hooks") if isinstance(settings, dict) else None
            if isinstance(hooks, dict):
                return [
                    ("agent hook command", c) for c in agents.McpConfigs._hook_commands(hooks) if c
                ]
            return []
        if path.endswith(agents._SERVER_SOURCE_SUFFIXES) and agents._MCP_SDK.search(text):
            return [
                ("MCP tool description", d)
                for d in dict.fromkeys(agents.McpServerSource._tool_descriptions(text))
            ]
        return []


class AgentJudgeDetector(BaseDetector):
    id = "agent-judge"
    version = "0.1.0"
    operator_enabled = True
    """Runs only when the operator names a judge; exercised against a deterministic provider in
    tests/unit/test_agent_judge.py."""
    categories = frozenset({Category.SUSPICIOUS, Category.OPERATIONAL})
    requires = DetectorRequirements(content=True, repository=True)

    REMEDIATION: ClassVar[str] = (
        "Read the quoted passage, and remove it if nobody the repository trusts wrote it."
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._judge: Judge | None = None
        self._failure: str | None = None
        self._resolved = False
        self._failure_reported = False
        self._budget_reported = False

    def applicable(self, ctx: ScanContext) -> bool:
        return bool(getattr(ctx.config, "judge", None))

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        def operational(rule_id: str, title: str, message: str, remediation: str) -> DeclaredRule:
            return DeclaredRule(
                id=rule_id,
                title=title,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                category=Category.OPERATIONAL,
                detector=AgentJudgeDetector.id,
                message=message,
                remediation=remediation,
                references=(ref.OWASP_LLM_PROMPT_INJECTION,),
            )

        return (
            DeclaredRule(
                id=JUDGED_RULE,
                title="A language model judges agent-facing text to be subverting the agent",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=AgentJudgeDetector.id,
                message=(
                    "The judge the operator named read this agent-facing text and judged a "
                    "passage in it to be steering the agent against its user: overriding its "
                    "instructions, hiding something, acting without approval, moving secrets, "
                    "running fetched code or widening its own permissions."
                ),
                references=(ref.OWASP_LLM_PROMPT_INJECTION,),
                remediation=AgentJudgeDetector.REMEDIATION,
            ),
            operational(
                STATUS_RULE,
                "A language model judged the scan's agent-facing text",
                "Agent-facing text in this scan was also judged by the model named here.",
                "None needed.",
            ),
            operational(
                UNAVAILABLE_RULE,
                "The judge was asked for and could not be used",
                "The scan was asked to use a judge and could not, so agent-facing text was not judged.",
                "Check the --judge setting, the model's availability and its API key.",
            ),
            operational(
                BUDGET_RULE,
                "The judge's call budget ran out",
                "The judge reached its call budget, so agent-facing text after that point was not judged.",
                "Raise --judge-max-calls, or narrow the scan.",
            ),
        )

    # -- the run -----------------------------------------------------------------------------

    def _ready(self, ctx: ScanContext) -> bool:
        """Build the judge once: the backend, the organisation's network policy, the cache."""
        with self._lock:
            if self._resolved:
                return self._judge is not None
            self._resolved = True
            try:
                provider = ProviderFactory.from_spec(str(ctx.config.judge))
            except JudgeError as exc:
                self._failure = str(exc)
                return False
            if provider.remote:
                constraints = getattr(ctx.config, "constraints", None)
                if constraints is not None and not getattr(constraints, "allow_network", True):
                    self._failure = (
                        f"{provider.label} would send agent-facing text off this machine, and "
                        "the organisation's policy forbids network access"
                    )
                    return False
                if not getattr(ctx.config, "intel_feed", True):
                    self._failure = (
                        f"{provider.label} would send agent-facing text off this machine, and "
                        "the scan was run with --offline"
                    )
                    return False
            cache = VerdictCache(
                VerdictCache.default_directory() if getattr(ctx.config, "use_cache", True) else None
            )
            self._judge = Judge(
                provider,
                cache=cache,
                max_calls=int(getattr(ctx.config, "judge_max_calls", DEFAULT_MAX_CALLS)),
            )
            return True

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if isinstance(unit, RepositoryUnit):
            if not self._ready(ctx):
                with self._lock:
                    first = not self._failure_reported
                    self._failure_reported = True
                return (
                    [
                        self._operational(
                            UNAVAILABLE_RULE,
                            f"The judge could not be used: {self._failure}.",
                            ctx,
                            incomplete=True,
                        )
                    ]
                    if first
                    else []
                )
            if self._judge is None:
                return []
            provider = self._judge.provider
            where = "a remote service" if provider.remote else "this machine"
            return [
                self._operational(
                    STATUS_RULE,
                    f"Agent-facing text was also judged by {provider.label}, on {where}.",
                    ctx,
                )
            ]
        if not isinstance(unit, FileUnit) or unit.content.is_binary:
            return ()
        pieces = AgentText.of(unit)
        if not pieces or not self._ready(ctx):
            return ()
        findings: list[Finding] = []
        for kind, text in pieces:
            for chunk in Chunker.split(text):
                verdict = self._ask(unit, ctx, kind, chunk, findings)
                if verdict is not None and verdict.verdict != "benign" and verdict.verified:
                    findings.append(self._finding(unit, ctx, kind, verdict))
                    break
        return findings

    def _ask(
        self, unit: FileUnit, ctx: ScanContext, kind: str, text: str, findings: list[Finding]
    ) -> Verdict | None:
        if self._judge is None or self._failure is not None:
            return None
        try:
            return self._judge.judge(kind, unit.content.path, text)
        except BudgetExhausted:
            with self._lock:
                first = not self._budget_reported
                self._budget_reported = True
            if first:
                findings.append(
                    self._operational(
                        BUDGET_RULE,
                        f"The judge's budget of {self._judge.max_calls} calls ran out at "
                        f"{unit.content.path}; agent-facing text after it was not judged.",
                        ctx,
                        incomplete=True,
                    )
                )
            return None
        except JudgeError as exc:
            with self._lock:
                first = self._failure is None
                self._failure = str(exc)
            if first:
                findings.append(
                    self._operational(
                        UNAVAILABLE_RULE,
                        f"The judge stopped answering during the scan: {exc}.",
                        ctx,
                        incomplete=True,
                    )
                )
            return None

    def _finding(self, unit: FileUnit, ctx: ScanContext, kind: str, verdict: Verdict) -> Finding:
        content = unit.content
        index = content.text.find(verdict.evidence)
        start = len(content.text[: max(index, 0)].encode("utf-8"))
        end = start + len(verdict.evidence.encode("utf-8")) if index >= 0 else start
        if verdict.verdict == "malicious":
            severity = (
                Severity.HIGH if getattr(ctx.config, "judge_blocks", False) else Severity.MEDIUM
            )
        else:
            severity = Severity.LOW
        message = (
            f"{verdict.judge} judged this {kind} {verdict.verdict} ({verdict.category}): "
            f"{verdict.reason} Not reproducible offline: it rests on a language model's reading."
        )
        return Finding(
            rule_id=JUDGED_RULE,
            category=Category.SUSPICIOUS,
            severity=severity,
            confidence=Confidence.MEDIUM,
            message=message,
            location=Location(
                path=content.path,
                line=content.line_of(start),
                byte_start=start,
                byte_end=end,
                project=unit.project,
            ),
            evidence=Evidence(
                kind=EvidenceKind.SNIPPET,
                match_hash=Evidence.hash_bytes(verdict.evidence.encode("utf-8")),
                redaction=RedactionMode.MASKED,
                snippet=Redactor.mask(verdict.evidence[:200]),
                span=(start, end),
                metadata=(
                    ("judge", verdict.judge),
                    ("family", verdict.family),
                    ("category", verdict.category),
                ),
            ),
            remediation=self.REMEDIATION,
            explanation=Explanation(summary=verdict.reason, matched_rule=JUDGED_RULE),
            risk=ctx.scorer.score(severity, Confidence.MEDIUM),
            detector=self.id,
            references=(ref.OWASP_LLM_PROMPT_INJECTION,),
        )

    def _operational(
        self, rule_id: str, message: str, ctx: ScanContext, *, incomplete: bool = False
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            category=Category.OPERATIONAL,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            message=message,
            location=Location(path="."),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(f"{rule_id}:{message}".encode()),
                redaction=RedactionMode.NONE,
            ),
            remediation="None needed." if rule_id == STATUS_RULE else "Check the --judge setting.",
            explanation=Explanation(summary=message, matched_rule=rule_id),
            risk=ctx.scorer.score(Severity.INFO, Confidence.CONFIRMED),
            detector=self.id,
            degrades_coverage=incomplete,
        )


__all__ = ["AgentJudgeDetector", "AgentText"]
