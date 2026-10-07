"""Remote MCP servers, read as they serve now (advanced gap M6). Only with `--online`.

For every remote server an MCP configuration in the repository names, the tools it serves are
listed (`intel/live_mcp.py`) and:

* each served description is held to the same test as a description in a server's source
  (`McpServerSource._poisoned_description`): reaching for other tools, secrecy, tags addressed to
  the model, credential files, invisible characters;
* where the repository records approved fingerprints (`.cordon/mcp-tools.json`, written by
  `cordon-scanner agent mcp-approve`), every tool added or changed since is reported: what the
  agent is told today is not what somebody reviewed;
* a server that could not be read is said, never passed.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Final

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
from cordon_scanner.core.scoring import ScoringContext
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit
from cordon_scanner.detect.catalogue import DeclaredRule

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import ScanContext, Unit

POISONED_RULE: Final = "SUSPECT.MCP.LIVE_TOOL_DESCRIPTION.001"
CHANGED_RULE: Final = "SUSPECT.MCP.TOOLS_CHANGED.001"
UNREAD_RULE: Final = "OPERATIONAL.MCP.LIVE_UNREAD.001"
MAX_SERVERS: Final = 10


class LiveMcpDetector(BaseDetector):
    id = "mcp-live"
    version = "0.1.0"
    categories = frozenset({Category.SUSPICIOUS, Category.OPERATIONAL})
    # A remote server is asked over the network, so the detector declares it: skipped offline,
    # and exercised against a substituted server in tests/unit/test_live_mcp.py.
    requires = DetectorRequirements(content=True, network=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return not ctx.offline

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id=POISONED_RULE,
                title="A remote MCP server serves a tool description that steers the agent",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=LiveMcpDetector.id,
                message=(
                    "A tool description the server serves now addresses the agent rather than "
                    "describing the tool. The agent reads it as an instruction, before any tool runs."
                ),
                references=(ref.MCP_SECURITY, ref.OWASP_LLM_PROMPT_INJECTION),
                remediation="Remove the server from the configuration until its publisher explains the description.",
            ),
            DeclaredRule(
                id=CHANGED_RULE,
                title="A remote MCP server's tools changed since they were approved",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=LiveMcpDetector.id,
                message=(
                    "The tools this server serves differ from the fingerprints recorded when it was "
                    "approved. A server decides its descriptions at request time, so a reviewed server "
                    "can change what it tells the agent without any change to the repository."
                ),
                references=(ref.MCP_SECURITY, ref.OWASP_LLM_PROMPT_INJECTION),
                remediation=(
                    "Read the changed descriptions; if they are what you expect, record them again "
                    "with `cordon-scanner agent mcp-approve`."
                ),
            ),
            DeclaredRule(
                id=UNREAD_RULE,
                title="A remote MCP server could not be read",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                category=Category.OPERATIONAL,
                detector=LiveMcpDetector.id,
                message="The server's tools were not listed, so what it serves now was not checked.",
                references=(ref.MCP_SECURITY,),
                remediation="Check the URL and that the server accepts unauthenticated tools/list, or review it by hand.",
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        from cordon_scanner.detect.agents import MCP_PATHS, AgentPaths, McpConfigs, McpServerSource
        from cordon_scanner.intel.live_mcp import LiveMcp, LiveMcpError, McpApprovals

        if (
            ctx.offline
            or not isinstance(unit, FileUnit)
            or unit.content.is_binary
            or "!" in unit.content.path
        ):
            return []
        if not AgentPaths._paths_match(unit.content.path, MCP_PATHS):
            return []
        root = Path(ctx.repository.root) if ctx.repository is not None else None
        approvals = McpApprovals.load(root) if root is not None else None
        findings: list[Finding] = []
        remote = [
            (name, url)
            for name, server in McpConfigs.mcp_servers(unit.content.path, unit.content.text)
            if (url := LiveMcp.remote_url(server))
        ]
        for name, url in remote[:MAX_SERVERS]:
            if ctx.out_of_time():
                break
            try:
                tools = LiveMcp.tools(url)
            except LiveMcpError as exc:
                findings.append(
                    self._finding(
                        UNREAD_RULE,
                        unit,
                        ctx,
                        name,
                        f"MCP server `{name}` ({url}) was not read: {exc}.",
                    )
                )
                continue
            for tool in tools:
                reason = McpServerSource._poisoned_description(tool.description)
                if reason is not None:
                    findings.append(
                        self._finding(
                            POISONED_RULE,
                            unit,
                            ctx,
                            name,
                            f"MCP server `{name}` serves tool `{tool.name}` with a description that {reason}. "
                            "This is what the agent is told now, not what the repository holds.",
                        )
                    )
            approved = (approvals or {}).get("servers", {}).get(name) if approvals else None
            if isinstance(approved, dict):
                changed = McpApprovals.differences(approved, tools)
                if changed:
                    listed = ", ".join(f"{kind} `{tool}`" for kind, tool in changed[:8])
                    findings.append(
                        self._finding(
                            CHANGED_RULE,
                            unit,
                            ctx,
                            name,
                            f"MCP server `{name}` serves tools that differ from the ones approved: {listed}"
                            + (f" and {len(changed) - 8} more" if len(changed) > 8 else "")
                            + ".",
                        )
                    )
        return findings

    def _finding(
        self, rule_id: str, unit: FileUnit, ctx: ScanContext, server: str, message: str
    ) -> Finding:
        rule = next(r for r in self.declared_rules() if r.id == rule_id)
        text = unit.content.text
        index = max(text.find(f'"{server}"'), 0)
        start = len(text[:index].encode("utf-8"))
        line = unit.content.line_of(start)
        return Finding(
            rule_id=rule.id,
            category=rule.category,
            severity=rule.severity,
            confidence=rule.confidence,
            message=message,
            location=Location(path=unit.content.path, line=line, project=unit.project),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(f"{rule_id}:{server}:{message}".encode()),
                redaction=RedactionMode.NONE,
                metadata=(("server", server),),
            ),
            remediation=rule.remediation,
            explanation=Explanation(summary=rule.title, matched_rule=rule.id),
            risk=ctx.scorer.score(
                rule.severity, rule.confidence, ScoringContext(in_install_hook=False)
            ),
            detector=self.id,
            always_report=rule.category is Category.OPERATIONAL,
            references=rule.references,
        )


__all__ = ["CHANGED_RULE", "POISONED_RULE", "UNREAD_RULE", "LiveMcpDetector"]
