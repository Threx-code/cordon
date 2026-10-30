"""A4: the packages MCP servers launch, read and scanned without being installed or run."""

from __future__ import annotations

import contextlib
import re
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Final

from cordon_scanner.detect.agents.findings import AgentFinding
from cordon_scanner.detect.agents.mcp_servers.declarations import McpConfigs
from cordon_scanner.detect.agents.mcp_servers.source import McpServerSource
from cordon_scanner.detect.agents.paths import MCP_PATHS, AgentPaths
from cordon_scanner.detect.agents.rule_catalogue import AgentRule
from cordon_scanner.detect.agents.text_patterns import FETCH_EXEC, HIDDEN, INJECTION, INJECTION_INTL
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.foundation import references as ref
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

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import ScanContext, Unit


class McpPackageDetector(BaseDetector):
    """A4: the packages MCP servers launch, read and scanned without being installed or run.

    Tools that inspect an MCP server by STARTING it run the thing they are checking: for a local
    server that is `npx -y some-package`, and a malicious package fires during the check. This
    reads the package instead, in this order:

    1. the copy already in the tree (`node_modules/<pkg>`, a virtualenv's `site-packages`), which
       is local and needs no network;
    2. with `--online`, the published archive, fetched from the registry's own host, verified
       against its digest, never installed and never run -- fetching names the package to the
       registry, which the default mode promises not to do;
    3. otherwise `OPERATIONAL.MCP.UNRESOLVED`: a server whose code was not read is never passed.

    Whatever it reads gets every rule, plus a tool-poisoning pass: hidden characters or
    agent-directed instructions in the tool descriptions the server will hand to the agent.
    """

    #: Ecosystems whose packages install into the project's own `node_modules`.
    INSTALLED_UNDER_NODE_MODULES: ClassVar[frozenset[str]] = frozenset({"npm"})

    id = "mcp-packages"
    version = "0.2.0"
    categories = frozenset(
        {Category.MALICIOUS, Category.SUSPICIOUS, Category.VULNERABLE, Category.OPERATIONAL}
    )
    requires = DetectorRequirements(content=True)
    MAX_REPORTED: Final = 20
    MAX_SOURCE_FILES: Final = 2000
    MAX_SOURCE_BYTES: Final = 1 << 20

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        rule = TOOL_POISONING_RULE
        return (
            DeclaredRule(
                id=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                confidence=rule.confidence,
                category=rule.category,
                detector=McpPackageDetector.id,
                message=rule.message,
                remediation=rule.remediation,
                references=rule.references,
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit) or unit.content.is_binary:
            return ()
        path = unit.content.path.rpartition("!")[2]
        if not AgentPaths._paths_match(path, MCP_PATHS) or "!" in unit.content.path:
            return ()
        config = McpConfigs._json(unit.content)
        servers = (
            (config.get("mcpServers") or config.get("servers") or {})
            if isinstance(config, dict)
            else {}
        )
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for name, server in servers.items() if isinstance(servers, dict) else ():
            if not isinstance(server, dict) or not isinstance(server.get("command"), str):
                continue
            args = [str(a) for a in server.get("args") or () if isinstance(a, (str, int, float))]
            spec = McpConfigs.launched_package(server["command"], args)
            if spec is None or spec[0] not in McpConfigs.SPLIT_SPECS or (spec[0], spec[1]) in seen:
                continue
            if ctx.out_of_time():
                break
            seen.add((spec[0], spec[1]))
            findings.extend(self._examine(unit, ctx, str(name), spec[0], spec[1]))
        return findings

    # -- where the package comes from ------------------------------------------------------

    @staticmethod
    def _scan_root(ctx: ScanContext) -> Path | None:
        root = Path(ctx.repository.root) if ctx.repository is not None else None
        return root if root is not None and root.is_dir() else None

    def _local_copy(
        self, ctx: ScanContext, config_path: str, ecosystem: str, name: str
    ) -> list[Path]:
        """The package's own files in the tree, if it is installed there."""
        root = self._scan_root(ctx)
        if root is None:
            return []
        resolved_root = root.resolve()
        config_dir = (root / config_path).parent
        if ecosystem in McpPackageDetector.INSTALLED_UNDER_NODE_MODULES:
            for base in dict.fromkeys((config_dir, root)):
                candidate = base / "node_modules" / name
                if (candidate / "package.json").is_file() and candidate.resolve().is_relative_to(
                    resolved_root
                ):
                    return [candidate]
            return []
        wanted = re.sub(r"[-_.]+", "_", name).lower()
        for venv in (".venv", "venv", "env"):
            for dist_info in sorted((root / venv).glob("lib/python*/site-packages/*.dist-info"))[
                :5000
            ]:
                distribution = dist_info.name.removesuffix(".dist-info").rsplit("-", 1)[0]
                if re.sub(r"[-_.]+", "_", distribution).lower() != wanted:
                    continue
                site = dist_info.parent
                tops: set[str] = set()
                with contextlib.suppress(OSError):
                    for line in (dist_info / "RECORD").read_text(encoding="utf-8").splitlines():
                        top = line.split(",", 1)[0].split("/", 1)[0]
                        if top and top != ".." and not top.endswith((".dist-info", ".data")):
                            tops.add(top)
                return [
                    site / top
                    for top in sorted(tops)
                    if (site / top).exists()
                    and (site / top).resolve().is_relative_to(resolved_root)
                ]
        return []

    def _examine(
        self, unit: FileUnit, ctx: ScanContext, server: str, ecosystem: str, spec: str
    ) -> list[Finding]:
        from cordon_scanner.intel.registry import RegistryArtifacts, RegistryError

        name, version = McpConfigs.split_spec(ecosystem, spec)
        local = self._local_copy(ctx, unit.content.path, ecosystem, name)
        if local:
            label = f"{ecosystem} package {name}, installed in this tree,"
            nested: tuple[Finding, ...] = tuple(
                f for target in local for f in McpServerSource._scan_path(target, ctx)
            )
            sources = list(
                McpServerSource._files_under(local, self.MAX_SOURCE_FILES, self.MAX_SOURCE_BYTES)
            )
            purl = f"pkg:{ecosystem}/{name}"
        elif not ctx.offline:
            try:
                archive = RegistryArtifacts.package_archive(ecosystem, name, version)
            except RegistryError as exc:
                return [
                    self._unresolved(
                        unit, ctx, server, ecosystem, spec, f"it could not be fetched ({exc})"
                    )
                ]
            label = f"{ecosystem} package {archive.name}@{archive.version}, fetched (not installed, not run),"
            nested = McpServerSource._scan_archive_bytes(archive.filename, archive.data, ctx)
            sources = list(
                McpServerSource._archive_sources(
                    archive.filename, archive.data, self.MAX_SOURCE_FILES, self.MAX_SOURCE_BYTES
                )
            )
            purl = f"pkg:{ecosystem}/{archive.name}@{archive.version}"
        else:
            why = "it is not installed in this tree, and fetching it needs --online"
            return [self._unresolved(unit, ctx, server, ecosystem, spec, why)]
        reported = self._relay(unit, server, label, purl, spec, nested)
        reported.extend(self._tool_poisoning(unit, ctx, server, label, purl, spec, sources))
        return reported[: self.MAX_REPORTED]

    @staticmethod
    def _unresolved(
        unit: FileUnit, ctx: ScanContext, server: str, ecosystem: str, spec: str, why: str
    ) -> Finding:
        return AgentFinding.at_text(
            "OPERATIONAL.MCP.UNRESOLVED",
            unit,
            ctx,
            unit.content.text,
            spec,
            message=f"MCP server {server!r} runs {ecosystem} package {spec}, whose code was not examined: {why}.",
        )

    # -- what was found in it ---------------------------------------------------------------

    @staticmethod
    def _anchor(unit: FileUnit, spec: str) -> int:
        index = unit.content.text.find(spec)
        return len(unit.content.text[: max(index, 0)].encode())

    def _relay(
        self,
        unit: FileUnit,
        server: str,
        label: str,
        purl: str,
        spec: str,
        nested: Iterable[Finding],
    ) -> list[Finding]:
        reported: list[Finding] = []
        start = self._anchor(unit, spec)
        for found in nested:
            if (
                found.category in (Category.OPERATIONAL, Category.POLICY)
                or found.severity < Severity.MEDIUM
            ):
                continue
            member = found.location.path.split("!", 1)[-1]
            reported.append(
                Finding(
                    rule_id=found.rule_id,
                    category=found.category,
                    severity=found.severity,
                    confidence=found.confidence,
                    message=f"MCP server {server!r} runs {label} and was examined. In {member}: {found.message}",
                    location=Location(
                        path=unit.content.path,
                        line=unit.content.line_of(start),
                        package=purl,
                        project=unit.project,
                    ),
                    evidence=Evidence(
                        kind=EvidenceKind.HASH,
                        match_hash=found.evidence.match_hash
                        or Evidence.hash_bytes(found.rule_id.encode()),
                        redaction=RedactionMode.HASH_ONLY,
                    ),
                    remediation=found.remediation,
                    explanation=Explanation(
                        summary=f"In MCP server package {purl}", matched_rule=found.rule_id
                    ),
                    risk=found.risk,
                    detector=self.id,
                    references=found.references,
                )
            )
            if len(reported) >= self.MAX_REPORTED:
                break
        return reported

    def _tool_poisoning(
        self,
        unit: FileUnit,
        ctx: ScanContext,
        server: str,
        label: str,
        purl: str,
        spec: str,
        sources: list[tuple[str, str]],
    ) -> list[Finding]:
        """Hidden characters or agent-directed instructions in the text a server gives the agent."""
        start = self._anchor(unit, spec)
        for member, text in sources:
            for description in McpServerSource._tool_descriptions(text):
                hidden = HIDDEN.search(description.encode("utf-8"))
                injected = (
                    INJECTION.search(description)
                    or INJECTION_INTL.search(description)
                    or FETCH_EXEC.search(description)
                )
                if not (hidden or injected):
                    continue
                severity = Severity.HIGH if hidden else Severity.MEDIUM
                confidence = Confidence.HIGH if hidden else Confidence.MEDIUM
                what = "invisible characters" if hidden else "instructions addressed to the agent"
                rule = TOOL_POISONING_RULE
                return [
                    Finding(
                        rule_id=rule.rule_id,
                        category=Category.SUSPICIOUS,
                        severity=severity,
                        confidence=confidence,
                        message=(
                            f"MCP server {server!r} runs {label} and a tool description in {member} "
                            f"carries {what}. The agent reads every tool description as context, so "
                            f"this text steers it without the user seeing it."
                        ),
                        location=Location(
                            path=unit.content.path,
                            line=unit.content.line_of(start),
                            package=purl,
                            project=unit.project,
                        ),
                        evidence=Evidence(
                            kind=EvidenceKind.HASH,
                            match_hash=Evidence.hash_bytes(description.encode("utf-8")),
                            redaction=RedactionMode.HASH_ONLY,
                        ),
                        remediation=rule.remediation,
                        explanation=Explanation(summary=rule.title, matched_rule=rule.rule_id),
                        risk=ctx.scorer.score(severity, confidence),
                        detector=self.id,
                        references=rule.references,
                    )
                ]
        return []


TOOL_POISONING_RULE: Final = AgentRule(
    "SUSPECT.MCP.TOOL_POISONING.001",
    "An MCP server's tool description hides text or instructs the agent",
    Category.SUSPICIOUS,
    Severity.HIGH,
    Confidence.HIGH,
    "A tool description in the package an MCP server runs carries invisible characters (HIGH) or "
    "instructions addressed to the agent (MEDIUM). Agents read every tool description as context, "
    "so this steers the agent -- tool poisoning -- without the user seeing it.",
    "Do not run the server. Report the package to its registry if you did not write it.",
    (ref.MCP_SECURITY, ref.OWASP_LLM_PROMPT_INJECTION),
)


__all__ = ["TOOL_POISONING_RULE", "McpPackageDetector"]
