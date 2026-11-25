"""The remote MCP rug pull at the agent hook (BP-12-5, BP-21-7): a tools list that changed since it was approved is REVIEW (R604).

An approval stores the digest of a remote server's tools list (T0, `.cordon/mcp-tools.json`, `agent mcp-approve`). At each session start
the hook reads the list of every approved remote server the project configures (T1) and compares: equal is quiet, different is
recorded in the device store with the diff (tools added, removed and redescribed, never a description). Every later call of a tool of
that server is then decided at the agent hook with the scanner's own finding for it (`SUSPECT.MCP.TOOLS_CHANGED.001`, which the decision
maps to R604), so the call is denied with an approval request until the list is approved again; the call of a server whose list is
unchanged is not gated. A server that cannot be read is not flagged: the sweep says it could not read it and the earlier state stands.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.cloud.runtime import ScanEvidence
from cordon_scanner.decide.decision.evidence import FindingFact
from cordon_scanner.decide.resolve.resolution import Resolution

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from cordon_scanner.cloud.local_store import LocalStore
    from cordon_scanner.decide.decision.evidence import ArtifactRef

KIND: Final = "rug-pull"
RULE: Final = "SUSPECT.MCP.TOOLS_CHANGED.001"


class RugPull:
    CONFIGS: ClassVar[tuple[str, ...]] = (
        ".mcp.json",
        ".cursor/mcp.json",
        ".vscode/mcp.json",
        ".windsurf/mcp.json",
        ".roo/mcp.json",
    )
    MAX_CONFIG_BYTES: ClassVar[int] = 1 << 20
    MAX_SERVERS: ClassVar[int] = 10
    SHOWN: ClassVar[int] = 5
    SAFE_NAME: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_.:-]{1,64}")

    # -- the server a tool call belongs to -------------------------------------------------

    @staticmethod
    def key(server: str) -> str:
        """The name a server is kept under: lower case, only characters a store name allows."""
        return re.sub(r"[^a-z0-9._-]", "_", server.lower())[:60] or "server"

    @classmethod
    def held_key(cls, store: LocalStore, hook_input: Mapping[str, Any]) -> str | None:
        """The key of the server a tool call belongs to when the last session start found its list changed, else None."""
        tool = hook_input.get("tool_name")
        if not isinstance(tool, str) or not tool.startswith("mcp__") or tool.count("__") < 2:
            return None
        key = cls.key(tool.split("__", 2)[1])
        return key if cls.record(store, key) is not None else None

    @classmethod
    def record(cls, store: LocalStore, key: str) -> dict[str, Any] | None:
        """What the last session start found of this server, when its list had changed."""
        blob = store.blob(KIND, key)
        if blob is None:
            return None
        try:
            found = json.loads(blob.data)
        except ValueError:
            return None  # S2: a damaged record is no record; the next session start writes it again
        return found if isinstance(found, dict) and found.get("state") == "changed" else None

    # -- what the runtime reads ----------------------------------------------------------------

    @classmethod
    def resolver(cls, store: LocalStore) -> Callable[[str], Resolution]:
        """The resolver of `mcp_tool`: the server as it is now, by the digest of the list it serves."""

        def resolve(reference: str) -> Resolution:
            found = cls.record(store, reference)
            if found is None:
                return Resolution.failed(
                    "mcp_server", Resolution.stand_in("mcp", reference), "unparseable"
                )
            return Resolution(
                kind="mcp_server",
                subject_id=f"mcp/{reference}",
                status="resolved",
                digest=f"sha256:{str(found.get('t1', '')).removeprefix('sha256:')}",
            )

        return resolve

    @classmethod
    def scan(cls, store: LocalStore) -> Callable[[ArtifactRef], ScanEvidence | None]:
        """The scan source: the finding the sweep made for a server, and nothing for any other artifact (which stays unscanned)."""
        from cordon_scanner.detect.agents.mcp_servers.live import LiveMcpDetector

        rule = next(r for r in LiveMcpDetector.declared_rules() if r.id == RULE)

        def scanned(artifact: ArtifactRef) -> ScanEvidence | None:
            if (
                not artifact.subject_id.startswith("mcp/")
                or cls.record(store, artifact.subject_id[4:]) is None
            ):
                return None
            fact = FindingFact(
                rule_id=RULE,
                severity=rule.severity.name.lower(),
                confidence=rule.confidence.name.lower(),
                category=rule.category.name.lower(),
            )
            return ScanEvidence(findings=(fact,))

        return scanned

    # -- the session start ------------------------------------------------------------------------

    @classmethod
    def sweep(
        cls,
        store: LocalStore,
        hook_input: Mapping[str, Any],
        clock: datetime,
        fetch: Callable[[str], list[Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Read the list of each approved remote server this project configures and record the ones that changed. Returns the records."""
        from cordon_scanner.detect.agents.mcp_servers.declarations import McpConfigs
        from cordon_scanner.intel.registry import LiveMcp, LiveMcpError, McpApprovals

        cwd = hook_input.get("cwd")
        if not isinstance(cwd, str) or not cwd:
            return []
        root = Path(cwd)
        approvals = McpApprovals.load(root)
        if approvals is None:
            return []
        read = fetch or LiveMcp.tools
        found: list[dict[str, Any]] = []
        for name, url in cls.remote_servers(root, McpConfigs, LiveMcp)[: cls.MAX_SERVERS]:
            approved = approvals["servers"].get(name)
            if not isinstance(approved, dict):
                continue
            try:
                tools = read(url)
            except LiveMcpError:
                continue  # S2: not read is not flagged; the state from the last read stands
            key = cls.key(name)
            t1 = McpApprovals.digest(tools)
            if McpApprovals.unchanged(approved, t1):
                store.put_blob(KIND, key, b'{"state": "clear"}', clock.isoformat())
                continue
            changed = McpApprovals.differences(approved, tools)
            record = cls.changed(name, approved, t1, changed, clock)
            store.put_blob(
                KIND, key, json.dumps(record, sort_keys=True).encode(), clock.isoformat()
            )
            found.append(record)
        return found

    @classmethod
    def remote_servers(cls, root: Path, configs: Any, live: Any) -> list[tuple[str, str]]:
        servers: list[tuple[str, str]] = []
        for relative in cls.CONFIGS:
            path = root / relative
            try:
                if not path.is_file() or path.stat().st_size > cls.MAX_CONFIG_BYTES:
                    continue
                text = path.read_text(encoding="utf-8")
            except (OSError, ValueError):
                continue  # S2: an unreadable config file names no server
            for name, server in configs.mcp_servers(relative, text):
                url = live.remote_url(server)
                if url:
                    servers.append((name, url))
        return servers

    @classmethod
    def changed(
        cls,
        name: str,
        approved: dict[str, Any],
        t1: str | None,
        changed: list[tuple[str, str]],
        clock: datetime,
    ) -> dict[str, Any]:
        """The record of one changed server: digests, and the tools added, removed and redescribed by name only."""
        kinds: dict[str, list[str]] = {}
        for kind, tool in changed:
            kinds.setdefault(kind, []).append(
                tool if cls.SAFE_NAME.fullmatch(tool) else "(a name that is not plain text)"
            )
        return {
            "state": "changed",
            "server": cls.key(name),
            "t0": str(approved.get("list_digest", "none")),
            "t1": t1 or "none",
            "added": kinds.get("added", []),
            "removed": kinds.get("removed", []),
            "description_changed": kinds.get("description changed", []),
            "changed": kinds.get("changed", []),
            "read_at": clock.isoformat(),
        }

    @classmethod
    def describe(cls, record: dict[str, Any]) -> str:
        """The diff as the agent's user reads it: tool names only, at most `SHOWN` of each kind."""
        parts = []
        for label, field in (
            ("added", "added"),
            ("removed", "removed"),
            ("description changed", "description_changed"),
            ("changed", "changed"),
        ):
            names = record.get(field) or []
            if names:
                extra = f" and {len(names) - cls.SHOWN} more" if len(names) > cls.SHOWN else ""
                parts.append(f"{label}: {', '.join(names[: cls.SHOWN])}{extra}")
        return "; ".join(parts) or "its list digest differs"

    @classmethod
    def session_context(cls, records: list[dict[str, Any]]) -> str:
        """What the session start tells the agent's user: which servers changed and that their calls are held for review."""
        lines = [
            f"Cordon: MCP server {r['server']} serves tools that differ from the ones approved ({cls.describe(r)}); its tools are held for review (R604)."
            for r in records
        ]
        return "\n".join(lines)


__all__ = ["KIND", "RULE", "RugPull"]
