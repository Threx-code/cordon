"""`agent inventory`, `agent report` and `agent mcp-approve`: this machine's AI agents and MCP
servers, for an organisation's device management, and the tools a repository's remote MCP servers
are approved to serve."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from cordon_scanner.foundation.errors import CordonError, ExitCode
from cordon_scanner.version import PROGRAM


class AgentCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        agent = sub.add_parser(
            "agent",
            help="this machine's AI agents and MCP servers, for an organisation's MDM (read-only, disclosed)",
        ).add_subparsers(dest="agent_command")
        agent.add_parser(
            "inventory", help="print exactly what `agent report` would send; sends nothing"
        )
        agent_report = agent.add_parser(
            "report", help="send the inventory with the MDM's device token"
        )
        agent_report.add_argument("--url", default=None, help="Cordon Cloud API base")
        approve = agent.add_parser(
            "mcp-approve",
            help="record the tools each remote MCP server in the repository serves now (.cordon/mcp-tools.json)",
        )
        approve.add_argument(
            "target", nargs="?", default=".", help="repository directory (default: .)"
        )

    @classmethod
    def run(cls, args: argparse.Namespace) -> int:
        import json

        from cordon_scanner.cloud import CloudError, device

        action = getattr(args, "agent_command", None)
        if action == "mcp-approve":
            return cls._approve_mcp_tools(Path(args.target))
        if action not in ("inventory", "report"):
            print(f"{PROGRAM}: agent needs inventory, report or mcp-approve", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)
        payload = device.DeviceInventory.collect()
        if action == "inventory":
            print(json.dumps(payload, indent=2, sort_keys=True))
            return int(ExitCode.CLEAN)
        try:
            receipt = device.DeviceInventory.report(payload, url=args.url)
        except CloudError as exc:
            print(f"{PROGRAM}: {exc}", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)
        inventory = payload["inventory"]
        print(
            f"sent: {len(inventory['tools'])} tool(s), {len(inventory['mcp_servers'])} MCP server(s), "
            f"{len(payload['findings'])} finding(s){f' (receipt {receipt})' if receipt else ''}"
        )
        return int(ExitCode.CLEAN)

    @staticmethod
    def _approve_mcp_tools(root: Path) -> int:
        """List every remote MCP server's tools and record their fingerprints. A later `scan
        --online` reports any tool added or changed since (`SUSPECT.MCP.TOOLS_CHANGED.001`)."""
        from cordon_scanner.detect.agents.agents import MCP_PATHS, McpConfigs
        from cordon_scanner.foundation.files.globs import PathGlob
        from cordon_scanner.intel.store.live_mcp import LiveMcp, LiveMcpError, McpApprovals

        if not root.is_dir():
            raise CordonError(f"mcp-approve needs a repository directory: {root}")
        recorded: dict[str, dict[str, Any]] = {}
        failed = 0
        for path in sorted(p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts)[
            :200_000
        ]:
            relative = path.relative_to(root).as_posix()
            if not any(PathGlob.matches(relative, pattern) for pattern in MCP_PATHS):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for name, server in McpConfigs.mcp_servers(relative, text):
                url = LiveMcp.remote_url(server)
                if url is None or name in recorded:
                    continue
                try:
                    tools = LiveMcp.tools(url)
                except LiveMcpError as exc:
                    failed += 1
                    print(f"{PROGRAM}: {name} ({url}) not read: {exc}", file=sys.stderr)
                    continue
                recorded[name] = McpApprovals.record(url, tools)
                print(f"{name}: {len(tools)} tool(s) recorded from {url}")
        if not recorded:
            print(f"{PROGRAM}: no remote MCP server was read; nothing recorded", file=sys.stderr)
            return int(ExitCode.SCANNER_ERROR if failed else ExitCode.CLEAN)
        written = McpApprovals.write(root, recorded)
        print(f"wrote {written}: commit it, so a reviewer sees what was approved")
        return int(ExitCode.SCANNER_ERROR if failed else ExitCode.CLEAN)


__all__ = ["AgentCommand"]
