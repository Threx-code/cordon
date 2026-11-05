"""The `cordon-scanner mcp` options, read by the command line (`McpCommand`) and by the server's own
parser (`Server.parser`) alike, so neither imports the other to describe them."""

from __future__ import annotations

import argparse
from pathlib import Path


class McpOptions:
    @staticmethod
    def configure(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
        """The `mcp` options, on this command's own parser and on the CLI's `mcp` subparser, so
        help, completion and the generated command reference show what the command accepts."""
        sub = parser.add_subparsers(dest="mcp_command")
        config = sub.add_parser(
            "config", help="print the configuration that adds this server to an agent"
        )
        from cordon_scanner.mcp.clients import CLIENTS

        config.add_argument(
            "--client",
            required=True,
            choices=sorted(CLIENTS),
            metavar="CLIENT",
            help=f"the agent: {', '.join(sorted(CLIENTS))}",
        )
        config.add_argument(
            "--allow-online", action="store_true", help="configure the server with --allow-online"
        )
        parser.add_argument(
            "--root",
            action="append",
            metavar="DIR",
            help="a directory tools may read (repeatable; default: the current directory)",
        )
        parser.add_argument(
            "--allow-online",
            action="store_true",
            help="let tools ask registries, fetch packages, images and extensions, and read remote MCP servers",
        )
        parser.add_argument(
            "--allow-machine",
            action="store_true",
            help="let tools read this machine's installed packages and AI agent configuration",
        )
        parser.add_argument(
            "--model",
            metavar="SERVER",
            help="have Cordon's own model score the packages each scan holds: cordon-cloud, or the "
            "https:// address of a cordon-model-server (token in CORDON_MODEL_TOKEN). Only features are sent",
        )
        parser.add_argument(
            "--allow-private-network",
            action="store_true",
            help="let online tools connect to private and local addresses (an intranet MCP server or "
            "registry); by default a name an agent passes in may lead only to the public network",
        )
        parser.add_argument(
            "--timeout",
            type=float,
            default=600.0,
            metavar="SECONDS",
            help="deadline for one scan (default 600)",
        )
        parser.add_argument(
            "--per-file-timeout",
            type=float,
            default=None,
            metavar="SECONDS",
            help="budget for one file within a scan (default: the scanner's own; 0 means none)",
        )
        parser.add_argument(
            "--max-concurrent",
            type=int,
            default=4,
            metavar="N",
            help="scans run at once (default 4)",
        )
        parser.add_argument(
            "--rate",
            type=int,
            default=120,
            metavar="N",
            help="tool calls allowed per minute (default 120)",
        )
        parser.add_argument(
            "--max-findings",
            type=int,
            default=50,
            metavar="N",
            help="findings returned per call unless the call asks (default 50)",
        )
        parser.add_argument(
            "--audit-log",
            type=Path,
            metavar="PATH",
            help="append one JSON line per tool call: tool, verdict, duration (never arguments)",
        )
        return parser


__all__ = ["McpOptions"]
