"""The `cordon-scanner mcp` command as the command line registers it: its name, help and options.

The command line builds its parser for every command, a scan included, and found this front end by
entry point on `mcp.server:Server`, so every scan imported the MCP server and its tools to describe
one subcommand (0.13 s of a pre-commit scan's start, 4 Nov). This class describes the command and
imports the server only when `mcp` runs.
"""

from __future__ import annotations

import argparse
from typing import ClassVar

from cordon_scanner.mcp.options import McpOptions


class McpCommand:
    """The command line's front-end contract (`cli.parser.CommandParser.front_ends`)."""

    NAME: ClassVar[str] = "mcp"
    HELP: ClassVar[str] = "serve Cordon to AI agents over the Model Context Protocol (stdio)"

    @staticmethod
    def configure(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
        return McpOptions.configure(parser)

    @staticmethod
    def main(argv: list[str] | None = None) -> int:
        from cordon_scanner.mcp.server import Server

        return Server.main(argv)


__all__ = ["McpCommand"]
