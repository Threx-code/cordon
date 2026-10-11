"""Cordon's MCP server: the scanner, offered to AI agents as Model Context Protocol tools.

`cordon-scanner mcp` serves over stdio. An agent asks before it acts -- is this package safe to
install, this skill safe to load, this MCP server safe to add -- and gets the scanner's own verdict.
Every tool reads; none installs, runs, writes into the workspace or changes configuration. Scans run
in a child process with a deadline, so a hung or oversized scan is ended, never inherited.

    server      JSON-RPC over stdio, both protocol eras: per-request `_meta` (2026-07-28) and the
                `initialize` handshake (2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05)
    tools       the tool catalogue and what each one runs
    results     a scan turned into a verdict an agent acts on
    runner      the child-process scanner: deadline, cancellation, output caps
    workspace   which paths a tool may read
    packages    package checks: stand-in lockfiles and install-command parsing
    extensions  editor extensions fetched by id, digest-verified where the registry allows
    untrusted   text from scanned files, made safe to hand to a model
    clients     configuration snippets for each agent
"""

from __future__ import annotations

from cordon_scanner.mcp.server import Server

__all__ = ["main"]

#: The entry point: `cordon-scanner mcp` hands the rest of its command line here.
main = Server.main
