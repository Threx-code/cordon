"""The tool-call guard: one MCP `tools/call` judged before it runs.

The scanner reads what a package, a skill or a server ships. A guard reads what an agent is about
to do: the tool's name and the arguments it was called with, at the moment of the call, in a proxy
between the agent and the server (the backend's `firewall-proxy`) or in an agent's own hook. What it
sees is data the model produced -- often from text an attacker planted -- so every check reads the
values as data and nothing in them is ever run, fetched or decoded into anything but a string.

A verdict names each reason with the argument it came from (`GuardFinding`), so a block can be
explained to the person whose agent was stopped. See `ToolCallGuard`.
"""

from __future__ import annotations

from cordon_scanner.guard.calls import GuardFinding, GuardVerdict, ToolCallGuard

__all__ = ["GuardFinding", "GuardVerdict", "ToolCallGuard"]
