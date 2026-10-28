"""Where a remote MCP server lives, judged from its host alone, and the hosts that are placeholders or
this machine.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar, Final

from cordon_scanner.detect.agents import agent_config

if TYPE_CHECKING:
    from collections.abc import Iterator


PLACEHOLDER: Final = re.compile(
    r"^\$\{[^}]+\}$|^\$[A-Z_][A-Z0-9_]*$|^<[^>]+>$|^(?:your|changeme|xxx+|placeholder)", re.I
)

# Hosts to recognise in a URL, not addresses to bind.
LOCAL_HOSTS: Final = frozenset(
    {"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "host.docker.internal"}  # noqa: S104
)


class McpEndpoints:
    """Where a remote MCP server lives, judged from its host alone."""

    _WILDCARD_IP: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:^|[.-])(\d{1,3}(?:[.-]\d{1,3}){3})\.(?:sslip\.io|nip\.io)$"
    )
    #: Where instructions configure a server: an `mcpServers` block, or an `mcp add` command.
    _CONFIG: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)[\"']?mcp_?servers[\"']?\s*[:=]\s*[{\[]|\bmcp\s+add\b"
    )
    _URL: ClassVar[re.Pattern[str]] = re.compile(r"https?://[^\s\"'`<>)\]]{4,300}")
    #: A URL written for the reader to fill in: `https://YOUR-NGROK.ngrok.io`, `abc123.ngrok.app`.
    _PLACEHOLDER: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)your|xxx|example|abc123|placeholder|subdomain|\.\.\.|[<>{}*]|_id\b"
    )

    @staticmethod
    def untrusted(host: str) -> bool:
        """A tunnel, paste or interaction host, or a public IP address -- written bare or behind
        sslip.io/nip.io, which only resolve a name back to the address inside it."""
        import ipaddress

        from cordon_scanner.analysis.shared.destinations import Destinations

        host = host.lower().strip("[]").rstrip(".")
        if host in LOCAL_HOSTS:
            return False
        if Destinations.destination_matcher().search(host.encode("utf-8", "replace")):
            return True
        wildcard = McpEndpoints._WILDCARD_IP.search(host)
        literal = wildcard.group(1).replace("-", ".") if wildcard else host
        try:
            address = ipaddress.ip_address(literal)
        except ValueError:
            return False
        return address.is_global

    @staticmethod
    def in_text(text: str) -> Iterator[str]:
        """Every remote MCP server URL an instruction file tells the agent to connect to: those in
        the 1,500 characters after an `mcpServers` block opens, or on an `mcp add` line, that are
        not a placeholder for the reader to fill in."""
        for config in McpEndpoints._CONFIG.finditer(text):
            span = text[config.start() : config.end() + 1500]
            if config.group(0).lower().endswith("add"):
                span = span.split("\n", 1)[0]
            for found in McpEndpoints._URL.finditer(span):
                url = found.group(0).rstrip(".,;")
                if not McpEndpoints._PLACEHOLDER.search(agent_config.ApiTraffic.host_of(url)):
                    yield url


__all__ = ["LOCAL_HOSTS", "PLACEHOLDER", "McpEndpoints"]
