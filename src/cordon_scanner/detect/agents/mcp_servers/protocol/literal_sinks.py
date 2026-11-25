"""Addresses an MCP server writes into its own source that no tool of a server should reach.

```
  cloud metadata   http://169.254.169.254/latest/meta-data/iam/...    a cloud machine's own credentials, handed to
                   http://metadata.google.internal/computeMetadata/v1/ whatever asks from the machine
  webhook          a chat webhook with its secret written in            write-only channels to somebody's chat
  drop             an anonymous paste or file-drop service              somewhere to send data and to fetch it again
  tunnel           a tunnel, request-capture or interaction host        a callback address for whoever wrote the server
  logger           an IP-logging link                                   a link that reports who opened it
```

A cloud SDK reaches the metadata service inside its own library; a tool server whose source names the address is after
what the machine holds. A webhook URL is a credential: a server that carries its author's, rather than reading the
user's from configuration, sends what its tools handle to the author. Only string literals are read, in any language;
a bare address with no scheme (an entry of a blocklist) and a placeholder written for a reader to fill in are neither.
The hosts are the shared destination lists (`analysis/shared/destinations.py`).
"""

from __future__ import annotations

import re
from typing import ClassVar, Final
from urllib.parse import urlsplit

from cordon_scanner.analysis.shared import destinations as shared

_MAX: Final = 1500
_PLACEHOLDER: Final = re.compile(r"(?i)[<>{}*]|xxxx|\byour\b|placeholder|\.\.\.")


class McpLiteralSinks:
    """`metadata(literal)` / `sink_kind(literal)`: what a string literal is."""

    _METADATA_URL: ClassVar[re.Pattern[str]] = re.compile(
        r"^https?://(?:169\.254\.169\.254|169\.254\.170\.2|168\.63\.129\.16|100\.100\.100\.200"
        r"|metadata\.google\.internal|metadata\.goog|\[?fd00:ec2::254\]?|instance-data(?:\.ec2\.internal)?)"
        r"(?::\d+)?(?:[/?#]|$)",
        re.IGNORECASE,
    )
    _METADATA_PATH: ClassVar[re.Pattern[str]] = re.compile(
        r"^/(?:latest/(?:meta-data|api/token|user-data|dynamic)|computeMetadata/v1"
        r"|metadata/(?:instance|identity)|opc/v[12])(?:[/?#]|$)",
        re.IGNORECASE,
    )
    #: A webhook whose secret is in the address.
    _WEBHOOKS: ClassVar[tuple[re.Pattern[str], ...]] = (
        re.compile(
            r"^https://(?:discord|discordapp)\.com/api(?:/v\d+)?/webhooks/\d{4,22}/[\w-]{8,}",
            re.I,
        ),
        re.compile(
            r"^https://hooks\.slack\.com/(?:services|workflows)/T[A-Z0-9]{3,}/B[A-Z0-9]{3,}/[\w-]{8,}",
            re.I,
        ),
        re.compile(r"^https://api\.telegram\.org/bot\d{4,12}:[\w-]{8,}/", re.I),
        re.compile(
            r"^https://[\w.-]+\.webhook\.office\.com/webhookb2/[\w@-]+/IncomingWebhook/\w+/[\w-]+",
            re.I,
        ),
    )
    #: The kinds, by the destination list that names their hosts, in the order a literal is tried.
    KINDS: ClassVar[tuple[str, ...]] = ("webhook", "drop", "tunnel", "logger")

    @classmethod
    def metadata(cls, literal: str) -> bool:
        """Whether a literal is a request to a cloud instance's metadata service: a URL to its address, or a path
        only it serves."""
        if len(literal) > _MAX:
            return False
        return bool(cls._METADATA_URL.match(literal) or cls._METADATA_PATH.match(literal))

    @staticmethod
    def _on(host: str, hosts: frozenset[str]) -> bool:
        return any(host == h or host.endswith("." + h) for h in hosts)

    @classmethod
    def sink_kind(cls, literal: str) -> str | None:
        """`webhook`, `drop`, `tunnel` or `logger` when the literal is an address of that kind, else None: a webhook
        with its secret written in, a path on a paste or file-drop host, a request-capture, tunnel or interaction
        host, or an IP-logging link. A placeholder and a bare service address are none."""
        if len(literal) > _MAX or _PLACEHOLDER.search(literal):
            return None
        if any(p.match(literal) for p in cls._WEBHOOKS):
            return "webhook"
        if not literal.lower().startswith(("https://", "http://")):
            return None
        try:
            parts = urlsplit(literal)
            host = (parts.hostname or "").lower()
        except ValueError:
            return None  # an address that does not parse (`https://[your-host]/x`) is no sink
        path = parts.path.strip("/")
        if not host:
            return None
        if cls._on(host, shared.PASTE_HOSTS) and len(path) >= 3:
            return "drop"
        # A tunnel is reached at a subdomain it hands out (`abcd.ngrok-free.app`); the bare service is a link.
        if cls._on(host, shared.TUNNEL_HOSTS) and (
            len(path) >= 3 or host not in shared.TUNNEL_HOSTS
        ):
            return "tunnel"
        if cls._on(host, shared.IP_LOGGER_HOSTS) and len(path) >= 3:
            return "logger"
        return None


__all__ = ["McpLiteralSinks"]
