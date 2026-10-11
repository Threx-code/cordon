"""Public network only: a scan whose input decides where it connects cannot reach inside the network.

With `--online`, some of what a scan connects to is named by what it scans: a remote MCP server's
URL in a configuration, an image's registry, a chart repository, an archive URL in a build file.
Scanning untrusted content online could then be steered at internal services -- a cloud metadata
endpoint, an admin console on 10.x, a database on localhost (server-side request forgery).

The guard sits at the one place every connection resolves: `socket.getaddrinfo`. Each answer is
filtered to globally routable addresses, and a name that resolves only to private, loopback,
link-local, carrier-grade NAT, reserved or multicast addresses is refused. The connection is made to
an address this filter returned, so a name that resolves publicly for a check and privately for the
connection (DNS rebinding) is refused too: there is no second resolution to win.

On in every scan the MCP server runs (its inputs come from an agent); for the CLI and CI, set
`CORDON_PUBLIC_NETWORK_ONLY=1` when scanning untrusted content online. Hosts the operator names in
`CORDON_ALLOWED_PRIVATE_HOSTS` (comma-separated: an internal registry, an intranet MCP server) are
exempt; nothing in a scanned repository can add to that list. A connection through a configured
HTTP proxy is resolved by the proxy, which applies its own egress rules.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import threading
from typing import Any, ClassVar, Final

ENABLE: Final = "CORDON_PUBLIC_NETWORK_ONLY"
ALLOWED: Final = "CORDON_ALLOWED_PRIVATE_HOSTS"


class PrivateAddressRefused(socket.gaierror):
    """A name that resolves only to addresses inside the network, refused by the guard."""


class NetworkGuard:
    _installed: ClassVar[bool] = False
    _lock: ClassVar[threading.Lock] = threading.Lock()
    _allowed: ClassVar[frozenset[str]] = frozenset()

    @staticmethod
    def public(address: str) -> bool:
        """Whether an address is globally routable: what may be connected to."""
        try:
            ip = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError:
            return False
        if isinstance(ip, ipaddress.IPv6Address):
            # An IPv4 address inside IPv6 is judged as the IPv4 address it carries.
            embedded = ip.ipv4_mapped or ip.sixtofour or (ip.teredo[1] if ip.teredo else None)
            if embedded is not None:
                ip = embedded
        return bool(ip.is_global) and not ip.is_multicast

    @staticmethod
    def host_key(host: Any) -> str:
        if isinstance(host, bytes):
            host = host.decode("ascii", "replace")
        return str(host or "").strip().strip("[]").rstrip(".").lower()

    @classmethod
    def enabled_by_environment(cls) -> bool:
        return os.environ.get(ENABLE, "").strip().lower() in {"1", "true", "yes", "on"}

    @classmethod
    def install(cls, allowed: frozenset[str] | None = None) -> None:
        """Filter every name resolution in this process from now on. Idempotent."""
        with cls._lock:
            if allowed is None:
                allowed = frozenset(
                    cls.host_key(h) for h in os.environ.get(ALLOWED, "").split(",") if h.strip()
                )
            cls._allowed = allowed
            if cls._installed:
                return
            original = socket.getaddrinfo

            def guarded(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
                answers = original(host, port, *args, **kwargs)
                key = cls.host_key(host)
                if key in cls._allowed:
                    return answers
                kept = [a for a in answers if cls.public(str(a[4][0]))]
                if not kept:
                    raise PrivateAddressRefused(
                        socket.EAI_NONAME,
                        f"refused {key or 'an empty host'}: it resolves only to private or local "
                        f"addresses, and this scan may reach the public network only ({ENABLE})",
                    )
                return kept

            socket.getaddrinfo = guarded
            cls._installed = True

    @classmethod
    def install_if_enabled(cls) -> bool:
        if cls.enabled_by_environment():
            cls.install()
            return True
        return False
