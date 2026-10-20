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

import contextlib
import ipaddress
import os
import socket
import threading
from collections.abc import Iterator
from typing import Any, ClassVar, Final

ENABLE: Final = "CORDON_PUBLIC_NETWORK_ONLY"
ALLOWED: Final = "CORDON_ALLOWED_PRIVATE_HOSTS"


class PrivateAddressRefused(socket.gaierror):
    """A name that resolves only to addresses inside the network, refused by the guard."""


class NetworkSealed(socket.gaierror):
    """Any name resolution attempted during a sealed (offline) scan phase, refused outright.

    The seal is the security invariant behind "scan offline": once the pre-scan intel pull is
    done, the scan phase must not reach the network at all, even if a detector, a parser or a
    third-party library attempts it. An application flag that merely declines to fetch is not that
    guarantee -- a bug or a hostile dependency could still open a socket. The seal sits at the one
    place every outbound connection resolves (`socket.getaddrinfo`) and refuses it there, so the
    guarantee is enforced rather than promised.
    """


class NetworkGuard:
    _installed: ClassVar[bool] = False
    _lock: ClassVar[threading.Lock] = threading.Lock()
    _allowed: ClassVar[frozenset[str]] = frozenset()
    _sealed: ClassVar[bool] = False

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
                key = cls.host_key(host)
                if cls._sealed:
                    # The scan phase is sealed: refuse before resolving, so nothing reaches the
                    # network even for the lookup. A loopback name is still refused -- a sealed
                    # scan talks to nothing, and a detector with a real local-service need runs
                    # outside the seal (online mode), not through an exception here.
                    raise NetworkSealed(
                        socket.EAI_NONAME,
                        f"refused {key or 'an empty host'}: the scan phase is sealed and must not "
                        f"reach the network; intel is pulled before the scan, never during it",
                    )
                answers = original(host, port, *args, **kwargs)
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
    @contextlib.contextmanager
    def sealed(cls) -> Iterator[None]:
        """Seal the network for the duration of the scan phase: every resolution is refused.

        Installs the guard first (so `getaddrinfo` is patched even when the public-only mode was
        not enabled), sets the seal, and restores the previous seal state on exit -- so nesting
        and an online phase that follows an offline one both behave. The engine enters this around
        the detector phase of a scan that may not use the network, so the "offline" guarantee is
        enforced rather than trusted.
        """
        cls.install(cls._allowed if cls._installed else None)
        with cls._lock:
            previous = cls._sealed
            cls._sealed = True
        try:
            yield
        finally:
            with cls._lock:
                cls._sealed = previous

    @classmethod
    def install_if_enabled(cls) -> bool:
        if cls.enabled_by_environment():
            cls.install()
            return True
        return False
