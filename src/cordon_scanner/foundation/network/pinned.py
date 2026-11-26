"""One lookup, one connection: a name is resolved once, the addresses it gave are checked, and the connection goes to one of them.

A check made on one lookup and a download made on another leaves a window for a name that answers a public address to the
check and a private one (a cloud metadata address, an internal host) to the download. Here the checked answer is the one
connected to, and the certificate is still checked against the name."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import urllib.request
from typing import Any


class Pinned:
    @staticmethod
    def addresses(host: str, port: int) -> list[tuple[int, str]]:
        """`(family, address)` for each address the name resolves to, in the resolver's order."""
        found = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return [(entry[0], str(entry[4][0])) for entry in found]

    @staticmethod
    def is_global(address: str) -> bool:
        try:
            return ipaddress.ip_address(address.split("%")[0]).is_global
        except ValueError:
            return False


class PinnedConnection(http.client.HTTPSConnection):
    """An HTTPS connection that resolves its host once; with `public_only`, every address must be a global one."""

    public_only = False

    def connect(self) -> None:
        if getattr(self, "_tunnel_host", None):
            # Through a proxy the proxy resolves the name, so the address cannot be checked here: a name that must be public is
            # refused rather than trusted to the proxy; a registry on a list is connected as the standard library does.
            if self.public_only:
                raise OSError(
                    f"{self.host} is reached through a proxy, which resolves it: its address cannot be checked"
                )
            super().connect()
            return
        candidates = Pinned.addresses(self.host, self.port)
        if not candidates:
            raise OSError(f"{self.host} has no address")
        if self.public_only and not all(Pinned.is_global(address) for _, address in candidates):
            raise OSError(f"{self.host} resolves to an address that is not a public one")
        last: OSError | None = None
        for family, address in candidates:
            sock = socket.socket(family, socket.SOCK_STREAM)
            try:
                sock.settimeout(self.timeout if isinstance(self.timeout, (int, float)) else None)
                sock.connect((address, self.port))
            except OSError as exc:
                sock.close()
                last = exc
                continue
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)  # type: ignore[attr-defined]
            return
        raise last or OSError(f"{self.host} could not be reached")


class PinnedHTTPS(urllib.request.HTTPSHandler):
    """The handler that opens HTTPS through `PinnedConnection`."""

    def __init__(self, *, public_only: bool = False) -> None:
        super().__init__()
        self.public_only = public_only

    def https_open(self, req: urllib.request.Request) -> Any:
        flag = self.public_only

        class Connection(PinnedConnection):
            public_only = flag

        return self.do_open(Connection, req)
