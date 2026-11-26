"""Which hosts an archive named by a registry's document may be downloaded from.

A registry that serves its own archives names them on its own file hosts (`ArchiveSource.HOSTS`). A registry whose release records the
archive of the project's own source (a Bazel module, an opam package, a Conan recipe) names a URL on the project's host, which no list
can hold: the digest the registry states is what makes the bytes trusted, and the host only has to be a public one, so the scanner
cannot be sent to a machine of the scan's own network."""

from __future__ import annotations

import ipaddress
import socket
from typing import ClassVar


class PublicHost:
    #: Names that are never a public host, whatever they resolve to.
    LOCAL_SUFFIXES: ClassVar[tuple[str, ...]] = (
        ".local",
        ".localhost",
        ".internal",
        ".lan",
        ".home.arpa",
        ".corp",
    )
    MAX_ADDRESSES: ClassVar[int] = 16

    @classmethod
    def named(cls, host: str) -> bool:
        """A host name that could be public: a dotted name, not an address, not a local suffix."""
        lowered = host.lower().rstrip(".")
        if not lowered or "." not in lowered or len(lowered) > 253 or lowered == "localhost":
            return False
        if lowered.endswith(cls.LOCAL_SUFFIXES):
            return False
        try:
            ipaddress.ip_address(lowered.strip("[]"))
        except ValueError:
            pass
        else:
            return False
        return all(
            label and len(label) <= 63 and label[0] != "-" and label[-1] != "-"
            for label in lowered.split(".")
        )

    @classmethod
    def ok(cls, host: str) -> bool:
        """A public host: it is named like one, and every address it resolves to is a global one."""
        if not cls.named(host):
            return False
        try:
            found = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        except OSError:
            return False
        addresses = {entry[4][0] for entry in found[: cls.MAX_ADDRESSES]}
        try:
            return bool(addresses) and all(
                ipaddress.ip_address(str(a).split("%")[0]).is_global for a in addresses
            )
        except ValueError:
            return False
