"""Which hosts an archive named by a registry's document may be downloaded from.

A registry that serves its own archives names them on its own file hosts (`ArchiveSource.HOSTS`). A registry whose release records the
archive of the project's own source (a Bazel module, an opam package, a Conan recipe) names a URL on the project's host, which no list
can hold: the digest the registry states is what makes the bytes trusted, and the host only has to be a public one. Here is only the
NAME's half of that (`named`: a dotted name, not an address, not a local suffix); the addresses are checked where the connection is
made (`foundation/network/pinned`: the name is resolved once and the connection goes to an address that was checked), so there is no
second lookup for a name to answer differently."""

from __future__ import annotations

import ipaddress
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
