"""Where an install's files may be downloaded from: the public registries' own file hosts, and the
private registries the operator named with `--cordon-registry-token URL=VAR` (or
`CORDON_REGISTRY_TOKENS`). A project's `.npmrc` or `pip.conf` may point its package manager anywhere;
Cordon fetches only from these, and refuses the install otherwise.

The credential rules are `intel/registries/private_registries.py`'s: the operator names the variable,
the token goes to the exact host it was named for, over https, with no redirect followed, and no
message repeats it.
"""

from __future__ import annotations

import os
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.plan import InstallRefused

if TYPE_CHECKING:
    from cordon_scanner.intel.base import PrivateRegistry


@dataclass(frozen=True)
class InstallRegistries:
    """The hosts this install trusts, and the fetcher that keeps to them."""

    private: tuple[PrivateRegistry, ...] = ()

    #: Hosts that serve the same bytes as a public registry under another name: a lockfile written
    #: against the alias is fetched from the registry itself, and the hash still decides.
    ALIASES: ClassVar[dict[str, str]] = {"registry.yarnpkg.com": "registry.npmjs.org"}

    @classmethod
    def configured(cls, values: Iterable[str] = ()) -> InstallRegistries:
        from cordon_scanner.intel.registries.private_registries import PrivateRegistries

        given = [*values]
        if not given and os.environ.get("CORDON_REGISTRY_TOKENS"):
            given = [os.environ["CORDON_REGISTRY_TOKENS"]]
        return cls(PrivateRegistries.parse(given))

    @staticmethod
    def public(ecosystem: str) -> frozenset[str]:
        from cordon_scanner.intel.registries.registry_request import ARCHIVE_HOSTS

        return ARCHIVE_HOSTS.get(ecosystem, frozenset())

    def canonical(self, url: str) -> str:
        """`url` on the host Cordon fetches it from (an alias replaced by its registry)."""
        parts = urllib.parse.urlsplit(url)
        host = (parts.hostname or "").lower()
        if host in self.ALIASES and parts.port is None:
            return urllib.parse.urlunsplit(parts._replace(netloc=self.ALIASES[host], fragment=""))
        return urllib.parse.urlunsplit(parts._replace(fragment=""))

    def registry_for(self, url: str) -> PrivateRegistry | None:
        parts = urllib.parse.urlsplit(url)
        target = f"https://{parts.netloc.lower()}{parts.path}"
        return next(
            (r for r in self.private if target == r.base or target.startswith(r.base + "/")),
            None,
        )

    def admit(self, ecosystem: str, label: str, url: object) -> str:
        """The URL to fetch `label` from, or `InstallRefused` when no trusted host serves it."""
        from cordon_scanner.version import PROGRAM

        if not isinstance(url, str) or not url.startswith("https://"):
            raise InstallRefused(
                f"{label} does not come from a registry Cordon can fetch ({str(url)[:120]!r})"
            )
        fetched = self.canonical(url)
        host = (urllib.parse.urlsplit(fetched).hostname or "").lower()
        if host in self.public(ecosystem) or self.registry_for(fetched) is not None:
            return fetched
        raise InstallRefused(
            f"{label} resolves to {host}, which Cordon has not been told to trust",
            hint=(
                f"Name that registry for Cordon: `{PROGRAM} <tool> --cordon-registry-token "
                "https://host/path=TOKEN_VARIABLE ...` (or CORDON_REGISTRY_TOKENS)."
            ),
        )

    def fetch(self, url: str, ecosystem: str) -> bytes:
        """One file from a trusted host: a private registry with its operator-named credential,
        else the public registry's host-pinned download."""
        from cordon_scanner.intel.registries.private_registries import PrivateRegistries
        from cordon_scanner.intel.registries.registry_request import RegistryRequest

        registry = self.registry_for(url)
        if registry is None:
            return RegistryRequest.fetch_bytes(url, ecosystem)
        credential = PrivateRegistries.credential(registry)
        if credential is None:
            raise InstallRefused(
                f"{registry.host} needs the token in {registry.variable}, which is not set"
            )
        return PrivateRegistries.get(registry, url, credential, accept="application/octet-stream")


__all__ = ["InstallRegistries"]
