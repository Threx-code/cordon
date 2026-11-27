"""A Nix binary cache: what it says about a store path (`<hash>.narinfo`), the same on cache.nixos.org and on a private
cache (a hosted one, an Attic, a self-hosted nix-serve).

    StorePath: /nix/store/<hash>-<name>   URL: nar/<file>   FileHash: sha256:<base32>   NarHash: sha256:<base32>
"""

from __future__ import annotations

import re

from cordon_scanner.intel.base import PackageFacts
from cordon_scanner.intel.registries.registry_hosts import HOSTS
from cordon_scanner.intel.registries.registry_http import RegistryHttp
from cordon_scanner.intel.registries.registry_request import RegistryError

#: Nix's own base-32 alphabet has no e, o, t, u.
HASH = re.compile(r"[0-9a-df-np-sv-z]{32}")


class NixCaches:
    @staticmethod
    def nix(name: str, version: str | None) -> PackageFacts:
        """The cache's narinfo of a store path, given as `<hash>` or `<hash>-<name>`: the hashes of the archive and of
        the store path's contents. A path the cache does not hold is not found."""
        key, _, _ = name.partition("-")
        if not HASH.fullmatch(key):
            raise RegistryError(f"{name} does not start with a Nix store path hash")
        text = RegistryHttp.text(f"{HOSTS['nix']}/{key}.narinfo")
        fields = dict(line.partition(": ")[::2] for line in text.splitlines() if ": " in line)
        if not fields.get("StorePath", "").startswith(f"/nix/store/{key}-"):
            raise RegistryError("the cache answered with a narinfo for another store path")
        digests = tuple(
            fields[k] for k in ("FileHash", "NarHash") if fields.get(k, "").startswith("sha256:")
        )
        return PackageFacts(
            name=name,
            version=version,
            yanked=False,
            yanked_reason=None,
            latest=None,
            digests=digests,
            releases=1,
        )
