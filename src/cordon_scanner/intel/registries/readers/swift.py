"""The Swift Package Registry (SE-0292): the one protocol a registry for Swift packages speaks.

Swift has no public registry of its own: packages are resolved from their git repositories. An organisation that runs
one serves these routes, so this reader is asked only through a private registry (`PrivateRoute`), and
`HOSTS["swift"]` names no real host, so a public question is refused.

    GET <registry>/<scope>/<name>             the releases: {"releases": {"1.0.0": {"url": ..., "problem": ...}}}
    GET <registry>/<scope>/<name>/<version>   the release: its `resources`, each with a type and a `checksum`
"""

from __future__ import annotations

import json
import re

from cordon_scanner.intel.base import PackageFacts
from cordon_scanner.intel.registries.registry_hosts import HOSTS
from cordon_scanner.intel.registries.registry_http import RegistryHttp
from cordon_scanner.intel.registries.registry_request import RegistryError

ACCEPT = "application/vnd.swift.registry.v1+json"


class SwiftRegistries:
    @staticmethod
    def swift(name: str, version: str | None) -> PackageFacts:
        """A package's releases, which of them the registry marks with a problem (withdrawn), and the checksum of the
        source archive of the version asked for. The name is `scope.name`, as SE-0292 writes a package identity."""
        scope, dot, package = name.partition(".")
        if not (dot and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}", scope)):
            raise RegistryError(f"{name} is not a Swift package identity (scope.name)")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", package):
            raise RegistryError(f"{name} is not a Swift package identity (scope.name)")
        if version is not None and not re.fullmatch(r"[0-9A-Za-z.+-]{1,64}", version):
            raise RegistryError(f"{version} is not a release version")
        base = f"{HOSTS['swift']}/{scope}/{package}"
        listing = RegistryHttp.mapping(json.loads(RegistryHttp.get(base, accept=ACCEPT)))
        releases = RegistryHttp.mapping(listing.get("releases"))
        digests: tuple[str, ...] = ()
        reason = None
        if version is not None and version not in releases:
            reason = "not a version the registry holds"
        elif version is not None and RegistryHttp.mapping(releases[version]).get("problem"):
            reason = "withdrawn: the registry marks the release with a problem"
        elif version is not None:
            release = RegistryHttp.mapping(
                json.loads(RegistryHttp.get(f"{base}/{version}", accept=ACCEPT))
            )
            digests = tuple(
                f"sha256:{resource['checksum']}"
                for resource in RegistryHttp.entries(release.get("resources"))
                if resource.get("name") == "source-archive"
                and isinstance(resource.get("checksum"), str)
            )
        live = [
            v for v, entry in releases.items() if not RegistryHttp.mapping(entry).get("problem")
        ]
        return PackageFacts(
            name=name,
            version=version,
            yanked=reason is not None,
            yanked_reason=reason,
            latest=RegistryHttp.latest([str(v) for v in live]),
            digests=digests,
            releases=len(releases),
        )
