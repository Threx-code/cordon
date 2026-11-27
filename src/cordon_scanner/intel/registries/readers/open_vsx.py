"""Open VSX as a source of facts about an extension: its versions, the checksum of each .vsix.

GET <registry>/api/<namespace>/<extension>             allVersions: version -> URL (and the aliases latest, pre-release)
GET <registry>/api/<namespace>/<extension>/<version>   files.sha256: the address of the .vsix's checksum
"""

from __future__ import annotations

import re

from cordon_scanner.intel.base import PackageFacts
from cordon_scanner.intel.registries.openvsx import OpenVsx
from cordon_scanner.intel.registries.private_route import PrivateRoute
from cordon_scanner.intel.registries.registry_hosts import HOSTS
from cordon_scanner.intel.registries.registry_http import RegistryHttp
from cordon_scanner.intel.registries.registry_request import RegistryError

PART = re.compile(r"[A-Za-z0-9][\w-]{0,100}")
ALIASES = ("latest", "pre-release")


class ExtensionRegistries:
    @staticmethod
    def vscode(name: str, version: str | None) -> PackageFacts:
        """The versions the registry holds for `publisher.extension`, whether the one asked for is among them, and the
        sha256 the registry publishes for its .vsix."""
        namespace, _, extension = name.partition(".")
        if not (PART.fullmatch(namespace) and PART.fullmatch(extension)):
            raise RegistryError(f"{name!r} is not an Open VSX publisher.extension")
        if version is not None and not re.fullmatch(r"[0-9A-Za-z.+-]{1,64}", version):
            raise RegistryError(f"{version} is not an extension version")
        base = f"{HOSTS['vscode']}/api/{namespace}/{extension}"
        listing = RegistryHttp.mapping(RegistryHttp.json(base))
        versions = [
            str(v) for v in RegistryHttp.mapping(listing.get("allVersions")) if v not in ALIASES
        ]
        digests: tuple[str, ...] = ()
        reason = None
        if version is not None and version not in versions:
            reason = "not a version the registry holds"
        elif version is not None:
            document = RegistryHttp.mapping(RegistryHttp.json(f"{base}/{version}"))
            address = RegistryHttp.mapping(document.get("files")).get("sha256")
            if isinstance(address, str) and address.startswith("https://"):
                # Public: the file link is held to the file hosts, never fetched wherever the document points. Private:
                # the route refuses any address that is not the private registry's own.
                if PrivateRoute.current() is None:
                    address = OpenVsx.on_file_host(address)
                digest = RegistryHttp.text(address).split()
                if digest and re.fullmatch(r"[0-9a-f]{64}", digest[0]):
                    digests = (f"sha256:{digest[0]}",)
        return PackageFacts(
            name=name,
            version=version,
            yanked=reason is not None,
            yanked_reason=reason,
            latest=RegistryHttp.latest(versions),
            digests=digests,
            releases=len(versions),
        )
