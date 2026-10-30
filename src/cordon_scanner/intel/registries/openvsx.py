"""Open VSX: when each release of an extension was published, and its archive. Network, for the
`intel acquire` step only; a scan reads what this stored and never the network.

An extension's own established release is its genuine twin: the code it shipped months ago, before
whatever this release changed. `ReleaseHistory` compares a scanned `.vsix` with it, as it compares
an npm tarball with its predecessor (review 98).

    https://open-vsx.org/api/<namespace>/<extension>              allVersions: version -> URL
    https://open-vsx.org/api/<namespace>/<extension>/<version>    timestamp, files.download/sha256
    https://openvsx.eclipsecontent.org/<namespace>/<extension>/<version>/<file>.vsix
                                                                  where a download redirects
"""

from __future__ import annotations

import hashlib
import re
import urllib.parse
from datetime import datetime
from typing import Any, ClassVar, Final

from cordon_scanner.intel.base import PackageArchive
from cordon_scanner.intel.registries.registry_client import RegistryError
from cordon_scanner.intel.registries.registry_request import RegistryRequest

API: Final = "https://open-vsx.org/api"
FILES: Final = "https://openvsx.eclipsecontent.org"


class OpenVsx:
    """The Open VSX registry's published facts about an extension."""

    _NAME: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][\w-]{0,100}")
    MAX_VERSIONS: ClassVar[int] = 40

    @classmethod
    def split(cls, name: str) -> tuple[str, str]:
        """`publisher.extension` as the two path segments the API takes, checked."""
        namespace, _, extension = name.partition(".")
        if not (cls._NAME.fullmatch(namespace) and cls._NAME.fullmatch(extension)):
            raise RegistryError(f"{name!r} is not an Open VSX publisher.extension")
        return namespace, extension

    @staticmethod
    def _json(url: str) -> dict[str, Any]:
        from cordon_scanner.intel.registries.registry_http import RegistryHttp

        return RegistryHttp.mapping(RegistryHttp.json(url))

    @classmethod
    def timeline(cls, name: str, version: str) -> dict[str, datetime]:
        """When each of the newest releases up to `version` was published."""
        from cordon_scanner.intel.advisories.versions import Versions

        namespace, extension = cls.split(name)
        listing = cls._json(f"{API}/{namespace}/{extension}")
        versions = [
            v
            for v in MoreVersions.listed(listing)
            if Versions.compare("npm", v, version) <= 0 or v == version
        ]
        versions.sort(key=lambda v: Versions.sort_key("npm", v), reverse=True)
        out: dict[str, datetime] = {}
        for release in versions[: cls.MAX_VERSIONS]:
            document = cls._json(
                f"{API}/{namespace}/{extension}/{urllib.parse.quote(release, safe='')}"
            )
            stamp = document.get("timestamp")
            if isinstance(stamp, str):
                try:
                    out[release] = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                except ValueError:
                    continue
        return out

    @classmethod
    def _on_file_host(cls, url: Any) -> str:
        """An API file link (`/api/<ns>/<ext>/<version>/file/<name>`) as the file host serves it,
        with the publisher's own spelling: the file host is case-sensitive, the API is not."""
        prefix = f"{API}/"
        if not isinstance(url, str) or not url.startswith(prefix):
            raise RegistryError("Open VSX gave no file link")
        parts = url[len(prefix) :].split("/")
        if len(parts) != 5 or parts[3] != "file":
            raise RegistryError("an Open VSX file link of an unknown shape")
        namespace, extension, version, _, filename = parts
        return f"{FILES}/{namespace}/{extension}/{version}/{filename}"

    @classmethod
    def archive(cls, name: str, version: str) -> PackageArchive:
        """The `.vsix` the registry publishes for `version`, checked against its own SHA-256."""
        from cordon_scanner.intel.registries.registry_http import RegistryHttp

        namespace, extension = cls.split(name)
        document = cls._json(
            f"{API}/{namespace}/{extension}/{urllib.parse.quote(version, safe='')}"
        )
        files = RegistryHttp.mapping(document.get("files"))
        published = RegistryHttp.text(cls._on_file_host(files.get("sha256"))).split()
        if not published or not re.fullmatch(r"[0-9a-fA-F]{64}", published[0]):
            raise RegistryError(f"Open VSX publishes no SHA-256 for {name}@{version}")
        download = cls._on_file_host(files.get("download"))
        data = RegistryRequest.fetch_bytes(download, "openvsx")
        if hashlib.sha256(data).hexdigest() != published[0].lower():
            raise RegistryError(f"{name}@{version} does not match the SHA-256 Open VSX publishes")
        filename = urllib.parse.unquote(download.rpartition("/")[2])
        return PackageArchive("openvsx", name, version, filename, data)


class MoreVersions:
    """The release versions an Open VSX listing names: not the `latest` or `pre-release` tags."""

    @staticmethod
    def listed(listing: dict[str, Any]) -> list[str]:
        versions = listing.get("allVersions")
        if not isinstance(versions, dict):
            return []
        return [v for v in versions if isinstance(v, str) and v not in ("latest", "pre-release")]


__all__ = ["OpenVsx"]
