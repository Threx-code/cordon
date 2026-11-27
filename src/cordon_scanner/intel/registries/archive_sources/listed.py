"""Registries whose release document states the archive's own digest and where to download it: anaconda.org and Ansible Galaxy."""

from __future__ import annotations

import re
import urllib.parse
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.intel.registries.archive_sources.base import ArchiveSource, Located
from cordon_scanner.intel.registries.archive_sources.hosts import PublicHost
from cordon_scanner.intel.registries.archive_sources.readers import Digest
from cordon_scanner.intel.registries.record_sources.ansible import NAME as COLLECTION
from cordon_scanner.intel.registries.record_sources.base import Document
from cordon_scanner.intel.registries.record_sources.catalogs.helm import HelmSource
from cordon_scanner.intel.registries.record_sources.conda import CondaSource
from cordon_scanner.intel.registries.registry_record import RegistryRecord

if TYPE_CHECKING:
    from collections.abc import Mapping

HEX = re.compile(r"[0-9a-f]+")


class CondaArchive(ArchiveSource):
    """A conda package: the file of the release anaconda.org lists for the channel, with its sha256. A release has one file per
    platform and build: `noarch`, else `linux-64`; the `.conda` format before `.tar.bz2`; of those, the newest upload."""

    ecosystem: ClassVar[str] = "conda"
    HOSTS: ClassVar[frozenset[str]] = frozenset({"conda.anaconda.org", "repo.anaconda.com"})
    PLATFORMS: ClassVar[tuple[str, ...]] = ("noarch", "linux-64")
    FORMATS: ClassVar[tuple[str, ...]] = (".conda", ".tar.bz2")

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        address = CondaSource.address(name)
        return (
            (Document(f"https://api.anaconda.org/package/{address[0]}/{address[1]}"),)
            if address
            else ()
        )

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        files = RegistryRecord._mapping(next(iter(documents.values()), None)).get("files") or ()
        mine = [f for f in files if isinstance(f, dict) and f.get("version") == version]
        for platform in self.PLATFORMS:
            for suffix in self.FORMATS:
                found = [
                    f
                    for f in mine
                    if str(f.get("basename") or "").startswith(f"{platform}/")
                    and str(f.get("basename")).endswith(suffix)
                ]
                if found:
                    newest = max(found, key=lambda f: str(f.get("upload_time") or ""))
                    return self._located(newest)
        return None

    @staticmethod
    def _located(entry: dict[str, Any]) -> Located | None:
        sha = str(entry.get("sha256") or "").lower()
        address = str(entry.get("download_url") or "")
        if len(sha) != 64 or not HEX.fullmatch(sha) or not address.startswith("//"):
            return None
        return Located(
            f"https:{address}", str(entry["basename"]).rsplit("/", 1)[-1], (("sha256", sha),)
        )


class AnsibleArchive(ArchiveSource):
    """An Ansible collection: the version's own document names the artifact, its sha256 and a download address (which answers with a
    signed redirect to the same host)."""

    ecosystem: ClassVar[str] = "ansible"
    HOSTS: ClassVar[frozenset[str]] = frozenset({"galaxy.ansible.com"})
    REDIRECTS: ClassVar[int] = 2
    INDEX: ClassVar[str] = (
        "https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/index"
    )

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        parts = COLLECTION.fullmatch(name)
        if parts is None or not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}", version):
            return ()
        return (Document(f"{self.INDEX}/{parts[1]}/{parts[2]}/versions/{version}/"),)

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        document = RegistryRecord._mapping(next(iter(documents.values()), None))
        artifact = RegistryRecord._mapping(document.get("artifact"))
        sha = str(artifact.get("sha256") or "").lower()
        address = str(document.get("download_url") or "")
        if document.get("version") != version or len(sha) != 64 or not HEX.fullmatch(sha):
            return None
        if not address.startswith(f"{self.INDEX.rsplit('/index', 1)[0]}/artifacts/"):
            return None
        return Located(address, str(artifact.get("filename") or ""), (("sha256", sha),))


class HelmArchive(ArchiveSource):
    """A Helm chart: Artifact Hub's document of the chart version names the archive (`content_url`, on the chart repository's own host,
    a public one) and its sha256 (`digest`, the one the repository's index states). A chart kept in an OCI registry has no such address."""

    ecosystem: ClassVar[str] = "helm"
    HOSTS: ClassVar[frozenset[str]] = frozenset()
    REDIRECTS: ClassVar[int] = 3
    PUBLIC: ClassVar[bool] = True
    API: ClassVar[str] = "https://artifacthub.io/api/v1/packages"

    def allows(self, host: str) -> bool:
        return PublicHost.named(host)

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        asked = HelmSource().documents(name, version)
        if len(asked) != 1 or not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,127}", version):
            return ()
        return (
            (Document(f"{asked[0].url}/{urllib.parse.quote(version, safe='')}"),)
            if "/search?" not in asked[0].url
            else asked
        )

    def followed(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> tuple[Document, ...]:
        if "/" in name or len(documents) != 1:
            return ()
        found = HelmSource().followed(name, version, documents)
        return tuple(Document(f"{d.url}/{urllib.parse.quote(version, safe='')}") for d in found)

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        package = RegistryRecord._mapping(list(documents.values())[-1] if documents else None)
        digest = Digest.hex("sha256", str(package.get("digest") or ""))
        url = str(package.get("content_url") or "")
        if (
            package.get("version") != version
            or digest is None
            or urllib.parse.urlsplit(url).scheme != "https"
        ):
            return None
        return Located(
            url,
            urllib.parse.unquote(urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1])
            or f"{name}-{version}.tgz",
            (digest,),
        )
