"""The registries that publish their own archives with a digest, one source each: npm, PyPI, crates.io, RubyGems, NuGet, the Go proxy, Hex,
pub.dev, Maven Central and Gradle's. Each names where the archive is on its own file host and the digest it must match."""

from __future__ import annotations

import base64
import binascii
import urllib.parse
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.intel.base import PackageArchive
from cordon_scanner.intel.registries.archive_sources.base import ArchiveSource, Located
from cordon_scanner.intel.registries.archive_sources.git import GO_H1
from cordon_scanner.intel.registries.archive_sources.readers import Digest
from cordon_scanner.intel.registries.archive_sources.upstream import Reading
from cordon_scanner.intel.registries.record_sources.base import Document
from cordon_scanner.intel.registries.registry_record import RegistryRecord

if TYPE_CHECKING:
    from collections.abc import Mapping

NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


class Docs:
    """Reading what the registries' documents say, the same way for each source."""

    @staticmethod
    def first(documents: Mapping[str, Any]) -> dict[str, Any]:
        return RegistryRecord._mapping(next(iter(documents.values()), None))

    @staticmethod
    def quote(text: str) -> str:
        return urllib.parse.quote(text, safe="")

    @staticmethod
    def on(url: str, hosts: frozenset[str]) -> bool:
        parts = urllib.parse.urlsplit(url)
        return parts.scheme == "https" and (parts.hostname or "") in hosts


class NpmArchive(ArchiveSource):
    """npm: the version's own document (a few kilobytes, not the whole packument) names the tarball and its sha512 `integrity`."""

    ecosystem: ClassVar[str] = "npm"
    HOSTS: ClassVar[frozenset[str]] = frozenset({"registry.npmjs.org"})
    API: ClassVar[str] = "https://registry.npmjs.org"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        if not name or len(name) > 214 or ".." in name or not Reading.plain_version(version):
            return ()
        return (
            Document(f"{self.API}/{urllib.parse.quote(name, safe='@/')}/{Docs.quote(version)}"),
        )

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        entry = Docs.first(documents)
        dist = RegistryRecord._mapping(entry.get("dist"))
        url, digest = str(dist.get("tarball") or ""), Digest.sri(str(dist.get("integrity") or ""))
        if (
            entry.get("version") != version
            or digest is None
            or digest[0] != "sha512"
            or not Docs.on(url, self.HOSTS)
        ):
            return None
        return Located(url, Reading.file_name(url, f"{name}-{version}.tgz"), (digest,))


class PypiArchive(ArchiveSource):
    """PyPI: the version's JSON lists its files with their sha256; the source distribution is compared, else the first file."""

    ecosystem: ClassVar[str] = "pypi"
    HOSTS: ClassVar[frozenset[str]] = frozenset({"files.pythonhosted.org"})
    API: ClassVar[str] = "https://pypi.org/pypi"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        if not name or len(name) > 214 or ".." in name or not Reading.plain_version(version):
            return ()
        return (Document(f"{self.API}/{Docs.quote(name)}/{Docs.quote(version)}/json"),)

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        files = [f for f in Docs.first(documents).get("urls") or () if isinstance(f, dict)]
        chosen = next(
            (f for f in files if f.get("packagetype") == "sdist"), files[0] if files else None
        )
        if chosen is None:
            return None
        url = str(chosen.get("url") or "")
        digest = Digest.hex(
            "sha256", str(RegistryRecord._mapping(chosen.get("digests")).get("sha256") or "")
        )
        if digest is None or not Docs.on(url, self.HOSTS):
            return None
        return Located(url, str(chosen.get("filename") or Reading.file_name(url, name)), (digest,))


class CargoArchive(ArchiveSource):
    """crates.io: the version's document carries the crate's sha256 `checksum`; the file is on `static.crates.io`."""

    ecosystem: ClassVar[str] = "cargo"
    HOSTS: ClassVar[frozenset[str]] = frozenset({"static.crates.io"})
    API: ClassVar[str] = "https://crates.io/api/v1/crates"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        if not name or set(name) - NAME_CHARS or not Reading.plain_version(version):
            return ()
        return (Document(f"{self.API}/{Docs.quote(name)}/{Docs.quote(version)}"),)

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        entry = RegistryRecord._mapping(Docs.first(documents).get("version"))
        digest = Digest.hex("sha256", str(entry.get("checksum") or ""))
        if entry.get("num") != version or digest is None:
            return None
        filename = f"{name}-{version}.crate"
        return Located(
            f"https://static.crates.io/crates/{Docs.quote(name)}/{Docs.quote(filename)}",
            filename,
            (digest,),
        )


class RubygemsArchive(ArchiveSource):
    """RubyGems: the version's v2 document names the gem and its sha256 `sha`."""

    ecosystem: ClassVar[str] = "rubygems"
    HOSTS: ClassVar[frozenset[str]] = frozenset({"rubygems.org"})
    API: ClassVar[str] = "https://rubygems.org/api/v2/rubygems"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        if not name or set(name) - NAME_CHARS or not Reading.plain_version(version):
            return ()
        return (Document(f"{self.API}/{Docs.quote(name)}/versions/{Docs.quote(version)}.json"),)

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        entry = Docs.first(documents)
        digest, url = (
            Digest.hex("sha256", str(entry.get("sha") or "")),
            str(entry.get("gem_uri") or ""),
        )
        if entry.get("version") != version or digest is None or not Docs.on(url, self.HOSTS):
            return None
        return Located(url, Reading.file_name(url, f"{name}-{version}.gem"), (digest,))


class NugetArchive(ArchiveSource):
    """NuGet: the version's registration names its catalog entry, whose `packageHash` (SHA-512, base64) is the .nupkg's."""

    ecosystem: ClassVar[str] = "nuget"
    HOSTS: ClassVar[frozenset[str]] = frozenset({"api.nuget.org"})
    REGISTRATION: ClassVar[str] = "https://api.nuget.org/v3/registration5-gz-semver2"
    CATALOG: ClassVar[str] = "https://api.nuget.org/v3/catalog0/"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        if not name or set(name) - NAME_CHARS or not Reading.plain_version(version):
            return ()
        return (
            Document(
                f"{self.REGISTRATION}/{Docs.quote(name.lower())}/{Docs.quote(version.lower())}.json"
            ),
        )

    def followed(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> tuple[Document, ...]:
        entry = str(Docs.first(documents).get("catalogEntry") or "")
        return (Document(entry),) if entry.startswith(self.CATALOG) and len(documents) == 1 else ()

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        listing, catalog = [*documents.values(), None, None][:2]
        content = str(RegistryRecord._mapping(listing).get("packageContent") or "")
        entry = RegistryRecord._mapping(catalog)
        try:
            raw = base64.b64decode(str(entry.get("packageHash") or ""), validate=True)
        except (binascii.Error, ValueError):
            return None
        digest = (
            Digest.hex("sha512", raw.hex())
            if str(entry.get("packageHashAlgorithm")).upper() == "SHA512"
            else None
        )
        if digest is None or not Docs.on(content, self.HOSTS):
            return None
        return Located(content, Reading.file_name(content, f"{name}.{version}.nupkg"), (digest,))


class GomodArchive(ArchiveSource):
    """The Go proxy: the module's zip, checked against the `h1:` the checksum database records for it (what go.sum holds), so the
    proxy's zip is held to the log and not to itself."""

    ecosystem: ClassVar[str] = "gomod"
    HOSTS: ClassVar[frozenset[str]] = frozenset({"proxy.golang.org"})
    SUMDB: ClassVar[str] = "https://sum.golang.org/lookup"
    PROXY: ClassVar[str] = "https://proxy.golang.org"

    @staticmethod
    def escaped(text: str) -> str:
        """The proxy's case encoding: each upper-case letter is `!` and its lower-case form."""
        return "".join(f"!{c.lower()}" if c.isupper() else c for c in text)

    @staticmethod
    def canonical(version: str) -> str:
        """A module version is `v1.2.3`; a dependency may be recorded without its `v`, which the checksum database answers 400 to."""
        return version if version.startswith("v") else f"v{version}"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        version = self.canonical(version)
        if (
            not name
            or ".." in name
            or "//" in name
            or set(name) - (NAME_CHARS | {"/", "~"})
            or not Reading.plain_version(version)
        ):
            return ()
        return (
            Document(
                f"{self.SUMDB}/{urllib.parse.quote(self.escaped(name), safe='/!')}@{Docs.quote(version)}",
                kind="text",
            ),
        )

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        version = self.canonical(version)
        text = next(iter(documents.values()), None)
        if not isinstance(text, str):
            return None
        prefix = f"{name} {version} "
        recorded = next(
            (line[len(prefix) :].strip() for line in text.splitlines() if line.startswith(prefix)),
            "",
        )
        if not recorded.startswith("h1:") or " " in recorded:
            return None
        escaped = urllib.parse.quote(self.escaped(name), safe="/!")
        return Located(
            f"{self.PROXY}/{escaped}/@v/{urllib.parse.quote(self.escaped(version), safe='!')}.zip",
            f"{name.replace('/', '_')}@{version}.zip",
            ((GO_H1, recorded),),
        )


class HexArchive(ArchiveSource):
    """Hex: the release's document carries the tarball's sha256 `checksum`; the file is on `repo.hex.pm`."""

    ecosystem: ClassVar[str] = "hex"
    HOSTS: ClassVar[frozenset[str]] = frozenset({"repo.hex.pm"})
    API: ClassVar[str] = "https://hex.pm/api/packages"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        if not name or set(name) - NAME_CHARS or not Reading.plain_version(version):
            return ()
        return (Document(f"{self.API}/{Docs.quote(name)}/releases/{Docs.quote(version)}"),)

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        entry = Docs.first(documents)
        digest = Digest.hex("sha256", str(entry.get("checksum") or ""))
        if entry.get("version") != version or digest is None:
            return None
        filename = f"{name}-{version}.tar"
        return Located(f"https://repo.hex.pm/tarballs/{Docs.quote(filename)}", filename, (digest,))


class PubArchive(ArchiveSource):
    """pub.dev: the package's document lists every version with its `archive_sha256` and `archive_url`."""

    ecosystem: ClassVar[str] = "pub"
    HOSTS: ClassVar[frozenset[str]] = frozenset({"pub.dev"})
    API: ClassVar[str] = "https://pub.dev/api/packages"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        if not name or set(name) - NAME_CHARS or not Reading.plain_version(version):
            return ()
        return (Document(f"{self.API}/{Docs.quote(name)}"),)

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        versions = [v for v in Docs.first(documents).get("versions") or () if isinstance(v, dict)]
        entry = next((v for v in versions if v.get("version") == version), None)
        if entry is None:
            return None
        digest, url = (
            Digest.hex("sha256", str(entry.get("archive_sha256") or "")),
            str(entry.get("archive_url") or ""),
        )
        if digest is None or not Docs.on(url, self.HOSTS):
            return None
        return Located(url, Reading.file_name(url, f"{name}-{version}.tar.gz"), (digest,))


class MavenArchive(ArchiveSource):
    """Maven Central: the jar, checked against the strongest of the `.sha512`, `.sha256`, `.sha1` and `.md5` files kept beside it."""

    ecosystem: ClassVar[str] = "maven"
    HOSTS: ClassVar[frozenset[str]] = frozenset({"repo.maven.apache.org"})
    ROOT: ClassVar[str] = "https://repo.maven.apache.org/maven2"
    ALGORITHMS: ClassVar[tuple[str, ...]] = ("sha512", "sha256", "sha1", "md5")

    def base(self, name: str, version: str) -> str:
        group, _, artifact = name.partition(":")
        parts = [group, artifact]
        if (
            not group
            or not artifact
            or ":" in artifact
            or any(set(p) - (NAME_CHARS | {"+"}) or ".." in p for p in parts)
            or not Reading.plain_version(version)
        ):
            return ""
        return f"{self.ROOT}/{group.replace('.', '/')}/{artifact}/{Docs.quote(version)}/{artifact}-{Docs.quote(version)}.jar"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        base = self.base(name, version)
        return (
            tuple(Document(f"{base}.{a}", kind="text", required=False) for a in self.ALGORITHMS)
            if base
            else ()
        )

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        base = self.base(name, version)
        for algorithm in self.ALGORITHMS:
            text = documents.get(f"{base}.{algorithm}")
            stated = str(text).split()[0] if isinstance(text, str) and text.split() else ""
            digest = Digest.hex(algorithm, stated)
            if digest is not None:
                return Located(base, base.rsplit("/", 1)[-1], (digest,))
        return None


class GradleArchive(MavenArchive):
    """Gradle resolves `group:artifact` from Maven Central: the same archive, under its own ecosystem."""

    ecosystem: ClassVar[str] = "gradle"


class VscodeArchive(ArchiveSource):
    """An editor extension: the `.vsix` Open VSX publishes for the version, checked against the SHA-256 it publishes beside it (its
    reader pulls both from Open VSX's own hosts). The VS Code Marketplace names no digest of its packages."""

    ecosystem: ClassVar[str] = "vscode"
    HOSTS: ClassVar[frozenset[str]] = frozenset({"openvsx.eclipsecontent.org"})

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        return ()

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        return None

    def fetch(self, name: str, version: str) -> PackageArchive | None:
        from cordon_scanner.intel.registries.openvsx import OpenVsx

        if not name or not Reading.plain_version(version):
            return None
        return OpenVsx.archive(name, version)


class HackageArchive(ArchiveSource):
    """Hackage: each tarball is served with a `Content-MD5` header, the registry's own statement of its digest (the SHA-2 digests live
    only in its 1 GB TUF index, which no per-release lookup reads), so the archive is checked by MD5 and reported as such."""

    ecosystem: ClassVar[str] = "hackage"
    HOSTS: ClassVar[frozenset[str]] = frozenset({"hackage.haskell.org"})
    ROOT: ClassVar[str] = "https://hackage.haskell.org/package"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        return ()

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        return None

    def fetch(self, name: str, version: str) -> PackageArchive | None:
        from cordon_scanner.intel.registries.registry_request import RegistryError, RegistryRequest

        if not name or set(name) - NAME_CHARS or not Reading.plain_version(version):
            return None
        filename = f"{name}-{version}.tar.gz"
        url = f"{self.ROOT}/{Docs.quote(f'{name}-{version}')}/{Docs.quote(filename)}"
        try:
            stated = base64.b64decode(
                RegistryRequest.headers(url, lambda host: host in self.HOSTS).get(
                    "content-md5", ""
                ),
                validate=True,
            ).hex()
        except (binascii.Error, ValueError):
            stated = ""
        digest = Digest.hex("md5", stated)
        if digest is None:
            raise RegistryError(
                f"hackage states no MD5 for {name}@{version}; nothing to verify against"
            )
        data = RegistryRequest.fetch_bytes(url, lambda host: host in self.HOSTS)
        if not self.digest_ok(data, digest):
            raise RegistryError(f"{name}@{version} does not match the md5 hackage publishes")
        return PackageArchive("hackage", name, version, filename, data, "md5")

    @staticmethod
    def digest_ok(data: bytes, digest: tuple[str, str]) -> bool:
        from cordon_scanner.intel.registries.archive_sources.base import ArchiveFetch

        return ArchiveFetch.digest_ok(data, (digest,))
