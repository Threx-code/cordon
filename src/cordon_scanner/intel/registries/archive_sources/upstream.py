"""Registries that record the project's own source archive and its digest: the Bazel Central Registry, opam-repository, ConanCenter
and CRAN. The archive is on the project's host (a public one), so what makes the bytes trusted is the digest the registry states."""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.intel.registries.archive_sources.base import ArchiveSource, Located
from cordon_scanner.intel.registries.archive_sources.hosts import PublicHost
from cordon_scanner.intel.registries.archive_sources.readers import Digest, Lines
from cordon_scanner.intel.registries.record_sources.base import Document

if TYPE_CHECKING:
    from collections.abc import Mapping

LOWER = "abcdefghijklmnopqrstuvwxyz"
DIGITS = "0123456789"
VERSION_CHARS = frozenset(LOWER + LOWER.upper() + DIGITS + "._+~-")


def plain_version(version: str) -> bool:
    """A version that can sit in a path: its own characters only, no empty part."""
    return (
        0 < len(version) <= 128
        and set(version) <= VERSION_CHARS
        and ".." not in version
        and version[0] not in ".-"
    )


def file_name(url: str, fallback: str) -> str:
    """The last path segment of an archive's URL (the name it is kept under)."""
    segment = urllib.parse.unquote(urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1])
    return segment or fallback


class UpstreamArchive(ArchiveSource):
    """An archive the registry's own document names on the project's host."""

    HOSTS: ClassVar[frozenset[str]] = frozenset()
    REDIRECTS: ClassVar[int] = (
        3  # a release download on a code host answers with a redirect to its storage
    )

    def allows(self, host: str) -> bool:
        return PublicHost.ok(host)

    @staticmethod
    def https(url: str) -> bool:
        return urllib.parse.urlsplit(url).scheme == "https"


class BazelArchive(UpstreamArchive):
    """A Bazel module: `modules/<name>/<version>/source.json` (the archive's URL and its SRI integrity). A module taken from a git
    repository (`type: git_repository`) has no archive."""

    ecosystem: ClassVar[str] = "bazel"
    RAW: ClassVar[str] = (
        "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/main/modules"
    )
    FIRST: ClassVar[str] = LOWER
    REST: ClassVar[str] = LOWER + DIGITS + "._-"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        if (
            not name
            or name[0] not in self.FIRST
            or any(c not in self.REST for c in name)
            or not plain_version(version)
        ):
            return ()
        return (Document(f"{self.RAW}/{name}/{version}/source.json"),)

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        source = next(iter(documents.values()), None)
        if not isinstance(source, dict) or source.get("type") not in (None, "archive"):
            return None
        url, digest = str(source.get("url") or ""), Digest.sri(str(source.get("integrity") or ""))
        if not self.https(url) or digest is None:
            return None
        return Located(url, file_name(url, f"{name}-{version}"), (digest,))


class OpamArchive(UpstreamArchive):
    """An opam package: its `opam` file's `url { src: ... checksum: [...] }` block; every checksum stated must match."""

    ecosystem: ClassVar[str] = "opam"
    RAW: ClassVar[str] = "https://raw.githubusercontent.com/ocaml/opam-repository/master/packages"
    FIRST: ClassVar[str] = LOWER + LOWER.upper() + DIGITS
    REST: ClassVar[str] = LOWER + LOWER.upper() + DIGITS + "_+-"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        if (
            not name
            or name[0] not in self.FIRST
            or any(c not in self.REST for c in name)
            or not plain_version(version)
        ):
            return ()
        return (Document(f"{self.RAW}/{name}/{name}.{version}/opam", kind="text"),)

    @staticmethod
    def block(text: str) -> list[str]:
        """The lines inside the file's `url { ... }` block."""
        lines = text.splitlines()
        for start, line in enumerate(lines):
            if line.rstrip() == "url {":
                body: list[str] = []
                for follower in lines[start + 1 :]:
                    if follower.rstrip() == "}":
                        return body
                    body.append(follower)
        return []

    @staticmethod
    def checksums(lines: list[str]) -> list[str]:
        """The quoted checksums of `checksum: [ "a" "b" ]` (one line, or one to a line) or `checksum: "a"`."""
        found: list[str] = []
        reading = False
        for line in lines:
            stripped = line.strip()
            if not reading:
                if not stripped.startswith("checksum:"):
                    continue
                stripped = stripped[len("checksum:") :]
                reading = "[" in stripped and "]" not in stripped
            else:
                reading = "]" not in stripped
            found.extend(stripped.split('"')[1::2])
            if not reading and found:
                break
        return found

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        text = next(iter(documents.values()), None)
        if not isinstance(text, str):
            return None
        lines = self.block(text)
        url = Lines.scalar(lines, "src") if not Lines.scalar(lines, "src").startswith("git") else ""
        digests: list[tuple[str, str]] = []
        for stated in self.checksums(lines):
            found = Digest.labelled(stated)
            if found is not None:
                digests.append(found)
        if not self.https(url) or not digests:
            return None
        return Located(url, file_name(url, f"{name}.{version}"), tuple(digests))


class ConanArchive(UpstreamArchive):
    """A ConanCenter recipe: `recipes/<name>/config.yml` names the folder of a version, and its `conandata.yml` the source URL and sha256."""

    ecosystem: ClassVar[str] = "conan"
    RAW: ClassVar[str] = (
        "https://raw.githubusercontent.com/conan-io/conan-center-index/master/recipes"
    )
    FIRST: ClassVar[str] = LOWER + DIGITS + "_"
    REST: ClassVar[str] = LOWER + DIGITS + "_+.-"
    FOLDER: ClassVar[frozenset[str]] = frozenset(LOWER + DIGITS + "_-")

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        if (
            not name
            or name[0] not in self.FIRST
            or any(c not in self.REST for c in name)
            or ".." in name
            or not plain_version(version)
        ):
            return ()
        return (Document(f"{self.RAW}/{name}/config.yml", kind="text"),)

    def folder(self, version: str, documents: Mapping[str, Any]) -> str:
        text = next(iter(documents.values()), None)
        found = (
            Lines.scalar(Lines.under(text, version, at=2), "folder")
            if isinstance(text, str)
            else ""
        )
        return found if found and set(found) <= self.FOLDER else ""

    def followed(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> tuple[Document, ...]:
        folder = self.folder(version, documents)
        if not folder or len(documents) > 1:
            return ()
        return (Document(f"{self.RAW}/{name}/{folder}/conandata.yml", kind="text"),)

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        data = next(
            (
                t
                for u, t in documents.items()
                if u.endswith("/conandata.yml") and isinstance(t, str)
            ),
            None,
        )
        if data is None:
            return None
        entry = Lines.under(data, version, at=2)
        digest = Digest.hex("sha256", Lines.scalar(entry, "sha256"))
        urls = [u for u in Lines.items(entry, "url") if self.https(u)]
        if digest is None or not urls:
            return None
        return Located(urls[0], file_name(urls[0], f"{name}-{version}"), (digest,))


class CranArchive(ArchiveSource):
    """A CRAN package: the version's document carries the archive's MD5 (CRAN publishes nothing stronger: the strength is reported as
    `md5`), the file is under `src/contrib` while the version is current and under `src/contrib/Archive/<name>` after."""

    ecosystem: ClassVar[str] = "cran"
    HOSTS: ClassVar[frozenset[str]] = frozenset({"cran.r-project.org"})
    API: ClassVar[str] = "https://crandb.r-pkg.org"
    FILES: ClassVar[str] = "https://cran.r-project.org/src/contrib"
    FIRST: ClassVar[str] = LOWER + LOWER.upper()
    REST: ClassVar[str] = LOWER + LOWER.upper() + DIGITS + "."

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        if (
            not name
            or name[0] not in self.FIRST
            or any(c not in self.REST for c in name)
            or ".." in name
            or not plain_version(version)
        ):
            return ()
        return (
            Document(f"{self.API}/{name}/{version}"),
            Document(f"{self.API}/{name}", required=False),
        )

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        first, latest = ([*documents.values(), None, None])[:2]
        if not isinstance(first, dict) or first.get("Version") != version:
            return None
        digest = Digest.hex("md5", str(first.get("MD5sum") or ""))
        if digest is None:
            return None
        current = isinstance(latest, dict) and latest.get("Version") == version
        base = self.FILES if current else f"{self.FILES}/Archive/{name}"
        return Located(f"{base}/{name}_{version}.tar.gz", f"{name}_{version}.tar.gz", (digest,))
