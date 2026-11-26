"""Registries whose release is a revision of a git repository: GitHub Actions, Swift packages, Nix inputs, Packagist, CocoaPods,
Terraform modules and Julia's General registry. The archive is the code host's tarball of the revision (or, for Julia, the package
server's tarball of the tree), and what it is checked against is the strongest the registry states:

* Julia: the tree's `git-tree-sha1`, a hash of the files themselves;
* a commit the registry names (Packagist's `reference`, a pinned Nix revision, a pod's `commit`): the commit id the tarball says it is of;
* a tag only (an action, a Swift package, a module's tag): the tarball must name a commit, which is the host's own resolution of the tag
  and is reported as the weakest check (`git-tag`)."""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.intel.registries.archive_sources.base import ArchiveSource, Located
from cordon_scanner.intel.registries.archive_sources.git import GIT_COMMIT, GIT_TAG, GIT_TREE
from cordon_scanner.intel.registries.archive_sources.hosts import PublicHost
from cordon_scanner.intel.registries.archive_sources.readers import Digest
from cordon_scanner.intel.registries.record_sources.base import Document
from cordon_scanner.intel.registries.record_sources.composer import ComposerSource
from cordon_scanner.intel.registries.registry_record import RegistryRecord

if TYPE_CHECKING:
    from collections.abc import Mapping

NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
REF_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-/")
HEX = frozenset("0123456789abcdef")


class Repo:
    """A repository on GitHub, and the address of its tarball (served by `codeload.github.com`, with no API and no rate limit)."""

    CODELOAD: ClassVar[str] = "https://codeload.github.com"

    @staticmethod
    def part(text: str) -> bool:
        return 0 < len(text) <= 100 and set(text) <= NAME_CHARS and text not in (".", "..")

    @classmethod
    def of(cls, address: str) -> tuple[str, str] | None:
        """`(owner, repository)` of a github.com address (`https://github.com/o/r`, with or without `.git` or a trailing slash)."""
        parts = urllib.parse.urlsplit(address.strip())
        if parts.scheme != "https" or (parts.hostname or "").lower() not in (
            "github.com",
            "www.github.com",
        ):
            return None
        segments = [s for s in parts.path.split("/") if s]
        if len(segments) < 2:
            return None
        owner, name = segments[0], segments[1].removesuffix(".git")
        return (owner, name) if cls.part(owner) and cls.part(name) else None

    @staticmethod
    def sha(ref: str) -> bool:
        return len(ref) in (40, 64) and set(ref) <= HEX

    @classmethod
    def tarball(cls, owner: str, repo: str, ref: str) -> str:
        return f"{cls.CODELOAD}/{owner}/{repo}/tar.gz/{ref if cls.sha(ref) else 'refs/tags/' + ref}"

    @classmethod
    def located(
        cls, owner: str, repo: str, ref: str, *, commit: str = "", fallbacks: tuple[str, ...] = ()
    ) -> Located | None:
        """The tarball of `ref`; checked against `commit` when the registry names one, else against the tag only."""
        if not ref or set(ref) - REF_CHARS or ".." in ref or ref.startswith(("/", "-")):
            return None
        stated = commit if cls.sha(commit) else ref if cls.sha(ref) else ""
        digests = ((GIT_COMMIT, stated.lower()),) if stated else ((GIT_TAG, ""),)
        urls = [cls.tarball(owner, repo, r) for r in (ref, *fallbacks) if r]
        return Located(urls[0], f"{repo}-{ref.replace('/', '_')}.tar.gz", digests, tuple(urls[1:]))


class GitArchive(ArchiveSource):
    HOSTS: ClassVar[frozenset[str]] = frozenset({"codeload.github.com"})


class RepositoryArchive(GitArchive):
    """A package that is a repository's tag (`owner/repo`; an action may name a folder inside it): no registry document is read."""

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        return ()

    @staticmethod
    def valid(name: str, version: str) -> bool:
        parts = name.split("/")
        return len(parts) >= 2 and Repo.part(parts[0]) and Repo.part(parts[1]) and bool(version)

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        if not self.valid(name, version):
            return None
        owner, repo = name.split("/")[:2]
        return Repo.located(owner, repo, version, fallbacks=self.variants(version))

    @staticmethod
    def variants(version: str) -> tuple[str, ...]:
        """A release tag is written `v1.2.3` or `1.2.3`: the other spelling is tried when the first is not a tag."""
        return (version.removeprefix("v"),) if version.startswith("v") else (f"v{version}",)


class ActionsArchive(RepositoryArchive):
    ecosystem: ClassVar[str] = "actions"


class SwiftArchive(RepositoryArchive):
    ecosystem: ClassVar[str] = "swift"


class NixArchive(RepositoryArchive):
    """A flake input `owner/repo` at a revision: a commit pins the archive to it; a tag or branch is the host's resolution."""

    ecosystem: ClassVar[str] = "nix"

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        owner, repo = [*name.split("/"), "", ""][:2]
        return (
            Repo.located(owner, repo, version)
            if self.valid(name, version) and name.count("/") == 1
            else None
        )


class ComposerArchive(GitArchive):
    """A Packagist package: the version's `source` names the repository and the exact commit (`reference`). The registry names no
    digest of the archive (its `dist.shasum` is empty for a GitHub dist), so the archive is the code host's tarball of that commit."""

    ecosystem: ClassVar[str] = "composer"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        return ComposerSource().documents(name, version)

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        document = RegistryRecord._mapping(next(iter(documents.values()), None))
        listed = RegistryRecord._mapping(document.get("packages")).get(name)
        entries = ComposerSource.expand(listed) if isinstance(listed, list) else []
        entry = next((e for e in entries if e.get("version") == version), None)
        source = RegistryRecord._mapping(entry.get("source") if entry else None)
        found = Repo.of(str(source.get("url") or ""))
        reference = str(source.get("reference") or "").lower()
        if found is None or not Repo.sha(reference):
            return None
        return Repo.located(found[0], found[1], reference)


class CocoapodsArchive(ArchiveSource):
    """A pod: its podspec's `source` is a git repository at a `tag` or a `commit` (GitHub), or an archive at an address with the digest
    the podspec states (`sha256`, else `sha1`)."""

    ecosystem: ClassVar[str] = "cocoapods"
    HOSTS: ClassVar[frozenset[str]] = frozenset({"codeload.github.com"})
    REDIRECTS: ClassVar[int] = 3
    PUBLIC: ClassVar[bool] = True
    API: ClassVar[str] = "https://trunk.cocoapods.org/api/v1/pods"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        if (
            not name
            or ".." in name
            or set(name) - (NAME_CHARS | {"+"})
            or not version
            or set(version) - REF_CHARS
        ):
            return ()
        return (
            Document(
                f"{self.API}/{urllib.parse.quote(name, safe='')}/specs/{urllib.parse.quote(version, safe='')}"
            ),
        )

    def allows(self, host: str) -> bool:
        return host in self.HOSTS or PublicHost.named(host)

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        spec = RegistryRecord._mapping(next(iter(documents.values()), None))
        if spec.get("version") != version:
            return None
        source = RegistryRecord._mapping(spec.get("source"))
        if source.get("git"):
            found = Repo.of(str(source["git"]))
            ref = str(source.get("commit") or source.get("tag") or "")
            return (
                Repo.located(found[0], found[1], ref, commit=str(source.get("commit") or ""))
                if found
                else None
            )
        address = str(source.get("http") or "")
        for algorithm in ("sha256", "sha1"):
            digest = Digest.hex(algorithm, str(source.get(algorithm) or ""))
            if digest and urllib.parse.urlsplit(address).scheme == "https":
                return Located(
                    address,
                    urllib.parse.unquote(urllib.parse.urlsplit(address).path.rsplit("/", 1)[-1])
                    or f"{name}-{version}",
                    (digest,),
                )
        return None


class TerraformArchive(ArchiveSource):
    """A Terraform provider (`namespace/type`): the registry's download answer for linux/amd64 names the zip on HashiCorp's release host
    and its sha256. A module (`namespace/name/provider`): the registry's version document names the repository and the tag."""

    ecosystem: ClassVar[str] = "terraform"
    HOSTS: ClassVar[frozenset[str]] = frozenset({"codeload.github.com", "releases.hashicorp.com"})
    API: ClassVar[str] = "https://registry.terraform.io/v1"
    PLATFORM: ClassVar[str] = "linux/amd64"

    @staticmethod
    def parts(name: str) -> list[str] | None:
        found = name.split("/")
        return found if len(found) in (2, 3) and all(Repo.part(p) for p in found) else None

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        parts = self.parts(name)
        if parts is None or not version or set(version) - REF_CHARS:
            return ()
        quoted = urllib.parse.quote(version, safe="")
        if len(parts) == 3:
            return (Document(f"{self.API}/modules/{'/'.join(parts)}/{quoted}"),)
        return (
            Document(f"{self.API}/providers/{'/'.join(parts)}/{quoted}/download/{self.PLATFORM}"),
        )

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        parts = self.parts(name)
        document = RegistryRecord._mapping(next(iter(documents.values()), None))
        if parts is None:
            return None
        if len(parts) == 2:
            digest = Digest.hex("sha256", str(document.get("shasum") or ""))
            url = str(document.get("download_url") or "")
            host = urllib.parse.urlsplit(url).hostname
            if (
                digest is None
                or host != "releases.hashicorp.com"
                or not str(document.get("filename") or "")
            ):
                return None
            return Located(url, str(document["filename"]), (digest,))
        found = Repo.of(str(document.get("source") or ""))
        tag = str(document.get("tag") or "")
        if found is None or document.get("version") != version or not tag:
            return None
        return Repo.located(found[0], found[1], tag, fallbacks=RepositoryArchive.variants(tag))


class JuliaArchive(ArchiveSource):
    """A Julia package: the General registry holds each version's `git-tree-sha1`, and the package server serves the tarball of that
    tree. The archive is checked by hashing its own files as git hashes a tree, so no host has to be trusted for it."""

    ecosystem: ClassVar[str] = "julia"
    HOSTS: ClassVar[frozenset[str]] = frozenset({"pkg.julialang.org"})
    REDIRECTS: ClassVar[int] = 2
    RAW: ClassVar[str] = "https://raw.githubusercontent.com/JuliaRegistries/General/master"
    SERVER: ClassVar[str] = "https://pkg.julialang.org/package"
    ALLOWED: ClassVar[frozenset[str]] = frozenset(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
    )

    def allows(self, host: str) -> bool:
        return host == "pkg.julialang.org" or host.endswith(".pkg.julialang.org")

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        if (
            not name
            or not name[0].isalpha()
            or set(name) - self.ALLOWED
            or not version
            or set(version) - REF_CHARS
        ):
            return ()
        base = f"{self.RAW}/{name[0].upper()}/{name}"
        return (
            Document(f"{base}/Package.toml", kind="text"),
            Document(f"{base}/Versions.toml", kind="text"),
        )

    @staticmethod
    def value(lines: list[str], key: str) -> str:
        for line in lines:
            label, equals, value = line.partition("=")
            if equals and label.strip() == key:
                return value.strip().strip('"')
        return ""

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        package, versions = [*documents.values(), None, None][:2]
        if not isinstance(package, str) or not isinstance(versions, str):
            return None
        uuid = self.value(package.splitlines(), "uuid").lower()
        section: list[str] = []
        inside = False
        for line in versions.splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                inside = stripped.strip("[]").strip('"') == version
            elif inside and stripped:
                section.append(stripped)
        tree = self.value(section, "git-tree-sha1").lower()
        if len(uuid) != 36 or set(uuid) - (HEX | {"-"}) or len(tree) != 40 or set(tree) - HEX:
            return None
        return Located(f"{self.SERVER}/{uuid}/{tree}", f"{name}-{tree}.tar.gz", ((GIT_TREE, tree),))
