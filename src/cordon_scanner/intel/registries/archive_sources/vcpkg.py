"""vcpkg: the port at the git tree a version names, and the source archive its portfile downloads with the SHA-512 it states.

`versions/<l>-/<name>.json` names each version's `git-tree`; the host's API gives that tree's entries and the two blobs read (`portfile.cmake`
and `vcpkg.json`), each of which is checked against its own git blob id, so the port read is the port the tree names."""

from __future__ import annotations

import base64
import binascii
import hashlib
import urllib.parse
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.intel.registries.archive_sources.base import Located
from cordon_scanner.intel.registries.archive_sources.readers import Digest
from cordon_scanner.intel.registries.archive_sources.upstream import Reading, UpstreamArchive
from cordon_scanner.intel.registries.record_sources.base import Document
from cordon_scanner.intel.registries.registry_record import RegistryRecord

if TYPE_CHECKING:
    from collections.abc import Mapping

LOWER = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
HEX = frozenset("0123456789abcdef")
KEY_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
WANTED = ("portfile.cmake", "vcpkg.json")
MAX_PORT_BYTES = 1 << 20


class Portfile:
    """The one call of a portfile that downloads its source, read as the words it is made of (no CMake is run)."""

    CALLS: ClassVar[tuple[str, ...]] = (
        "vcpkg_from_github",
        "vcpkg_from_gitlab",
        "vcpkg_download_distfile",
    )

    @staticmethod
    def call(text: str, name: str) -> list[str]:
        """The words between the parentheses of the first `name(...)` call, or [] when there is none."""
        start = text.find(f"{name}(")
        if start < 0:
            return []
        end = text.find(")", start)
        return text[start + len(name) + 1 : end].split() if end > start else []

    @staticmethod
    def values(words: list[str], keys: tuple[str, ...]) -> dict[str, list[str]]:
        """Each key's words, up to the next key written in capitals."""
        found: dict[str, list[str]] = {}
        current = ""
        for word in words:
            if word[:1].isalpha() and word == word.upper() and set(word) <= KEY_CHARS:
                current = word
                found.setdefault(current, [])
            elif current:
                found[current].append(word.strip('"'))
        return {k: v for k, v in found.items() if k in keys}


class VcpkgArchive(UpstreamArchive):
    ecosystem: ClassVar[str] = "vcpkg"
    RAW: ClassVar[str] = "https://raw.githubusercontent.com/microsoft/vcpkg/master/versions"
    API: ClassVar[str] = "https://api.github.com/repos/microsoft/vcpkg/git"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        base = version.partition("#")[0]
        if (
            not name
            or name[0] not in "abcdefghijklmnopqrstuvwxyz0123456789"
            or set(name) - LOWER
            or not Reading.plain_version(base)
        ):
            return ()
        return (Document(f"{self.RAW}/{name[0]}-/{name}.json"),)

    @staticmethod
    def tree(version: str, listing: Any) -> str:
        """The git tree of the port at `version` (`1.3.2` or `1.3.2#3`: the port revision, 0 when none is written)."""
        base, _, revision = version.partition("#")
        wanted = int(revision) if revision.isdigit() else 0
        for entry in RegistryRecord._mapping(listing).get("versions") or ():
            if not isinstance(entry, dict):
                continue
            named = next(
                (
                    entry[k]
                    for k in ("version", "version-semver", "version-date", "version-string")
                    if k in entry
                ),
                None,
            )
            if named == base and int(entry.get("port-version") or 0) == wanted:
                tree = str(entry.get("git-tree") or "")
                return tree if len(tree) == 40 and set(tree) <= HEX else ""
        return ""

    def followed(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> tuple[Document, ...]:
        if len(documents) == 1:
            tree = self.tree(version, next(iter(documents.values())))
            return (Document(f"{self.API}/trees/{tree}"),) if tree else ()
        tree_doc = next((d for u, d in documents.items() if "/git/trees/" in u), None)
        if len(documents) == 2 and isinstance(tree_doc, dict):
            return tuple(
                Document(f"{self.API}/blobs/{e['sha']}")
                for e in tree_doc.get("tree") or ()
                if isinstance(e, dict)
                and e.get("path") in WANTED
                and e.get("type") == "blob"
                and len(str(e.get("sha"))) == 40
            )
        return ()

    @staticmethod
    def blobs(documents: Mapping[str, Any]) -> dict[str, str]:
        """The text of each blob the tree named, kept only when it hashes to the id it was asked under."""
        out: dict[str, str] = {}
        for url, document in documents.items():
            if (
                "/git/blobs/" not in url
                or not isinstance(document, dict)
                or document.get("encoding") != "base64"
            ):
                continue
            try:
                raw = base64.b64decode(str(document.get("content") or ""), validate=False)
            except (binascii.Error, ValueError):
                continue
            blob = hashlib.sha1(b"blob %d\0" % len(raw) + raw, usedforsecurity=False).hexdigest()
            if len(raw) <= MAX_PORT_BYTES and blob == url.rsplit("/", 1)[-1]:
                out[blob] = raw.decode("utf-8", "replace")
        return out

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        tree_doc = next((d for u, d in documents.items() if "/git/trees/" in u), None)
        if not isinstance(tree_doc, dict):
            return None
        shas = {
            e.get("path"): e.get("sha") for e in tree_doc.get("tree") or () if isinstance(e, dict)
        }
        blobs = self.blobs(documents)
        portfile, manifest = (
            blobs.get(str(shas.get("portfile.cmake"))),
            blobs.get(str(shas.get("vcpkg.json"))),
        )
        if portfile is None:
            return None
        variables = {"PORT": name, "VERSION": self.manifest_version(manifest, version)}
        for call in Portfile.CALLS:
            words = Portfile.call(portfile, call)
            if words:
                return self.located(call, words, variables, name, version)
        return None

    @staticmethod
    def manifest_version(manifest: str | None, version: str) -> str:
        import json

        try:
            document = json.loads(manifest or "{}")
        except ValueError:
            return version.partition("#")[0]
        return str(
            next(
                (
                    document[k]
                    for k in ("version", "version-semver", "version-date", "version-string")
                    if k in document
                ),
                version.partition("#")[0],
            )
        )

    def located(
        self, call: str, words: list[str], variables: dict[str, str], name: str, version: str
    ) -> Located | None:
        keys = Portfile.values(words, ("REPO", "REF", "SHA512", "GITLAB_URL", "URLS", "FILENAME"))

        def one(key: str) -> str:
            value = " ".join(keys.get(key, [])[:1])
            for variable, text in variables.items():
                value = value.replace("${" + variable + "}", text)
            return "" if "${" in value else value

        digest = Digest.hex("sha512", one("SHA512"))
        if digest is None:
            return None
        if call == "vcpkg_from_github":
            repo, ref = one("REPO"), one("REF")
            if repo.count("/") != 1 or not ref or "?" in ref or ".." in ref:
                return None
            url = f"https://github.com/{repo}/archive/{urllib.parse.quote(ref, safe='')}.tar.gz"
        elif call == "vcpkg_from_gitlab":
            host, repo, ref = one("GITLAB_URL") or "https://gitlab.com", one("REPO"), one("REF")
            if not repo or not ref or "?" in ref or ".." in ref or ".." in repo:
                return None
            url = f"{host.rstrip('/')}/{repo}/-/archive/{urllib.parse.quote(ref, safe='')}/{repo.rsplit('/', 1)[-1]}-{urllib.parse.quote(ref, safe='')}.tar.gz"
        else:
            urls = [self.substituted(u, variables) for u in keys.get("URLS", [])]
            url = next((u for u in urls if u and u.startswith("https://")), "")
        if not self.https(url):
            return None
        return Located(
            url, one("FILENAME") or Reading.file_name(url, f"{name}-{version}"), (digest,)
        )

    @staticmethod
    def substituted(text: str, variables: dict[str, str]) -> str:
        for variable, value in variables.items():
            text = text.replace("${" + variable + "}", value)
        return "" if "${" in text else text
