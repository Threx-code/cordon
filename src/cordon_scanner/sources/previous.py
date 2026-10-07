"""The release before this one, fetched from its registry for `--online` release comparison.

Only with `--online`: it names the package to the registry. The artefact is identified from its
own metadata (`package/package.json` in an npm tarball, `PKG-INFO` in an sdist, `METADATA` in a
wheel), the registry's version history decides which release came before it, and the download is
checked against the digest the registry publishes before anything reads it.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import re
import tarfile
import tempfile
import urllib.parse
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

MAX_METADATA_BYTES = 1 << 20


@dataclass(frozen=True)
class Identity:
    ecosystem: str
    name: str
    version: str


@dataclass(frozen=True)
class Previous:
    path: Path
    label: str
    publisher_change: str = ""
    """On npm, a sentence naming both accounts when the publisher differs; empty otherwise."""


class PreviousRelease:
    """The release published before this one, fetched for comparison."""

    @staticmethod
    def identify(target: Path) -> Identity | None:
        """Which package and version this artefact is, from its own metadata."""
        name = target.name.lower()
        try:
            if name.endswith((".tgz", ".tar.gz")):
                with tarfile.open(target) as archive:
                    for entry in archive:
                        if not entry.isfile() or entry.size > MAX_METADATA_BYTES:
                            continue
                        parts = entry.name.split("/")
                        if parts[-1] == "package.json" and len(parts) == 2:
                            handle = archive.extractfile(entry)
                            document = json.loads(handle.read()) if handle else {}
                            if document.get("name") and document.get("version"):
                                return Identity("npm", document["name"], document["version"])
                        if parts[-1] == "PKG-INFO" and len(parts) == 2:
                            handle = archive.extractfile(entry)
                            return PreviousRelease._from_metadata(
                                "pypi", handle.read().decode("utf-8", "replace") if handle else ""
                            )
            elif name.endswith(".whl"):
                with zipfile.ZipFile(target) as archive:
                    for info in archive.infolist():
                        if (
                            info.filename.endswith(".dist-info/METADATA")
                            and info.file_size <= MAX_METADATA_BYTES
                        ):
                            return PreviousRelease._from_metadata(
                                "pypi", archive.read(info).decode("utf-8", "replace")
                            )
        except (tarfile.TarError, zipfile.BadZipFile, OSError, ValueError):
            return None
        return None

    @staticmethod
    def _from_metadata(ecosystem: str, text: str) -> Identity | None:
        name = re.search(r"(?m)^Name:\s*(\S+)", text)
        version = re.search(r"(?m)^Version:\s*(\S+)", text)
        return Identity(ecosystem, name.group(1), version.group(1)) if name and version else None

    @staticmethod
    def _document(url: str) -> dict[str, Any]:
        """A registry document, through the bounded, redirect-free registry client."""
        from cordon_scanner.intel.registry_client import RegistryClient, RegistryError

        try:
            return RegistryClient._fetch(url)
        except RegistryError as exc:
            raise ValueError(str(exc)) from exc

    @staticmethod
    def _artefact(url: str, ecosystem: str) -> bytes:
        """An archive the registry names, fetched only from that registry's own file hosts.

        The packument chooses the URL, so it is untrusted: a tarball URL pointing anywhere else, or
        a redirect, would have the scanner fetch from a host the publisher picked.
        """
        from cordon_scanner.intel.registry_client import RegistryClient, RegistryError

        try:
            return RegistryClient._fetch_bytes(url, ecosystem)
        except RegistryError as exc:
            raise ValueError(str(exc)) from exc

    @staticmethod
    def fetch_previous(identity: Identity, into: Path) -> Previous | None:
        """Download the release published before `identity`, verified, into `into`."""
        if identity.ecosystem not in ("npm", "pypi"):
            return PreviousRelease._from_registry(identity, into)
        if identity.ecosystem == "npm":
            document = PreviousRelease._document(
                f"https://registry.npmjs.org/{urllib.parse.quote(identity.name, safe='@')}"
            )
            times = document.get("time", {})
            current = times.get(identity.version)
            earlier = sorted(
                (t, v)
                for v, t in times.items()
                if v in document.get("versions", {}) and current and t < current
            )
            if not earlier:
                return None
            version = earlier[-1][1]
            meta = document["versions"][version]
            blob = PreviousRelease._artefact(meta["dist"]["tarball"], "npm")
            integrity = meta["dist"].get("integrity", "")
            # sha512 only: a release with nothing but npm's legacy sha1 shasum cannot be checked
            # against a digest an attacker could not also have chosen.
            if not integrity.startswith("sha512-"):
                raise ValueError("previous release carries no sha512 integrity to check")
            if base64.b64encode(hashlib.sha512(blob).digest()).decode() != integrity[7:]:
                raise ValueError("previous release failed its integrity check")
            path = into / PreviousRelease._safe(f"{identity.name.replace('/', '__')}-{version}.tgz")
            path.write_bytes(blob)
            before = (meta.get("_npmUser") or {}).get("name", "")
            now = ((document["versions"].get(identity.version) or {}).get("_npmUser") or {}).get(
                "name", ""
            )
            change = (
                f"{identity.name} {identity.version} was published by `{now}`; {version} by `{before}`."
                if before and now and before != now
                else ""
            )
            return Previous(path, f"{identity.name} {version}", change)

        document = PreviousRelease._document(
            f"https://pypi.org/pypi/{urllib.parse.quote(identity.name, safe='')}/json"
        )
        releases = document.get("releases", {})
        current_files = releases.get(identity.version) or []
        current = min((f["upload_time_iso_8601"] for f in current_files), default=None)
        earlier = sorted(
            (min(f["upload_time_iso_8601"] for f in files), v)
            for v, files in releases.items()
            if files
            and current
            and min(f["upload_time_iso_8601"] for f in files) < current
            and not any(f.get("yanked") for f in files)
        )
        if not earlier:
            return None
        version = earlier[-1][1]
        files = releases[version]
        chosen = next((f for f in files if f.get("packagetype") == "sdist"), files[0])
        blob = PreviousRelease._artefact(chosen["url"], "pypi")
        if hashlib.sha256(blob).hexdigest() != chosen["digests"]["sha256"]:
            raise ValueError("previous release failed its digest check")
        path = into / PreviousRelease._safe(str(chosen["filename"]))
        path.write_bytes(blob)
        return Previous(path, f"{identity.name} {version}")

    @staticmethod
    def _from_registry(identity: Identity, into: Path) -> Previous | None:
        """Crates.io, RubyGems, NuGet, the Go proxy, Hex, pub and Maven Central: the release before
        this one by the ecosystem's version order, fetched and verified against the digest its
        registry publishes (`RegistryClient.package_archive`)."""
        from cordon_scanner.intel.more_registries import MoreRegistries
        from cordon_scanner.intel.registry_client import RegistryClient, RegistryError
        from cordon_scanner.sources.package import PackageTarget

        try:
            version = MoreRegistries.previous(identity.ecosystem, identity.name, identity.version)
            if version is None:
                return None
            archive = RegistryClient.package_archive(identity.ecosystem, identity.name, version)
        except RegistryError as exc:
            raise ValueError(str(exc)) from exc
        path = into / PackageTarget.safe_filename(archive.filename, identity.ecosystem)
        path.write_bytes(archive.data)
        return Previous(path, f"{identity.name} {version}")

    @staticmethod
    def _safe(filename: str) -> str:
        """A registry-chosen filename as one plain path component inside the workspace."""
        from cordon_scanner.sources.package import PackageTarget

        return PackageTarget.safe_filename(filename, "pypi" if filename.endswith(".whl") else "npm")

    @staticmethod
    @contextlib.contextmanager
    def workspace() -> Iterator[Path]:
        with tempfile.TemporaryDirectory(prefix="cordon-previous-") as directory:
            yield Path(directory)


__all__ = ["Identity", "Previous", "PreviousRelease"]
