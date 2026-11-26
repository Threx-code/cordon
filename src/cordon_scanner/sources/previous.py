"""The release before this one, fetched from its registry for `--online` release comparison.

Only with `--online`: it names the package to the registry. The artefact is identified from its
own metadata (`package/package.json` in an npm tarball, `PKG-INFO` in an sdist, `METADATA` in a
wheel), the registry's version history decides which release came before it, and the download is
checked against the digest the registry publishes before anything reads it.
"""

from __future__ import annotations

import contextlib
import re
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.foundation.formats.scanned_json import ScannedJson

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
    """A sentence naming both accounts when the registry names the publisher of each and they differ; empty otherwise."""


class PreviousRelease:
    #: Ecosystems whose package names itself inside its archive, so `identify` reads the identity
    #: from the archive rather than from what the command line named.
    FROM_ARCHIVE: ClassVar[frozenset[str]] = frozenset({"npm", "pypi"})
    """The release published before this one, fetched for comparison."""

    @staticmethod
    def supported() -> frozenset[str]:
        """Every ecosystem a previous release can be fetched for: the ones with a verified archive (`FROM_ARCHIVE` is only those whose
        archive names its own package, so `identify` can read the identity from it)."""
        from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources

        return ArchiveSources.fetchable()

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
                            document = ScannedJson.loads(handle.read()) if handle else {}
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
    def fetch_previous(identity: Identity, into: Path) -> Previous | None:
        """Download the release published before `identity`, verified, into `into`.

        The release before it is read from the registry's history (the one its registry record is built from) and its archive is
        fetched by the ecosystem's archive source, which checks it against what the registry states; the label says so when that
        check is weaker than a SHA-2 digest."""
        from cordon_scanner.intel.registries.archive_sources.base import ArchiveFetch
        from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources
        from cordon_scanner.intel.registries.registry_client import RegistryError
        from cordon_scanner.sources.package import PackageTarget

        try:
            before = ArchiveFetch.previous_release(
                identity.ecosystem, identity.name, identity.version
            )
            if before is None:
                return None
            archive = ArchiveSources.package_archive(
                identity.ecosystem, identity.name, before.version
            )
            now = next(
                (
                    r.publisher
                    for r in ArchiveFetch.releases(
                        identity.ecosystem, identity.name, identity.version
                    )
                    if r.version == identity.version
                ),
                "",
            )
        except RegistryError as exc:
            raise ValueError(str(exc)) from exc
        path = into / PackageTarget.safe_filename(archive.filename, identity.ecosystem)
        path.write_bytes(archive.data)
        weak = f" (checked by {archive.strength} only)" if archive.strength else ""
        change = (
            f"{identity.name} {identity.version} was published by `{now}`; {before.version} by `{before.publisher}`."
            if before.publisher and now and before.publisher != now
            else ""
        )
        return Previous(path, f"{identity.name} {before.version}{weak}", change)

    @staticmethod
    @contextlib.contextmanager
    def workspace() -> Iterator[Path]:
        with tempfile.TemporaryDirectory(prefix="cordon-previous-") as directory:
            yield Path(directory)


__all__ = ["Identity", "Previous", "PreviousRelease"]
