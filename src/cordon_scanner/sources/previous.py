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
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

USER_AGENT = "cordon-scanner (release comparison)"
TIMEOUT = 30
MAX_METADATA_BYTES = 1 << 20
MAX_ARTEFACT_BYTES = 200 << 20


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
                        return _from_metadata(
                            "pypi", handle.read().decode("utf-8", "replace") if handle else ""
                        )
        elif name.endswith(".whl"):
            with zipfile.ZipFile(target) as archive:
                for info in archive.infolist():
                    if (
                        info.filename.endswith(".dist-info/METADATA")
                        and info.file_size <= MAX_METADATA_BYTES
                    ):
                        return _from_metadata("pypi", archive.read(info).decode("utf-8", "replace"))
    except (tarfile.TarError, zipfile.BadZipFile, OSError, ValueError):
        return None
    return None


def _from_metadata(ecosystem: str, text: str) -> Identity | None:
    name = re.search(r"(?m)^Name:\s*(\S+)", text)
    version = re.search(r"(?m)^Version:\s*(\S+)", text)
    return Identity(ecosystem, name.group(1), version.group(1)) if name and version else None


def _get(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("registry URLs are https only")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310  (https enforced above)
        body: bytes = response.read(MAX_ARTEFACT_BYTES + 1)
    if len(body) > MAX_ARTEFACT_BYTES:
        raise ValueError("artefact larger than the comparison limit")
    return body


def fetch_previous(identity: Identity, into: Path) -> Previous | None:
    """Download the release published before `identity`, verified, into `into`."""
    if identity.ecosystem == "npm":
        document = json.loads(
            _get(f"https://registry.npmjs.org/{identity.name.replace('/', '%2F')}")
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
        blob = _get(meta["dist"]["tarball"])
        integrity = meta["dist"].get("integrity", "")
        if integrity.startswith("sha512-"):
            if base64.b64encode(hashlib.sha512(blob).digest()).decode() != integrity[7:]:
                raise ValueError("previous release failed its integrity check")
        elif hashlib.sha1(blob).hexdigest() != meta["dist"].get("shasum"):  # noqa: S324  (npm's own legacy digest)
            raise ValueError("previous release failed its integrity check")
        path = into / f"{identity.name.replace('/', '__')}-{version}.tgz"
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

    document = json.loads(_get(f"https://pypi.org/pypi/{urllib.parse.quote(identity.name)}/json"))
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
    blob = _get(chosen["url"])
    if hashlib.sha256(blob).hexdigest() != chosen["digests"]["sha256"]:
        raise ValueError("previous release failed its digest check")
    path = into / chosen["filename"]
    path.write_bytes(blob)
    return Previous(path, f"{identity.name} {version}")


@contextlib.contextmanager
def workspace() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="cordon-previous-") as directory:
        yield Path(directory)


__all__ = ["Identity", "Previous", "fetch_previous", "identify", "workspace"]
