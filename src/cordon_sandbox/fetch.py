"""Getting the artefact before the isolation goes up.

The first working version of this component installed the package inside a
container with no network, which meant the installer could not reach the
registry and every package failed at the fetch step. The observation "it failed
without a network" then fired on everything, which is a signal that means
nothing.

The fix is the structure a sandbox needs anyway: separate *getting* the code
from *running* it.

**Fetching does not execute anything.** This reads the registry's JSON metadata
and downloads the artefact over HTTP. A `.tar.gz` or a `.tgz` arriving as bytes
runs nothing; the code in it runs later, inside the container, which is the
point. Doing this with `pip download` instead would be a mistake -- pip executes
`setup.py egg_info` on a source distribution to resolve it, so the payload would
run on the host before the sandbox existed.

**The artefact goes in without a mount.** It is copied into the created
container rather than bind-mounted, so no host path is reachable from inside at
any point, and the install runs with `--no-index` against the local file.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from cordon_sandbox.isolation import IsolationError

TIMEOUT_SECONDS = 30.0
MAX_ARTEFACT_BYTES = 256 << 20
"""Ceiling on what will be downloaded. A package larger than this is not
something to analyse by accident."""

USER_AGENT = "cordon-sandbox (+https://github.com/Threx-code/cordon)"


@dataclass(frozen=True, slots=True)
class Artefact:
    """A downloaded package, held in memory until it is copied in."""

    filename: str
    data: bytes
    source_url: str


def _get(url: str, *, accept: str) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise IsolationError(f"refusing a non-HTTPS artefact URL: {url}")

    request = urllib.request.Request(  # noqa: S310  (scheme checked above)
        url, headers={"User-Agent": USER_AGENT, "Accept": accept}, method="GET"
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            body = response.read(MAX_ARTEFACT_BYTES + 1)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        raise IsolationError(f"could not fetch {url}: {type(exc).__name__}") from exc

    if len(body) > MAX_ARTEFACT_BYTES:
        raise IsolationError(f"{url} exceeded {MAX_ARTEFACT_BYTES} bytes and was not downloaded")
    return bytes(body)


def _mapping(value: object) -> dict[str, object]:
    """A mapping, or an empty one. Registry documents are written by whoever
    published the package, so a field documented as an object arrives as
    whatever they put there."""
    return value if isinstance(value, dict) else {}


def fetch(ecosystem: str, package: str) -> Artefact:
    """Download the artefact for a package, without running any of it."""
    if ecosystem == "pypi":
        return _pypi(package)
    if ecosystem == "npm":
        return _npm(package)
    raise IsolationError(f"no fetcher is defined for {ecosystem!r}")


def _split(package: str, separator: str) -> tuple[str, str | None]:
    name, found, version = package.rpartition(separator)
    if not found:
        return package, None
    return name, version or None


def _pypi(package: str) -> Artefact:
    name, version = _split(package, "==")
    document = json.loads(
        _get(
            f"https://pypi.org/pypi/{urllib.parse.quote(name, safe='')}/json",
            accept="application/json",
        )
    )
    releases = _mapping(document.get("releases"))
    info = _mapping(document.get("info"))
    declared = info.get("version")
    version = version or (declared if isinstance(declared, str) else None)

    entries = releases.get(version) if version else None
    if not isinstance(entries, list) or not entries:
        raise IsolationError(f"pypi has no downloadable files for {name} {version}")

    # A source distribution is preferred over a wheel, because `setup.py` is
    # where install-time code lives and a wheel usually has none. Analysing the
    # wheel of a package whose payload is in its sdist would observe nothing and
    # report it as nothing found.
    ordered = sorted(entries, key=lambda e: e.get("packagetype") != "sdist")
    chosen = ordered[0]
    url = chosen.get("url")
    if not isinstance(url, str):
        raise IsolationError(f"pypi returned no URL for {name} {version}")

    return Artefact(
        filename=str(chosen.get("filename") or "package.tar.gz"),
        data=_get(url, accept="application/octet-stream"),
        source_url=url,
    )


def _npm(package: str) -> Artefact:
    name, version = _split(package, "@") if not package.startswith("@") else (package, None)
    if package.startswith("@") and package.count("@") > 1:
        name, _, version = package.rpartition("@")

    document = json.loads(
        _get(
            f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@/')}",
            accept="application/json",
        )
    )
    dist_tags = _mapping(document.get("dist-tags"))
    versions = _mapping(document.get("versions"))
    latest = dist_tags.get("latest")
    version = version or (latest if isinstance(latest, str) else None)

    entry = _mapping(versions.get(version)) if version else {}
    dist = _mapping(entry.get("dist"))
    url = dist.get("tarball")
    if not isinstance(url, str):
        raise IsolationError(f"npm has no tarball for {name} {version}")

    return Artefact(
        filename=f"{name.replace('/', '-').lstrip('@')}-{version}.tgz",
        data=_get(url, accept="application/octet-stream"),
        source_url=url,
    )


__all__ = ["MAX_ARTEFACT_BYTES", "TIMEOUT_SECONDS", "Artefact", "fetch"]
