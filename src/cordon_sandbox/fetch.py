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
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import PurePosixPath

from cordon_sandbox.isolation import IsolationError

TIMEOUT_SECONDS = 30.0
MAX_ARTEFACT_BYTES = 256 << 20
"""Ceiling on what will be downloaded. A package larger than this is not
something to analyse by accident."""

USER_AGENT = "cordon-sandbox (+https://github.com/Threx-code/cordon)"

ALLOWED_HOSTS = frozenset(
    {
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
    }
)
"""The only hosts this component will talk to.

The metadata URLs are written here, but the ARTEFACT url is not: it arrives in
the registry's JSON, as `releases[].url` or `dist.tarball`, which is a field
whoever published the package has a say in. Checking the scheme of the URL that
was asked for says nothing about where the request ends up, and `urlopen`
follows a redirect without asking.

`intel/osv_import.py` pins its one host for the same reason. This is the same
discipline applied to the component that then feeds what it downloaded to an
installer."""


class _ValidatingRedirect(urllib.request.HTTPRedirectHandler):
    """Re-check scheme and host at every hop.

    Redirects are allowed rather than refused: both registries use them, and a
    fetcher that breaks on a legitimate 302 is one nobody runs. What is not
    allowed is arriving somewhere the allowlist does not name -- which is the
    difference between following a CDN and being pointed at an internal
    address by a registry response.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        _check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _check_url(url: str) -> None:
    """HTTPS, and a host on the allowlist. Raises otherwise."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise IsolationError(f"refusing a non-HTTPS artefact URL: {url}")
    # `hostname` rather than `netloc`: it drops the port and, more importantly,
    # any `user@` prefix, so `https://files.pythonhosted.org@attacker.invalid/x`
    # is read as the host it actually resolves to.
    if parsed.hostname not in ALLOWED_HOSTS:
        raise IsolationError(
            f"refusing a host outside the fixed allowlist: {parsed.hostname}. "
            f"The artefact URL comes from the registry's own response, so it is "
            f"checked rather than trusted"
        )


_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._+-]")


def safe_artefact_name(name: str, fallback: str) -> str:
    """A filename safe to build an in-container path from.

    `Artefact.filename` for PyPI is `chosen.get("filename")` -- the registry's
    JSON, so a field the package's own publisher controls, and the publisher is
    the adversary this component exists to analyse. It is `shlex.quote`d before
    it reaches a shell, which stops command injection and does nothing about
    `../`.

    What that reaches: the artefact is written to `/work/{filename}`, and
    `/work/.cordon-trace` is where the observer's own trace lives. A filename
    of `../work/.cordon-trace`, or `.cordon-trace` itself, lets the analysed
    package overwrite the record of what it did. Not a host compromise -- the
    container holds -- but the sandbox reporting on itself is exactly the thing
    that has to be true.

    `archive/safe.py` applies this discipline to archive members already. This
    is the same input class arriving through a different door.
    """
    candidate = PurePosixPath(name).name
    candidate = _SAFE_FILENAME.sub("_", candidate).lstrip(".")
    return candidate or fallback


@dataclass(frozen=True, slots=True)
class Artefact:
    """A downloaded package, held in memory until it is copied in."""

    filename: str
    data: bytes
    source_url: str


def _get(url: str, *, accept: str) -> bytes:
    _check_url(url)

    request = urllib.request.Request(  # noqa: S310  (scheme and host checked above)
        url, headers={"User-Agent": USER_AGENT, "Accept": accept}, method="GET"
    )
    opener = urllib.request.build_opener(_ValidatingRedirect)
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
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
        filename=safe_artefact_name(str(chosen.get("filename") or ""), "package.tar.gz"),
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
        filename=safe_artefact_name(
            f"{name.replace('/', '-').lstrip('@')}-{version}.tgz", "package.tgz"
        ),
        data=_get(url, accept="application/octet-stream"),
        source_url=url,
    )


__all__ = ["MAX_ARTEFACT_BYTES", "TIMEOUT_SECONDS", "Artefact", "fetch"]
