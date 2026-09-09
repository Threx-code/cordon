"""Asking a package registry about a dependency.

Everything else in this project is offline by construction. This module is the
one place that is not, and it exists because four questions have no local
answer: has this version been yanked, is this pin far behind what is published,
does the hash in the lockfile match what the registry serves, and did this
release arrive with build provenance when the package's other releases did.

**Why it is not the default.** Constraint C2 makes offline the default for
reasons that are not about convenience. A scanner that phones a registry about
the code it is scanning leaks what you are building to whoever runs that
registry; it makes results non-reproducible, because the answer changes between
runs; and it introduces a dependency on a third party being up, in a tool whose
job is to run in a pipeline. So this is reached only when the caller has
explicitly asked for it, and every finding derived from it records that its
answer came from the network.

**What it will not do.** It sends no credentials, follows no redirects to
another host, reads no configured registry from the scan target -- the target is
untrusted, and letting it name the host we ask would let it choose who answers.
Requests are bounded in time and size, and any failure produces a finding saying
the question went unanswered rather than an absence of findings.

Written against `urllib` from the standard library, because C1 forbids a
third-party runtime dependency and an HTTP client is exactly the kind of
convenience that becomes one.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

TIMEOUT_SECONDS = 5.0
"""Per-request ceiling. A scan waiting on a slow registry is a scan somebody
kills, and a killed scan reports nothing at all."""

MAX_RESPONSE_BYTES = 4 << 20
"""How much of a response to read. Registry metadata for a large package runs to
a few megabytes; anything past this is not metadata."""

MAX_REDIRECTS = 0
"""Redirects are not followed.

A redirect is the registry naming a different host, and the point of pinning the
host is that we choose who answers. Registries do not need redirects to serve
metadata, so refusing them costs nothing and removes an entire class of
surprise."""

REGISTRY_HOSTS = {
    "pypi": "https://pypi.org",
    "npm": "https://registry.npmjs.org",
}
"""The hosts this will talk to, by ecosystem.

Fixed here rather than read from the scan target's configuration. A repository
that could name the registry could name a host it controls, and every answer
below would then be the attacker's answer."""

USER_AGENT = "cordon-scanner (+https://github.com/Threx-code/cordon)"


@dataclass(frozen=True, slots=True)
class PackageFacts:
    """What a registry says about one package version."""

    name: str
    version: str | None
    yanked: bool = False
    yanked_reason: str | None = None
    latest: str | None = None
    repository: str | None = None
    """The source repository the registry records, for comparison with what the
    package claims locally."""

    digests: tuple[str, ...] = ()
    """Hashes the registry publishes for this version's artefacts."""

    attested: bool = False
    """Whether the registry holds build provenance for *this* version."""

    attested_versions: int = 0
    """Attested releases published *before* the one pinned here.

    Not a total, and the distinction is the rule. A package that has never
    published provenance says nothing by not publishing it, and so does one
    that started attesting last month -- every older pin predates the practice,
    and counting totals made `requests==2.31.0` look like a gap because
    `requests` attests now.

    What is worth reporting is a release that shipped while the package was
    already attesting and skipped it. That needs the ordering, so this counts
    only the siblings that came first."""


class RegistryError(RuntimeError):
    """A question that could not be answered.

    Raised rather than returning a default, so a caller cannot mistake "the
    registry was unreachable" for "the registry said no". The two have opposite
    meanings and the same shape if this returns `False`.
    """


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuses every redirect by returning no follow-up request."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _fetch(url: str, *, accept: str = "application/json") -> dict[str, Any]:
    """One GET, bounded, with no credentials and no redirects."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise RegistryError(f"refusing a non-HTTPS registry URL: {parsed.scheme}")

    request = urllib.request.Request(  # noqa: S310  (scheme checked above)
        url,
        headers={"User-Agent": USER_AGENT, "Accept": accept},
        method="GET",
    )
    opener = urllib.request.build_opener(_NoRedirect)

    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as exc:
        raise RegistryError(f"{type(exc).__name__} asking {parsed.netloc}") from exc

    if len(body) > MAX_RESPONSE_BYTES:
        raise RegistryError(f"response from {parsed.netloc} exceeded {MAX_RESPONSE_BYTES} bytes")

    try:
        parsed_body = json.loads(body)
    except (json.JSONDecodeError, ValueError) as exc:
        raise RegistryError(f"unreadable response from {parsed.netloc}") from exc

    if not isinstance(parsed_body, dict):
        raise RegistryError(f"unexpected response shape from {parsed.netloc}")
    return parsed_body


def _mapping(value: Any) -> dict[str, Any]:
    """A mapping, or an empty one.

    Registry responses are attacker-adjacent: a package's own metadata is
    written by whoever published it, and a field that is documented as an
    object arrives as whatever they put there. Narrowing once here means every
    read below is a plain `.get` rather than a repeated isinstance dance, and
    means a malformed document produces an empty answer instead of an
    exception halfway through parsing.
    """
    return value if isinstance(value, dict) else {}


def facts(ecosystem: str, name: str, version: str | None) -> PackageFacts:
    """What the registry says about this package, or a `RegistryError`."""
    if ecosystem == "pypi":
        return _pypi(name, version)
    if ecosystem == "npm":
        return _npm(name, version)
    raise RegistryError(f"no registry configured for {ecosystem}")


def _pypi(name: str, version: str | None) -> PackageFacts:
    quoted = urllib.parse.quote(name, safe="")
    document = _fetch(f"{REGISTRY_HOSTS['pypi']}/pypi/{quoted}/json")

    info = _mapping(document.get("info"))
    releases = _mapping(document.get("releases"))

    urls: list[dict[str, Any]] = []
    yanked = False
    reason: str | None = None
    if version and isinstance(releases.get(version), list):
        urls = [entry for entry in releases[version] if isinstance(entry, dict)]
        # PyPI marks yanking per artefact. A version is yanked when its
        # artefacts are, and a partially yanked release is still a release
        # somebody was told not to use.
        yanked = bool(urls) and all(bool(entry.get("yanked")) for entry in urls)
        reason = next((str(e["yanked_reason"]) for e in urls if e.get("yanked_reason")), None)

    project_urls = _mapping(info.get("project_urls"))
    repository = next(
        (
            str(project_urls[key])
            for key in ("Source", "Source Code", "Repository", "Homepage")
            if isinstance(project_urls.get(key), str)
        ),
        None,
    )

    digests = tuple(
        str(entry["digests"]["sha256"])
        for entry in urls
        if isinstance(entry.get("digests"), dict) and entry["digests"].get("sha256")
    )

    # PEP 740. A file that was uploaded with attestations carries a link to
    # them; one that was not carries the key set to null, and an older PyPI
    # response does not carry the key at all. All three are read as "no
    # attestation for this file", which is what the caller compares.
    attested, attested_versions = _pypi_attestations(name, version)

    return PackageFacts(
        name=name,
        version=version,
        yanked=yanked,
        yanked_reason=reason,
        latest=str(info["version"]) if isinstance(info.get("version"), str) else None,
        repository=repository,
        digests=digests,
        attested=attested,
        attested_versions=attested_versions,
    )


def _pypi_attestations(name: str, version: str | None) -> tuple[bool, int]:
    """Whether PyPI holds PEP 740 attestations for this version, and for how
    many of the package's files overall.

    A second request, and to a different API, because the one above cannot
    answer it. `/pypi/{name}/json` carries no provenance field at all -- this
    was written against it, read `entry.get("provenance")` on every file, and
    got `None` every time, so the rule that depends on it could never have
    fired. A check that cannot fire is indistinguishable from one that found
    nothing, which is the failure this whole project is organised against, and
    it took one live request to see.

    The simple API's JSON form does carry `provenance` per file: a URL into
    PyPI's integrity endpoint where the bundle lives. A failure here is not
    fatal -- the caller still gets withdrawal, distance and hashes -- so it is
    reported as "no attestation seen" rather than raised, which is the
    conservative direction: the rule it feeds only fires on an *absence* beside
    other versions' presence, and an unanswered question suppresses it.
    """
    quoted = urllib.parse.quote(name, safe="")
    try:
        document = _fetch(
            f"{REGISTRY_HOSTS['pypi']}/simple/{quoted}/",
            accept="application/vnd.pypi.simple.v1+json",
        )
    except RegistryError:
        return (False, 0)

    files = document.get("files")
    if not isinstance(files, list):
        return (False, 0)

    marker = f"-{version}" if version else None
    here = False
    pinned_at: str | None = None
    attested_at: list[str] = []

    for entry in files:
        if not isinstance(entry, dict):
            continue
        filename = str(entry.get("filename", ""))
        uploaded = entry.get("upload-time")
        uploaded = uploaded if isinstance(uploaded, str) else ""
        mine = marker is not None and marker in filename
        if mine and (pinned_at is None or uploaded < pinned_at):
            pinned_at = uploaded
        if not isinstance(entry.get("provenance"), str):
            continue
        if mine:
            here = True
        attested_at.append(uploaded)

    if here or pinned_at is None:
        return (here, 0)
    # Attested releases that came first. ISO-8601 in UTC sorts lexically, which
    # is the whole reason the format is written that way.
    return (False, sum(1 for uploaded in attested_at if uploaded and uploaded < pinned_at))


def _npm(name: str, version: str | None) -> PackageFacts:
    quoted = urllib.parse.quote(name, safe="@/")
    document = _fetch(f"{REGISTRY_HOSTS['npm']}/{quoted}")

    versions = _mapping(document.get("versions"))
    dist_tags = _mapping(document.get("dist-tags"))
    entry = _mapping(versions.get(version)) if version else {}

    # npm has no yank. It has unpublish, and a version that is gone from
    # `versions` while the package still exists is the same situation from the
    # consumer's side: something they depend on was withdrawn.
    withdrawn = bool(version) and bool(versions) and version not in versions

    repository_field = entry.get("repository") or document.get("repository")
    repository: str | None = None
    if isinstance(repository_field, str):
        repository = repository_field
    else:
        url = _mapping(repository_field).get("url")
        repository = url if isinstance(url, str) else None

    dist = _mapping(entry.get("dist"))
    digests = tuple(str(dist[key]) for key in ("integrity", "shasum") if dist.get(key))

    # `npm publish --provenance` records a sigstore bundle against the version,
    # and the packument carries a pointer to it under `dist.attestations`.
    attested = bool(_mapping(dist.get("attestations")))
    # Only the attested releases published before this one -- see
    # `PackageFacts.attested_versions`. The packument's `time` map carries an
    # ISO-8601 timestamp per version, which sorts lexically.
    published_at = _mapping(document.get("time"))
    pinned_at = published_at.get(version) if version else None
    attested_versions = 0
    if isinstance(pinned_at, str) and not attested:
        attested_versions = sum(
            1
            for name_, published in versions.items()
            if _mapping(_mapping(_mapping(published).get("dist")).get("attestations"))
            and isinstance(published_at.get(name_), str)
            and str(published_at[name_]) < pinned_at
        )

    return PackageFacts(
        name=name,
        version=version,
        yanked=withdrawn,
        yanked_reason="the version is no longer published" if withdrawn else None,
        latest=str(dist_tags["latest"]) if isinstance(dist_tags.get("latest"), str) else None,
        repository=repository,
        digests=digests,
        attested=attested,
        attested_versions=attested_versions,
    )


__all__ = [
    "MAX_RESPONSE_BYTES",
    "REGISTRY_HOSTS",
    "TIMEOUT_SECONDS",
    "PackageFacts",
    "RegistryError",
    "facts",
]
