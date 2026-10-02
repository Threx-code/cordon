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

import functools
import json
import time
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

RETRY_ATTEMPTS = 3
"""How many times one question is asked before it is given up on.

Three, not more. The budget this spends is bounded by the scan's own deadline,
and a registry that has refused three times in a row is down rather than busy."""

RETRY_BACKOFF_SECONDS = 0.25
"""Base for an exponential backoff: 0.25s, then 0.5s. Short, because a scan is
interactive and a retry that costs more than the answer is worth is not one."""

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
"""Statuses that mean "ask again". Everything else is a decision: a 404 is the
registry saying it does not have the package, and asking twice does not help."""

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

#: Hosts an attestation pointer may resolve to, by ecosystem. A registry answer
#: names the URL where a bundle lives, and that answer is attacker-adjacent, so
#: the URL is confined to the registry's own hosts before it is fetched -- the
#: same reasoning `REGISTRY_HOSTS` records, applied to the second hop.
ATTESTATION_HOSTS = {
    "npm": frozenset({"registry.npmjs.org"}),
    "pypi": frozenset({"pypi.org", "files.pythonhosted.org"}),
}

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

    first_published: str | None = None
    """ISO-8601 time of the package's first release: how long the name has existed."""

    releases: int = 0

    weekly_downloads: int | None = None
    """npm's last-week download count, asked only for a package under a quarter old. None when not
    asked, or for a registry with no first-party download figures (PyPI)."""

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


class PackageNotFound(RegistryError):
    """The registry answered, and it has no package by that name.

    Not an outage: a definite answer about the name. A dependency the public registry does not
    have is either private -- and a public package registered under the name would win, which is
    dependency confusion -- or invented, which is what an AI assistant does when it suggests a
    package that sounds right, and what slopsquatting registers.
    """


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuses every redirect by returning no follow-up request."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class RegistryClient:
    "Questions to the npm and PyPI registries, bounded and credential-free."

    @staticmethod
    def _fetch(url: str, *, accept: str = "application/json") -> dict[str, Any]:
        """One answer, bounded, with no credentials and no redirects.

        Retried, because a registry is a shared service and a single refused
        connection is not an answer. Without this one transient failure removed a
        package from every online check for the whole run, and the report said the
        registry "could not be asked" -- true, and indistinguishable from a package
        the registry does not have.

        Only the transport is retried. An HTTP status, a body that is too large and
        a body that is not JSON are all answers, and repeating the question does not
        change them.
        """
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https":
            raise RegistryError(f"refusing a non-HTTPS registry URL: {parsed.scheme}")

        request = urllib.request.Request(  # noqa: S310  (scheme checked above)
            url,
            headers={"User-Agent": USER_AGENT, "Accept": accept},
            method="GET",
        )
        opener = urllib.request.build_opener(_NoRedirect)

        body = b""
        for attempt in range(RETRY_ATTEMPTS):
            try:
                with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                    body = response.read(MAX_RESPONSE_BYTES + 1)
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    raise PackageNotFound(f"{parsed.netloc} has no package by that name") from exc
                # A status is the registry answering. 429 and 5xx are the two it
                # uses to say "not now", and only those are worth asking again.
                if exc.code not in RETRY_STATUSES or attempt == RETRY_ATTEMPTS - 1:
                    raise RegistryError(f"HTTP {exc.code} from {parsed.netloc}") from exc
                time.sleep(RETRY_BACKOFF_SECONDS * (2**attempt))
            except (urllib.error.URLError, OSError, ValueError) as exc:
                if attempt == RETRY_ATTEMPTS - 1:
                    raise RegistryError(f"{type(exc).__name__} asking {parsed.netloc}") from exc
                time.sleep(RETRY_BACKOFF_SECONDS * (2**attempt))

        if len(body) > MAX_RESPONSE_BYTES:
            raise RegistryError(
                f"response from {parsed.netloc} exceeded {MAX_RESPONSE_BYTES} bytes"
            )

        try:
            parsed_body = json.loads(body)
        except (json.JSONDecodeError, ValueError) as exc:
            raise RegistryError(f"unreadable response from {parsed.netloc}") from exc

        if not isinstance(parsed_body, dict):
            raise RegistryError(f"unexpected response shape from {parsed.netloc}")
        return parsed_body

    @staticmethod
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

    @staticmethod
    @functools.lru_cache(maxsize=2048)
    def _cached_facts(ecosystem: str, name: str, version: str | None) -> PackageFacts:
        if ecosystem == "pypi":
            return RegistryClient._pypi(name, version)
        if ecosystem == "npm":
            return RegistryClient._npm(name, version)
        raise RegistryError(f"no registry configured for {ecosystem}")

    @staticmethod
    def facts(ecosystem: str, name: str, version: str | None) -> PackageFacts:
        """What the registry says about this package, or a `RegistryError`.

        Memoised for the life of the process. Two detectors ask the same question
        about the same dependency -- the registry detector for withdrawal and
        hashes, the provenance detector for whether an attestation exists -- and
        npm answers both from one packument. Without this, a 250-dependency lockfile
        fetched the same document twice per package and spent most of an online scan
        waiting for bytes it already had.

        Per process, never written to disk. A registry answer is the one input that
        must not be stale: whether a version was yanked an hour ago is exactly the
        question being asked, and a cache that outlived the run would answer it with
        yesterday's truth.
        """
        return RegistryClient._cached_facts(ecosystem, name, version)

    @staticmethod
    def _pypi(name: str, version: str | None) -> PackageFacts:
        quoted = urllib.parse.quote(name, safe="")
        document = RegistryClient._fetch(f"{REGISTRY_HOSTS['pypi']}/pypi/{quoted}/json")

        info = RegistryClient._mapping(document.get("info"))
        releases = RegistryClient._mapping(document.get("releases"))

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

        project_urls = RegistryClient._mapping(info.get("project_urls"))
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
        attested, attested_versions = RegistryClient._pypi_attestations(name, version)

        uploads = [
            str(entry["upload_time_iso_8601"])
            for files in releases.values()
            if isinstance(files, list)
            for entry in files
            if isinstance(entry, dict) and isinstance(entry.get("upload_time_iso_8601"), str)
        ]

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
            first_published=min(uploads) if uploads else None,
            releases=sum(1 for files in releases.values() if isinstance(files, list) and files),
        )

    @staticmethod
    def _is_file_for_version(filename: str, version: str) -> bool:
        """Whether a PyPI filename is an artefact of exactly this version.

        A substring test on `-{version}` is not enough: `-1.2` occurs in
        `foo-1.2.3.tar.gz`, so a pin on `1.2` matched its own successor's files and
        could be credited with, or blamed for, provenance that belongs to a
        different release.

        PyPI filenames put the version in a fixed position -- `{name}-{version}` for
        an sdist, `{name}-{version}-{python}-{abi}-{platform}.whl` for a wheel -- so
        the version is the field after the first hyphen that follows the name, and
        what may follow it is a hyphen (a wheel's tags) or the start of an
        extension.
        """
        marker = f"-{version}"
        start = filename.find(marker)
        while start != -1:
            after = filename[start + len(marker) :]
            # A hyphen begins a wheel's compatibility tags; anything else must be
            # the whole remaining extension. Accepting any `.` here is what let
            # `-1.2` match `foo-1.2.3.tar.gz`, where the `.3` continues the version.
            if after == "" or after.startswith("-") or after.lower() in _SDIST_SUFFIXES:
                return True
            start = filename.find(marker, start + 1)
        return False

    @staticmethod
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
            document = RegistryClient._fetch(
                f"{REGISTRY_HOSTS['pypi']}/simple/{quoted}/",
                accept="application/vnd.pypi.simple.v1+json",
            )
        except RegistryError:
            return (False, 0)

        files = document.get("files")
        if not isinstance(files, list):
            return (False, 0)

        here = False
        pinned_at: str | None = None
        attested_at: list[str] = []

        for entry in files:
            if not isinstance(entry, dict):
                continue
            filename = str(entry.get("filename", ""))
            uploaded = entry.get("upload-time")
            uploaded = uploaded if isinstance(uploaded, str) else ""
            mine = version is not None and RegistryClient._is_file_for_version(filename, version)
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

    @staticmethod
    def _npm(name: str, version: str | None) -> PackageFacts:
        quoted = urllib.parse.quote(name, safe="@/")
        document = RegistryClient._fetch(f"{REGISTRY_HOSTS['npm']}/{quoted}")

        versions = RegistryClient._mapping(document.get("versions"))
        dist_tags = RegistryClient._mapping(document.get("dist-tags"))
        entry = RegistryClient._mapping(versions.get(version)) if version else {}

        # npm has no yank. It has unpublish, and a version that is gone from
        # `versions` while the package still exists is the same situation from the
        # consumer's side: something they depend on was withdrawn.
        withdrawn = bool(version) and bool(versions) and version not in versions

        repository_field = entry.get("repository") or document.get("repository")
        repository: str | None = None
        if isinstance(repository_field, str):
            repository = repository_field
        else:
            url = RegistryClient._mapping(repository_field).get("url")
            repository = url if isinstance(url, str) else None

        dist = RegistryClient._mapping(entry.get("dist"))
        digests = tuple(str(dist[key]) for key in ("integrity", "shasum") if dist.get(key))

        # `npm publish --provenance` records a sigstore bundle against the version,
        # and the packument carries a pointer to it under `dist.attestations`.
        attested = bool(RegistryClient._mapping(dist.get("attestations")))
        # Only the attested releases published before this one -- see
        # `PackageFacts.attested_versions`. The packument's `time` map carries an
        # ISO-8601 timestamp per version, which sorts lexically.
        published_at = RegistryClient._mapping(document.get("time"))
        pinned_at = published_at.get(version) if version else None
        attested_versions = 0
        if isinstance(pinned_at, str) and not attested:
            attested_versions = sum(
                1
                for name_, published in versions.items()
                if RegistryClient._mapping(
                    RegistryClient._mapping(RegistryClient._mapping(published).get("dist")).get(
                        "attestations"
                    )
                )
                and isinstance(published_at.get(name_), str)
                and str(published_at[name_]) < pinned_at
            )

        created = published_at.get("created")
        first_published = str(created) if isinstance(created, str) else None
        return PackageFacts(
            first_published=first_published,
            releases=len(versions),
            weekly_downloads=RegistryClient._npm_weekly_downloads(name)
            if RegistryClient._younger_than(first_published, NEW_PACKAGE_DAYS)
            else None,
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

    @staticmethod
    def _younger_than(timestamp: str | None, days: int) -> bool:
        import datetime as _dt

        if not timestamp:
            return False
        try:
            when = _dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            return False
        if when.tzinfo is None:
            when = when.replace(tzinfo=_dt.UTC)
        return (_dt.datetime.now(_dt.UTC) - when).days < days

    @staticmethod
    def _npm_weekly_downloads(name: str) -> int | None:
        quoted = urllib.parse.quote(name, safe="@/")
        try:
            document = RegistryClient._fetch(
                f"{NPM_DOWNLOADS_HOST}/downloads/point/last-week/{quoted}"
            )
        except RegistryError:
            return None
        value = document.get("downloads")
        return int(value) if isinstance(value, int) else None

    @staticmethod
    def attestation_payload(
        ecosystem: str, name: str, version: str | None
    ) -> dict[str, Any] | None:
        """The raw attestation document a registry serves for a version, or `None`.

        The transport only: this fetches the JSON the registry publishes (npm's
        attestations endpoint, PyPI's per-file provenance) and confines the URL to
        the ecosystem's own hosts. Turning that document into verifiable sigstore
        bundles is `intel.attest`'s job, because it needs the crypto stack the base
        does not carry. `None` means no attestation was published or the registry
        could not be reached -- both leave verification simply not attempted.
        """
        if not version:
            return None
        try:
            if ecosystem == "npm":
                return RegistryClient._npm_attestation_payload(name, version)
            if ecosystem == "pypi":
                return RegistryClient._pypi_attestation_payload(name, version)
        except RegistryError:
            return None
        return None

    @staticmethod
    def _fetch_from_allowlist(
        url: str, ecosystem: str, *, accept: str = "application/json"
    ) -> dict[str, Any]:
        host = urllib.parse.urlsplit(url).hostname or ""
        if host not in ATTESTATION_HOSTS.get(ecosystem, frozenset()):
            raise RegistryError(
                f"refusing an attestation URL off the {ecosystem} allowlist: {host!r}"
            )
        return RegistryClient._fetch(url, accept=accept)

    @staticmethod
    def _npm_attestation_payload(name: str, version: str) -> dict[str, Any] | None:
        quoted = urllib.parse.quote(name, safe="@/")
        packument = RegistryClient._fetch(f"{REGISTRY_HOSTS['npm']}/{quoted}")
        entry = RegistryClient._mapping(
            RegistryClient._mapping(packument.get("versions")).get(version)
        )
        attestations = RegistryClient._mapping(
            RegistryClient._mapping(entry.get("dist")).get("attestations")
        )
        url = attestations.get("url")
        if not isinstance(url, str):
            return None
        return RegistryClient._fetch_from_allowlist(url, "npm")

    @staticmethod
    def _pypi_attestation_payload(name: str, version: str) -> dict[str, Any] | None:
        quoted = urllib.parse.quote(name, safe="")
        simple = RegistryClient._fetch(
            f"{REGISTRY_HOSTS['pypi']}/simple/{quoted}/",
            accept="application/vnd.pypi.simple.v1+json",
        )
        files = simple.get("files")
        if not isinstance(files, list):
            return None
        for entry in files:
            if not isinstance(entry, dict):
                continue
            if not RegistryClient._is_file_for_version(str(entry.get("filename", "")), version):
                continue
            provenance = entry.get("provenance")
            if isinstance(provenance, str):
                return RegistryClient._fetch_from_allowlist(provenance, "pypi")
        return None

    @staticmethod
    def package_archive(ecosystem: str, name: str, version: str | None) -> PackageArchive:
        """Download the archive a registry publishes for a version (`None` means the latest).

        Never installed and never run: the bytes are returned for a scan to read. The download is
        host-pinned, size-bounded, redirect-free, and compared with the digest the registry
        publishes (npm's `integrity`, PyPI's sha256) before it is returned.
        """
        if ecosystem == "npm":
            return RegistryClient._npm_archive(name, version)
        if ecosystem == "pypi":
            return RegistryClient._pypi_archive(name, version)
        raise RegistryError(f"no archive support for {ecosystem}")

    @staticmethod
    def _fetch_bytes(url: str, ecosystem: str) -> bytes:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or (parsed.hostname or "") not in ARCHIVE_HOSTS.get(
            ecosystem, frozenset()
        ):
            raise RegistryError(
                f"refusing an archive URL off the {ecosystem} allowlist: {parsed.hostname!r}"
            )
        request = urllib.request.Request(  # noqa: S310 - scheme and host checked above
            url, headers={"User-Agent": USER_AGENT}, method="GET"
        )
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=TIMEOUT_SECONDS * 6) as response:
                body = response.read(MAX_ARCHIVE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise RegistryError(f"HTTP {exc.code} from {parsed.netloc}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise RegistryError(f"{type(exc).__name__} fetching from {parsed.netloc}") from exc
        if len(body) > MAX_ARCHIVE_BYTES:
            raise RegistryError(f"archive from {parsed.netloc} exceeded {MAX_ARCHIVE_BYTES} bytes")
        return bytes(body)

    @staticmethod
    def _npm_archive(name: str, version: str | None) -> PackageArchive:
        import base64
        import hashlib

        quoted = urllib.parse.quote(name, safe="@/")
        packument = RegistryClient._fetch(f"{REGISTRY_HOSTS['npm']}/{quoted}")
        resolved = version or str(
            RegistryClient._mapping(packument.get("dist-tags")).get("latest") or ""
        )
        entry = RegistryClient._mapping(
            RegistryClient._mapping(packument.get("versions")).get(resolved)
        )
        dist = RegistryClient._mapping(entry.get("dist"))
        url = dist.get("tarball")
        if not resolved or not isinstance(url, str):
            raise RegistryError(f"npm has no tarball for {name}@{version or 'latest'}")
        data = RegistryClient._fetch_bytes(url, "npm")
        integrity = str(dist.get("integrity", ""))
        if integrity.startswith("sha512-"):
            expected = base64.b64decode(integrity[len("sha512-") :])
            if hashlib.sha512(data).digest() != expected:
                raise RegistryError(f"{name}@{resolved} does not match the integrity npm publishes")
        else:
            raise RegistryError(f"npm publishes no sha512 integrity for {name}@{resolved}")
        return PackageArchive("npm", name, resolved, url.rsplit("/", 1)[-1], data)

    @staticmethod
    def _pypi_archive(name: str, version: str | None) -> PackageArchive:
        import hashlib

        quoted = urllib.parse.quote(name, safe="")
        path = (
            f"/pypi/{quoted}/{urllib.parse.quote(version, safe='')}/json"
            if version
            else f"/pypi/{quoted}/json"
        )
        document = RegistryClient._fetch(f"{REGISTRY_HOSTS['pypi']}{path}")
        resolved = str(
            RegistryClient._mapping(document.get("info")).get("version") or version or ""
        )
        files = [f for f in document.get("urls") or () if isinstance(f, dict)]
        # The sdist first: it is what a source install runs, including its build hooks.
        chosen = next((f for f in files if f.get("packagetype") == "sdist"), None) or next(
            (f for f in files if f.get("packagetype") == "bdist_wheel"), None
        )
        if chosen is None or not isinstance(chosen.get("url"), str):
            raise RegistryError(f"PyPI has no archive for {name}=={resolved}")
        data = RegistryClient._fetch_bytes(str(chosen["url"]), "pypi")
        expected = str(RegistryClient._mapping(chosen.get("digests")).get("sha256", ""))
        if not expected or hashlib.sha256(data).hexdigest() != expected:
            raise RegistryError(f"{name}=={resolved} does not match the sha256 PyPI publishes")
        return PackageArchive(
            "pypi", name, resolved, str(chosen.get("filename") or "package.tar.gz"), data
        )


#: Archive extensions a PyPI source distribution is published under. The
#: version is the last field before one of these, so the set is what decides
#: where a filename's version ends.
_SDIST_SUFFIXES = frozenset(
    {".tar.gz", ".tar.bz2", ".tar.xz", ".tar.z", ".tgz", ".zip", ".egg", ".whl"}
)


NEW_PACKAGE_DAYS = 90
"""A package younger than this has had little time to be noticed, reviewed or reported."""

NPM_DOWNLOADS_HOST = "https://api.npmjs.org"


#: Hosts a package archive may be downloaded from, by ecosystem. The registry names the URL, so
#: it is confined to the registry's own file hosts before it is fetched.
ARCHIVE_HOSTS = {
    "npm": frozenset({"registry.npmjs.org"}),
    "pypi": frozenset({"files.pythonhosted.org"}),
}
MAX_ARCHIVE_BYTES = 64 << 20


@dataclass(frozen=True, slots=True)
class PackageArchive:
    """One published package archive, downloaded and checked against the registry's digest."""

    ecosystem: str
    name: str
    version: str
    filename: str
    data: bytes


__all__ = [
    "ARCHIVE_HOSTS",
    "ATTESTATION_HOSTS",
    "MAX_RESPONSE_BYTES",
    "REGISTRY_HOSTS",
    "TIMEOUT_SECONDS",
    "PackageArchive",
    "PackageFacts",
    "PackageNotFound",
    "RegistryClient",
    "RegistryError",
]
