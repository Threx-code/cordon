"""The online questions for the registries beyond npm and PyPI (G5).

The same four questions `registry_client` asks npm and PyPI - withdrawn, how far behind, does the hash
agree, is there provenance - each answered from the registry's own public API, or stated as a question
that registry cannot answer:

| Ecosystem | Withdrawn | Latest | Hash | Provenance |
|---|---|---|---|---|
| crates.io | `yanked` per version | `max_stable_version` | sha256 `checksum` (what Cargo.lock records) | none published |
| RubyGems | a yanked version disappears from the versions list | gem `version` | sha256 per platform build | none in the public API |
| NuGet | `listed: false` (unlisted) | newest listed stable | catalog `packageHash` sha512 (packages.lock.json `contentHash`) | none published |
| Go | `retract` directives in the latest go.mod | the proxy's `@latest` | `h1:` from sum.golang.org (go.sum) | none for modules |
| Maven Central | never: Central does not delete releases | `release` in maven-metadata.xml | the artefact's published sha512, sha256 and sha1 | whether a Sigstore bundle sits beside the jar (no history of earlier releases, so the gap rule does not fire) |
| Packagist | a deleted tag disappears from the version list | newest stable | `dist.shasum` when the package publishes one (most do not) | none published |
| pub.dev | `retracted` per version | `latest` | `archive_sha256` (pubspec.lock `sha256`) | none published |
| Hex | `retirements` with the author's reason | `latest_stable_version` | the release's outer checksum (mix.lock's last hash) | none published |

The same rules as the rest of the client: fixed hosts, no credentials, no redirects, bounded reads, and
a failure raised rather than read as "no". Responses are attacker-adjacent (a gem's metadata is written
by whoever pushed it) and every field is narrowed before use. Text formats (Maven metadata, go.mod) are
read with patterns, never an XML parser.
"""

from __future__ import annotations

import gzip
import io
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Final

from cordon_scanner.intel import registry_client as base
from cordon_scanner.intel.registry_client import PackageFacts, PackageNotFound, RegistryError

HOSTS: Final = {
    "cargo": "https://crates.io",
    "rubygems": "https://rubygems.org",
    "nuget": "https://api.nuget.org",
    "gomod": "https://proxy.golang.org",
    "gosum": "https://sum.golang.org",
    "maven": "https://repo.maven.apache.org",
    "composer": "https://repo.packagist.org",
    "pub": "https://pub.dev",
    "hex": "https://hex.pm",
}

#: Ecosystem ids these readers answer for, and the reader's own id where the scanner has two
#: names for one registry (Gradle resolves from Maven Central).
ALIASES: Final = {
    "cargo": "cargo",
    "rubygems": "rubygems",
    "nuget": "nuget",
    "gomod": "gomod",
    "maven": "maven",
    "gradle": "maven",
    "composer": "composer",
    "pub": "pub",
    "hex": "hex",
}

#: The public hosts a lockfile records when a package came from these registries: a dependency
#: resolved from anywhere else came from a private source.
PUBLIC_HOSTS: Final = frozenset(
    {
        "crates.io",
        "static.crates.io",
        "index.crates.io",
        "rubygems.org",
        "index.rubygems.org",
        "api.nuget.org",
        "www.nuget.org",
        "proxy.golang.org",
        "repo.maven.apache.org",
        "repo1.maven.org",
        "repo.packagist.org",
        "packagist.org",
        "pub.dev",
        "pub.dartlang.org",
        "hex.pm",
        "repo.hex.pm",
    }
)

_MAX_GZIP_BYTES: Final = base.MAX_RESPONSE_BYTES
_VERSION_TAG: Final = re.compile(rb"<version>\s*([^<\s]{1,128})\s*</version>")
_RELEASE_TAG: Final = re.compile(rb"<(release|latest)>\s*([^<\s]{1,128})\s*</(?:release|latest)>")
_DIGEST_LINE: Final = re.compile(r"^\s*([0-9a-fA-F]{40,128})\b")


class MoreRegistries:
    """Readers for the registries `RegistryClient` does not speak, returning the same `PackageFacts`."""

    # -- transport -------------------------------------------------------------------------

    @staticmethod
    def _get(url: str, *, accept: str = "application/json") -> bytes:
        """One bounded, redirect-free, credential-free answer, decompressed when the server sent
        gzip (NuGet's registration pages always are), with the decompressed size bounded too."""
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https":
            raise RegistryError(f"refusing a non-HTTPS registry URL: {parsed.scheme}")
        request = urllib.request.Request(  # noqa: S310 (scheme checked above)
            url,
            headers={"User-Agent": base.USER_AGENT, "Accept": accept, "Accept-Encoding": "gzip"},
            method="GET",
        )
        opener = urllib.request.build_opener(base._NoRedirect)
        body, encoding = b"", ""
        for attempt in range(base.RETRY_ATTEMPTS):
            try:
                with opener.open(request, timeout=base.TIMEOUT_SECONDS) as response:
                    body = response.read(base.MAX_RESPONSE_BYTES + 1)
                    encoding = str(response.headers.get("Content-Encoding", "")).lower()
                break
            except urllib.error.HTTPError as exc:
                if exc.code in (404, 410):
                    # The Go proxy answers 410 Gone for a module it will not serve.
                    raise PackageNotFound(f"{parsed.netloc} has no package by that name") from exc
                if exc.code not in base.RETRY_STATUSES or attempt == base.RETRY_ATTEMPTS - 1:
                    raise RegistryError(f"HTTP {exc.code} from {parsed.netloc}") from exc
                time.sleep(base.RETRY_BACKOFF_SECONDS * (2**attempt))
            except (urllib.error.URLError, OSError, ValueError) as exc:
                if attempt == base.RETRY_ATTEMPTS - 1:
                    raise RegistryError(f"{type(exc).__name__} asking {parsed.netloc}") from exc
                time.sleep(base.RETRY_BACKOFF_SECONDS * (2**attempt))
        if len(body) > base.MAX_RESPONSE_BYTES:
            raise RegistryError(
                f"response from {parsed.netloc} exceeded {base.MAX_RESPONSE_BYTES} bytes"
            )
        if encoding == "gzip" or body[:2] == b"\x1f\x8b":
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:
                    body = stream.read(_MAX_GZIP_BYTES + 1)
            except (OSError, EOFError) as exc:
                raise RegistryError(f"unreadable compressed response from {parsed.netloc}") from exc
            if len(body) > _MAX_GZIP_BYTES:
                raise RegistryError(
                    f"response from {parsed.netloc} expands past {_MAX_GZIP_BYTES} bytes"
                )
        return body

    @staticmethod
    def _json(url: str) -> Any:
        body = MoreRegistries._get(url)
        try:
            return json.loads(body)
        except (json.JSONDecodeError, ValueError) as exc:
            raise RegistryError(
                f"unreadable response from {urllib.parse.urlsplit(url).netloc}"
            ) from exc

    @staticmethod
    def _text(url: str) -> str:
        return MoreRegistries._get(url, accept="text/plain").decode("utf-8", "replace")

    @staticmethod
    def _mapping(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _entries(value: Any) -> list[dict[str, Any]]:
        return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []

    @staticmethod
    def _str(value: Any) -> str | None:
        return value if isinstance(value, str) and value else None

    # -- dispatch --------------------------------------------------------------------------

    @staticmethod
    def facts(ecosystem: str, name: str, version: str | None) -> PackageFacts:
        reader = {
            "cargo": MoreRegistries.cargo,
            "rubygems": MoreRegistries.rubygems,
            "nuget": MoreRegistries.nuget,
            "gomod": MoreRegistries.gomod,
            "maven": MoreRegistries.maven,
            "composer": MoreRegistries.composer,
            "pub": MoreRegistries.pub,
            "hex": MoreRegistries.hex,
        }.get(ALIASES.get(ecosystem, ""))
        if reader is None:
            raise RegistryError(f"no registry configured for {ecosystem}")
        return reader(name, version)

    # -- crates.io -------------------------------------------------------------------------

    @staticmethod
    def cargo(name: str, version: str | None) -> PackageFacts:
        document = MoreRegistries._mapping(
            MoreRegistries._json(
                f"{HOSTS['cargo']}/api/v1/crates/{urllib.parse.quote(name, safe='')}"
            )
        )
        crate = MoreRegistries._mapping(document.get("crate"))
        versions = MoreRegistries._entries(document.get("versions"))
        entry = next((v for v in versions if v.get("num") == version), {}) if version else {}
        checksum = MoreRegistries._str(entry.get("checksum"))
        return PackageFacts(
            name=name,
            version=version,
            yanked=bool(entry.get("yanked")),
            yanked_reason=MoreRegistries._str(entry.get("yank_message")),
            latest=MoreRegistries._str(crate.get("max_stable_version"))
            or MoreRegistries._str(crate.get("newest_version")),
            repository=MoreRegistries._str(crate.get("repository")),
            digests=(checksum,) if checksum else (),
            first_published=MoreRegistries._str(crate.get("created_at")),
            releases=len(versions),
        )

    # -- RubyGems --------------------------------------------------------------------------

    @staticmethod
    def rubygems(name: str, version: str | None) -> PackageFacts:
        quoted = urllib.parse.quote(name, safe="")
        gem = MoreRegistries._mapping(
            MoreRegistries._json(f"{HOSTS['rubygems']}/api/v1/gems/{quoted}.json")
        )
        versions = MoreRegistries._entries(
            MoreRegistries._json(f"{HOSTS['rubygems']}/api/v1/versions/{quoted}.json")
        )

        def matches(v: dict[str, Any]) -> bool:
            number, platform = str(v.get("number", "")), str(v.get("platform", "ruby"))
            return version in (number, f"{number}-{platform}")

        builds = [v for v in versions if matches(v)] if version else []
        # RubyGems removes a yanked version from this list: a version the gem no longer lists, while
        # the gem itself exists, is one its owner withdrew.
        yanked = bool(version) and not builds
        created = [str(v["created_at"]) for v in versions if isinstance(v.get("created_at"), str)]
        return PackageFacts(
            name=name,
            version=version,
            yanked=yanked,
            yanked_reason="no longer listed on rubygems.org" if yanked else None,
            latest=MoreRegistries._str(gem.get("version")),
            repository=MoreRegistries._str(gem.get("source_code_uri"))
            or MoreRegistries._str(gem.get("homepage_uri")),
            digests=tuple(str(v["sha"]) for v in builds if isinstance(v.get("sha"), str)),
            first_published=min(created) if created else None,
            releases=len({v.get("number") for v in versions}),
        )

    # -- NuGet -----------------------------------------------------------------------------

    @staticmethod
    def _nuget_allowed(url: str) -> str:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or parts.hostname != "api.nuget.org":
            raise RegistryError("NuGet named a page outside api.nuget.org; it was not fetched")
        return url

    @staticmethod
    def nuget(name: str, version: str | None) -> PackageFacts:
        package_id = name.lower()
        index = MoreRegistries._mapping(
            MoreRegistries._json(
                f"{HOSTS['nuget']}/v3/registration5-gz-semver2/{urllib.parse.quote(package_id, safe='')}/index.json"
            )
        )
        leaves: list[dict[str, Any]] = []
        for page in MoreRegistries._entries(index.get("items"))[:50]:
            items = page.get("items")
            if not isinstance(items, list):
                url = MoreRegistries._str(page.get("@id"))
                if url is None:
                    continue
                items = MoreRegistries._mapping(
                    MoreRegistries._json(MoreRegistries._nuget_allowed(url))
                ).get("items")
            for item in MoreRegistries._entries(items):
                entry = MoreRegistries._mapping(item.get("catalogEntry"))
                if entry:
                    leaves.append(entry)

        def same(v: Any) -> bool:
            return isinstance(v, str) and version is not None and v.lower() == version.lower()

        entry = next((e for e in leaves if same(e.get("version"))), {})
        listed = entry.get("listed", True) is not False
        deprecation = MoreRegistries._mapping(entry.get("deprecation"))
        reasons = [str(r) for r in deprecation.get("reasons") or [] if isinstance(r, str)]
        digest: tuple[str, ...] = ()
        leaf_url = MoreRegistries._str(entry.get("@id"))
        if leaf_url:
            leaf = MoreRegistries._mapping(
                MoreRegistries._json(MoreRegistries._nuget_allowed(leaf_url))
            )
            algorithm = str(leaf.get("packageHashAlgorithm", "")).lower()
            package_hash = MoreRegistries._str(leaf.get("packageHash"))
            if package_hash and algorithm in ("sha512", "sha256"):
                digest = (f"{algorithm}-{package_hash}",)
        stable = [
            str(e["version"])
            for e in leaves
            if isinstance(e.get("version"), str)
            and e.get("listed", True) is not False
            and "-" not in str(e["version"])
        ]
        # An unlisted package reports `published` as 1900-01-01: not a date, so not counted.
        published = sorted(
            str(e["published"])
            for e in leaves
            if isinstance(e.get("published"), str) and not str(e["published"]).startswith("1900")
        )
        reason = None
        if not listed:
            reason = "unlisted on nuget.org" + (
                f"; deprecated: {', '.join(reasons)}" if reasons else ""
            )
        return PackageFacts(
            name=name,
            version=version,
            yanked=bool(version) and bool(entry) and not listed,
            yanked_reason=reason,
            latest=stable[-1] if stable else None,
            repository=MoreRegistries._str(entry.get("projectUrl")),
            digests=digest,
            first_published=published[0] if published else None,
            releases=len(leaves),
        )

    # -- Go --------------------------------------------------------------------------------

    @staticmethod
    def go_escape(path: str) -> str:
        return "".join(f"!{c.lower()}" if "A" <= c <= "Z" else c for c in path)

    @staticmethod
    def retractions(go_mod: str) -> dict[str, str]:
        """`version -> rationale` for every version a go.mod retracts, single or in ranges.
        Ranges are expanded against nothing: they are returned as `lo..hi` keys for `retracted`."""
        out: dict[str, str] = {}
        text = re.sub(r"(?s)/\*.*?\*/", "", go_mod)
        blocks = re.findall(r"(?ms)^\s*retract\s*\((.*?)^\s*\)", text)
        singles = re.findall(r"(?m)^\s*retract\s+([^(\n][^\n]*)$", text)
        for line in [ln for block in blocks for ln in block.splitlines()] + singles:
            body, _, comment = line.partition("//")
            body = body.strip()
            rationale = comment.strip()
            if not body:
                continue
            ranged = re.match(r"^\[\s*(v[^\s,\]]+)\s*,\s*(v[^\s,\]]+)\s*\]$", body)
            if ranged:
                out[f"{ranged.group(1)}..{ranged.group(2)}"] = rationale
            elif re.match(r"^v\S+$", body):
                out[body] = rationale
        return out

    @staticmethod
    def retracted(version: str, retractions: dict[str, str]) -> str | None:
        """The rationale when `version` is retracted, single or within a range; else None."""
        if version in retractions:
            return retractions[version] or "retracted by its author"
        key = MoreRegistries._semver_key(version)
        if key is None:
            return None
        for span, rationale in retractions.items():
            if ".." not in span:
                continue
            low, high = (MoreRegistries._semver_key(v) for v in span.split("..", 1))
            if low is not None and high is not None and low <= key <= high:
                return rationale or "retracted by its author"
        return None

    @staticmethod
    def _semver_key(version: str) -> tuple[Any, ...] | None:
        match = re.match(
            r"^v(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$", version
        )
        if not match:
            return None
        major, minor, patch, pre = match.groups()
        ids = (
            tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
            if pre
            else ()
        )
        return (int(major), int(minor), int(patch), 0 if pre else 1, ids)

    @staticmethod
    def gomod(name: str, version: str | None) -> PackageFacts:
        module = MoreRegistries.go_escape(name)
        listing = [
            v.strip()
            for v in MoreRegistries._text(f"{HOSTS['gomod']}/{module}/@v/list").splitlines()
            if v.strip()
        ]
        latest = MoreRegistries._str(
            MoreRegistries._mapping(MoreRegistries._json(f"{HOSTS['gomod']}/{module}/@latest")).get(
                "Version"
            )
        )
        rationale = None
        if latest and version:
            try:
                go_mod = MoreRegistries._text(
                    f"{HOSTS['gomod']}/{module}/@v/{MoreRegistries.go_escape(latest)}.mod"
                )
            except PackageNotFound:
                go_mod = ""
            rationale = MoreRegistries.retracted(version, MoreRegistries.retractions(go_mod))
        digests: tuple[str, ...] = ()
        if version:
            try:
                lookup = MoreRegistries._text(
                    f"{HOSTS['gosum']}/lookup/{module}@{MoreRegistries.go_escape(version)}"
                )
            except PackageNotFound:
                lookup = ""
            digests = tuple(
                parts[2]
                for parts in (line.split() for line in lookup.splitlines())
                if len(parts) == 3 and parts[0] == name and parts[2].startswith("h1:")
            )
        repository = (
            f"https://{name}"
            if name.startswith(("github.com/", "gitlab.com/", "bitbucket.org/"))
            else None
        )
        return PackageFacts(
            name=name,
            version=version,
            yanked=rationale is not None,
            yanked_reason=rationale if rationale else None,
            latest=latest,
            repository=repository,
            digests=digests,
            releases=len(listing),
        )

    # -- Maven Central ---------------------------------------------------------------------

    @staticmethod
    def maven(name: str, version: str | None) -> PackageFacts:
        group, _, artifact = name.partition(":")
        if not group or not artifact or "/" in name or ".." in name:
            raise RegistryError(f"{name} is not a Maven group:artifact")
        root = f"{HOSTS['maven']}/maven2/{group.replace('.', '/')}/{artifact}"
        metadata = MoreRegistries._get(f"{root}/maven-metadata.xml", accept="application/xml")
        versions = [v.decode() for v in _VERSION_TAG.findall(metadata)]
        tags = {kind.decode(): value.decode() for kind, value in _RELEASE_TAG.findall(metadata)}
        digests: tuple[str, ...] = ()
        attested = False
        if version and version in versions:
            stem = f"{root}/{version}/{artifact}-{version}.jar"
            # Every algorithm Central publishes, because a lockfile records one and a comparison
            # is only made within an algorithm: Gradle verification commonly records sha256 or
            # sha512, and older artefacts carry only sha1.
            found = []
            for algorithm in ("sha512", "sha256", "sha1"):
                try:
                    match = _DIGEST_LINE.match(MoreRegistries._text(f"{stem}.{algorithm}"))
                except RegistryError:
                    # Absent or unreachable: that algorithm is not compared, and the rest still are.
                    continue
                if match:
                    found.append(f"{algorithm}:{match.group(1).lower()}")
            digests = tuple(found)
            try:
                attested = isinstance(MoreRegistries._json(f"{stem}.sigstore.json"), dict)
            except RegistryError:
                attested = False
        return PackageFacts(
            name=name,
            version=version,
            # Maven Central never deletes a release, so nothing on it is ever withdrawn.
            yanked=False,
            latest=tags.get("release")
            or tags.get("latest")
            or (versions[-1] if versions else None),
            digests=digests,
            attested=attested,
            releases=len(versions),
        )

    # -- Packagist -------------------------------------------------------------------------

    @staticmethod
    def expand_minified(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Composer 2's minified metadata: each version lists only the keys that changed from the one
        before it, and `"__unset"` removes one. Expanded so every version is a whole record."""
        expanded: list[dict[str, Any]] = []
        current: dict[str, Any] = {}
        for entry in entries:
            current = dict(current)
            for key, value in entry.items():
                if value == "__unset":
                    current.pop(key, None)
                else:
                    current[key] = value
            expanded.append(current)
        return expanded

    @staticmethod
    def _stable(version: str) -> bool:
        lowered = version.lower()
        return not any(tag in lowered for tag in ("dev", "alpha", "beta", "rc", "-"))

    @staticmethod
    def composer(name: str, version: str | None) -> PackageFacts:
        vendor, _, package = name.lower().partition("/")
        if not vendor or not package or "/" in package or ".." in name:
            raise RegistryError(f"{name} is not a Composer vendor/package")
        document = MoreRegistries._mapping(
            MoreRegistries._json(
                f"{HOSTS['composer']}/p2/{urllib.parse.quote(vendor, safe='')}/{urllib.parse.quote(package, safe='')}.json"
            )
        )
        raw = MoreRegistries._mapping(document.get("packages")).get(name.lower())
        versions = MoreRegistries.expand_minified(MoreRegistries._entries(raw))
        development = version is None or version.startswith("dev-") or version.endswith("-dev")

        def same(entry: dict[str, Any]) -> bool:
            return version is not None and version in (
                entry.get("version"),
                entry.get("version_normalized"),
            )

        entry = next((e for e in versions if same(e)), {})
        # A Packagist version is a tag in the package's repository: one the list no longer carries,
        # while the package does, had its tag deleted after it was published. Development branches
        # are never in this list, so their absence means nothing.
        withdrawn = not development and bool(versions) and not entry
        dist = MoreRegistries._mapping(entry.get("dist"))
        shasum = MoreRegistries._str(dist.get("shasum"))
        stable = [
            str(e["version"])
            for e in versions
            if isinstance(e.get("version"), str) and MoreRegistries._stable(str(e["version"]))
        ]
        times = sorted(str(e["time"]) for e in versions if isinstance(e.get("time"), str))
        return PackageFacts(
            name=name,
            version=version,
            yanked=withdrawn,
            yanked_reason="no longer published on Packagist" if withdrawn else None,
            latest=stable[0] if stable else None,
            repository=MoreRegistries._str(
                MoreRegistries._mapping(
                    entry.get("source") or (versions[0].get("source") if versions else None)
                ).get("url")
            ),
            digests=(shasum,) if shasum else (),
            first_published=times[0] if times else None,
            releases=len(versions),
        )

    # -- pub.dev ---------------------------------------------------------------------------

    @staticmethod
    def pub(name: str, version: str | None) -> PackageFacts:
        document = MoreRegistries._mapping(
            MoreRegistries._json(f"{HOSTS['pub']}/api/packages/{urllib.parse.quote(name, safe='')}")
        )
        versions = MoreRegistries._entries(document.get("versions"))
        latest = MoreRegistries._mapping(document.get("latest"))
        pubspec = MoreRegistries._mapping(latest.get("pubspec"))
        entry = next((v for v in versions if v.get("version") == version), {}) if version else {}
        digest = MoreRegistries._str(entry.get("archive_sha256"))
        published = sorted(
            str(v["published"]) for v in versions if isinstance(v.get("published"), str)
        )
        return PackageFacts(
            name=name,
            version=version,
            yanked=entry.get("retracted") is True,
            yanked_reason="retracted by its publisher" if entry.get("retracted") is True else None,
            latest=MoreRegistries._str(latest.get("version")),
            repository=MoreRegistries._str(pubspec.get("repository"))
            or MoreRegistries._str(pubspec.get("homepage")),
            digests=(f"sha256:{digest.lower()}",) if digest else (),
            first_published=published[0] if published else None,
            releases=len(versions),
        )

    # -- Hex -------------------------------------------------------------------------------

    @staticmethod
    def hex(name: str, version: str | None) -> PackageFacts:
        quoted = urllib.parse.quote(name, safe="")
        document = MoreRegistries._mapping(
            MoreRegistries._json(f"{HOSTS['hex']}/api/packages/{quoted}")
        )
        retirements = MoreRegistries._mapping(document.get("retirements"))
        retired = MoreRegistries._mapping(retirements.get(version)) if version else {}
        releases = MoreRegistries._entries(document.get("releases"))
        links = MoreRegistries._mapping(MoreRegistries._mapping(document.get("meta")).get("links"))
        repository = next(
            (
                str(links[k])
                for k in links
                if isinstance(links[k], str)
                and k.lower() in ("github", "gitlab", "source", "repository")
            ),
            None,
        )
        digests: tuple[str, ...] = ()
        if version and any(r.get("version") == version for r in releases):
            release = MoreRegistries._mapping(
                MoreRegistries._json(
                    f"{HOSTS['hex']}/api/packages/{quoted}/releases/{urllib.parse.quote(version, safe='')}"
                )
            )
            checksum = MoreRegistries._str(release.get("checksum"))
            digests = (f"sha256:{checksum.lower()}",) if checksum else ()
        reason = None
        if retired:
            reason = (
                " - ".join(
                    str(retired[k])
                    for k in ("reason", "message")
                    if isinstance(retired.get(k), str) and retired[k]
                )
                or "retired by its owner"
            )
        return PackageFacts(
            name=name,
            version=version,
            yanked=bool(retired),
            yanked_reason=reason,
            latest=MoreRegistries._str(document.get("latest_stable_version"))
            or MoreRegistries._str(document.get("latest_version")),
            repository=repository,
            digests=digests,
            first_published=MoreRegistries._str(document.get("inserted_at")),
            releases=len(releases),
        )
