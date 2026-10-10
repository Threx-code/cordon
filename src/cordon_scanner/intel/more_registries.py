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
import tomllib
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
    "cocoapods": "https://cdn.cocoapods.org",
    "conda": "https://api.anaconda.org",
    "cran": "https://crandb.r-pkg.org",
    "hackage": "https://hackage.haskell.org",
    "julia": "https://raw.githubusercontent.com/JuliaRegistries/General/master",
    "opam": "https://raw.githubusercontent.com/ocaml/opam-repository/master",
    "opam-site": "https://opam.ocaml.org",
    "conan": "https://center2.conan.io",
    "vcpkg": "https://raw.githubusercontent.com/microsoft/vcpkg/master",
    "actions": "https://github.com",
    "ansible": "https://galaxy.ansible.com",
    "terraform": "https://registry.terraform.io",
    "bazel": "https://bcr.bazel.build",
    "homebrew": "https://formulae.brew.sh",
    "image": "https://registry-1.docker.io",
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
    "cocoapods": "cocoapods",
    "conda": "conda",
    "cran": "cran",
    "hackage": "hackage",
    "julia": "julia",
    "opam": "opam",
    "conan": "conan",
    "vcpkg": "vcpkg",
    "actions": "actions",
    "ansible": "ansible",
    "terraform": "terraform",
    "helm": "helm",
    "bazel": "bazel",
    "homebrew": "homebrew",
    "brew": "homebrew",
    "image": "image",
    "docker": "image",
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
        "cdn.cocoapods.org",
        "trunk.cocoapods.org",
        "conda.anaconda.org",
        "api.anaconda.org",
        "cran.r-project.org",
        "cloud.r-project.org",
        "crandb.r-pkg.org",
        "hackage.haskell.org",
        "center2.conan.io",
        "center.conan.io",
        "galaxy.ansible.com",
        "registry.terraform.io",
        "bcr.bazel.build",
        "formulae.brew.sh",
        "releases.hashicorp.com",
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
    def facts(
        ecosystem: str, name: str, version: str | None, source: str | None = None
    ) -> PackageFacts:
        if ALIASES.get(ecosystem) == "helm":
            # The one registry that is not one: each chart's repository is its own.
            return MoreRegistries.helm(name, version, source)
        reader = {
            "cargo": MoreRegistries.cargo,
            "rubygems": MoreRegistries.rubygems,
            "nuget": MoreRegistries.nuget,
            "gomod": MoreRegistries.gomod,
            "maven": MoreRegistries.maven,
            "composer": MoreRegistries.composer,
            "pub": MoreRegistries.pub,
            "hex": MoreRegistries.hex,
            "cocoapods": MoreRegistries.cocoapods,
            "conda": MoreRegistries.conda,
            "cran": MoreRegistries.cran,
            "hackage": MoreRegistries.hackage,
            "julia": MoreRegistries.julia,
            "opam": MoreRegistries.opam,
            "conan": MoreRegistries.conan,
            "vcpkg": MoreRegistries.vcpkg,
            "actions": MoreRegistries.actions,
            "ansible": MoreRegistries.ansible,
            "terraform": MoreRegistries.terraform,
            "bazel": MoreRegistries.bazel,
            "homebrew": MoreRegistries.homebrew,
            "image": MoreRegistries.image,
        }.get(ALIASES.get(ecosystem, ""))
        if reader is None:
            raise RegistryError(f"no registry configured for {ecosystem}")
        return reader(name, version)

    # -- CRAN (crandb) -----------------------------------------------------------------------

    @staticmethod
    def cran(name: str, version: str | None) -> PackageFacts:
        """crandb, r-pkg.org's database of CRAN: every version with its DESCRIPTION, the
        publication timeline, and whether CRAN archived the package -- removed it for problems the
        maintainer did not fix, which is CRAN's withdrawal. CRAN publishes no archive hash a lock
        could be compared with, so none is returned."""
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9.]{0,127}", name):
            raise RegistryError(f"{name} is not a CRAN package name")
        document = MoreRegistries._mapping(MoreRegistries._json(f"{HOSTS['cran']}/{name}/all"))
        versions = MoreRegistries._mapping(document.get("versions"))
        timeline = MoreRegistries._mapping(document.get("timeline"))
        archived = document.get("archived") is True
        # R reads a version as integers separated by single `.` or `-` (`package_version`):
        # `1.2.16` and `1.2-16` are one version. A renv.lock pinning AER `1.2.16` -- CRAN's
        # `1.2-16` -- was reported withdrawn, as were 60 more of one real lock.
        wanted = MoreRegistries._r_version(version) if version else None
        known = bool(version) and (
            version in versions
            or (
                wanted is not None and any(MoreRegistries._r_version(v) == wanted for v in versions)
            )
        )
        latest = (
            MoreRegistries._mapping(document.get("latest"))
            if isinstance(document.get("latest"), dict)
            else {}
        )
        dates = [str(v) for v in timeline.values() if isinstance(v, str)]
        return PackageFacts(
            name=name,
            version=version,
            yanked=archived or (bool(version) and not known),
            yanked_reason="archived by CRAN"
            if archived
            else ("not a version CRAN published" if version and not known else None),
            latest=MoreRegistries._str(latest.get("Version"))
            or (
                max(versions, key=lambda v: MoreRegistries._r_version(v) or ())
                if versions
                else None
            ),
            first_published=min(dates) if dates else None,
            last_published=max(dates) if dates else None,
            releases=len(versions),
        )

    @staticmethod
    def _r_version(value: str) -> tuple[int, ...] | None:
        """An R package version as R compares it: its integers, separated by `.` or `-`. None
        for a string that is not one."""
        if not re.fullmatch(r"\d+(?:[.-]\d+)+", value):
            return None
        return tuple(int(part) for part in re.split(r"[.-]", value))

    # -- Container images ------------------------------------------------------------------

    MANIFEST_TYPES: Final = ", ".join(
        (
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        )
    )

    MAX_REFERRERS: Final = 8
    BUNDLE_TYPE: Final = "application/vnd.dev.sigstore.bundle"

    @staticmethod
    def _image_location(name: str) -> str:
        from cordon_scanner.ecosystems.image import ImageReference, PublicRegistries

        reference = ImageReference.parse(name)
        if (
            reference is None
            or reference.tag
            or reference.digest
            or (reference.registry and not PublicRegistries.covers(reference.registry))
        ):
            raise RegistryError(f"{name} is not an image on a public registry")
        return f"https://{reference.registry or 'registry-1.docker.io'}/v2/{reference.repository}"

    @staticmethod
    def _image_referrers(base_url: str, digest: str) -> list[dict[str, Any]]:
        """The Sigstore bundles attached to a manifest: from the OCI referrers API, or the
        `sha256-<hex>` tag a registry without one holds them under (the OCI 1.1 fallback)."""
        index: Any = None
        try:
            index = MoreRegistries._oci(
                f"{base_url}/referrers/{digest}", "application/vnd.oci.image.index.v1+json"
            )
        except PackageNotFound:
            index = None
        if not MoreRegistries._entries(MoreRegistries._mapping(index).get("manifests")):
            try:
                index = MoreRegistries._oci(
                    f"{base_url}/manifests/{digest.replace(':', '-')}",
                    "application/vnd.oci.image.index.v1+json",
                )
            except PackageNotFound:
                return []
        return [
            entry
            for entry in MoreRegistries._entries(MoreRegistries._mapping(index).get("manifests"))
            if str(entry.get("artifactType", "")).startswith(MoreRegistries.BUNDLE_TYPE)
            and isinstance(entry.get("digest"), str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", entry["digest"])
        ][: MoreRegistries.MAX_REFERRERS]

    @staticmethod
    def _image_source(base_url: str, document: dict[str, Any]) -> str | None:
        """The repository an image says it was built from: `org.opencontainers.image.source`, in
        the manifest's annotations or the (first platform's) configuration's labels."""
        key = "org.opencontainers.image.source"
        stated = MoreRegistries._mapping(document.get("annotations")).get(key)
        if not isinstance(stated, str):
            manifest = document
            platforms = [
                entry
                for entry in MoreRegistries._entries(document.get("manifests"))
                if MoreRegistries._mapping(entry.get("platform")).get("os") not in (None, "unknown")
            ]
            if platforms and isinstance(platforms[0].get("digest"), str):
                manifest = MoreRegistries._mapping(
                    MoreRegistries._oci(
                        f"{base_url}/manifests/{platforms[0]['digest']}",
                        MoreRegistries.MANIFEST_TYPES,
                    )
                )
            config = MoreRegistries._mapping(manifest.get("config")).get("digest")
            if isinstance(config, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", config):
                document = MoreRegistries._mapping(
                    json.loads(MoreRegistries._oci_blob(base_url, config))
                )
                stated = MoreRegistries._mapping(
                    MoreRegistries._mapping(document.get("config")).get("Labels")
                ).get(key)
        return stated if isinstance(stated, str) and stated.startswith("https://") else None

    @staticmethod
    def _oci_blob(base_url: str, digest: str) -> bytes:
        """A blob, which is content-addressed: refused unless its bytes hash to its digest."""
        import hashlib

        data = MoreRegistries._oci_bytes(f"{base_url}/blobs/{digest}", "*/*", follow=True)
        if f"sha256:{hashlib.sha256(data).hexdigest()}" != digest:
            raise RegistryError("a registry served a blob whose bytes do not match its digest")
        return data

    @staticmethod
    def image_attestations(name: str, version: str | None) -> dict[str, Any] | None:
        """The Sigstore bundles signed for the manifest a tag or digest names, for `intel.attest`
        to verify against the digest the project pinned."""
        if version is None:
            return None
        import hashlib

        base_url = MoreRegistries._image_location(name)
        if re.fullmatch(r"sha256:[0-9a-f]{64}", version):
            digest = version
        else:
            if not re.fullmatch(r"[\w][\w.-]{0,127}", version):
                return None
            digest = f"sha256:{hashlib.sha256(MoreRegistries._oci_bytes(f'{base_url}/manifests/{version}', MoreRegistries.MANIFEST_TYPES)).hexdigest()}"
        bundles: list[Any] = []
        for referrer in MoreRegistries._image_referrers(base_url, digest):
            manifest = MoreRegistries._mapping(
                MoreRegistries._oci(
                    f"{base_url}/manifests/{referrer['digest']}",
                    "application/vnd.oci.image.manifest.v1+json",
                )
            )
            for layer in MoreRegistries._entries(manifest.get("layers"))[:2]:
                if (
                    str(layer.get("mediaType", "")).startswith(MoreRegistries.BUNDLE_TYPE)
                    and isinstance(layer.get("digest"), str)
                    and re.fullmatch(r"sha256:[0-9a-f]{64}", layer["digest"])
                ):
                    bundle = json.loads(MoreRegistries._oci_blob(base_url, layer["digest"]))
                    if isinstance(bundle, dict):
                        bundles.append(bundle)
        return {"bundles": bundles} if bundles else None

    @staticmethod
    def image(name: str, version: str | None) -> PackageFacts:
        """An image on a public registry, through the OCI distribution API: its tags, and the
        digest of what a tag (or a digest) names -- the SHA-256 of the manifest as served, which is
        what `image@sha256:...` pins, and of each platform's manifest under an index, since a pin
        can name either."""
        base_url = MoreRegistries._image_location(name)
        if version is not None and not re.fullmatch(
            r"[\w][\w.-]{0,127}|sha256:[0-9a-f]{64}", version
        ):
            raise RegistryError(f"{version} is not a tag or a digest")
        listed = [
            str(t)
            for t in MoreRegistries._mapping(
                MoreRegistries._oci(f"{base_url}/tags/list?n=1000", "application/json")
            ).get("tags")
            or []
            if isinstance(t, str)
        ]
        digests: tuple[str, ...] = ()
        found = True
        source = None
        attested = False
        if version is not None:
            try:
                raw = MoreRegistries._oci_bytes(
                    f"{base_url}/manifests/{version}", MoreRegistries.MANIFEST_TYPES
                )
            except PackageNotFound:
                found = False
            else:
                import hashlib

                document = MoreRegistries._mapping(json.loads(raw))
                platforms = [
                    str(entry["digest"]).lower()
                    for entry in MoreRegistries._entries(document.get("manifests"))[
                        : MoreRegistries.MAX_PLATFORMS
                    ]
                    if isinstance(entry.get("digest"), str)
                    and re.fullmatch(r"sha256:[0-9a-fA-F]{64}", entry["digest"])
                ]
                digests = (f"sha256:{hashlib.sha256(raw).hexdigest()}", *platforms)
                # What the image says of itself, and whether anything is signed for it: asked
                # after the digest, and unknown -- not fatal -- when either cannot be read.
                try:
                    source = MoreRegistries._image_source(base_url, document)
                except (PackageNotFound, RegistryError, ValueError):
                    source = None
                try:
                    attested = bool(MoreRegistries._image_referrers(base_url, digests[0]))
                except (RegistryError, ValueError):
                    attested = False
        return PackageFacts(
            name=name,
            version=version,
            yanked=not found,
            yanked_reason=None
            if found
            else (
                "not a digest the registry holds"
                if version and version.startswith("sha256:")
                else "not a tag the registry holds"
            ),
            # No latest: an image's tags are not one release line -- alpine's `3.20` sits beside its
            # `20260805` snapshots, python's `3.12-slim` beside `3.13-alpine` -- so no tag is the
            # newer version of another, and a distance between them would be invented.
            latest=None,
            repository=source,
            digests=digests,
            releases=len(listed),
            attested=attested,
        )

    # -- Homebrew --------------------------------------------------------------------------

    @staticmethod
    def homebrew(name: str, version: str | None) -> PackageFacts:
        """formulae.brew.sh: a formula's current version, its source checksum and every bottle's
        (what Brewfile.lock.json records), and whether it is deprecated or disabled; a name that is
        not a formula is looked up as a cask. Homebrew keeps one version of each formula: an older
        one is not on the registry any more."""
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9@+._\-]{0,127}", name):
            raise RegistryError(f"{name} is not a formula or cask name")
        try:
            data = MoreRegistries._mapping(
                MoreRegistries._json(f"{HOSTS['homebrew']}/api/formula/{name}.json")
            )
            current = str(MoreRegistries._mapping(data.get("versions")).get("stable") or "") or None
            stable = MoreRegistries._mapping(
                MoreRegistries._mapping(data.get("urls")).get("stable")
            )
            found = [stable["checksum"]] if isinstance(stable.get("checksum"), str) else []
            bottle = MoreRegistries._mapping(
                MoreRegistries._mapping(data.get("bottle")).get("stable")
            )
            for file in MoreRegistries._mapping(bottle.get("files")).values():
                digest = MoreRegistries._mapping(file).get("sha256")
                if isinstance(digest, str):
                    found.append(digest)
            homepage = data.get("homepage")
        except PackageNotFound:
            data = MoreRegistries._mapping(
                MoreRegistries._json(f"{HOSTS['homebrew']}/api/cask/{name}.json")
            )
            current = str(data.get("version") or "") or None
            found = (
                [data["sha256"]]
                if isinstance(data.get("sha256"), str) and data["sha256"] != "no_check"
                else []
            )
            homepage = data.get("homepage")
        revision = data.get("revision")
        installed = version.split("_", 1)[0] if version else None
        digests = (
            tuple(f"sha256:{d}" for d in found if re.fullmatch(r"[0-9a-f]{64}", d))
            if installed == current
            else ()
        )
        reason = None
        if data.get("disabled"):
            reason = f"disabled: {data.get('disable_reason') or 'no longer installable'}"
        elif data.get("deprecated"):
            reason = f"deprecated: {data.get('deprecation_reason') or 'no reason given'}"
        return PackageFacts(
            name=name,
            version=version,
            yanked=reason is not None,
            yanked_reason=reason,
            latest=f"{current}_{revision}"
            if current and isinstance(revision, int) and revision
            else current,
            repository=homepage if isinstance(homepage, str) else None,
            digests=digests,
            releases=1,
        )

    # -- Bazel Central Registry ------------------------------------------------------------

    @staticmethod
    def bazel(name: str, version: str | None) -> PackageFacts:
        """The Bazel Central Registry: a module's metadata.json (its versions, the ones yanked and
        why, its repository) and the version's source.json -- whose SHA-256 is what a Bazel 7.2+
        lock records, and whose `integrity` is the archive's, which an older lock records."""
        if not re.fullmatch(r"[a-z0-9][a-z0-9._\-]{0,127}", name):
            raise RegistryError(f"{name} is not a Bazel module name")
        if version is not None and not re.fullmatch(r"[A-Za-z0-9._+\-]{1,64}", version):
            raise RegistryError(f"{version} is not a module version")
        metadata = MoreRegistries._mapping(
            MoreRegistries._json(f"{HOSTS['bazel']}/modules/{name}/metadata.json")
        )
        versions = [str(v) for v in metadata.get("versions") or [] if isinstance(v, str)]
        yanked = MoreRegistries._mapping(metadata.get("yanked_versions"))
        repository = next(
            (str(r) for r in metadata.get("repository") or [] if isinstance(r, str)), None
        )
        if repository and repository.startswith("github:"):
            repository = f"https://github.com/{repository.removeprefix('github:')}"
        digests: tuple[str, ...] = ()
        if version is not None and version in versions:
            import hashlib

            raw = MoreRegistries._get(f"{HOSTS['bazel']}/modules/{name}/{version}/source.json")
            found = [f"sha256:{hashlib.sha256(raw).hexdigest()}"]
            try:
                integrity = MoreRegistries._mapping(json.loads(raw)).get("integrity")
            except (json.JSONDecodeError, ValueError):
                integrity = None
            if isinstance(integrity, str):
                found.append(integrity)
            digests = tuple(found)
        reason = None
        if version is not None and version not in versions:
            reason = "not a version the registry holds"
        elif version is not None and version in yanked:
            reason = f"yanked: {yanked[version]}" if isinstance(yanked[version], str) else "yanked"
        return PackageFacts(
            name=name,
            version=version,
            yanked=reason is not None,
            yanked_reason=reason,
            latest=MoreRegistries._latest([v for v in versions if v not in yanked]),
            repository=repository,
            digests=digests,
            releases=len(versions),
        )

    # -- Helm chart repositories -------------------------------------------------------------

    @staticmethod
    def helm(name: str, version: str | None, source: str | None = None) -> PackageFacts:
        """A chart's own repository -- Helm has no central one. Over HTTPS, the repository's
        index.yaml: every version, its digest (the archive's SHA-256, which a downloaded chart in
        charts/ is hashed to), and `deprecated`. Over OCI, the registry's tags and the chart
        layer's digest, which is the same SHA-256. A chart from a repository named only (`@name`)
        or from the project itself has no repository to ask: nothing is claimed about it."""
        if not re.fullmatch(r"[A-Za-z0-9][\w.\-]{0,127}", name):
            raise RegistryError(f"{name} is not a chart name")
        if version is not None and not re.fullmatch(r"[A-Za-z0-9][\w.+\-]{0,63}", version):
            raise RegistryError(f"{version} is not a chart version")
        if source and source.startswith("oci://"):
            return MoreRegistries._helm_oci(name, version, source)
        if not source or not source.startswith("https://"):
            return PackageFacts(name=name, version=version)
        from cordon_scanner.core.datayaml import DataYaml

        text = MoreRegistries._text(f"{source.rstrip('/')}/index.yaml")
        try:
            index = DataYaml.load(text, source="index.yaml")
        except ValueError as exc:
            raise RegistryError("an unreadable chart repository index") from exc
        entries = MoreRegistries._mapping(MoreRegistries._mapping(index).get("entries"))
        listed = MoreRegistries._entries(entries.get(name))
        if not listed:
            raise PackageNotFound(f"the repository lists no chart {name}")
        entry = next((e for e in listed if str(e.get("version")) == version), None)
        digest = MoreRegistries._str(entry.get("digest")) if entry else None
        return PackageFacts(
            name=name,
            version=version,
            yanked=version is not None and entry is None,
            yanked_reason="not a version the repository's index lists"
            if version is not None and entry is None
            else None,
            latest=MoreRegistries._latest(
                [str(e.get("version")) for e in listed if e.get("version")]
            ),
            digests=(f"sha256:{digest.lower()}",)
            if digest and re.fullmatch(r"[0-9a-fA-F]{64}", digest)
            else (),
            deprecated="deprecated in its repository"
            if entry and entry.get("deprecated") is True
            else None,
            releases=len(listed),
        )

    @staticmethod
    def _helm_oci(name: str, version: str | None, source: str) -> PackageFacts:
        host, _, path = source.removeprefix("oci://").partition("/")
        if not re.fullmatch(r"[a-z0-9.\-]+(?::\d+)?", host) or ".." in path:
            raise RegistryError("not an OCI registry reference")
        repository = f"{path.strip('/')}/{name}" if path.strip("/") else name
        tags = MoreRegistries._mapping(
            MoreRegistries._oci(f"https://{host}/v2/{repository}/tags/list", "application/json")
        )
        # helm `pkg/registry/reference.go` pushes version `1.0.0+build` as tag `1.0.0_build`, and
        # reads a tag back with `_` as `+` (`client.go`, Tags).
        listed = [str(t).replace("_", "+") for t in tags.get("tags") or [] if isinstance(t, str)]
        if not listed:
            raise PackageNotFound(f"{host} has no chart {repository}")
        digests: tuple[str, ...] = ()
        if version is not None and version in listed:
            manifest = MoreRegistries._mapping(
                MoreRegistries._oci(
                    f"https://{host}/v2/{repository}/manifests/{version.replace('+', '_')}",
                    "application/vnd.oci.image.manifest.v1+json",
                )
            )
            layers = MoreRegistries._entries(manifest.get("layers"))
            chart = [
                str(layer["digest"])
                for layer in layers
                # The chart layer's media type, and the legacy one older charts were pushed with.
                if (
                    "helm.chart.content" in str(layer.get("mediaType"))
                    or layer.get("mediaType") == "application/tar+gzip"
                )
                and isinstance(layer.get("digest"), str)
            ]
            digests = tuple(d.lower() for d in chart if re.fullmatch(r"sha256:[0-9a-fA-F]{64}", d))
        return PackageFacts(
            name=name,
            version=version,
            yanked=version is not None and version not in listed,
            yanked_reason="not a tag the registry holds"
            if version is not None and version not in listed
            else None,
            latest=MoreRegistries._latest(listed),
            digests=digests,
            releases=len(listed),
        )

    @staticmethod
    def _redirected(exc: urllib.error.HTTPError) -> bytes:
        """A registry's blob, where it sends it: a storage URL, fetched over HTTPS without the
        registry's token, whose bytes the caller checks against the blob's digest."""
        location = str(exc.headers.get("Location", ""))
        if not location.startswith("https://"):
            raise RegistryError("an OCI registry redirected a blob somewhere other than HTTPS")
        return MoreRegistries._get(location, accept="*/*")

    @staticmethod
    def _oci(url: str, accept: str) -> Any:
        """An OCI distribution request's JSON body."""
        try:
            return json.loads(MoreRegistries._oci_bytes(url, accept))
        except ValueError as exc:
            raise RegistryError("an OCI registry answered with something other than JSON") from exc

    @staticmethod
    def _oci_bytes(url: str, accept: str, *, follow: bool = False) -> bytes:
        """An OCI distribution request, with the anonymous bearer token a public registry hands
        out when it answers 401 with `WWW-Authenticate: Bearer realm=...`. The body as served:
        a manifest's digest is the hash of exactly these bytes."""
        # https is checked by the caller.
        headers = {"User-Agent": base.USER_AGENT, "Accept": accept}
        request = urllib.request.Request(url, headers=headers)  # noqa: S310
        opener = urllib.request.build_opener(base._NoRedirect)
        try:
            with opener.open(request, timeout=base.TIMEOUT_SECONDS) as response:
                return bytes(response.read(base.MAX_RESPONSE_BYTES))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise PackageNotFound("the registry has no such artefact") from exc
            if follow and exc.code in (301, 302, 303, 307, 308):
                return MoreRegistries._redirected(exc)
            challenge = str(exc.headers.get("WWW-Authenticate", "")) if exc.code == 401 else ""
            if not challenge.startswith("Bearer "):
                raise RegistryError(f"HTTP {exc.code} from an OCI registry") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise RegistryError(f"{type(exc).__name__} asking an OCI registry") from exc
        fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = fields.get("realm", "")
        if not realm.startswith("https://"):
            raise RegistryError("an OCI registry asked for credentials somewhere other than HTTPS")
        query = urllib.parse.urlencode(
            {k: v for k, v in fields.items() if k in ("service", "scope")}
        )
        token = MoreRegistries._mapping(MoreRegistries._json(f"{realm}?{query}")).get("token")
        if not isinstance(token, str):
            raise RegistryError("an OCI registry gave no token")
        bearer = {**headers, "Authorization": f"Bearer {token}"}
        authorised = urllib.request.Request(url, headers=bearer)  # noqa: S310
        try:
            with opener.open(authorised, timeout=base.TIMEOUT_SECONDS) as response:
                return bytes(response.read(base.MAX_RESPONSE_BYTES))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise PackageNotFound("the registry has no such artefact") from exc
            if follow and exc.code in (301, 302, 303, 307, 308):
                return MoreRegistries._redirected(exc)
            raise RegistryError(f"HTTP {exc.code} from an OCI registry") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise RegistryError(f"{type(exc).__name__} asking an OCI registry") from exc

    # -- Terraform registry ----------------------------------------------------------------

    MAX_PLATFORMS: Final = 32

    @staticmethod
    def terraform(name: str, version: str | None) -> PackageFacts:
        """The Terraform registry: a provider's versions and the SHA-256 of every platform's zip
        (what a lock's `zh:` hashes are), or a module's versions and its deprecation. Every
        platform's hash is gathered -- from the release's SHA256SUMS, or one platform at a time --
        because a lock records several, and comparing against one platform's alone would call
        every other one a mismatch."""
        parts = name.split("/")
        if not all(re.fullmatch(r"[A-Za-z0-9][\w\-]{0,63}", p) for p in parts) or len(
            parts
        ) not in (2, 3):
            raise RegistryError(f"{name} is not a registry provider or module address")
        if version is not None and not re.fullmatch(r"[0-9A-Za-z.+\-]{1,64}", version):
            raise RegistryError(f"{version} is not a version")
        if len(parts) == 3:
            document = MoreRegistries._mapping(
                MoreRegistries._json(f"{HOSTS['terraform']}/v1/modules/{name}/versions")
            )
            modules = MoreRegistries._entries(document.get("modules"))
            versions = MoreRegistries._entries(modules[0].get("versions")) if modules else []
            listed = [str(v.get("version")) for v in versions if v.get("version")]
            entry = next((v for v in versions if v.get("version") == version), None)
            notice = (
                MoreRegistries._mapping(entry.get("deprecation"))
                if entry and isinstance(entry.get("deprecation"), dict)
                else {}
            )
            return PackageFacts(
                name=name,
                version=version,
                yanked=version is not None and entry is None,
                yanked_reason="not a version the registry holds"
                if version is not None and entry is None
                else None,
                latest=MoreRegistries._latest(listed),
                deprecated=(
                    "deprecated on the registry"
                    + (f": {notice['reason']}" if isinstance(notice.get("reason"), str) else "")
                )
                if notice
                else None,
                releases=len(listed),
            )
        document = MoreRegistries._mapping(
            MoreRegistries._json(f"{HOSTS['terraform']}/v1/providers/{name}/versions")
        )
        versions = MoreRegistries._entries(document.get("versions"))
        listed = [str(v.get("version")) for v in versions if v.get("version")]
        entry = next((v for v in versions if v.get("version") == version), None)
        digests: tuple[str, ...] = ()
        if entry is not None:
            digests = MoreRegistries._provider_digests(
                name, str(version), MoreRegistries._entries(entry.get("platforms"))
            )
        return PackageFacts(
            name=name,
            version=version,
            yanked=version is not None and entry is None,
            yanked_reason="not a version the registry holds"
            if version is not None and entry is None
            else None,
            latest=MoreRegistries._latest(listed),
            digests=digests,
            releases=len(listed),
        )

    @staticmethod
    def _provider_digests(
        name: str, version: str, platforms: list[dict[str, Any]]
    ) -> tuple[str, ...]:
        found: set[str] = set()
        for platform in platforms[: MoreRegistries.MAX_PLATFORMS]:
            os_name, arch = platform.get("os"), platform.get("arch")
            if not (
                isinstance(os_name, str)
                and isinstance(arch, str)
                and re.fullmatch(r"[a-z0-9_]+", os_name + arch)
            ):
                continue
            download = MoreRegistries._mapping(
                MoreRegistries._json(
                    f"{HOSTS['terraform']}/v1/providers/{name}/{version}/download/{os_name}/{arch}"
                )
            )
            if not found and isinstance(download.get("shasums_url"), str):
                try:
                    sums = MoreRegistries._text(download["shasums_url"])
                except RegistryError:
                    sums = ""
                listed = {
                    line.split()[0].lower()
                    for line in sums.splitlines()
                    if re.match(r"^[0-9a-fA-F]{64}\s", line)
                }
                if listed:
                    return tuple(sorted(f"sha256:{s}" for s in listed))
            shasum = download.get("shasum")
            if isinstance(shasum, str) and re.fullmatch(r"[0-9a-fA-F]{64}", shasum):
                found.add(shasum.lower())
        return tuple(sorted(f"sha256:{s}" for s in found))

    @staticmethod
    def _latest(versions: list[str]) -> str | None:
        def order(v: str) -> tuple[Any, ...]:
            core, _, pre = v.removeprefix("v").partition("-")
            # A fixed width, so `1` and `1.2.3` compare number by number and never a number
            # against the prerelease that follows a shorter one.
            numbers = [int(p) if p.isdigit() else 0 for p in core.split(".")][:8]
            return (*numbers, *([0] * (8 - len(numbers))), pre == "", pre)

        return max(versions, key=order) if versions else None

    # -- Ansible Galaxy ---------------------------------------------------------------------

    @staticmethod
    def ansible(name: str, version: str | None) -> PackageFacts:
        """Galaxy: a collection's index (its highest version, and whether it is deprecated) and
        the version's artefact SHA-256 from the v3 API; failing that, a role's versions from the
        v1 API. `namespace.name` names either, so the collection is asked first."""
        found = re.fullmatch(r"([A-Za-z0-9_]{1,64})\.([A-Za-z0-9_\-]{1,100})", name)
        if not found:
            raise RegistryError(f"{name} is not a Galaxy namespace.name")
        namespace, short = found.groups()
        if version is not None and not re.fullmatch(r"[A-Za-z0-9_.+\-]{1,64}", version):
            raise RegistryError(f"{version} is not a Galaxy version")
        index_url = f"{HOSTS['ansible']}/api/v3/plugin/ansible/content/published/collections/index/{namespace}/{short}/"
        try:
            index = MoreRegistries._mapping(MoreRegistries._json(index_url))
        except PackageNotFound:
            return MoreRegistries._galaxy_role(namespace, short, name, version)
        highest = MoreRegistries._mapping(index.get("highest_version"))
        digests: tuple[str, ...] = ()
        missing = False
        if version is not None:
            try:
                detail = MoreRegistries._mapping(
                    MoreRegistries._json(f"{index_url}versions/{version}/")
                )
            except PackageNotFound:
                missing = True
            else:
                artifact = MoreRegistries._mapping(detail.get("artifact"))
                digest = MoreRegistries._str(artifact.get("sha256"))
                digests = (
                    (f"sha256:{digest.lower()}",)
                    if digest and re.fullmatch(r"[0-9a-fA-F]{64}", digest)
                    else ()
                )
        return PackageFacts(
            name=name,
            version=version,
            yanked=missing,
            yanked_reason="not a version Galaxy holds" if missing else None,
            latest=MoreRegistries._str(highest.get("version")),
            digests=digests,
            first_published=MoreRegistries._str(index.get("created_at")),
            last_published=MoreRegistries._str(index.get("updated_at")),
            deprecated="deprecated on Galaxy" if index.get("deprecated") is True else None,
        )

    @staticmethod
    def _galaxy_role(namespace: str, short: str, name: str, version: str | None) -> PackageFacts:
        listing = MoreRegistries._mapping(
            MoreRegistries._json(
                f"{HOSTS['ansible']}/api/v1/roles/?owner__username={namespace}&name={urllib.parse.quote(short)}"
            )
        )
        results = MoreRegistries._entries(listing.get("results"))
        if not results:
            raise PackageNotFound(f"Galaxy has no collection or role {name}")
        role = results[0]
        summary = MoreRegistries._mapping(role.get("summary_fields"))
        versions = [
            str(v.get("name")).lstrip("v")
            for v in MoreRegistries._entries(summary.get("versions"))
            if v.get("name")
        ]
        missing = version is not None and version.lstrip("v") not in versions
        user, repository = (
            MoreRegistries._str(role.get("github_user")),
            MoreRegistries._str(role.get("github_repo")),
        )

        def order(v: str) -> tuple[int, ...]:
            return tuple(int(p) if p.isdigit() else -1 for p in re.split(r"[.+\-]", v))

        return PackageFacts(
            name=name,
            version=version,
            yanked=missing,
            yanked_reason="not a version Galaxy lists for the role" if missing else None,
            latest=max(versions, key=order) if versions else None,
            repository=f"https://github.com/{user}/{repository}" if user and repository else None,
            releases=len(versions),
        )

    # -- GitHub Actions (a repository's tags) -----------------------------------------------

    @staticmethod
    def tags(advertisement: bytes) -> dict[str, str]:
        """`tag -> commit` from git's smart-HTTP ref advertisement (pkt-lines), annotated tags
        peeled to the commit they name."""
        out: dict[str, str] = {}
        index = 0
        while index + 4 <= len(advertisement):
            try:
                length = int(advertisement[index : index + 4], 16)
            except ValueError as exc:
                raise RegistryError("an unreadable ref advertisement") from exc
            if length == 0:
                index += 4
                continue
            if length < 4 or index + length > len(advertisement):
                raise RegistryError("an unreadable ref advertisement")
            line = (
                advertisement[index + 4 : index + length]
                .split(b"\0", 1)[0]
                .decode("ascii", "replace")
                .strip()
            )
            index += length
            sha, _, ref = line.partition(" ")
            if not ref.startswith("refs/tags/") or not re.fullmatch(r"[0-9a-f]{40}", sha):
                continue
            tag = ref.removeprefix("refs/tags/")
            if tag.endswith("^{}"):
                out[tag[:-3]] = sha  # the commit an annotated tag names
            else:
                out.setdefault(tag, sha)
        return out

    @staticmethod
    def actions(name: str, version: str | None) -> PackageFacts:
        """The action repository's tags, read the way git reads them (no API, no rate limit): the
        commit the release tag names is what a SHA pin must equal -- so a `# vX.Y.Z` comment that
        does not match its commit is caught."""
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9\-]{0,38}/[A-Za-z0-9._\-]{1,100}", name)
            or ".." in name
        ):
            raise RegistryError(f"{name} is not an owner/repository")
        try:
            advertisement = MoreRegistries._get(
                f"{HOSTS['actions']}/{name}.git/info/refs?service=git-upload-pack", accept="*/*"
            )
        except RegistryError as exc:
            # GitHub asks for credentials, rather than answering 404, for a repository that does
            # not exist (or is private).
            if str(exc).startswith("HTTP 401"):
                raise PackageNotFound(f"github.com has no public repository {name}") from exc
            raise
        tags = MoreRegistries.tags(advertisement)

        def release(tag: str) -> tuple[int, ...] | None:
            found = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", tag)
            return tuple(int(p) for p in found.groups()) if found else None

        releases = {tag: key for tag in tags if (key := release(tag)) is not None}
        commit = None
        if version is not None:
            commit = tags.get(f"v{version}") or tags.get(version)
        missing = version is not None and commit is None
        return PackageFacts(
            name=name,
            version=version,
            yanked=missing,
            yanked_reason="no tag of the repository names this release" if missing else None,
            latest=max(releases, key=releases.__getitem__).lstrip("v") if releases else None,
            repository=f"https://github.com/{name}",
            digests=(commit,) if commit else (),
            releases=len(releases),
        )

    # -- vcpkg (the builtin registry) -------------------------------------------------------

    @staticmethod
    def vcpkg(name: str, version: str | None) -> PackageFacts:
        """The builtin registry's version database, `versions/<x>-/<port>.json`: every version and
        port-version of the port with the git-tree it builds from. Read at the registry's tip."""
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) or len(name) > 128:
            raise RegistryError(f"{name} is not a vcpkg port name")
        document = MoreRegistries._mapping(
            MoreRegistries._json(f"{HOSTS['vcpkg']}/versions/{name[0]}-/{name}.json")
        )
        versions = MoreRegistries._entries(document.get("versions"))

        def named(entry: dict[str, Any]) -> str | None:
            for key in ("version", "version-semver", "version-date", "version-string"):
                if isinstance(entry.get(key), str):
                    return str(entry[key])
            return None

        listed = [named(v) for v in versions]
        matching = [v for v in versions if version is not None and named(v) == version]
        digests = tuple(
            f"git-tree-sha1:{str(v['git-tree']).lower()}"
            for v in matching
            if isinstance(v.get("git-tree"), str)
            and re.fullmatch(r"[0-9a-fA-F]{40}", v["git-tree"])
        )
        missing = version is not None and not matching
        return PackageFacts(
            name=name,
            version=version,
            yanked=missing,
            yanked_reason="not a version the vcpkg registry holds" if missing else None,
            latest=next((v for v in listed if v), None),
            digests=digests,
            releases=len({v for v in listed if v}),
        )

    # -- ConanCenter ------------------------------------------------------------------------

    @staticmethod
    def conan(name: str, version: str | None) -> PackageFacts:
        """ConanCenter's v2 API: `search` for the versions it holds, and a version's recipe
        `revisions` -- each the MD5 of the recipe's manifest, which a lock pins. ConanCenter has
        no user/channel namespaces, so only plain references are asked about."""
        if not re.fullmatch(r"[a-z0-9_][a-z0-9_+.\-]{0,100}", name):
            raise RegistryError(f"{name} is not a ConanCenter recipe name")
        found = MoreRegistries._mapping(
            MoreRegistries._json(f"{HOSTS['conan']}/v2/conans/search?q={urllib.parse.quote(name)}")
        )
        versions = [
            str(r).split("@")[0].partition("/")[2]
            for r in found.get("results") or ()
            if isinstance(r, str) and str(r).split("@")[0].partition("/")[0] == name
        ]
        if not versions:
            raise PackageNotFound(f"ConanCenter has no recipe {name}")

        def order(v: str) -> tuple[Any, ...]:
            return tuple((0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"[.+\-]", v))

        digests: tuple[str, ...] = ()
        published = None
        reason = None
        if version is not None:
            if not re.fullmatch(r"[A-Za-z0-9_+.\-]{1,100}", version):
                raise RegistryError(f"{version} is not a Conan version")
            if version not in versions:
                reason = "not a version ConanCenter holds"
            else:
                document = MoreRegistries._mapping(
                    MoreRegistries._json(
                        f"{HOSTS['conan']}/v2/conans/{name}/{version}/_/_/revisions"
                    )
                )
                revisions = MoreRegistries._entries(document.get("revisions"))
                digests = tuple(
                    f"md5:{str(r['revision']).lower()}"
                    for r in revisions
                    if isinstance(r.get("revision"), str)
                    and re.fullmatch(r"[0-9a-fA-F]{32}", r["revision"])
                )
                times = sorted(str(r["time"]) for r in revisions if isinstance(r.get("time"), str))
                published = times[0] if times else None
        return PackageFacts(
            name=name,
            version=version,
            yanked=reason is not None,
            yanked_reason=reason,
            latest=max(versions, key=order),
            digests=digests,
            last_published=published,
            releases=len(versions),
        )

    # -- opam-repository --------------------------------------------------------------------

    @staticmethod
    def opam(name: str, version: str | None) -> PackageFacts:
        """opam-repository's definition of the version, `packages/<n>/<n>.<v>/opam`: the archive's
        checksums (what dune's lock records), dev-repo, and the `deprecated` / `avoid-version`
        flags its maintainers set. A version that is not there is checked against the package's
        page on opam.ocaml.org, so a removed version is told apart from an unknown package."""
        from cordon_scanner.core.content import FileContent
        from cordon_scanner.ecosystems.opam import OpamDocument, OpamError

        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_+\-]{0,127}", name):
            raise RegistryError(f"{name} is not an opam package name")
        if version is not None and not re.fullmatch(r"[A-Za-z0-9_+.~\-]{1,64}", version):
            raise RegistryError(f"{version} is not an opam version")
        if version is None:
            MoreRegistries._text(f"{HOSTS['opam-site']}/packages/{name}/")
            return PackageFacts(name=name, version=None)
        try:
            text = MoreRegistries._text(f"{HOSTS['opam']}/packages/{name}/{name}.{version}/opam")
        except PackageNotFound:
            # The package page answers for the name; a 404 here is an unknown package.
            MoreRegistries._text(f"{HOSTS['opam-site']}/packages/{name}/")
            return PackageFacts(
                name=name,
                version=version,
                yanked=True,
                yanked_reason="not a version opam-repository holds",
            )
        try:
            document = OpamDocument.load(FileContent.from_bytes("opam", text.encode()))
        except OpamError as exc:
            raise RegistryError("unreadable package definition from opam-repository") from exc
        digests: list[str] = []
        for section in document.fields.get("section:url", []):
            for entry in section.items:
                if entry.text != "checksum":
                    continue
                for node in entry.items:
                    values = node.items if node.kind == "list" else [node]
                    for value in values:
                        algorithm, _, digest = value.text.partition("=")
                        if (
                            value.kind == "str"
                            and algorithm in ("sha256", "sha512", "md5")
                            and re.fullmatch(r"[0-9a-fA-F]+", digest)
                        ):
                            digests.append(f"{algorithm}:{digest.lower()}")
        flags: set[str] = set()
        for node in document.fields.get("flags", []):
            for item in node.items if node.kind == "list" else [node]:
                if item.kind == "ident":
                    flags.add(item.text)
        return PackageFacts(
            name=name,
            version=version,
            yanked="avoid-version" in flags,
            yanked_reason="flagged avoid-version: the solver avoids it"
            if "avoid-version" in flags
            else None,
            repository=document.string("dev-repo"),
            digests=tuple(digests),
            deprecated="deprecated in opam-repository" if "deprecated" in flags else None,
        )

    # -- Julia (the General registry) -------------------------------------------------------

    @staticmethod
    def julia(name: str, version: str | None) -> PackageFacts:
        """The General registry, a git repository of TOML: `<L>/<Name>/Package.toml` (the
        package's UUID and repository, and `[metadata.deprecated]` when its maintainers retired
        it) and `Versions.toml` (every version's git-tree-sha1 -- the tree a manifest pins -- and
        `yanked`). Read from the repository's raw files; a package registered elsewhere is not
        found here, which is not evidence of anything."""
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", name):
            raise RegistryError(f"{name} is not a Julia package name")
        base_url = f"{HOSTS['julia']}/{name[0].upper()}/{name}"
        try:
            package = tomllib.loads(MoreRegistries._text(f"{base_url}/Package.toml"))
            versions = tomllib.loads(MoreRegistries._text(f"{base_url}/Versions.toml"))
        except tomllib.TOMLDecodeError as exc:
            raise RegistryError("unreadable registry entry from the General registry") from exc
        if package.get("name") != name:
            raise RegistryError("the General registry entry names another package")
        entry = MoreRegistries._mapping(versions.get(version)) if version else {}
        known = not version or version in versions
        tree = MoreRegistries._str(entry.get("git-tree-sha1"))
        metadata = MoreRegistries._mapping(package.get("metadata"))
        retired = (
            MoreRegistries._mapping(metadata.get("deprecated"))
            if "deprecated" in metadata
            else None
        )
        notice = None
        if retired is not None:
            alternative = MoreRegistries._str(retired.get("alternative"))
            notice = "deprecated in the General registry" + (
                f" in favour of {alternative}" if alternative else ""
            )
        reason = None
        if version and not known:
            reason = "not a version the General registry holds"
        elif entry.get("yanked") is True:
            reason = "yanked from the General registry"

        def order(v: str) -> tuple[int, ...]:
            return tuple(int(p) if p.isdigit() else -1 for p in re.split(r"[.+-]", v))

        listed = sorted(
            (v for v in versions if not MoreRegistries._mapping(versions[v]).get("yanked")),
            key=order,
        )
        return PackageFacts(
            name=name,
            version=version,
            yanked=reason is not None,
            yanked_reason=reason,
            latest=listed[-1] if listed else None,
            repository=MoreRegistries._str(package.get("repo")),
            digests=(f"git-tree-sha1:{tree.lower()}",)
            if tree and re.fullmatch(r"[0-9a-fA-F]{40}", tree)
            else (),
            deprecated=notice,
            releases=len(versions),
        )

    # -- Hackage -----------------------------------------------------------------------------

    @staticmethod
    def hackage(name: str, version: str | None) -> PackageFacts:
        """Hackage's JSON API: `preferred` (every version, and those the maintainer deprecated --
        the ones the solver avoids, Hackage's withdrawal), `deprecated` (the package as a whole,
        and what replaces it), and the version's metadata `revisions` with each revision's
        SHA-256 -- the cabal-file hash a Stack lock pins."""
        if not re.fullmatch(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*", name) or len(name) > 128:
            raise RegistryError(f"{name} is not a Hackage package name")
        preferred = MoreRegistries._mapping(
            MoreRegistries._json(f"{HOSTS['hackage']}/package/{name}/preferred")
        )
        normal = [str(v) for v in preferred.get("normal-version") or () if isinstance(v, str)]
        withdrawn = [
            str(v) for v in preferred.get("deprecated-version") or () if isinstance(v, str)
        ]
        package = MoreRegistries._mapping(
            MoreRegistries._json(f"{HOSTS['hackage']}/package/{name}/deprecated")
        )
        replacements = [str(r) for r in package.get("in-favour-of") or () if isinstance(r, str)]
        notice = None
        if package.get("is-deprecated") is True:
            notice = "deprecated on Hackage" + (
                f" in favour of {', '.join(replacements)}" if replacements else ""
            )
        digests: tuple[str, ...] = ()
        published = None
        known = True
        if version:
            if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", version):
                raise RegistryError(f"{version} is not a Hackage version")
            known = version in normal or version in withdrawn
            if known:
                revisions = MoreRegistries._entries(
                    MoreRegistries._json(f"{HOSTS['hackage']}/package/{name}-{version}/revisions/")
                )
                digests = tuple(
                    f"sha256:{str(r['sha256']).lower()}"
                    for r in revisions
                    if isinstance(r.get("sha256"), str)
                    and re.fullmatch(r"[0-9a-fA-F]{64}", r["sha256"])
                )
                times = sorted(str(r["time"]) for r in revisions if isinstance(r.get("time"), str))
                published = times[0] if times else None
        reason = None
        if version and not known:
            reason = "not a version Hackage published"
        elif version and version in withdrawn:
            reason = "deprecated by its maintainer: the solver avoids it"
        return PackageFacts(
            name=name,
            version=version,
            yanked=reason is not None,
            yanked_reason=reason,
            latest=normal[0] if normal else None,
            digests=digests,
            last_published=published,
            deprecated=notice,
            releases=len(normal) + len(withdrawn),
        )

    # -- anaconda.org (conda-forge) ---------------------------------------------------------

    @staticmethod
    def conda(name: str, version: str | None) -> PackageFacts:
        """conda-forge's files on anaconda.org: every build of every version, each with its md5
        and sha256 and its labels. A version whose every build is labelled `broken` was withdrawn
        by conda-forge. A package conda-forge does not have may be another channel's (bioconda),
        so its absence is not checked, not reported as a missing package."""
        if not re.fullmatch(r"[a-z0-9_.\-]{1,128}", name):
            raise RegistryError(f"{name} is not a conda package name")
        try:
            files = MoreRegistries._entries(
                MoreRegistries._json(f"{HOSTS['conda']}/package/conda-forge/{name}/files")
            )
        except PackageNotFound as exc:
            raise RegistryError(
                f"{name} is not on conda-forge; other channels are not asked"
            ) from exc
        versions = sorted({str(f.get("version")) for f in files if f.get("version")})
        builds = [f for f in files if version and str(f.get("version")) == version]
        digests: list[str] = []
        for build in builds:
            for algorithm in ("sha256", "md5"):
                value = build.get(algorithm)
                if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32,64}", value):
                    digests.append(f"{algorithm}:{value}")
        broken = bool(builds) and all("broken" in (b.get("labels") or []) for b in builds)
        return PackageFacts(
            name=name,
            version=version,
            yanked=broken,
            yanked_reason="labelled broken by conda-forge" if broken else None,
            latest=versions[-1] if versions else None,
            digests=tuple(dict.fromkeys(digests)),
            releases=len(versions),
        )

    # -- CocoaPods trunk --------------------------------------------------------------------

    @staticmethod
    def cocoapods_shard(name: str) -> tuple[str, str, str]:
        """Trunk shards specs by the first three hex digits of the pod name's MD5."""
        import hashlib

        digest = hashlib.md5(name.encode("utf-8"), usedforsecurity=False).hexdigest()
        return digest[0], digest[1], digest[2]

    @staticmethod
    def cocoapods(name: str, version: str | None) -> PackageFacts:
        """CocoaPods trunk's CDN: the shard's `all_pods_versions_<a>_<b>_<c>.txt` lists every
        version, and each version's podspec JSON is what `SPEC CHECKSUMS` hashes -- so its SHA-1
        is the digest a lock's checksum is compared with."""
        import hashlib

        if not re.fullmatch(r"[A-Za-z0-9_.+\-]{1,128}", name) or (
            version and not re.fullmatch(r"[\w.+\-]{1,64}", version)
        ):
            raise RegistryError(f"{name} is not a pod name")
        a, b, c = MoreRegistries.cocoapods_shard(name)
        listing = MoreRegistries._text(f"{HOSTS['cocoapods']}/all_pods_versions_{a}_{b}_{c}.txt")
        versions: list[str] = []
        for line in listing.splitlines():
            parts = line.strip().split("/")
            if parts and parts[0] == name:
                versions = parts[1:]
                break
        else:
            raise PackageNotFound(f"{name} is not on CocoaPods trunk")
        digests: tuple[str, ...] = ()
        deprecated = None
        if version and version in versions:
            body = MoreRegistries._get(
                f"{HOSTS['cocoapods']}/Specs/{a}/{b}/{c}/{name}/{version}/{name}.podspec.json"
            )
            digests = (f"sha1:{hashlib.sha1(body, usedforsecurity=False).hexdigest()}",)
            try:
                spec = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                spec = {}
            if isinstance(spec, dict) and spec.get("deprecated"):
                replacement = spec.get("deprecated_in_favor_of")
                deprecated = (
                    f"deprecated in favour of {replacement}"
                    if isinstance(replacement, str)
                    else "deprecated"
                )
        return PackageFacts(
            name=name,
            version=version,
            # Trunk keeps every version it published: a version missing from the listing while the
            # pod exists was deleted by its owner.
            yanked=bool(version) and version not in versions,
            latest=versions[-1] if versions else None,
            digests=digests,
            deprecated=deprecated,
            releases=len(versions),
        )

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
        attested = False
        if builds and version:
            # Sigstore bundles published through trusted publishing; absent (404) for most gems.
            try:
                attested = (
                    base.RegistryClient._rubygems_attestation_payload(name, version) is not None
                )
            except RegistryError:
                attested = False
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
            attested=attested,
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
        # Cordon records Go versions as OSV does, without the `v` (`0.9.1`); the proxy and the
        # checksum database answer only for the canonical `v0.9.1`, and refused every lookup with
        # HTTP 400 -- so no Go module's go.sum hash was ever compared with the log.
        canonical = version if not version or version.startswith("v") else f"v{version}"
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
        if latest and canonical:
            try:
                go_mod = MoreRegistries._text(
                    f"{HOSTS['gomod']}/{module}/@v/{MoreRegistries.go_escape(latest)}.mod"
                )
            except PackageNotFound:
                go_mod = ""
            rationale = MoreRegistries.retracted(canonical, MoreRegistries.retractions(go_mod))
        digests: tuple[str, ...] = ()
        if canonical:
            try:
                lookup = MoreRegistries._text(
                    f"{HOSTS['gosum']}/lookup/{module}@{MoreRegistries.go_escape(canonical)}"
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
        repository: str | None = None
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
            repository = MoreRegistries._maven_scm(f"{root}/{version}/{artifact}-{version}.pom")
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
            repository=repository,
        )

    @staticmethod
    def _maven_scm(pom_url: str) -> str | None:
        """The source repository a published POM declares (`<scm><url>`, else `<url>`), the
        identity a Sigstore signature is tied to. Read structurally and never expanded
        (`core/safexml.py`); a POM that cannot be read declares nothing."""
        from cordon_scanner.core.safexml import SafeXml, SafeXmlError

        try:
            root = SafeXml.parse(MoreRegistries._text(pom_url), source=pom_url)
        except (RegistryError, SafeXmlError):
            return None
        for path in (("scm", "url"), ("scm", "connection"), ("url",)):
            value = root.value(*path)
            if value:
                return value.removeprefix("scm:git:")
        return None

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

    # -- archives (scan pkg:<purl>) ------------------------------------------------------------

    ARCHIVE_ECOSYSTEMS = frozenset(
        {"cargo", "rubygems", "nuget", "gomod", "hex", "pub", "maven", "gradle"}
    )

    @staticmethod
    def versions(ecosystem: str, name: str) -> list[str]:
        """Every version the registry publishes and has not withdrawn, unordered."""
        quoted = urllib.parse.quote(name, safe="")
        if ecosystem == "cargo":
            document = MoreRegistries._mapping(
                MoreRegistries._json(f"{HOSTS['cargo']}/api/v1/crates/{quoted}")
            )
            return [
                str(v["num"])
                for v in MoreRegistries._entries(document.get("versions"))
                if v.get("num") and not v.get("yanked")
            ]
        if ecosystem == "rubygems":
            listed = MoreRegistries._json(f"{HOSTS['rubygems']}/api/v1/versions/{quoted}.json")
            return (
                [str(v["number"]) for v in listed if isinstance(v, dict) and v.get("number")]
                if isinstance(listed, list)
                else []
            )
        if ecosystem == "nuget":
            document = MoreRegistries._mapping(
                MoreRegistries._json(
                    f"https://api.nuget.org/v3-flatcontainer/{quoted.lower()}/index.json"
                )
            )
            return [str(v) for v in document.get("versions") or [] if isinstance(v, str)]
        if ecosystem == "gomod":
            listing = MoreRegistries._text(
                f"{HOSTS['gomod']}/{MoreRegistries.go_escape(name)}/@v/list"
            )
            return [v.strip().lstrip("v") for v in listing.splitlines() if v.strip()]
        if ecosystem == "hex":
            document = MoreRegistries._mapping(
                MoreRegistries._json(f"{HOSTS['hex']}/api/packages/{quoted}")
            )
            return [
                str(r["version"])
                for r in MoreRegistries._entries(document.get("releases"))
                if r.get("version")
            ]
        if ecosystem == "pub":
            document = MoreRegistries._mapping(
                MoreRegistries._json(f"{HOSTS['pub']}/api/packages/{quoted}")
            )
            return [
                str(v["version"])
                for v in MoreRegistries._entries(document.get("versions"))
                if v.get("version") and v.get("retracted") is not True
            ]
        if ecosystem in ("maven", "gradle"):
            group, _, artifact = name.partition(":")
            text = MoreRegistries._text(
                f"{HOSTS['maven']}/maven2/{group.replace('.', '/')}/{artifact}/maven-metadata.xml"
            )
            return re.findall(r"<version>([^<]{1,80})</version>", text)
        raise RegistryError(f"no version list for {ecosystem}")

    @staticmethod
    def previous(ecosystem: str, name: str, version: str) -> str | None:
        """The release before `version`, by the ecosystem's own version order."""
        from cordon_scanner.intel.versions import Versions

        current = version.lstrip("v") if ecosystem == "gomod" else version
        earlier = [
            v
            for v in MoreRegistries.versions(ecosystem, name)
            if Versions.compare(ecosystem, v, current) < 0
        ]
        if not earlier:
            return None
        best = earlier[0]
        for candidate in earlier[1:]:
            if Versions.compare(ecosystem, candidate, best) > 0:
                best = candidate
        return best

    @staticmethod
    def go_h1(data: bytes) -> str:
        """Go's `h1:` hash of a module zip (golang.org/x/mod/sumdb/dirhash Hash1): the SHA-256 of
        one `<sha256 hex>  <name>` line per file, sorted by name -- what go.sum and the checksum
        database record, so a proxy's zip is checked against the log, not against itself."""
        import base64
        import hashlib
        import io
        import zipfile

        lines = []
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in sorted(archive.infolist(), key=lambda i: i.filename):
                if info.is_dir():
                    continue
                if "\n" in info.filename:
                    raise RegistryError("a module zip names a file with a newline")
                lines.append(f"{hashlib.sha256(archive.read(info)).hexdigest()}  {info.filename}\n")
        return "h1:" + base64.b64encode(hashlib.sha256("".join(lines).encode()).digest()).decode()

    @staticmethod
    def archive(ecosystem: str, name: str, version: str | None) -> base.PackageArchive:
        """The archive the registry publishes for a version (`None` means the latest), downloaded from
        the registry's own file host and refused unless it matches the digest the registry publishes.
        Never unpacked to disk and never run: the bytes go to the scanner's archive reader."""
        import hashlib

        facts = MoreRegistries.facts(ecosystem, name, version)
        resolved = version or facts.latest
        if not resolved:
            raise RegistryError(f"{ecosystem} names no current version of {name}")
        if version is None:
            facts = MoreRegistries.facts(ecosystem, name, resolved)
        if ecosystem == "gomod":
            resolved = resolved if resolved.startswith("v") else f"v{resolved}"
            filename = f"{name.replace('/', '_')}@{resolved}.zip"
            url = f"{HOSTS['gomod']}/{MoreRegistries.go_escape(name)}/@v/{MoreRegistries.go_escape(resolved)}.zip"
            expected = [d for d in facts.digests if d.startswith("h1:")]
            if not expected:
                raise RegistryError(
                    f"the Go checksum database has no h1 for {name}@{resolved}; nothing to verify against"
                )
            data = base.RegistryClient._fetch_bytes(url, ecosystem)
            if MoreRegistries.go_h1(data) not in expected:
                raise RegistryError(
                    f"{name}@{resolved} does not match the h1 the Go checksum database records"
                )
            return base.PackageArchive(ecosystem, name, resolved, filename, data)
        if ecosystem in ("hex", "pub", "maven", "gradle"):
            if ecosystem == "hex":
                filename = f"{name}-{resolved}.tar"
                url = f"https://repo.hex.pm/tarballs/{urllib.parse.quote(filename, safe='')}"
            elif ecosystem == "pub":
                filename = f"{name}-{resolved}.tar.gz"
                url = f"{HOSTS['pub']}/api/archives/{urllib.parse.quote(filename, safe='')}"
            else:
                group, _, artifact = name.partition(":")
                if not group or not artifact or "/" in name or ".." in name:
                    raise RegistryError(f"{name} is not a Maven group:artifact")
                filename = f"{artifact}-{resolved}.jar"
                url = f"{HOSTS['maven']}/maven2/{group.replace('.', '/')}/{artifact}/{urllib.parse.quote(resolved, safe='')}/{urllib.parse.quote(filename, safe='')}"
            # Hex and pub publish a SHA-256 of the archive; Maven Central the strongest of SHA-512,
            # SHA-256 and SHA-1 it carries for the jar.
            for algorithm, width in (("sha512", 128), ("sha256", 64), ("sha1", 40)):
                expected = [
                    d.partition(":")[2].lower()
                    for d in facts.digests
                    if d.startswith(f"{algorithm}:") and len(d.partition(":")[2]) == width
                ]
                if expected:
                    break
            else:
                raise RegistryError(
                    f"{ecosystem} publishes no digest for {name}@{resolved}; nothing to verify against"
                )
            data = base.RegistryClient._fetch_bytes(
                url, "maven" if ecosystem == "gradle" else ecosystem
            )
            if hashlib.new(algorithm, data).hexdigest() not in expected:
                raise RegistryError(
                    f"{name}@{resolved} does not match the {algorithm} {ecosystem} publishes"
                )
            return base.PackageArchive(ecosystem, name, resolved, filename, data)
        if ecosystem == "cargo":
            filename = f"{name}-{resolved}.crate"
            url = f"https://static.crates.io/crates/{urllib.parse.quote(name, safe='')}/{urllib.parse.quote(filename, safe='')}"
            expected = [d.lower() for d in facts.digests if len(d) == 64]
            algorithm = "sha256"
        elif ecosystem == "rubygems":
            filename = f"{name}-{resolved}.gem"
            url = f"https://rubygems.org/gems/{urllib.parse.quote(filename, safe='')}"
            expected = [d.lower() for d in facts.digests if len(d) == 64]
            algorithm = "sha256"
        else:
            package_id, number = name.lower(), resolved.lower()
            filename = f"{package_id}.{number}.nupkg"
            url = (
                f"https://api.nuget.org/v3-flatcontainer/{urllib.parse.quote(package_id, safe='')}/"
                f"{urllib.parse.quote(number, safe='')}/{urllib.parse.quote(filename, safe='')}"
            )
            import base64

            expected = []
            for digest in facts.digests:
                label, _, encoded = digest.partition("-")
                if label == "sha512":
                    try:
                        expected.append(base64.b64decode(encoded, validate=True).hex())
                    except ValueError:
                        continue
            algorithm = "sha512"
        if not expected:
            raise RegistryError(
                f"{ecosystem} publishes no {algorithm} for {name}@{resolved}; nothing to verify against"
            )
        data = base.RegistryClient._fetch_bytes(url, ecosystem)
        if hashlib.new(algorithm, data).hexdigest() not in expected:
            raise RegistryError(
                f"{name}@{resolved} does not match the {algorithm} {ecosystem} publishes"
            )
        return base.PackageArchive(ecosystem, name, resolved, filename, data)
