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

import io
import re
import urllib.error
import urllib.parse
import urllib.request

from cordon_scanner.intel.base import PackageArchive, PackageFacts
from cordon_scanner.intel.registries.image_registries import ImageRegistries
from cordon_scanner.intel.registries.infra_registries import InfraRegistries
from cordon_scanner.intel.registries.package_registries import PackageRegistries
from cordon_scanner.intel.registries.registry_hosts import (
    ALIASES,
    HOSTS,
)
from cordon_scanner.intel.registries.registry_http import RegistryHttp
from cordon_scanner.intel.registries.registry_request import RegistryError, RegistryRequest


class MoreRegistries:
    """Readers for the registries `RegistryClient` does not speak, returning the same `PackageFacts`."""

    # -- transport -------------------------------------------------------------------------

    # -- dispatch --------------------------------------------------------------------------

    @staticmethod
    def facts(
        ecosystem: str, name: str, version: str | None, source: str | None = None
    ) -> PackageFacts:
        if ALIASES.get(ecosystem) == "helm":
            # The one registry that is not one: each chart's repository is its own.
            return InfraRegistries.helm(name, version, source)
        reader = {
            "cargo": PackageRegistries.cargo,
            "rubygems": PackageRegistries.rubygems,
            "nuget": PackageRegistries.nuget,
            "gomod": PackageRegistries.gomod,
            "maven": PackageRegistries.maven,
            "composer": PackageRegistries.composer,
            "pub": PackageRegistries.pub,
            "hex": PackageRegistries.hex,
            "cocoapods": PackageRegistries.cocoapods,
            "conda": PackageRegistries.conda,
            "cran": PackageRegistries.cran,
            "hackage": PackageRegistries.hackage,
            "julia": PackageRegistries.julia,
            "opam": PackageRegistries.opam,
            "conan": InfraRegistries.conan,
            "vcpkg": InfraRegistries.vcpkg,
            "actions": InfraRegistries.actions,
            "ansible": InfraRegistries.ansible,
            "terraform": InfraRegistries.terraform,
            "bazel": InfraRegistries.bazel,
            "homebrew": InfraRegistries.homebrew,
            "image": ImageRegistries.image,
        }.get(ALIASES.get(ecosystem, ""))
        if reader is None:
            raise RegistryError(f"no registry configured for {ecosystem}")
        return reader(name, version)

    # -- CRAN (crandb) -----------------------------------------------------------------------

    # -- Container images ------------------------------------------------------------------

    # -- Homebrew --------------------------------------------------------------------------

    # -- Bazel Central Registry ------------------------------------------------------------

    # -- Helm chart repositories -------------------------------------------------------------

    # -- Terraform registry ----------------------------------------------------------------

    # -- Ansible Galaxy ---------------------------------------------------------------------

    # -- GitHub Actions (a repository's tags) -----------------------------------------------

    # -- vcpkg (the builtin registry) -------------------------------------------------------

    # -- ConanCenter ------------------------------------------------------------------------

    # -- opam-repository --------------------------------------------------------------------

    # -- Julia (the General registry) -------------------------------------------------------

    # -- Hackage -----------------------------------------------------------------------------

    # -- anaconda.org (conda-forge) ---------------------------------------------------------

    # -- CocoaPods trunk --------------------------------------------------------------------

    # -- crates.io -------------------------------------------------------------------------

    # -- RubyGems --------------------------------------------------------------------------

    # -- NuGet -----------------------------------------------------------------------------

    # -- Go --------------------------------------------------------------------------------

    # -- Maven Central ---------------------------------------------------------------------

    # -- Packagist -------------------------------------------------------------------------

    # -- pub.dev ---------------------------------------------------------------------------

    # -- Hex -------------------------------------------------------------------------------

    # -- archives (scan pkg:<purl>) ------------------------------------------------------------

    ARCHIVE_ECOSYSTEMS = frozenset(
        {"cargo", "rubygems", "nuget", "gomod", "hex", "pub", "maven", "gradle"}
    )

    @staticmethod
    def versions(ecosystem: str, name: str) -> list[str]:
        """Every version the registry publishes and has not withdrawn, unordered."""
        quoted = urllib.parse.quote(name, safe="")
        if ecosystem == "cargo":
            document = RegistryHttp.mapping(
                RegistryHttp.json(f"{HOSTS['cargo']}/api/v1/crates/{quoted}")
            )
            return [
                str(v["num"])
                for v in RegistryHttp.entries(document.get("versions"))
                if v.get("num") and not v.get("yanked")
            ]
        if ecosystem == "rubygems":
            listed = RegistryHttp.json(f"{HOSTS['rubygems']}/api/v1/versions/{quoted}.json")
            return (
                [str(v["number"]) for v in listed if isinstance(v, dict) and v.get("number")]
                if isinstance(listed, list)
                else []
            )
        if ecosystem == "nuget":
            document = RegistryHttp.mapping(
                RegistryHttp.json(
                    f"https://api.nuget.org/v3-flatcontainer/{quoted.lower()}/index.json"
                )
            )
            return [str(v) for v in document.get("versions") or [] if isinstance(v, str)]
        if ecosystem == "gomod":
            listing = RegistryHttp.text(
                f"{HOSTS['gomod']}/{PackageRegistries.go_escape(name)}/@v/list"
            )
            return [v.strip().lstrip("v") for v in listing.splitlines() if v.strip()]
        if ecosystem == "hex":
            document = RegistryHttp.mapping(
                RegistryHttp.json(f"{HOSTS['hex']}/api/packages/{quoted}")
            )
            return [
                str(r["version"])
                for r in RegistryHttp.entries(document.get("releases"))
                if r.get("version")
            ]
        if ecosystem == "pub":
            document = RegistryHttp.mapping(
                RegistryHttp.json(f"{HOSTS['pub']}/api/packages/{quoted}")
            )
            return [
                str(v["version"])
                for v in RegistryHttp.entries(document.get("versions"))
                if v.get("version") and v.get("retracted") is not True
            ]
        if ecosystem in ("maven", "gradle"):
            group, _, artifact = name.partition(":")
            text = RegistryHttp.text(
                f"{HOSTS['maven']}/maven2/{group.replace('.', '/')}/{artifact}/maven-metadata.xml"
            )
            return re.findall(r"<version>([^<]{1,80})</version>", text)
        raise RegistryError(f"no version list for {ecosystem}")

    @staticmethod
    def previous(ecosystem: str, name: str, version: str) -> str | None:
        """The release before `version`, by the ecosystem's own version order."""
        from cordon_scanner.intel.advisories.versions import Versions

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
    def archive(ecosystem: str, name: str, version: str | None) -> PackageArchive:
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
            url = f"{HOSTS['gomod']}/{PackageRegistries.go_escape(name)}/@v/{PackageRegistries.go_escape(resolved)}.zip"
            expected = [d for d in facts.digests if d.startswith("h1:")]
            if not expected:
                raise RegistryError(
                    f"the Go checksum database has no h1 for {name}@{resolved}; nothing to verify against"
                )
            data = RegistryRequest.fetch_bytes(url, ecosystem)
            if MoreRegistries.go_h1(data) not in expected:
                raise RegistryError(
                    f"{name}@{resolved} does not match the h1 the Go checksum database records"
                )
            return PackageArchive(ecosystem, name, resolved, filename, data)
        if ecosystem in ("hex", "pub", "maven", "gradle"):
            filename, url, expected, data = MoreRegistries._hex_pub_maven_archive(
                ecosystem, name, resolved, facts
            )
            return PackageArchive(ecosystem, name, resolved, filename, data)
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
        data = RegistryRequest.fetch_bytes(url, ecosystem)
        if hashlib.new(algorithm, data).hexdigest() not in expected:
            raise RegistryError(
                f"{name}@{resolved} does not match the {algorithm} {ecosystem} publishes"
            )
        return PackageArchive(ecosystem, name, resolved, filename, data)

    @staticmethod
    def _hex_pub_maven_archive(
        ecosystem: str, name: str, resolved: str, facts: PackageFacts
    ) -> tuple[str, str, list[str], bytes]:
        """Where Hex, pub and Maven keep the archive of a release, and its bytes, checked against the digest the registry gives."""
        import hashlib

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
        data = RegistryRequest.fetch_bytes(url, "maven" if ecosystem == "gradle" else ecosystem)
        if hashlib.new(algorithm, data).hexdigest() not in expected:
            raise RegistryError(
                f"{name}@{resolved} does not match the {algorithm} {ecosystem} publishes"
            )
        return filename, url, expected, data
