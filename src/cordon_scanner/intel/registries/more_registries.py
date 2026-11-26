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

from cordon_scanner.intel.base import PackageFacts
from cordon_scanner.intel.registries.image_registries import ImageRegistries
from cordon_scanner.intel.registries.infra_registries import InfraRegistries
from cordon_scanner.intel.registries.package_registries import PackageRegistries
from cordon_scanner.intel.registries.registry_hosts import ALIASES
from cordon_scanner.intel.registries.registry_request import RegistryError


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
