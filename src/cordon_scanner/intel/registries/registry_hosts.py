"""The package registries Cordon reads, and what reading them assumes: each ecosystem's registry hosts
and their aliases, the public hosts a private registry must not be mistaken for, the size a
compressed response may expand to, the shapes of version and release tags, and the redirect a
registry may answer with.
"""

from __future__ import annotations

import re
from typing import Final

from cordon_scanner.intel.registries import registry_client as base
from cordon_scanner.intel.registries.registry_client import (
    RegistryError,
)

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


class Redirected(RegistryError):
    """A registry answered with a redirect, which `_get` never follows on its own."""

    def __init__(self, message: str, location: str) -> None:
        super().__init__(message)
        self.location = location


__all__ = ["ALIASES", "HOSTS", "PUBLIC_HOSTS", "Redirected"]
