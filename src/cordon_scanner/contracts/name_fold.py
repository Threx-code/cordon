"""How each registry treats the case and the separators of a package name, so two spellings of one package get one id.

Keeping the case can never merge two packages wrongly; folding it can, so an ecosystem folds only where its own registry documents
that the spellings are one name (the page is the comment on its line). One table, keyed by ecosystem id, that holds every ecosystem:
a test fails for a registered ecosystem that is missing, so a new one cannot be added without stating its fold.
"""

from __future__ import annotations

from enum import Enum
from typing import ClassVar


class NameFold(Enum):
    """The fold of one registry: whether the case is folded to lower, and whether `-`, `_` and `.` are one separator."""

    KEPT = (False, False)
    LOWER = (True, False)
    PEP_503 = (True, True)

    def __init__(self, lower: bool, one_separator: bool) -> None:
        self.lower = lower
        self.one_separator = one_separator


class NameFolds:
    """`of(ecosystem, purl_type)`: the fold of the registry a package name belongs to."""

    BY_ID: ClassVar[dict[str, NameFold]] = {
        # https://docs.npmjs.com/cli/v10/configuring-npm/package-json#name
        "npm": NameFold.LOWER,
        # https://packaging.python.org/en/latest/specifications/name-normalization/
        "pypi": NameFold.PEP_503,
        # https://learn.microsoft.com/en-us/nuget/reference/nuspec#id
        "nuget": NameFold.LOWER,
        # https://getcomposer.org/doc/04-schema.md#name
        "composer": NameFold.LOWER,
        # https://go.dev/ref/mod#module-path (the stored id has always been lower case; kept)
        "gomod": NameFold.LOWER,
        # https://hex.pm/docs/publish
        "hex": NameFold.LOWER,
        # https://docs.swift.org/swiftpm/documentation/packagemanagerdocs/ (the stored id has always been lower case; kept)
        "swift": NameFold.LOWER,
        # https://guides.cocoapods.org/syntax/podspec.html#name (the stored id has always been lower case; kept)
        "cocoapods": NameFold.LOWER,
        # https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#jobsjob_idstepsuses
        "actions": NameFold.LOWER,
        # https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pull (repository names are lower case)
        "image": NameFold.LOWER,
        # https://docs.conda.io/projects/conda-build/en/stable/resources/package-spec.html
        "conda": NameFold.LOWER,
        # https://docs.brew.sh/Formula-Cookbook#grab-the-url
        "homebrew": NameFold.LOWER,
        # https://developer.hashicorp.com/terraform/language/providers/requirements#source-addresses
        "terraform": NameFold.LOWER,
        # https://learn.microsoft.com/en-us/vcpkg/reference/vcpkg-json#name
        "vcpkg": NameFold.LOWER,
        # https://code.visualstudio.com/api/references/extension-manifest
        "vscode": NameFold.LOWER,
        # https://docs.ansible.com/ansible/latest/dev_guide/collections_galaxy_meta.html
        "ansible": NameFold.LOWER,
        # https://dart.dev/tools/pub/pubspec#name
        "pub": NameFold.LOWER,
        # https://bazel.build/external/module#module_name
        "bazel": NameFold.KEPT,
        # https://cran.r-project.org/doc/manuals/r-release/R-exts.html#The-DESCRIPTION-file
        "cran": NameFold.KEPT,
        # https://cabal.readthedocs.io/en/stable/cabal-package-description-file.html#pkg-field-name
        "hackage": NameFold.KEPT,
        # https://pkgdocs.julialang.org/v1/toml-files/
        "julia": NameFold.KEPT,
        # https://opam.ocaml.org/doc/Manual.html (unclear on case: kept)
        "opam": NameFold.KEPT,
        # https://docs.conan.io/2/reference/conanfile/attributes.html#name (unclear on case: kept)
        "conan": NameFold.KEPT,
        # https://nix.dev/manual/nix/stable/language/derivations.html
        "nix": NameFold.KEPT,
        # https://helm.sh/docs/topics/charts/#the-chartyaml-file (unclear on case: kept)
        "helm": NameFold.KEPT,
        # https://maven.apache.org/guidelines.html#create-a-pom (served by Maven: case kept)
        "gradle": NameFold.KEPT,
        # https://maven.apache.org/guides/mini/guide-naming-conventions.html
        "maven": NameFold.KEPT,
        # https://doc.rust-lang.org/cargo/reference/manifest.html#the-name-field (the stored id has always kept the case)
        "cargo": NameFold.KEPT,
        # https://guides.rubygems.org/specification-reference/#name
        "rubygems": NameFold.KEPT,
    }
    #: The fold of each purl type that is not an ecosystem's id (the type a package URL or a tool says), and of the forges
    #: that host packages. A type no registry owns (`oci`: container images are folded by their own kind) keeps its case.
    BY_TYPE: ClassVar[dict[str, NameFold]] = {
        "golang": NameFold.LOWER,
        "gem": NameFold.KEPT,
        "brew": NameFold.LOWER,
        "githubactions": NameFold.LOWER,
        "vscode-extension": NameFold.LOWER,
        "github": NameFold.LOWER,
        "bitbucket": NameFold.LOWER,
    }

    @classmethod
    def of(cls, ecosystem: str, purl_type: str) -> NameFold:
        """The fold for the ecosystem called `ecosystem` (an id); failing that, for the one that owns `purl_type`;
        the case is kept for a type nobody owns."""
        key = ecosystem.strip().lower()
        if key in cls.BY_ID:
            return cls.BY_ID[key]
        return cls.BY_TYPE.get(purl_type) or cls.BY_ID.get(purl_type, NameFold.KEPT)
