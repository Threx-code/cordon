"""A mirror of the platform's `decisions/helpers/declared_packages.py`: the package URLs a device may declare.

The platform refuses a device statement that carries a package URL outside this form, so the scanner names only what it accepts and
counts the rest. `tests/unit/cloud/test_device_attestation.py` checks every ecosystem's package-URL type is in the table. The platform's
own text follows.

The package URLs a device or a runtime may declare: one closed form for every ecosystem Cordon reads, each with its
own name and version rules.

A declared package is `pkg:<type>/<name>@<version>` with the type one of the table below (the scanner's package URL
types, one for each ecosystem it reads). What is allowed is narrower than any package URL the platform reads,
because the device is not trusted: a name is the characters its registry writes (lower case where the registry's
names are lower case, a `%40` for npm's scope, never a name that reads back as a path), at most the segments its
registry has, and no longer than the bound below. The bounds are this platform's, for what a device may say; a
registry's own limit is named only where it publishes one (npm 214, crates 64, NuGet 100)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar
from urllib.parse import unquote


@dataclass(frozen=True)
class DeclaredType:
    #: The most `/`-separated parts a name has (a Go module path, a Maven group and artifact, a Terraform module).
    segments: int
    max_name: int
    max_version: int
    #: Whether the registry writes names in lower case; where it does not, a capital is a character of the name.
    lower: bool = True
    #: Characters a version may hold beyond the common ones (`:` in an image's `sha256:<hex>` digest).
    version_extra: str = ""
    #: Whether a name may start with a scope, written `%40scope/name` as a package URL does (npm).
    scoped: bool = False


class DeclaredPackages:
    TYPES: ClassVar[dict[str, DeclaredType]] = {
        "npm": DeclaredType(2, 214, 64, scoped=True),
        "pypi": DeclaredType(1, 214, 64),
        "cargo": DeclaredType(1, 64, 64),
        "golang": DeclaredType(16, 512, 128, lower=False),
        "maven": DeclaredType(2, 255, 128, lower=False),
        "nuget": DeclaredType(1, 100, 64, lower=False),
        "composer": DeclaredType(2, 214, 64),
        "gem": DeclaredType(1, 128, 64, lower=False),
        "pub": DeclaredType(1, 64, 64),
        "hex": DeclaredType(1, 64, 64),
        "cran": DeclaredType(1, 64, 64, lower=False),
        "swift": DeclaredType(4, 214, 64, lower=False),
        "hackage": DeclaredType(1, 128, 64, lower=False),
        "julia": DeclaredType(1, 128, 64, lower=False),
        "opam": DeclaredType(1, 128, 64),
        "conda": DeclaredType(1, 128, 64),
        "cocoapods": DeclaredType(1, 128, 64, lower=False),
        "bazel": DeclaredType(1, 128, 64),
        "brew": DeclaredType(1, 128, 64),
        "conan": DeclaredType(1, 128, 64),
        "vcpkg": DeclaredType(1, 128, 64),
        "nix": DeclaredType(1, 128, 64),
        "helm": DeclaredType(1, 128, 64),
        "terraform": DeclaredType(3, 214, 64),
        "oci": DeclaredType(8, 512, 128, version_extra=":"),
        #: The scanner calls an image's package URL type `docker`; the platform's identity says `oci`: both are read.
        "docker": DeclaredType(8, 512, 128, version_extra=":"),
        #: A GitHub Action: `owner/repo` and the path of an action inside it; its version is the ref it is pinned to.
        "githubactions": DeclaredType(3, 214, 64, lower=False),
        "ansible": DeclaredType(2, 128, 64),
        #: An editor extension (VS Code Marketplace, Open VSX): `publisher.name`, lower case, and its version as published.
        "vscode-extension": DeclaredType(1, 128, 64),
    }
    SHAPE: ClassVar[re.Pattern[str]] = re.compile(
        r"pkg:(?P<type>[a-z][a-z0-9.+-]*)/(?P<name>[^@]+)@(?P<version>[^@/]+)"
    )

    @classmethod
    def read(cls, value: object) -> tuple[str, str, str] | None:
        """`(type, name as written, version)` when `value` is a declarable package, else None."""
        found = cls.SHAPE.fullmatch(value) if isinstance(value, str) else None
        rule = cls.TYPES.get(found["type"]) if found else None
        if found is None or rule is None:
            return None
        name, version = found["name"], found["version"]
        if len(name) > rule.max_name or len(version) > rule.max_version:
            return None
        if not cls._written(name, rule) or not cls._plain(unquote(name), rule):
            return None
        if not re.fullmatch(r"[A-Za-z0-9._+~" + re.escape(rule.version_extra) + r"-]+", version):
            return None
        return found["type"], name, version

    @staticmethod
    def _characters(rule: DeclaredType, extra: str = "") -> str:
        """The inside of a character class: the name's characters, `extra` ones, and the hyphen last."""
        return ("a-z" if rule.lower else "A-Za-z") + "0-9._~+" + extra + "-"

    @classmethod
    def _written(cls, name: str, rule: DeclaredType) -> bool:
        """The name as it is written in the URL: its characters, with `%` for an escape, in at most `segments` parts."""
        part = "[" + cls._characters(rule, "%") + "]+"
        return (
            re.fullmatch(part + "(?:/" + part + "){0," + str(rule.segments - 1) + "}", name)
            is not None
        )

    @classmethod
    def _plain(cls, name: str, rule: DeclaredType) -> bool:
        """The name once its escapes are read is still a name: its characters (and the scope's `@`, first, where the
        registry has scopes), the same most parts, and no part that is `.` or `..`."""
        part = "[" + cls._characters(rule) + "]+"
        scope = "@?" if rule.scoped else ""
        shape = scope + part + "(?:/" + part + "){0," + str(rule.segments - 1) + "}"
        return re.fullmatch(shape, name) is not None and not any(
            p in (".", "..") for p in name.split("/")
        )
