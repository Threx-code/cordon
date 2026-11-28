"""The package name and the version an install command names, by the rules of the package manager's ecosystem."""

from __future__ import annotations

import re
from typing import ClassVar, Final


class InstallSpec:
    """Reads what follows `npm install`, `pip install`, `cargo add`, `brew install` and the other package managers' own commands."""

    #: How each ecosystem writes a name and a version in one word of an install command (one table: S25), by the
    #: reader in `_READERS`: `at` `name@1.2`, `pip` `name==1.2`, `colon` `name:1.2`, `triple` `group:artifact:1.2`, `slash`
    #: `name/1.2`, `equals` `name=1.2`, `dot` `name.1.2`, `dash` `name-1.2`, `hash` `flake#name`, `whole` (the word is the
    #: name: the manager takes its version from a flag, or none in the word).
    KINDS: ClassVar[dict[str, str]] = {
        "npm": "at",
        "pypi": "pip",
        "cargo": "at",
        "gomod": "at",
        "rubygems": "whole",
        "composer": "colon",
        "nuget": "whole",
        "pub": "colon",
        "hex": "whole",
        "maven": "triple",
        "gradle": "triple",
        "conda": "equals",
        "homebrew": "whole",
        "image": "colon",
        "helm": "whole",
        "ansible": "colon",
        "nix": "hash",
        "swift": "whole",
        "vcpkg": "whole",
        "conan": "slash",
        "cran": "whole",
        "hackage": "dash",
        "julia": "whole",
        "opam": "dot",
        "vscode": "at",
        "cocoapods": "whole",
        "terraform": "whole",
        "actions": "at",
        "bazel": "whole",
    }
    _PIP: Final = re.compile(r"(==|>=|<=|~=|!=|<|>|\[)")
    _DOT: Final = re.compile(r"([A-Za-z][\w+-]*?)[.=](\d[\w.+~-]*)")
    _DASH: Final = re.compile(r"([A-Za-z][\w-]*?)-(\d+(?:\.\d+)*)")

    @staticmethod
    def _exact(version: str) -> str | None:
        """The version when the word pins one release (`1.2.3`, `v0.20.0`, a tag like `1.25`); None for `latest` and for a range."""
        return version if re.fullmatch(r"v?\d[\w.+-]*", version) else None

    @classmethod
    def _at(cls, spec: str) -> tuple[str, str | None]:
        name, at, version = spec.rpartition("@")
        return (name, cls._exact(version)) if at and name else (spec, None)

    @classmethod
    def _colon(cls, spec: str) -> tuple[str, str | None]:
        name, colon, version = spec.rpartition(":")
        usable = colon and name and "/" not in version and not version.startswith("//")
        return (name, cls._exact(version)) if usable else (spec, None)

    @staticmethod
    def _triple(spec: str) -> tuple[str, str | None]:
        parts = spec.split(":")
        return (":".join(parts[:2]), parts[2]) if len(parts) >= 3 else (spec, None)

    @staticmethod
    def _slash(spec: str) -> tuple[str, str | None]:
        name, slash, version = spec.partition("/")
        return (name, version.partition("@")[0]) if slash and name and version else (spec, None)

    @staticmethod
    def _equals(spec: str) -> tuple[str, str | None]:
        name, equals, version = spec.partition("=")
        return (name, version.lstrip("=")) if equals and name else (spec, None)

    @classmethod
    def _dot(cls, spec: str) -> tuple[str, str | None]:
        found = cls._DOT.fullmatch(spec)
        return (found.group(1), found.group(2)) if found else (spec, None)

    @classmethod
    def _dash(cls, spec: str) -> tuple[str, str | None]:
        found = cls._DASH.fullmatch(spec)
        return (found.group(1), found.group(2)) if found else (spec, None)

    @staticmethod
    def _hash(spec: str) -> tuple[str, str | None]:
        return (spec.rpartition("#")[2] or spec, None)

    @staticmethod
    def _whole(spec: str) -> tuple[str, str | None]:
        return spec, None

    @classmethod
    def _pip(cls, spec: str) -> tuple[str, str | None]:
        name = cls._PIP.split(spec, maxsplit=1)[0]
        pinned = re.search(r"==\s*([A-Za-z0-9.!+_-]+)\s*$", spec)
        return name, pinned.group(1) if pinned else None

    @classmethod
    def split(cls, ecosystem: str, spec: str) -> tuple[str, str | None]:
        """The package name and the version the install pins, or no version when it names the latest (or a range)."""
        reader = getattr(cls, f"_{cls.KINDS.get(ecosystem, 'pip')}")
        result: tuple[str, str | None] = reader(spec)
        return result
