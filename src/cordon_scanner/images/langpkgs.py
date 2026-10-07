"""Language packages installed in an image, read from the metadata each installer leaves behind.

`pip` writes `<name>-<version>.dist-info/METADATA` (or `.egg-info/PKG-INFO`), `npm` keeps each
package's `package.json` under `node_modules`, and RubyGems writes `specifications/<name>-<version>.gemspec`.
These are what an image's application actually runs, alongside the distribution's own packages,
and they are matched against the same advisory database as a repository's lockfile.
"""

from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass
from typing import Final

#: A runtime installed from its own release tarball rather than a package manager records its
#: version in a file of its own: the official python, node, golang and eclipse-temurin images all
#: do. `(path pattern, runtime name)`; the version is read from the file's content.
RUNTIME_FILES: Final = (
    (re.compile(r"^usr/local/include/python\d+\.\d+[a-z]?/patchlevel\.h$"), "python"),
    (re.compile(r"^usr/local/include/node/node_version\.h$"), "node"),
    (re.compile(r"^usr/local/go/VERSION$"), "go"),
    (
        re.compile(
            r"^(?:opt/java/openjdk|usr/lib/jvm/[^/]+|usr/local/openjdk[^/]*|opt/openjdk[^/]*)/release$"
        ),
        "oracle/openjdk",
    ),
    (re.compile(r"^usr/local/lib/ruby/\d+\.\d+\.\d+/[^/]+/rbconfig\.rb$"), "ruby"),
)
_PY_VERSION: Final = re.compile(rb'#define\s+PY_VERSION\s+"(\d+\.\d+\.\d+[\w.+]{0,20})"')
_NODE_PART: Final = re.compile(rb"#define\s+NODE_(MAJOR|MINOR|PATCH)_VERSION\s+(\d+)")
_GO_VERSION: Final = re.compile(rb"^go(\d+\.\d+(?:\.\d+)?(?:rc\d+|beta\d+)?)\b")
_JAVA_VERSION: Final = re.compile(rb'^JAVA_RUNTIME_VERSION="([^"\n]{1,60})"', re.M)
_JAVA_VERSION_SHORT: Final = re.compile(rb'^JAVA_VERSION="([^"\n]{1,60})"', re.M)
_RUBY_VERSION: Final = re.compile(rb'CONFIG\["RUBY_PROGRAM_VERSION"\]\s*=\s*"(\d+\.\d+\.\d+)"')
_NPM_DIRECTORY: Final = re.compile(r"^(?:@[^/@]+/)?[^/@]+$")
_YARN_HOME: Final = re.compile(r"^opt/yarn-v[^/]+/package\.json$")

_GEMSPEC: Final = re.compile(
    r"^(?P<name>[A-Za-z0-9_.-]+?)-(?P<version>\d[\w.]*)(?:-[\w-]+)?\.gemspec$"
)


@dataclass(frozen=True)
class LanguagePackage:
    ecosystem: str
    """As the advisory database names it: `pypi`, `npm`, `rubygems`, and from compiled artefacts
    `gomod`, `cargo`, `nuget` and `maven`."""
    name: str
    version: str
    path: str
    """Where in the image the metadata was found."""
    integrity: str | None = None
    """The checksum the build recorded, where it recorded one (Go's `h1:` module sums), or the
    artefact's own (a jar that is the artifact its pom.properties names)."""
    platform: tuple[str, ...] = ()
    """What the binary it came from says of itself: its architecture and whether it is signed."""
    named_by_file: bool = False
    """A jar with no Maven metadata, named after its file: no registry knows the coordinate."""

    @property
    def purl(self) -> str:
        if self.ecosystem == "npm" and self.name.startswith("@"):
            return f"pkg:npm/%40{self.name[1:]}@{self.version}"
        if self.ecosystem == "maven" and ":" in self.name:
            group, _, artifact = self.name.partition(":")
            return f"pkg:maven/{group}/{artifact}@{self.version}"
        kind = {"rubygems": "gem", "gomod": "golang", "runtime": "generic"}.get(
            self.ecosystem, self.ecosystem
        )
        return f"pkg:{kind}/{self.name}@{self.version}"


class LanguagePackages:
    """Language packages installed in an image, from their own metadata."""

    @staticmethod
    def is_metadata(path: str) -> bool:
        base = posixpath.basename(path)
        parent = posixpath.basename(posixpath.dirname(path))
        if base == "METADATA" and parent.endswith(".dist-info"):
            return True
        if base == "PKG-INFO" and parent.endswith(".egg-info"):
            return True
        # A distribution's Python packages often install their metadata as one FILE named
        # `<name>-<version>-py3.9.egg-info` (RPM's python3-iniparse), in PKG-INFO's format.
        if base.endswith(".egg-info") and parent in ("site-packages", "dist-packages"):
            return True
        if base == "package.json" and ("/node_modules/" in f"/{path}" or _YARN_HOME.match(path)):
            return True
        if any(pattern.match(path) for pattern, _ in RUNTIME_FILES):
            return True
        # Ruby's default gems (bundler, json, openssl...) ship with the interpreter and keep their
        # specs one level down, in `specifications/default/`.
        grandparent = posixpath.basename(posixpath.dirname(posixpath.dirname(path)))
        return base.endswith(".gemspec") and (
            parent == "specifications" or (parent == "default" and grandparent == "specifications")
        )

    @staticmethod
    def _email_header(data: bytes, field: str) -> str:
        for line in data.decode("utf-8", "replace").splitlines():
            if not line.strip():
                break  # the body starts after the first blank line
            key, _, value = line.partition(":")
            if key.strip().lower() == field:
                return value.strip()
        return ""

    @staticmethod
    def runtime(path: str, data: bytes) -> LanguagePackage | None:
        """A runtime's version, from the file its own build writes it to."""
        name = next((runtime for pattern, runtime in RUNTIME_FILES if pattern.match(path)), None)
        version = None
        if name == "python":
            found = _PY_VERSION.search(data)
            version = found.group(1).decode() if found else None
        elif name == "node":
            parts = {key.decode(): value.decode() for key, value in _NODE_PART.findall(data)}
            if {"MAJOR", "MINOR", "PATCH"} <= set(parts):
                version = f"{parts['MAJOR']}.{parts['MINOR']}.{parts['PATCH']}"
        elif name == "go":
            found = _GO_VERSION.search(data)
            version = found.group(1).decode() if found else None
        elif name == "ruby":
            found = _RUBY_VERSION.search(data)
            version = found.group(1).decode() if found else None
        elif name == "oracle/openjdk":
            found = _JAVA_VERSION.search(data) or _JAVA_VERSION_SHORT.search(data)
            version = found.group(1).decode() if found else None
        return LanguagePackage("runtime", name, version, path) if name and version else None

    @staticmethod
    def parse(path: str, data: bytes) -> LanguagePackage | None:
        base = posixpath.basename(path)
        if any(pattern.match(path) for pattern, _ in RUNTIME_FILES):
            return LanguagePackages.runtime(path, data)
        if base in ("METADATA", "PKG-INFO") or base.endswith(".egg-info"):
            name, version = (
                LanguagePackages._email_header(data, "name"),
                LanguagePackages._email_header(data, "version"),
            )
            return (
                LanguagePackage("pypi", name.lower(), version, path) if name and version else None
            )
        if base == "package.json":
            try:
                manifest = json.loads(data)
            except ValueError:
                return None
            if not isinstance(manifest, dict):
                return None
            raw_name, raw_version = manifest.get("name"), manifest.get("version")
            # A package.json is the installed package's own only where its directory is named for it;
            # test fixtures and examples inside a package carry package.json files of their own.
            directory = posixpath.dirname(path)
            rooted = f"/{directory}"
            expected = rooted.rsplit("/node_modules/", 1)[-1] if "/node_modules/" in rooted else ""
            if _YARN_HOME.match(path) and raw_name == "yarn":
                expected = raw_name  # Yarn 1's own tarball, unpacked where the node image puts it
            # An alias (`"wrap-ansi-cjs": "npm:wrap-ansi@7"`) is installed under the alias and its
            # package.json names the real package: still a package directory, one level under
            # node_modules, which a fixture deeper inside a package never is.
            aliased = bool(_NPM_DIRECTORY.match(expected)) and expected.startswith("@") == str(
                raw_name
            ).startswith("@")
            if (
                not isinstance(raw_name, str)
                or not isinstance(raw_version, str)
                or (expected != raw_name and not aliased)
            ):
                return None
            return LanguagePackage("npm", raw_name, raw_version, path)
        match = _GEMSPEC.match(base)
        if match:
            return LanguagePackage("rubygems", match.group("name"), match.group("version"), path)
        return None


__all__ = ["LanguagePackage", "LanguagePackages"]
