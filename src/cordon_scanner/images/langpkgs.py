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

_GEMSPEC: Final = re.compile(
    r"^(?P<name>[A-Za-z0-9_.-]+?)-(?P<version>\d[\w.]*)(?:-[\w-]+)?\.gemspec$"
)


@dataclass(frozen=True)
class LanguagePackage:
    ecosystem: str
    """`pypi`, `npm` or `rubygems`, as the advisory database names them."""
    name: str
    version: str
    path: str
    """Where in the image the metadata was found."""

    @property
    def purl(self) -> str:
        if self.ecosystem == "npm" and self.name.startswith("@"):
            return f"pkg:npm/%40{self.name[1:]}@{self.version}"
        return f"pkg:{'gem' if self.ecosystem == 'rubygems' else self.ecosystem}/{self.name}@{self.version}"


def is_metadata(path: str) -> bool:
    base = posixpath.basename(path)
    parent = posixpath.basename(posixpath.dirname(path))
    if base == "METADATA" and parent.endswith(".dist-info"):
        return True
    if base == "PKG-INFO" and parent.endswith(".egg-info"):
        return True
    if base == "package.json" and "/node_modules/" in f"/{path}":
        return True
    return base.endswith(".gemspec") and parent == "specifications"


def _email_header(data: bytes, field: str) -> str:
    for line in data.decode("utf-8", "replace").splitlines():
        if not line.strip():
            break  # the body starts after the first blank line
        key, _, value = line.partition(":")
        if key.strip().lower() == field:
            return value.strip()
    return ""


def parse(path: str, data: bytes) -> LanguagePackage | None:
    base = posixpath.basename(path)
    if base in ("METADATA", "PKG-INFO"):
        name, version = _email_header(data, "name"), _email_header(data, "version")
        return LanguagePackage("pypi", name.lower(), version, path) if name and version else None
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
        if (
            not isinstance(raw_name, str)
            or not isinstance(raw_version, str)
            or expected != raw_name
        ):
            return None
        return LanguagePackage("npm", raw_name, raw_version, path)
    match = _GEMSPEC.match(base)
    if match:
        return LanguagePackage("rubygems", match.group("name"), match.group("version"), path)
    return None


__all__ = ["LanguagePackage", "is_metadata", "parse"]
