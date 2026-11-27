"""How an ecosystem's own files say what the package is called.

A published package, or a repository that is one, carries a file that names it: `Cargo.toml`, `pubspec.yaml`, `Chart.yaml`, a
`.nuspec`. The name there is the package's own (a dependency's name is somewhere else), and a name one slip from a popular
package's is the finding `SUSPECT.TYPOSQUAT.PACKAGE_NAME.001`. Each adapter declares the files that carry it and how to read the name
(`OwnName`), or, where no file of the ecosystem states the name of the package it is part of, why not (`NoOwnName`).
"""

from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from collections.abc import Collection

    from cordon_scanner.ecosystems.base import Manifest
    from cordon_scanner.foundation.content import FileContent


@dataclass(frozen=True, slots=True)
class OwnName:
    """The files that state a package's own name: path patterns matched against the end of a path (`Cargo.toml`,
    `info/index.json`, `*.podspec.json`). `blocks`: whether a name that is a slip may block, because it was measured on this
    ecosystem's published packages (review 98); elsewhere it is recorded below the gate."""

    files: tuple[str, ...]
    blocks: bool = False
    #: A file's pattern -> the `OwnNameReaders` function that reads it; a file not named here is read as the manifest it is.
    readers: tuple[tuple[str, str], ...] = ()

    def reader(self, path: str) -> str | None:
        """The reader for the most specific pattern of `readers` that `path` matches, or None."""
        tail = PurePosixPath(path.rpartition("!")[2])
        found = [(len(PurePosixPath(p).parts), name) for p, name in self.readers if tail.match(p)]
        return max(found)[1] if found else None

    def matches(self, path: str) -> int:
        """How many components of `path` the longest matching pattern covers, 0 for none: the most specific pattern wins."""
        tail = path.rpartition("!")[2]
        best = 0
        for pattern in self.files:
            if PurePosixPath(tail).match(pattern):
                best = max(best, len(PurePosixPath(pattern).parts))
        return best


@dataclass(frozen=True, slots=True)
class NoOwnName:
    """An ecosystem none of whose files states the name of the package it belongs to, and why."""

    reason: str


OwnNameDeclaration = OwnName | NoOwnName


class OwnNameReaders:
    """How the name is read from a published file that is not read as a manifest (named by `OwnName.readers`), each
    as `(path, content) -> name or None`. The patterns that find the name are bounded: nothing here backtracks."""

    _TERM: ClassVar[re.Pattern[bytes]] = re.compile(
        rb'\{<<"(?P<key>[a-z_]+)">>,\s*<<"(?P<value>[^"]{1,200})">>\}'
    )

    @staticmethod
    def json_object(content: FileContent) -> dict[str, Any]:
        try:
            value = json.loads(content.text)
        except (ValueError, RecursionError):
            return {}
        return value if isinstance(value, dict) else {}

    @staticmethod
    def podspec_json(path: str, content: FileContent) -> str | None:
        name = OwnNameReaders.json_object(content).get("name")
        return name if isinstance(name, str) and name else None

    @staticmethod
    def collection_manifest(path: str, content: FileContent) -> str | None:
        """`namespace.name` of the collection a published `MANIFEST.json` describes."""
        info = OwnNameReaders.json_object(content).get("collection_info")
        if not isinstance(info, dict):
            return None
        namespace, name = info.get("namespace"), info.get("name")
        return (
            f"{namespace}.{name}" if isinstance(namespace, str) and isinstance(name, str) else None
        )

    @staticmethod
    def conda_index(path: str, content: FileContent) -> str | None:
        return OwnNameReaders.podspec_json(path, content)

    @staticmethod
    def hex_metadata(path: str, content: FileContent) -> str | None:
        return OwnNameReaders.erlang_term(content, "name")

    @staticmethod
    def formula_stem(path: str, content: FileContent) -> str | None:
        """A Homebrew formula is named for its file."""
        return OwnNameDefaults.stem(path) or None

    @staticmethod
    def nix_pname(path: str, content: FileContent) -> str | None:
        found = re.search(r'^\s*pname\s*=\s*"([^"\n]{1,200})"\s*;', content.text, re.MULTILINE)
        return found.group(1) if found else None

    @staticmethod
    def opam_name(path: str, content: FileContent) -> str | None:
        """The `name:` of an opam file; failing that the package the file sits under (`packages/dune/dune.3.15.3/opam`) or is named for."""
        found = re.search(r'^name:\s*"([^"\n]{1,200})"', content.text, re.MULTILINE)
        if found:
            return found.group(1)
        tail = PurePosixPath(path.rpartition("!")[2])
        if tail.name == "opam":
            versioned = re.match(r"^(.+?)\.\d", tail.parent.name)
            return versioned.group(1) if versioned else None
        return tail.stem or None

    @staticmethod
    def extension_manifest(path: str, content: FileContent) -> str | None:
        """`publisher.name`, the identifier an editor extension goes by."""
        manifest = OwnNameReaders.json_object(content)
        publisher, name = manifest.get("publisher"), manifest.get("name")
        if isinstance(publisher, str) and isinstance(name, str) and publisher and name:
            return f"{publisher}.{name}".lower()
        return None

    #: What an image names itself in its config blob: the title its publisher gives it, else the repository it says it was
    #: built from (`org.opencontainers.image.title`, `.source`).
    _IMAGE_NAME: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")

    @staticmethod
    def image_config(path: str, content: FileContent) -> str | None:
        """The name a published image's config blob gives itself; None for any other blob or file."""
        document = OwnNameReaders.json_object(content)
        settings = document.get("config")
        if "rootfs" not in document or not isinstance(settings, dict):
            return None
        labels = settings.get("Labels")
        if not isinstance(labels, dict):
            return None
        title = labels.get("org.opencontainers.image.title")
        if isinstance(title, str) and OwnNameReaders._IMAGE_NAME.fullmatch(title.strip()):
            return title.strip()
        source = labels.get("org.opencontainers.image.source")
        last = (
            source.rstrip("/").rpartition("/")[2].removesuffix(".git")
            if isinstance(source, str)
            else ""
        )
        return last if OwnNameReaders._IMAGE_NAME.fullmatch(last) else None

    @staticmethod
    def provider_binary(path: str, content: FileContent) -> str | None:
        """The provider type a release's binary is named for (`terraform-provider-null_v3.2.2_x5` -> `null`)."""
        found = re.fullmatch(
            r"terraform-provider-([A-Za-z0-9-]{1,64})_v\d[^/]{0,64}",
            posixpath.basename(path.rpartition("!")[2]),
        )
        return found.group(1) if found else None

    @staticmethod
    def gradle_root(path: str, content: FileContent) -> str | None:
        found = re.search(r"""rootProject\.name\s*=\s*["']([^"'\n]{1,200})["']""", content.text)
        return found.group(1) if found else None

    @staticmethod
    def nuspec_id(path: str, content: FileContent) -> str | None:
        found = re.search(r"<id>\s*([^<\s]{1,200})\s*</id>", content.text)
        return found.group(1) if found else None

    @classmethod
    def erlang_term(cls, content: FileContent, key: str) -> str | None:
        """A binary value of a flat Erlang term file (Hex's `metadata.config`: `{<<"name">>,<<"jason">>}.`)."""
        for found in cls._TERM.finditer(content.raw[:65536]):
            if found.group("key").decode() == key:
                return found.group("value").decode("utf-8", "replace")
        return None


class OwnNameDefaults:
    """What every adapter has of its own-name declaration: the declaration (no default: each ecosystem states it) and the
    read, which is the manifest's name unless the adapter's published file says it another way."""

    own_name: OwnNameDeclaration

    def parse_manifest(
        self, content: FileContent
    ) -> Manifest:  # pragma: no cover - the adapter's own
        raise NotImplementedError

    def own_name_of(
        self, path: str, content: FileContent, tree_paths: Collection[str]
    ) -> str | None:
        """The package's own name as `path` (one of the declared files) states it, or None."""
        declared = self.own_name
        reader = declared.reader(path) if isinstance(declared, OwnName) else None
        if reader is not None:
            read: str | None = getattr(OwnNameReaders, reader)(path, content)
            return read or None
        claims = getattr(self, "claims_manifest", None)
        if claims is not None and not claims(content, tree_paths):
            return None
        return self.parse_manifest(content).name or None

    @staticmethod
    def stem(path: str) -> str:
        """The name a file is named for (`Formula/j/jq.rb` -> `jq`)."""
        return posixpath.basename(path.rpartition("!")[2]).rpartition(".")[0]


__all__ = ["NoOwnName", "OwnName", "OwnNameDeclaration", "OwnNameDefaults", "OwnNameReaders"]
