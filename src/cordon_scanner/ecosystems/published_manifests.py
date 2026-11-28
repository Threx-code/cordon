"""A published package's identity file read as a manifest: its name, the packages it depends on.

Where an ecosystem's own manifest parser does not read the file a published package is identified by (Hex's `metadata.config`, a
conda `info/index.json`, a pod's `.podspec.json`, a collection's `MANIFEST.json`, a `.nuspec`, a formula, `package.nix`, an
image's config blob, an editor extension's `package.json`), its `OwnName.parsers` names the reader here. The campaign fingerprint
reads a package through this (`PublishedManifests.of`), so one declaration serves the own-name finding and the fingerprint.
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import TYPE_CHECKING

from cordon_scanner.ecosystems.base import BaseEcosystem, DeclaredDependency, Manifest
from cordon_scanner.ecosystems.own_names import OwnName, OwnNameReaders

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.foundation.content import FileContent


class PublishedManifests:
    @staticmethod
    def of(adapter: object, path: str, content: FileContent) -> Manifest:
        """The package's manifest as it is read from a published package: by the parser its `OwnName` declares for the file,
        else the ecosystem's own manifest parser."""
        declared = getattr(adapter, "own_name", None)
        parser = declared.parser(path) if isinstance(declared, OwnName) else None
        if parser is None or not isinstance(adapter, BaseEcosystem):
            manifest: Manifest = adapter.parse_manifest(content)  # type: ignore[attr-defined]
            return manifest
        read: Manifest = getattr(PublishedManifests, parser)(adapter.id, path, content)
        return read

    @staticmethod
    def _manifest(
        ecosystem: str, path: str, name: str | None, dependencies: Iterable[str]
    ) -> Manifest:
        return Manifest(
            path=path,
            ecosystem=ecosystem,
            name=name,
            dependencies=tuple(
                DeclaredDependency(name=d, spec="*") for d in dict.fromkeys(dependencies)
            ),
        )

    @staticmethod
    def hex_manifest(ecosystem: str, path: str, content: FileContent) -> Manifest:
        """A published Hex package's `metadata.config`: its name, and the name of each requirement it lists."""
        own = OwnNameReaders.erlang_term(content, "name")
        names = [
            m.group(1).decode()
            for m in re.finditer(rb'\{<<"name">>,\s*<<"([^"]{1,200})">>\}', content.raw[:65536])
        ]
        return PublishedManifests._manifest(ecosystem, path, own, [n for n in names if n != own])

    @staticmethod
    def conda_manifest(ecosystem: str, path: str, content: FileContent) -> Manifest:
        """A conda package's `info/index.json`: its name and the packages in `depends` (the first word of each)."""
        document = OwnNameReaders.json_object(content)
        depends = document.get("depends")
        names = (
            [d.split()[0] for d in depends if isinstance(d, str) and d.split()]
            if isinstance(depends, list)
            else []
        )
        own = document.get("name")
        return PublishedManifests._manifest(
            ecosystem, path, own if isinstance(own, str) else None, names
        )

    @staticmethod
    def collection_manifest_full(ecosystem: str, path: str, content: FileContent) -> Manifest:
        """A published collection's `MANIFEST.json`: its `namespace.name` and the collections it depends on."""
        info = OwnNameReaders.json_object(content).get("collection_info")
        info = info if isinstance(info, dict) else {}
        dependencies = info.get("dependencies")
        names = list(dependencies) if isinstance(dependencies, dict) else []
        return PublishedManifests._manifest(
            ecosystem,
            path,
            OwnNameReaders.collection_manifest(path, content),
            [str(n) for n in names],
        )

    @staticmethod
    def podspec_json_manifest(ecosystem: str, path: str, content: FileContent) -> Manifest:
        """A pod's `.podspec.json`: its name and the pods it depends on."""
        document = OwnNameReaders.json_object(content)
        dependencies = document.get("dependencies")
        names = list(dependencies) if isinstance(dependencies, dict) else []
        return PublishedManifests._manifest(
            ecosystem, path, OwnNameReaders.podspec_json(path, content), [str(n) for n in names]
        )

    @staticmethod
    def formula_manifest(ecosystem: str, path: str, content: FileContent) -> Manifest:
        """A Homebrew formula: its name (the file's) and each `depends_on` it writes."""
        names = re.findall(r'^\s*depends_on\s+"([^"\n]{1,100})"', content.text, re.MULTILINE)
        return PublishedManifests._manifest(
            ecosystem, path, OwnNameReaders.formula_stem(path, content), names
        )

    @staticmethod
    def nix_manifest(ecosystem: str, path: str, content: FileContent) -> Manifest:
        """A nixpkgs `package.nix`: its `pname` and the names its `buildInputs` and `nativeBuildInputs` list."""
        names: list[str] = []
        for block in re.finditer(
            r"(?:nativeBuildInputs|buildInputs)\s*=\s*\[([^\]]{0,4000})\]", content.text
        ):
            names += re.findall(r"[A-Za-z_][\w.-]{0,80}", block.group(1))
        return PublishedManifests._manifest(
            ecosystem, path, OwnNameReaders.nix_pname(path, content), names
        )

    @staticmethod
    def nuspec_manifest(ecosystem: str, path: str, content: FileContent) -> Manifest:
        """A .nuspec: its package id and the id of each dependency."""
        names = re.findall(r'<dependency\s+id="([^"]{1,200})"', content.text)
        return PublishedManifests._manifest(
            ecosystem, path, OwnNameReaders.nuspec_id(path, content), names
        )

    @staticmethod
    def image_manifest(ecosystem: str, path: str, content: FileContent) -> Manifest:
        """An image's config blob: its name; it declares no dependency (its layers are the contents)."""
        return PublishedManifests._manifest(
            ecosystem, path, OwnNameReaders.image_config(path, content), []
        )

    @staticmethod
    def extension_package(ecosystem: str, path: str, content: FileContent) -> Manifest:
        """An editor extension's `extension/package.json`, which is a package.json: read as one, named `publisher.name`."""
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        npm = EcosystemRegistry.get("npm")
        if npm is None:
            return PublishedManifests._manifest(ecosystem, path, None, [])
        parsed = npm.parse_manifest(content)
        return replace(
            parsed, ecosystem=ecosystem, name=OwnNameReaders.extension_manifest(path, content)
        )


__all__ = ["PublishedManifests"]
