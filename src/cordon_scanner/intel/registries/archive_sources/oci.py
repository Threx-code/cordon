"""Container images and Homebrew bottles, both held in OCI registries: pulled by `RegistryImage`, which checks every blob against its
digest and every child manifest against the index that names it.

What the registry cannot vouch for is the tag itself: a tag names whatever manifest the registry serves for it, so a release asked for by
tag is reported as checked by `oci-tag`; one asked for by digest (`sha256:...`) is checked against that digest."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.intel.base import PackageArchive
from cordon_scanner.intel.registries.archive_sources.base import ArchiveSource, Located
from cordon_scanner.intel.registries.archive_sources.hosts import PublicHost
from cordon_scanner.intel.registries.record_sources.base import Document
from cordon_scanner.intel.registries.registry_image import RegistryImage, RegistryImageError
from cordon_scanner.intel.registries.registry_request import RegistryError

if TYPE_CHECKING:
    from collections.abc import Mapping

OCI_TAG = "oci-tag"
LOWER = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._-")
HUB_NAMES = ("docker.io/", "index.docker.io/", "registry-1.docker.io/")
TAG = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-+")


class ImageRef:
    @staticmethod
    def of(name: str) -> tuple[str | None, str] | None:
        """`(registry, repository)` of an image name: Docker Hub (registry `None`, `library/` for an official image) when the first
        part is no host, else the registry that part names, which must be a public one. None for a name that is neither."""
        text = name.strip().lower()
        for hub in HUB_NAMES:
            text = text.removeprefix(hub)
        parts = text.split("/")
        host = parts[0] if len(parts) > 1 and ("." in parts[0] or ":" in parts[0]) else ""
        registry, path = (host, parts[1:]) if host else (None, parts)
        if registry is not None and not PublicHost.named(registry.rsplit(":", 1)[0]):
            return None
        if registry is None and len(path) == 1:
            path = ["library", *path]
        if not path or len(path) > 6 or any(not p or set(p) - LOWER or p[0] in ".-" for p in path):
            return None
        return registry, "/".join(path)


class OciArchive(ArchiveSource):
    """An archive that is pulled rather than fetched from one address: `fetch` returns it, or None when `name`/`version` name none."""

    HOSTS: ClassVar[frozenset[str]] = frozenset()

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        return ()

    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        return None

    def allows(self, host: str) -> bool:
        return False

    @staticmethod
    def reference(version: str) -> str:
        if (
            version.startswith("sha256:")
            and len(version) == 71
            and set(version[7:]) <= set("0123456789abcdef")
        ):
            return version
        return (
            version
            if version and set(version) <= TAG and version[0] not in ".-" and len(version) <= 128
            else ""
        )


class ImageArchive(OciArchive):
    """A container image: the OCI layout (`index.json`, the manifests, the config and every layer) of the tag or digest, as the scanner
    reads a saved image."""

    ecosystem: ClassVar[str] = "image"

    def current(self, name: str) -> str:
        return "latest"

    def fetch(self, name: str, version: str) -> PackageArchive | None:
        found, reference = ImageRef.of(name), self.reference(version)
        if found is None or not reference:
            return None
        try:
            layout, _pull = RegistryImage(found[0], found[1], public_only=True).pull(reference)
        except RegistryImageError as exc:
            raise RegistryError(str(exc)) from exc
        weak = "" if reference.startswith("sha256:") else OCI_TAG
        return PackageArchive(
            "image",
            name,
            version,
            f"{found[1].replace('/', '_')}-{version.replace(':', '_')}.tar",
            layout,
            weak,
        )


class HomebrewArchive(OciArchive):
    """A Homebrew bottle: `homebrew/core/<formula>` on ghcr.io holds one manifest per platform for each version; the bottle is the
    layer of the first platform of `PLATFORMS` the version has (a formula `name@3` is the repository `name/3`)."""

    ecosystem: ClassVar[str] = "homebrew"
    PLATFORMS: ClassVar[tuple[str, ...]] = (
        "arm64_sequoia",
        "arm64_sonoma",
        "x86_64_linux",
        "arm64_linux",
        "sonoma",
        "ventura",
    )
    NAME: ClassVar[frozenset[str]] = frozenset("abcdefghijklmnopqrstuvwxyz0123456789@+._-")

    def fetch(self, name: str, version: str) -> PackageArchive | None:
        reference = self.reference(version)
        if (
            not name
            or set(name) - self.NAME
            or name[0] in ".-@"
            or ".." in name
            or not reference
            or reference.startswith("sha256:")
        ):
            return None
        image = RegistryImage(
            "ghcr.io", "homebrew/core/" + name.replace("@", "/"), public_only=True
        )
        try:
            body, _media = image.manifest(reference)
            index = json.loads(body)
            descriptor = self.choose(index)
            if descriptor is None:
                return None
            child, _ = image.manifest(str(descriptor["digest"]))
            layers = json.loads(child).get("layers") or []
            digest = (
                str(layers[0].get("digest", "")) if layers and isinstance(layers[0], dict) else ""
            )
            from cordon_scanner.intel.registries.registry_image import Pull

            data = image.blob(digest, Pull())
        except RegistryImageError as exc:
            raise RegistryError(str(exc)) from exc
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise RegistryError(
                f"homebrew served a bottle manifest that cannot be read: {exc}"
            ) from exc
        if hashlib.sha256(data).hexdigest() != digest.partition(":")[2]:
            raise RegistryError("a bottle's bytes do not match its digest")
        return PackageArchive(
            "homebrew",
            name,
            version,
            f"{name.replace('@', '-')}-{version}.bottle.tar.gz",
            data,
            OCI_TAG,
        )

    @classmethod
    def choose(cls, index: Any) -> dict[str, Any] | None:
        """The manifest of the first platform in `PLATFORMS` the index lists (each is named in the `org.opencontainers.image.ref.name`
        annotation as `<version>.<platform>`)."""
        listed = [
            m
            for m in index.get("manifests") or []
            if isinstance(m, dict) and isinstance(m.get("digest"), str)
        ]
        for platform in cls.PLATFORMS:
            for manifest in listed:
                label = str(
                    (manifest.get("annotations") or {}).get("org.opencontainers.image.ref.name")
                    or ""
                )
                if label.endswith("." + platform):
                    return manifest
        return None
