"""What a container image is and holds: the digests a registry and a runtime know it by, its names, layers and platform, its packages and the files it adds."""

from __future__ import annotations

import io
import re
import tarfile
from dataclasses import dataclass, field
from typing import Any, ClassVar

from cordon_scanner.foundation.formats.scanned_json import ScannedJson
from cordon_scanner.images import langpkgs
from cordon_scanner.images import packages as pkgdb
from cordon_scanner.images.members import ImageArchive


@dataclass
class ImageIdentity:
    """What the image is, from its archive: the digests a registry and a runtime know it by, the
    names it was saved under, its layers, its platform, and what its labels say it was built from."""

    image_id: str | None = None
    """The SHA-256 of the image's configuration: the ID `docker images` shows."""
    manifest_digest: str | None = None
    """The digest a registry serves it under -- what `image@sha256:...` pins. An OCI layout (and
    `docker save` from Docker 25) records it; an older `docker save` does not."""
    references: tuple[str, ...] = ()
    layers: tuple[str, ...] = ()
    """Each layer's uncompressed digest (`rootfs.diff_ids`), bottom first."""
    platform: str = ""
    created: str = ""
    base_name: str | None = None
    base_digest: str | None = None
    source: str | None = None
    revision: str | None = None

    DIGEST: ClassVar[re.Pattern[str]] = re.compile(r"^sha256:[0-9a-f]{64}$")

    def to_dict(self) -> dict[str, Any]:
        return {
            "image_id": self.image_id,
            "manifest_digest": self.manifest_digest,
            "references": list(self.references),
            "layers": list(self.layers),
            "platform": self.platform or None,
            "created": self.created or None,
            "base": {"name": self.base_name, "digest": self.base_digest}
            if self.base_name
            else None,
            "source": self.source,
            "revision": self.revision,
        }

    @staticmethod
    def _mapping(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _digest(value: Any) -> str | None:
        return value if isinstance(value, str) and ImageIdentity.DIGEST.match(value) else None

    @staticmethod
    def read(data: bytes) -> ImageIdentity:
        import hashlib

        identity = ImageIdentity()
        references: list[str] = []
        config_bytes: bytes | None = None
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            by_path = ImageArchive.members_by_path(archive)
            if "index.json" in by_path:
                index = ScannedJson.loads(ImageArchive.read_member(archive, by_path["index.json"]))
                descriptor: Any = (
                    (index.get("manifests") or [{}])[0] if isinstance(index, dict) else {}
                )
                identity.manifest_digest = ImageIdentity._digest(descriptor.get("digest"))
                annotations = (
                    descriptor.get("annotations")
                    if isinstance(descriptor.get("annotations"), dict)
                    else {}
                )
                for key in ("io.containerd.image.name", "org.opencontainers.image.ref.name"):
                    value = annotations.get(key)
                    if (
                        isinstance(value, str)
                        and value
                        and value not in references
                        and (key != "org.opencontainers.image.ref.name" or not references)
                    ):
                        references.append(value)
                # An index (several platforms) leads to the manifest of the first, which names the config.
                for _ in range(4):
                    algorithm, _, hexdigest = str(descriptor.get("digest", "")).partition(":")
                    blob = by_path.get(f"blobs/{algorithm}/{hexdigest}")
                    if blob is None:
                        break
                    document = ScannedJson.loads(ImageArchive.read_member(archive, blob))
                    if isinstance(document, dict) and isinstance(document.get("config"), dict):
                        algorithm, _, hexdigest = str(
                            document["config"].get("digest", "")
                        ).partition(":")
                        config_path = by_path.get(f"blobs/{algorithm}/{hexdigest}")
                        if config_path is not None:
                            config_bytes = ImageArchive.read_member(archive, config_path)
                        break
                    manifests = document.get("manifests") if isinstance(document, dict) else None
                    if not manifests:
                        break
                    descriptor = manifests[0]
            if "manifest.json" in by_path:
                manifest = ScannedJson.loads(
                    ImageArchive.read_member(archive, by_path["manifest.json"])
                )
                entry = (
                    manifest[0]
                    if isinstance(manifest, list) and manifest and isinstance(manifest[0], dict)
                    else {}
                )
                for tag in entry.get("RepoTags") or ():
                    if isinstance(tag, str) and tag not in references:
                        references.append(tag)
                config_path = by_path.get(ImageArchive.normalise(str(entry.get("Config", ""))))
                if config_bytes is None and config_path is not None:
                    config_bytes = ImageArchive.read_member(archive, config_path)
        identity.references = tuple(references)
        if config_bytes is None:
            return identity
        identity.image_id = f"sha256:{hashlib.sha256(config_bytes).hexdigest()}"
        config = ScannedJson.loads(config_bytes)
        if not isinstance(config, dict):
            return identity
        rootfs = ImageIdentity._mapping(config.get("rootfs"))
        identity.layers = tuple(
            d for d in (rootfs.get("diff_ids") or ()) if ImageIdentity._digest(d)
        )
        identity.platform = "/".join(
            str(config[k])
            for k in ("os", "architecture", "variant")
            if isinstance(config.get(k), str) and config[k]
        )
        identity.created = str(config.get("created") or "")
        labels = ImageIdentity._mapping(ImageIdentity._mapping(config.get("config")).get("Labels"))
        text = {k: v for k, v in labels.items() if isinstance(k, str) and isinstance(v, str) and v}
        identity.base_name = text.get("org.opencontainers.image.base.name")
        identity.base_digest = ImageIdentity._digest(
            text.get("org.opencontainers.image.base.digest")
        )
        identity.source = text.get("org.opencontainers.image.source")
        identity.revision = text.get("org.opencontainers.image.revision")
        return identity


@dataclass
class ImageInventory:
    identity: ImageIdentity = field(default_factory=ImageIdentity)
    platform: str = ""
    """The platform this inventory is of, for a multi-platform image."""
    other_platforms: list[ImageInventory] = field(default_factory=list)
    """A multi-platform image's other platforms, their operating-system packages inventoried too;
    the files are content-scanned on the first platform only."""
    release: pkgdb.OsRelease | None = None
    packages: list[pkgdb.OsPackage] = field(default_factory=list)
    language_packages: list[langpkgs.LanguagePackage] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    """Anything that stopped part of the image being read. Each makes the scan incomplete."""
    layers: int = 0
    owned: frozenset[str] = frozenset()
    """Paths the distribution's packages install; their content is the distribution's."""
    added_files: int = 0
    skipped: dict[str, int] = field(default_factory=dict)
    """Reason -> files not content-scanned for it."""
    binaries_as_strings: int = 0
    """Files past the per-file limit content-scanned as their printable strings."""
    as_strings: dict[str, bytes] = field(default_factory=dict)
    """Those files by path, each with its real first bytes (`HEAD_BYTES`). What is scanned under
    the path is the file's strings, so a rule about what the bytes ARE -- an ELF named `.png` --
    judges these instead: padding a disguised executable past the limit does not hide it."""
    removed_files: int = 0
    """Added files a later layer deleted or replaced: absent from the running container, still in
    the image's layers for anyone who pulls it."""


__all__ = ["ImageIdentity", "ImageInventory"]
