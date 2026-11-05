"""Facts a container registry gives about an image: where it lives, its manifests by platform, the
attestations and signatures referring to it, and its source repository.
"""

from __future__ import annotations

import json
import re
from typing import Any, Final

from cordon_scanner.intel.base import PackageFacts
from cordon_scanner.intel.registries.registry_http import RegistryHttp
from cordon_scanner.intel.registries.registry_request import PackageNotFound, RegistryError


class ImageRegistries:
    """Facts from container image registries."""

    MANIFEST_TYPES: Final = ", ".join(
        (
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        )
    )

    MAX_REFERRERS: Final = 8

    BUNDLE_TYPE: Final = "application/vnd.dev.sigstore.bundle"

    @staticmethod
    def _image_location(name: str) -> str:
        from cordon_scanner.ecosystems.infra.image import ImageReference, PublicRegistries

        reference = ImageReference.parse(name)
        if (
            reference is None
            or reference.tag
            or reference.digest
            or (reference.registry and not PublicRegistries.covers(reference.registry))
        ):
            raise RegistryError(f"{name} is not an image on a public registry")
        return f"https://{reference.registry or 'registry-1.docker.io'}/v2/{reference.repository}"

    @staticmethod
    def _image_referrers(base_url: str, digest: str) -> list[dict[str, Any]]:
        """The Sigstore bundles attached to a manifest: from the OCI referrers API, or the
        `sha256-<hex>` tag a registry without one holds them under (the OCI 1.1 fallback)."""
        index: Any = None
        try:
            index = RegistryHttp.oci(
                f"{base_url}/referrers/{digest}", "application/vnd.oci.image.index.v1+json"
            )
        except PackageNotFound:
            index = None
        if not RegistryHttp.entries(RegistryHttp.mapping(index).get("manifests")):
            try:
                index = RegistryHttp.oci(
                    f"{base_url}/manifests/{digest.replace(':', '-')}",
                    "application/vnd.oci.image.index.v1+json",
                )
            except PackageNotFound:
                return []
        return [
            entry
            for entry in RegistryHttp.entries(RegistryHttp.mapping(index).get("manifests"))
            if str(entry.get("artifactType", "")).startswith(ImageRegistries.BUNDLE_TYPE)
            and isinstance(entry.get("digest"), str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", entry["digest"])
        ][: ImageRegistries.MAX_REFERRERS]

    @staticmethod
    def _image_source(base_url: str, document: dict[str, Any]) -> str | None:
        """The repository an image says it was built from: `org.opencontainers.image.source`, in
        the manifest's annotations or the (first platform's) configuration's labels."""
        key = "org.opencontainers.image.source"
        stated = RegistryHttp.mapping(document.get("annotations")).get(key)
        if not isinstance(stated, str):
            manifest = document
            platforms = [
                entry
                for entry in RegistryHttp.entries(document.get("manifests"))
                if RegistryHttp.mapping(entry.get("platform")).get("os") not in (None, "unknown")
            ]
            if platforms and isinstance(platforms[0].get("digest"), str):
                manifest = RegistryHttp.mapping(
                    RegistryHttp.oci(
                        f"{base_url}/manifests/{platforms[0]['digest']}",
                        ImageRegistries.MANIFEST_TYPES,
                    )
                )
            config = RegistryHttp.mapping(manifest.get("config")).get("digest")
            if isinstance(config, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", config):
                document = RegistryHttp.mapping(
                    json.loads(ImageRegistries.oci_blob(base_url, config))
                )
                stated = RegistryHttp.mapping(
                    RegistryHttp.mapping(document.get("config")).get("Labels")
                ).get(key)
        return stated if isinstance(stated, str) and stated.startswith("https://") else None

    @staticmethod
    def oci_blob(base_url: str, digest: str) -> bytes:
        """A blob, which is content-addressed: refused unless its bytes hash to its digest."""
        import hashlib

        data = RegistryHttp.oci_bytes(f"{base_url}/blobs/{digest}", "*/*", follow=True)
        if f"sha256:{hashlib.sha256(data).hexdigest()}" != digest:
            raise RegistryError("a registry served a blob whose bytes do not match its digest")
        return data

    @staticmethod
    def image_attestations(name: str, version: str | None) -> dict[str, Any] | None:
        """The Sigstore bundles signed for the manifest a tag or digest names, for `intel.attest`
        to verify against the digest the project pinned."""
        if version is None:
            return None
        import hashlib

        base_url = ImageRegistries._image_location(name)
        if re.fullmatch(r"sha256:[0-9a-f]{64}", version):
            digest = version
        else:
            if not re.fullmatch(r"[\w][\w.-]{0,127}", version):
                return None
            digest = f"sha256:{hashlib.sha256(RegistryHttp.oci_bytes(f'{base_url}/manifests/{version}', ImageRegistries.MANIFEST_TYPES)).hexdigest()}"
        bundles: list[Any] = []
        for referrer in ImageRegistries._image_referrers(base_url, digest):
            manifest = RegistryHttp.mapping(
                RegistryHttp.oci(
                    f"{base_url}/manifests/{referrer['digest']}",
                    "application/vnd.oci.image.manifest.v1+json",
                )
            )
            for layer in RegistryHttp.entries(manifest.get("layers"))[:2]:
                if (
                    str(layer.get("mediaType", "")).startswith(ImageRegistries.BUNDLE_TYPE)
                    and isinstance(layer.get("digest"), str)
                    and re.fullmatch(r"sha256:[0-9a-f]{64}", layer["digest"])
                ):
                    bundle = json.loads(ImageRegistries.oci_blob(base_url, layer["digest"]))
                    if isinstance(bundle, dict):
                        bundles.append(bundle)
        return {"bundles": bundles} if bundles else None

    @staticmethod
    def image(name: str, version: str | None) -> PackageFacts:
        """An image on a public registry, through the OCI distribution API: its tags, and the
        digest of what a tag (or a digest) names -- the SHA-256 of the manifest as served, which is
        what `image@sha256:...` pins, and of each platform's manifest under an index, since a pin
        can name either."""
        base_url = ImageRegistries._image_location(name)
        if version is not None and not re.fullmatch(
            r"[\w][\w.-]{0,127}|sha256:[0-9a-f]{64}", version
        ):
            raise RegistryError(f"{version} is not a tag or a digest")
        listed = [
            str(t)
            for t in RegistryHttp.mapping(
                RegistryHttp.oci(f"{base_url}/tags/list?n=1000", "application/json")
            ).get("tags")
            or []
            if isinstance(t, str)
        ]
        digests: tuple[str, ...] = ()
        found = True
        source = None
        attested = False
        if version is not None:
            try:
                raw = RegistryHttp.oci_bytes(
                    f"{base_url}/manifests/{version}", ImageRegistries.MANIFEST_TYPES
                )
            except PackageNotFound:
                found = False
            else:
                import hashlib

                document = RegistryHttp.mapping(json.loads(raw))
                platforms = [
                    str(entry["digest"]).lower()
                    for entry in RegistryHttp.entries(document.get("manifests"))[
                        : RegistryHttp.MAX_PLATFORMS
                    ]
                    if isinstance(entry.get("digest"), str)
                    and re.fullmatch(r"sha256:[0-9a-fA-F]{64}", entry["digest"])
                ]
                digests = (f"sha256:{hashlib.sha256(raw).hexdigest()}", *platforms)
                # What the image says of itself, and whether anything is signed for it: asked
                # after the digest, and unknown -- not fatal -- when either cannot be read.
                try:
                    source = ImageRegistries._image_source(base_url, document)
                except (PackageNotFound, RegistryError, ValueError):
                    source = None
                try:
                    attested = bool(ImageRegistries._image_referrers(base_url, digests[0]))
                except (RegistryError, ValueError):
                    attested = False
        return PackageFacts(
            name=name,
            version=version,
            yanked=not found,
            yanked_reason=None
            if found
            else (
                "not a digest the registry holds"
                if version and version.startswith("sha256:")
                else "not a tag the registry holds"
            ),
            # No latest: an image's tags are not one release line -- alpine's `3.20` sits beside its
            # `20260805` snapshots, python's `3.12-slim` beside `3.13-alpine` -- so no tag is the
            # newer version of another, and a distance between them would be invented.
            latest=None,
            repository=source,
            digests=digests,
            releases=len(listed),
            attested=attested,
        )


__all__ = ["ImageRegistries"]
