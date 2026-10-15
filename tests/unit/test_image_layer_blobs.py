"""Image layer blobs that are not filesystems, and zstd layers without Python 3.14 (review 98)."""

from __future__ import annotations

import io
import json
import tarfile

from cordon_scanner.images.oci import ImageLayers


class Kit:
    @staticmethod
    def image(layers: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            manifest = [{"Config": "config.json", "RepoTags": ["x:1"], "Layers": list(layers)}]
            for name, data in {
                **layers,
                "manifest.json": json.dumps(manifest).encode(),
                "config.json": b'{"architecture":"amd64","os":"linux","rootfs":{"type":"layers"}}',
            }.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    @staticmethod
    def layer(files: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()


class TestArtifactBlobs:
    def test_a_json_blob_is_not_an_unread_layer(self) -> None:
        image = Kit.image(
            {
                "a.tar": Kit.layer({"etc/os-release": b"ID=debian\nVERSION_ID=12\n"}),
                "b.tar.gz": b'{\n  "$schema": "https://example.invalid/attestation"\n}\n',
            }
        )
        _, inventory = ImageLayers.squash(image)
        assert not [p for p in inventory.problems if "was not read" in p]

    def test_a_broken_tar_is_still_reported(self) -> None:
        broken = Kit.layer({"etc/os-release": b"ID=debian\n"})[:700]
        image = Kit.image({"a.tar": broken})
        _, inventory = ImageLayers.squash(image)
        assert [p for p in inventory.problems if "was not read" in p]
