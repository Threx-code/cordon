"""What an image archive says it is (`images/identity`), and how its members are read (`images/members`)."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from typing import Any

import pytest

from cordon_scanner.images.identity import ImageIdentity
from cordon_scanner.images.members import ImageArchive


class _Kit_archive:
    @staticmethod
    def archive(members: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tar:
            for name, body in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(body)
                tar.addfile(info, io.BytesIO(body))
        return buffer.getvalue()


archive = _Kit_archive.archive


class _Kit_sha:
    @staticmethod
    def sha(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


sha = _Kit_sha.sha


class _Kit_blob:
    @staticmethod
    def blob(data: bytes) -> tuple[str, bytes]:
        return f"blobs/sha256/{sha(data)}", data


blob = _Kit_blob.blob


class TestOciLayouts:
    def test_the_manifest_leads_to_the_config_and_its_layers(self) -> None:
        diff = "sha256:" + "d" * 64
        config = json.dumps({"rootfs": {"diff_ids": [diff, "not a digest"]}}).encode()
        manifest = json.dumps(
            {"config": {"digest": f"sha256:{sha(config)}"}, "layers": []}
        ).encode()
        index = json.dumps(
            {
                "manifests": [
                    {
                        "digest": f"sha256:{sha(manifest)}",
                        "annotations": {
                            "io.containerd.image.name": "docker.io/library/app:1",
                            "org.opencontainers.image.ref.name": "ignored-after-the-first",
                        },
                    }
                ]
            }
        ).encode()
        members = dict([blob(config), blob(manifest)])
        members["index.json"] = index
        identity = ImageIdentity.read(archive(members))
        assert identity.image_id == f"sha256:{sha(config)}"
        assert identity.manifest_digest == f"sha256:{sha(manifest)}"
        assert identity.references == ("docker.io/library/app:1",)
        assert identity.layers == (diff,)

    def test_an_index_of_platforms_leads_to_the_first_manifest(self) -> None:
        config = json.dumps({"rootfs": {"diff_ids": []}}).encode()
        manifest = json.dumps({"config": {"digest": f"sha256:{sha(config)}"}}).encode()
        inner = json.dumps({"manifests": [{"digest": f"sha256:{sha(manifest)}"}]}).encode()
        index = json.dumps({"manifests": [{"digest": f"sha256:{sha(inner)}"}]}).encode()
        members = dict([blob(config), blob(manifest), blob(inner)])
        members["index.json"] = index
        assert ImageIdentity.read(archive(members)).image_id == f"sha256:{sha(config)}"

    def test_a_manifest_that_is_not_in_the_archive_leaves_the_image_unidentified(self) -> None:
        index = json.dumps({"manifests": [{"digest": "sha256:" + "a" * 64}]}).encode()
        identity = ImageIdentity.read(archive({"index.json": index}))
        assert identity.manifest_digest == "sha256:" + "a" * 64
        assert identity.image_id is None and identity.layers == ()

    def test_an_index_that_names_no_manifests_stops_there(self) -> None:
        empty = json.dumps({"manifests": []}).encode()
        index = json.dumps({"manifests": [{"digest": f"sha256:{sha(empty)}"}]}).encode()
        members = dict([blob(empty)])
        members["index.json"] = index
        assert ImageIdentity.read(archive(members)).image_id is None

    def test_a_config_that_is_not_an_object_has_an_id_and_nothing_else(self) -> None:
        config = b"[1, 2, 3]"
        manifest = json.dumps({"config": {"digest": f"sha256:{sha(config)}"}}).encode()
        index = json.dumps({"manifests": [{"digest": f"sha256:{sha(manifest)}"}]}).encode()
        members = dict([blob(config), blob(manifest)])
        members["index.json"] = index
        identity = ImageIdentity.read(archive(members))
        assert identity.image_id == f"sha256:{sha(config)}"
        assert identity.layers == () and identity.created == ""


class TestDockerSave:
    def test_repo_tags_and_the_config_are_read(self) -> None:
        config = json.dumps({"rootfs": {"diff_ids": ["sha256:" + "e" * 64]}}).encode()
        manifest = json.dumps([{"Config": "cfg.json", "RepoTags": ["app:1", "app:1", 5]}]).encode()
        identity = ImageIdentity.read(archive({"manifest.json": manifest, "cfg.json": config}))
        assert identity.references == ("app:1",)
        assert identity.layers == ("sha256:" + "e" * 64,)
        assert identity.manifest_digest is None


class TestMembers:
    def open(self, members: dict[str, bytes]) -> tarfile.TarFile:
        return tarfile.open(fileobj=io.BytesIO(archive(members)), mode="r:")

    def test_names_are_the_images_own_paths(self) -> None:
        with self.open({"./a/../b.txt": b"x", "/c": b"y"}) as tar:
            assert sorted(ImageArchive.members_by_path(tar)) == ["b.txt", "c"]

    def test_a_member_is_read_within_its_limit(self) -> None:
        with self.open({"f": b"hello"}) as tar:
            assert ImageArchive.read_member(tar, "f") == b"hello"
            with pytest.raises(ValueError, match="not a readable file within limits"):
                ImageArchive.read_member(tar, "f", limit=4)

    def test_a_directory_is_not_a_readable_file(self) -> None:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tar:
            info = tarfile.TarInfo("d")
            info.type = tarfile.DIRTYPE
            tar.addfile(info)
        with (
            tarfile.open(fileobj=io.BytesIO(buffer.getvalue())) as tar,
            pytest.raises(ValueError, match="not a readable file"),
        ):
            ImageArchive.read_member(tar, "d")

    def test_a_member_the_archive_cannot_open_is_reported(self) -> None:
        class Unopenable:
            def getmember(self, name: str) -> Any:
                return tarfile.TarInfo(name)

            def extractfile(self, member: Any) -> None:
                return None

        with pytest.raises(ValueError, match="could not be opened"):
            ImageArchive.read_member(Unopenable(), "f")  # type: ignore[arg-type]
