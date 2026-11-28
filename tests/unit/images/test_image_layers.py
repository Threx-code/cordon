"""Reading an image tarball's layers (`images/oci`): which image of several is read, what is refused,
what is reported unread, and what the image adds beyond its distribution's packages."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
import types
from typing import Any, ClassVar

import pytest

from cordon_scanner.images import binmeta, oci
from cordon_scanner.images.identity import ImageInventory
from cordon_scanner.images.oci import ImageConfig, ImageLayers, Peek, PrefixedReader
from kits.imagekit import DEBIAN_RELEASE, ImageKit

BASE_FILES: dict[str, bytes | None] = {
    "etc/os-release": DEBIAN_RELEASE,
    "var/lib/dpkg/status": b"",
}


class _Kit_tar:
    @staticmethod
    def tar(entries: list[tuple[str, bytes, bytes | None]]) -> bytes:
        """A tar of `(name, data, type)` entries; type None is a regular file, `b"5"` a directory."""
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name, data, kind in entries:
                info = tarfile.TarInfo(name)
                if kind is not None:
                    info.type = kind
                else:
                    info.size = len(data)
                archive.addfile(info, io.BytesIO(data) if kind is None else None)
        return buffer.getvalue()


tar = _Kit_tar.tar


class _Kit_sha:
    @staticmethod
    def sha(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


sha = _Kit_sha.sha


class _Kit_oci_with_config:
    @staticmethod
    def oci_with_config(layers: list[bytes], config: dict[str, Any], *, depth: int = 1) -> bytes:
        """An OCI layout whose manifest names a configuration, `depth` indexes below the top index."""
        blobs: dict[str, bytes] = {}

        def blob(data: bytes) -> str:
            blobs[sha(data)] = data
            return f"sha256:{sha(data)}"

        manifest = {
            "layers": [{"digest": blob(data)} for data in layers],
            "config": {"digest": blob(json.dumps(config).encode())},
        }
        top: dict[str, Any] = {"digest": blob(json.dumps(manifest).encode())}
        for _ in range(depth - 1):
            top = {"digest": blob(json.dumps({"manifests": [top]}).encode())}
        index = json.dumps({"manifests": [top]}).encode()
        entries = [("oci-layout", b"{}", None), ("index.json", index, None)]
        entries += [(f"blobs/sha256/{d}", data, None) for d, data in blobs.items()]
        return tar(entries)


oci_with_config = _Kit_oci_with_config.oci_with_config


class TestPlatformsOfAnImage:
    def test_a_docker_save_has_one_platform(self) -> None:
        assert ImageLayers.platforms(ImageKit.docker_save([ImageKit.layer(BASE_FILES)])) == []

    def test_an_index_of_several_images_lists_them(self) -> None:
        data = ImageKit.oci_multi_platform(
            {"linux/amd64": [ImageKit.layer(BASE_FILES)], "linux/arm64/v8": [ImageKit.layer({})]}
        )
        assert [label for _, label in ImageLayers.platforms(data)] == [
            "linux/amd64",
            "linux/arm64/v8",
        ]

    def test_a_single_manifest_is_not_a_choice(self) -> None:
        assert ImageLayers.platforms(ImageKit.oci_layout([ImageKit.layer(BASE_FILES)])) == []

    def test_only_attestations_beside_one_image_is_not_a_choice(self) -> None:
        data = ImageKit.oci_multi_platform({"linux/amd64": [ImageKit.layer(BASE_FILES)]})
        assert ImageLayers.platforms(data) == []

    def test_an_index_whose_manifest_is_missing_names_no_platforms(self) -> None:
        index = json.dumps({"manifests": [{"digest": "sha256:" + "a" * 64}]}).encode()
        assert ImageLayers.platforms(tar([("index.json", index, None)])) == []

    def test_an_index_nested_past_four_levels_names_no_platforms(self) -> None:
        data = oci_with_config([ImageKit.layer({})], {}, depth=7)
        assert ImageLayers.platforms(data) == []

    def test_an_archive_that_is_not_readable_names_no_platforms(self) -> None:
        assert ImageLayers.platforms(b"not a tar at all") == []
        assert ImageLayers.platforms(tar([("index.json", b"{broken", None)])) == []


class TestWhichImageIsRead:
    def test_a_tarball_of_two_images_reads_the_first_and_says_so(self) -> None:
        first = ImageKit.layer({**BASE_FILES, "app/one": b"1"})
        names = f"{sha(first)}/layer.tar"
        manifest = json.dumps(
            [{"Config": "c.json", "Layers": [names]}, {"Config": "c.json", "Layers": []}]
        ).encode()
        data = tar(
            [("manifest.json", manifest, None), ("c.json", b"{}", None), (names, first, None)]
        )
        _, inventory = ImageLayers.squash(data)
        assert inventory.layers == 1
        assert "the tarball holds 2 images; only the first was inventoried" in inventory.problems

    def test_a_platform_that_is_not_in_the_index_is_refused(self) -> None:
        data = ImageKit.oci_multi_platform(
            {"linux/amd64": [ImageKit.layer(BASE_FILES)], "linux/arm64": [ImageKit.layer({})]}
        )
        with pytest.raises(ValueError, match="no manifest 9"):
            ImageLayers.squash(data, platform=9)

    def test_the_named_platform_is_the_one_read(self) -> None:
        data = ImageKit.oci_multi_platform(
            {
                "linux/amd64": [ImageKit.layer({"etc/os-release": b"ID=debian\nVERSION_ID=12\n"})],
                "linux/arm64": [
                    ImageKit.layer({"etc/os-release": b"ID=alpine\nVERSION_ID=3.18\n"})
                ],
            }
        )
        files, _ = ImageLayers.squash(data, platform=1)
        assert files["etc/os-release"].startswith(b"ID=alpine")

    def test_an_index_that_leads_nowhere_names_no_image(self) -> None:
        empty = json.dumps({"manifests": []}).encode()
        index = json.dumps({"manifests": [{"digest": f"sha256:{sha(empty)}"}]}).encode()
        data = tar([("index.json", index, None), (f"blobs/sha256/{sha(empty)}", empty, None)])
        with pytest.raises(ValueError, match="names no image manifest"):
            ImageLayers.squash(data)


class TestLayersThatCannotBeRead:
    def test_more_layers_than_the_reader_takes_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(oci, "MAX_LAYERS", 1)
        data = ImageKit.docker_save([ImageKit.layer({"a": b"1"}), ImageKit.layer({"b": b"2"})])
        with pytest.raises(ValueError, match="more than 1 layers"):
            ImageLayers.squash(data)

    def test_a_layer_that_is_not_a_file_is_reported_unopenable(self) -> None:
        manifest = json.dumps([{"Config": "c.json", "Layers": ["dir"]}]).encode()
        data = tar([("manifest.json", manifest, None), ("c.json", b"{}", None), ("dir", b"", b"5")])
        _, inventory = ImageLayers.squash(data)
        assert inventory.problems == ["layer dir could not be opened"]

    def test_a_layer_with_more_members_than_the_reader_walks_is_reported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(oci, "MAX_MEMBERS_PER_LAYER", 1)
        data = ImageKit.docker_save([ImageKit.layer({"a": b"1", "b": b"2"})])
        _, inventory = ImageLayers.squash(data)
        assert any("has more members than the reader walks" in p for p in inventory.problems)

    def test_files_past_the_budget_stop_the_read_and_say_where(self) -> None:
        data = ImageKit.docker_save([ImageKit.layer({"var/lib/dpkg/status": b"x" * 100})])
        inventory = ImageInventory()
        files = ImageLayers._squash(data, lambda path, size: True, 10, inventory, count_layers=True)
        assert files == {}
        assert inventory.problems == [
            "the image's files are larger than the reader keeps; the files after that point were not examined"
        ]

    def test_a_replaced_file_costs_only_the_difference(self) -> None:
        data = ImageKit.docker_save(
            [ImageKit.layer({"f": b"x" * 8}), ImageKit.layer({"f": b"y" * 9})]
        )
        inventory = ImageInventory()
        files = ImageLayers._squash(data, lambda p, s: True, 9, inventory, count_layers=True)
        assert files == {"f": b"y" * 9} and inventory.problems == []

    def test_a_directory_in_a_later_layer_removes_the_file_it_replaces(self) -> None:
        first = ImageKit.layer({"gone": b"1", "kept": b"2"})
        second = tar([("gone", b"", b"5")])
        data = ImageKit.docker_save([first, second])
        inventory = ImageInventory()
        files = ImageLayers._squash(data, lambda p, s: True, 1 << 20, inventory, count_layers=True)
        assert files == {"kept": b"2"}


class TestImageIdentityProblems:
    def test_a_configuration_that_is_not_json_is_reported_beside_the_inventory(self) -> None:
        layer = ImageKit.layer(BASE_FILES)
        names = f"{sha(layer)}/layer.tar"
        manifest = json.dumps([{"Config": "c.json", "Layers": [names]}]).encode()
        data = tar(
            [("manifest.json", manifest, None), ("c.json", b"{broken", None), (names, layer, None)]
        )
        inventory = ImageLayers.read_image(data)
        assert any(
            p.startswith("the image's manifest and configuration were not read")
            for p in inventory.problems
        )
        assert inventory.release is not None


class TestDatabasesThatDoNotRead:
    def test_a_damaged_rpm_sqlite_database_is_reported_by_path(self) -> None:
        layer = ImageKit.layer(
            {"etc/os-release": b"ID=rocky\n", "var/lib/rpm/rpmdb.sqlite": b"junk"}
        )
        inventory = ImageLayers.read_image(ImageKit.docker_save([layer]))
        assert inventory.problems == [
            "the RPM database at var/lib/rpm/rpmdb.sqlite was not read (DatabaseError)"
        ]
        assert inventory.packages == []

    def test_apt_and_apk_say_which_packages_were_asked_for(self) -> None:
        from kits.imagekit import ImageKit as Kit

        status = (
            Kit.dpkg_stanza("curl", "8.0") + "\n" + Kit.dpkg_stanza("libcurl4", "8.0")
        ).encode()
        layer = ImageKit.layer(
            {
                **BASE_FILES,
                "var/lib/dpkg/status": status,
                "var/lib/apt/extended_states": b"Package: libcurl4\nAuto-Installed: 1\n\n",
            }
        )
        inventory = ImageLayers.read_image(ImageKit.docker_save([layer]))
        assert {p.name: p.requested for p in inventory.packages} == {
            "curl": True,
            "libcurl4": False,
        }


class TestZstdLayers:
    """Python 3.14 reads zstd itself; here its module is replaced by one that records how it is used."""

    def test_the_standard_librarys_error_is_raised_as_the_cores(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.intel.store.zstd import ZstdError

        class Refused(Exception):
            pass

        closed: list[bool] = []

        class ZstdFile(io.RawIOBase):
            def __init__(self, raw: Any) -> None:
                super().__init__()
                self.raw = raw

            def readinto(self, buffer: Any) -> int:
                raise Refused("frame is damaged")

            def close(self) -> None:
                closed.append(True)

        module = types.ModuleType("compression.zstd")
        module.ZstdFile = ZstdFile  # type: ignore[attr-defined]
        module.ZstdError = Refused  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "compression", types.ModuleType("compression"))
        monkeypatch.setitem(sys.modules, "compression.zstd", module)
        reader = ImageLayers._zstd_reader(io.BytesIO(b"\x28\xb5\x2f\xfd"))
        assert reader.readable()
        with pytest.raises(ZstdError, match="frame is damaged"):
            reader.read(10)
        reader.close()
        assert closed == [True]


class TestAddedFiles:
    def added(self, data: bytes, **limits: Any) -> tuple[dict[str, bytes], ImageInventory]:
        inventory = ImageLayers.read_image(data)
        found = dict(
            ImageLayers.added_files(
                data,
                inventory,
                max_file_bytes=limits.pop("max_file_bytes", 1 << 20),
                max_total_bytes=limits.pop("max_total_bytes", 1 << 26),
            )
        )
        return found, inventory

    def test_a_file_past_the_peek_limit_is_skipped_and_counted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(oci, "MAX_PEEK_BYTES", 100)
        data = ImageKit.docker_save([ImageKit.layer({**BASE_FILES, "app/huge.bin": b"x" * 500})])
        found, inventory = self.added(data, max_file_bytes=50)
        assert "app/huge.bin" not in found
        assert inventory.skipped[oci.OVERSIZE] == 1

    def test_a_large_file_is_streamed_when_it_is_past_the_hold_limit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(oci, "MAX_HELD_BYTES", 100)
        text = b"\x00connection-string https://cfg.example.invalid/stream\x00"
        data = ImageKit.docker_save(
            [ImageKit.layer({**BASE_FILES, "app/big.bin": b"\x00" * 200 + text + b"\x00" * 200})]
        )
        found, inventory = self.added(data, max_file_bytes=50)
        assert b"https://cfg.example.invalid/stream" in found["app/big.bin"]
        assert "app/big.bin" in inventory.as_strings
        assert inventory.as_strings["app/big.bin"].startswith(b"\x00\x00")

    def test_a_streamed_jar_names_the_artifacts_it_holds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import zipfile

        monkeypatch.setattr(oci, "MAX_HELD_BYTES", 100)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(
                "META-INF/maven/org.example/lib/pom.properties",
                "groupId=org.example\nartifactId=lib\nversion=1.2.3\n",
            )
            archive.writestr("pad", b"x" * 400)
        data = ImageKit.docker_save(
            [ImageKit.layer({**BASE_FILES, "app/uber.jar": buffer.getvalue()})]
        )
        _, inventory = self.added(data, max_file_bytes=50)
        assert ("maven", "org.example:lib", "1.2.3") in {
            (p.ecosystem, p.name, p.version) for p in inventory.language_packages
        }

    def test_text_past_the_strings_budget_is_said_to_be_cut_short(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(binmeta, "MAX_STRINGS_TOTAL", 16)
        blob = b"\x00".join(f"printable-string-number-{n}".encode() for n in range(40))
        without = ImageKit.docker_save([ImageKit.layer({**BASE_FILES})])
        _, plain = self.added(without, max_file_bytes=64)
        data = ImageKit.docker_save(
            [ImageKit.layer({**BASE_FILES, "app/blob.bin": blob + b"\x00" * 600})]
        )
        _, inventory = self.added(data, max_file_bytes=64)
        assert (
            inventory.skipped[oci.OVERSIZE_STRINGS]
            == plain.skipped.get(oci.OVERSIZE_STRINGS, 0) + 1
        )

    def test_a_go_toolchains_own_programs_are_read_for_their_modules(self) -> None:
        data = ImageKit.docker_save(
            [
                ImageKit.layer(
                    {
                        **BASE_FILES,
                        "usr/local/go/bin/gofmt": ImageKit.go_binary(
                            "dep\tgolang.org/x/net\tv0.17.0\th1:a=\n"
                        ),
                    }
                )
            ]
        )
        found, inventory = self.added(data)
        assert "usr/local/go/bin/gofmt" not in found
        assert ("gomod", "golang.org/x/net", "0.17.0") in {
            (p.ecosystem, p.name, p.version) for p in inventory.language_packages
        }

    def test_package_metadata_outside_the_skipped_trees_is_inventoried_and_scanned(self) -> None:
        data = ImageKit.docker_save(
            [
                ImageKit.layer(
                    {
                        **BASE_FILES,
                        "srv/app/package.json": b'{"name": "my-app", "version": "2.0.0"}',
                    }
                )
            ]
        )
        found, inventory = self.added(data)
        assert "srv/app/package.json" in found
        assert ("npm", "my-app", "2.0.0") in {
            (p.ecosystem, p.name, p.version) for p in inventory.language_packages
        }

    def test_a_distribution_installed_jar_is_read_for_what_it_records(self) -> None:
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(
                "META-INF/maven/org.example/lib/pom.properties",
                "groupId=org.example\nartifactId=lib\nversion=2.0\n",
            )
        status = ImageKit.dpkg_stanza("libexample-java", "2.0").encode()
        layer = ImageKit.layer(
            {
                **BASE_FILES,
                "var/lib/dpkg/status": status,
                "var/lib/dpkg/info/libexample-java.list": b"/usr/share/java/lib.jar\n",
                "usr/share/java/lib.jar": buffer.getvalue(),
            }
        )
        found, inventory = self.added(ImageKit.docker_save([layer]))
        assert "usr/share/java/lib.jar" not in found
        assert ("maven", "org.example:lib", "2.0") in {
            (p.ecosystem, p.name, p.version) for p in inventory.language_packages
        }

    def test_what_a_later_layer_removed_is_reported_once_under_its_layer(self) -> None:
        def entries(*payloads: bytes) -> bytes:
            return tar([("app/secret.txt", p, None) for p in payloads])

        layer = entries(b"A" * 8, b"B" * 8, b"A" * 8, b"B" * 8)
        data = ImageKit.docker_save([ImageKit.layer(BASE_FILES), layer])
        found, inventory = self.added(data)
        removed = sorted(p for p in found if p.startswith("layer-2-removed/"))
        assert removed == ["layer-2-removed/app/secret.txt"]
        assert inventory.removed_files == 2

    def test_a_removed_file_in_a_skipped_tree_is_not_reported(self) -> None:
        first = ImageKit.layer({"usr/local/go/VERSION": b"go1.21"})
        second = ImageKit.layer({"usr/local/go/VERSION": None})
        found, inventory = self.added(
            ImageKit.docker_save([ImageKit.layer(BASE_FILES), first, second])
        )
        assert not any(p.startswith("layer-") for p in found)
        assert inventory.removed_files == 0


class TestPrefixedReader:
    def test_the_first_bytes_are_given_back_before_the_rest(self) -> None:
        stream = io.BytesIO(b"cdef")
        reader = PrefixedReader(b"ab", stream)
        assert reader.read(1) == b"a"
        assert reader.read(3) == b"bcd"
        assert reader.read(10) == b"ef"
        assert reader.read(1) == b""

    def test_a_read_of_everything_joins_the_two(self) -> None:
        assert PrefixedReader(b"ab", io.BytesIO(b"cd")).read() == b"abcd"
        assert PrefixedReader(b"", io.BytesIO(b"cd")).read(1) == b"c"


class TestPeekStreams:
    def test_a_jar_is_walked_and_a_binary_is_read_for_its_strings(self) -> None:
        peek = Peek(10)
        data = b"\x7fELF" + b"\x00" * 20 + b"a-long-printable-string-here" + b"\x00" * 20
        peek.stream("bin/app", io.BytesIO(data), len(data))
        assert any(b"a-long-printable-string-here" in part for _, part in peek.files())
        assert peek.heads["bin/app"][:4] == b"\x7fELF"


class TestTheImageConfiguration:
    CONFIG: ClassVar[dict[str, Any]] = {
        "config": {
            "Env": ["TOKEN=abc", "NOEQUALS", 5],
            "Labels": {"b": "2", "a": "1"},
            "Entrypoint": ["/start", 1],
            "Cmd": ["--serve"],
            "WorkingDir": "/srv",
            "Healthcheck": {"Test": ["CMD", "curl", "-f", "http://x"]},
        },
        "history": [{"created_by": "RUN make"}, {"created_by": 5}, "x"],
    }

    def test_environment_labels_and_build_history_are_rendered_as_files(self) -> None:
        data = ImageKit.docker_save([ImageKit.layer({})], self.CONFIG)
        files = dict(ImageConfig.files(data))
        assert files["image-config/environment.env"] == b"TOKEN=abc\nLABEL_a=1\nLABEL_b=2\n"
        assert files["image-config/history.txt"].decode().splitlines() == [
            "ENTRYPOINT /start 1",
            "CMD --serve",
            "WORKDIR /srv",
            "HEALTHCHECK CMD curl -f http://x",
            "RUN make",
        ]

    def test_an_oci_layout_is_read_through_its_nested_indexes(self) -> None:
        data = oci_with_config([ImageKit.layer({})], self.CONFIG, depth=3)
        assert "image-config/environment.env" in dict(ImageConfig.files(data))

    def test_a_manifest_without_a_config_has_none(self) -> None:
        data = ImageKit.docker_save([ImageKit.layer({})], {})
        assert ImageConfig.files(data) == []

    def test_an_archive_that_cannot_be_read_has_none(self) -> None:
        assert ImageConfig.files(tar([("manifest.json", b"{broken", None)])) == []

    def test_an_index_that_leads_nowhere_has_none(self) -> None:
        empty = json.dumps({"manifests": []}).encode()
        index = json.dumps({"manifests": [{"digest": f"sha256:{sha(empty)}"}]}).encode()
        data = tar([("index.json", index, None), (f"blobs/sha256/{sha(empty)}", empty, None)])
        assert ImageConfig.files(data) == []
