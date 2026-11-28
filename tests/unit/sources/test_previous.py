"""The release a package is compared with (`--online`): the one before it on its own line, not the
latest published before it. `scan pkg:npm/express@4.21.2 --online` compared 4.21.2 with 5.0.1,
because 5.0.1 was published first: maintained release lines interleave in time."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.intel.base import PackageArchive
from cordon_scanner.intel.registries.archive_sources.base import ArchiveFetch
from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources
from cordon_scanner.intel.registries.record_sources.base import Release
from cordon_scanner.intel.registries.registry_client import RegistryClient, RegistryError
from cordon_scanner.intel.registries.registry_request import RegistryRequest
from cordon_scanner.sources.previous import (
    MAX_METADATA_BYTES,
    Identity,
    PreviousRelease,
)

BLOB = b"a release"
SHA512 = "sha512-" + base64.b64encode(hashlib.sha512(BLOB).digest()).decode()


class Registry:
    """Substitutes the documents a registry serves and the bytes of its archives."""

    @staticmethod
    def serve(monkeypatch: Any, documents: dict[str, dict[str, Any]]) -> list[str]:
        asked: list[str] = []

        def fetch(url: str, **_kwargs: Any) -> dict[str, Any]:
            asked.append(url)
            return documents[url]

        monkeypatch.setattr(RegistryClient, "_fetch", staticmethod(fetch))
        monkeypatch.setattr(
            RegistryRequest, "fetch_bytes", staticmethod(lambda url, allow, **k: BLOB)
        )
        return asked


class TestTheReleaseBefore:
    def test_npm_takes_the_release_before_on_its_own_line(self, tmp_path, monkeypatch) -> None:
        packument = {
            "name": "express",
            "time": {
                "4.21.1": "2024-10-08T00:00:00Z",
                "5.0.1": "2024-10-09T00:00:00Z",
                "4.21.2": "2024-12-05T00:00:00Z",
                "5.1.0": "2025-03-31T00:00:00Z",
            },
            "versions": {v: {} for v in ("4.21.1", "5.0.1", "4.21.2", "5.1.0")},
        }
        documents = {"https://registry.npmjs.org/express": packument}
        for v in packument["versions"]:
            documents[f"https://registry.npmjs.org/express/{v}"] = {
                "version": v,
                "dist": {
                    "tarball": f"https://registry.npmjs.org/express/-/express-{v}.tgz",
                    "integrity": SHA512,
                },
            }
        Registry.serve(monkeypatch, documents)

        found = PreviousRelease.fetch_previous(Identity("npm", "express", "4.21.2"), tmp_path)

        assert found is not None and found.label == "express 4.21.1"

    def test_pypi_takes_the_release_before_on_its_own_line(self, tmp_path, monkeypatch) -> None:
        def files(v: str, when: str) -> list[dict[str, Any]]:
            return [
                {
                    "upload_time_iso_8601": when,
                    "packagetype": "sdist",
                    "url": f"https://files.pythonhosted.org/demo-{v}.tar.gz",
                    "filename": f"demo-{v}.tar.gz",
                    "digests": {"sha256": hashlib.sha256(BLOB).hexdigest()},
                }
            ]

        releases = {
            "1.2.3": files("1.2.3", "2024-01-01T00:00:00Z"),
            "2.0.0": files("2.0.0", "2024-02-01T00:00:00Z"),
            "1.2.4": files("1.2.4", "2024-03-01T00:00:00Z"),
        }
        documents = {
            "https://pypi.org/pypi/demo/json": {"info": {"name": "demo"}, "releases": releases}
        }
        for v, found in releases.items():
            documents[f"https://pypi.org/pypi/demo/{v}/json"] = {"urls": found}
        Registry.serve(monkeypatch, documents)

        found = PreviousRelease.fetch_previous(Identity("pypi", "demo", "1.2.4"), tmp_path)

        assert found is not None and found.label == "demo 1.2.3"

    def test_an_archive_that_does_not_match_its_digest_is_an_error_not_a_comparison(
        self, tmp_path, monkeypatch
    ) -> None:
        import pytest

        packument = {
            "name": "demo",
            "time": {"1.0.0": "2024-01-01T00:00:00Z", "1.1.0": "2024-02-01T00:00:00Z"},
            "versions": {"1.0.0": {}, "1.1.0": {}},
        }
        documents = {"https://registry.npmjs.org/demo": packument}
        for v in ("1.0.0", "1.1.0"):
            documents[f"https://registry.npmjs.org/demo/{v}"] = {
                "version": v,
                "dist": {
                    "tarball": f"https://registry.npmjs.org/demo/-/demo-{v}.tgz",
                    "integrity": "sha512-" + base64.b64encode(b"x" * 64).decode(),
                },
            }
        Registry.serve(monkeypatch, documents)
        with pytest.raises(ValueError, match="does not match"):
            PreviousRelease.fetch_previous(Identity("npm", "demo", "1.1.0"), tmp_path)


class _Kit_tarball:
    @staticmethod
    def tarball(path: Path, members: dict[str, bytes]) -> Path:
        with tarfile.open(path, "w:gz") as archive:
            for name, body in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
        return path


tarball = _Kit_tarball.tarball


class TestIdentify:
    """A package says what it is in its own metadata, not in the name it was given."""

    def test_an_npm_tarball_names_itself_in_package_json(self, tmp_path: Path) -> None:
        body = json.dumps({"name": "demo", "version": "1.2.3"}).encode()
        found = PreviousRelease.identify(
            tarball(tmp_path / "x.tgz", {"package/package.json": body})
        )
        assert found == Identity("npm", "demo", "1.2.3")

    def test_a_package_json_without_a_version_is_not_an_identity(self, tmp_path: Path) -> None:
        body = json.dumps({"name": "demo"}).encode()
        assert (
            PreviousRelease.identify(tarball(tmp_path / "x.tgz", {"package/package.json": body}))
            is None
        )

    def test_a_nested_package_json_is_not_the_package(self, tmp_path: Path) -> None:
        body = json.dumps({"name": "inner", "version": "9"}).encode()
        members = {"package/node_modules/inner/package.json": body}
        assert PreviousRelease.identify(tarball(tmp_path / "x.tar.gz", members)) is None

    def test_an_sdist_names_itself_in_pkg_info(self, tmp_path: Path) -> None:
        info = b"Metadata-Version: 2.1\nName: demo\nVersion: 4.5.6\n"
        found = PreviousRelease.identify(
            tarball(tmp_path / "demo.tar.gz", {"demo-4.5.6/PKG-INFO": info})
        )
        assert found == Identity("pypi", "demo", "4.5.6")

    def test_a_pkg_info_without_a_version_is_not_an_identity(self, tmp_path: Path) -> None:
        info = b"Name: demo\n"
        assert (
            PreviousRelease.identify(tarball(tmp_path / "d.tgz", {"demo/PKG-INFO": info})) is None
        )

    def test_a_wheel_names_itself_in_metadata(self, tmp_path: Path) -> None:
        wheel = tmp_path / "demo-1.0-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("demo-1.0.dist-info/METADATA", "Name: demo\nVersion: 1.0\n")
        assert PreviousRelease.identify(wheel) == Identity("pypi", "demo", "1.0")

    def test_metadata_over_the_cap_is_not_read(self, tmp_path: Path) -> None:
        wheel = tmp_path / "big.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr(
                "demo-1.0.dist-info/METADATA",
                "Name: demo\nVersion: 1.0\n" + "x" * MAX_METADATA_BYTES,
            )
        assert PreviousRelease.identify(wheel) is None
        big = tarball(tmp_path / "b.tgz", {"package/package.json": b" " * (MAX_METADATA_BYTES + 1)})
        assert PreviousRelease.identify(big) is None

    @pytest.mark.parametrize("name", ["broken.tgz", "broken.whl"])
    def test_a_damaged_archive_is_not_an_identity(self, tmp_path: Path, name: str) -> None:
        path = tmp_path / name
        path.write_bytes(b"not an archive")
        assert PreviousRelease.identify(path) is None

    def test_another_kind_of_file_is_not_an_identity(self, tmp_path: Path) -> None:
        path = tmp_path / "demo.zip"
        path.write_bytes(b"PK")
        assert PreviousRelease.identify(path) is None


class TestFetchPreviousAccounts:
    def stub(
        self,
        monkeypatch: pytest.MonkeyPatch,
        *,
        before: Release | None,
        now: str,
        strength: str = "",
    ) -> None:
        when = datetime(2024, 1, 1, tzinfo=UTC)
        monkeypatch.setattr(
            ArchiveFetch, "previous_release", classmethod(lambda cls, e, n, v: before)
        )
        monkeypatch.setattr(
            ArchiveFetch,
            "releases",
            staticmethod(lambda e, n, v: [Release("2.0.0", when, now), Release("0.5", when, "z")]),
        )
        monkeypatch.setattr(
            ArchiveSources,
            "package_archive",
            classmethod(
                lambda cls, e, n, v: PackageArchive(
                    "npm", n, v, "demo-1.0.0.tgz", b"data", strength
                )
            ),
        )

    def test_no_earlier_release_means_nothing_to_compare(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.stub(monkeypatch, before=None, now="a")
        assert PreviousRelease.fetch_previous(Identity("npm", "demo", "2.0.0"), tmp_path) is None

    def test_a_new_publisher_is_named_beside_the_old_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        before = Release("1.0.0", datetime(2023, 1, 1, tzinfo=UTC), "alice")
        self.stub(monkeypatch, before=before, now="mallory", strength="md5")
        found = PreviousRelease.fetch_previous(Identity("npm", "demo", "2.0.0"), tmp_path)
        assert found is not None
        assert found.label == "demo 1.0.0 (checked by md5 only)"
        assert found.publisher_change == "demo 2.0.0 was published by `mallory`; 1.0.0 by `alice`."
        assert found.path.read_bytes() == b"data"
        assert found.path.parent == tmp_path

    def test_the_same_publisher_is_no_change(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        before = Release("1.0.0", datetime(2023, 1, 1, tzinfo=UTC), "alice")
        self.stub(monkeypatch, before=before, now="alice")
        found = PreviousRelease.fetch_previous(Identity("npm", "demo", "2.0.0"), tmp_path)
        assert found is not None and found.publisher_change == ""

    def test_a_registry_failure_is_a_value_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fail(cls: Any, e: str, n: str, v: str) -> Release:
            raise RegistryError("registry is down")

        monkeypatch.setattr(ArchiveFetch, "previous_release", classmethod(fail))
        with pytest.raises(ValueError, match="registry is down"):
            PreviousRelease.fetch_previous(Identity("npm", "demo", "2.0.0"), tmp_path)


class TestSupportedAndWorkspace:
    def test_npm_and_pypi_are_supported(self) -> None:
        assert {"npm", "pypi"} <= PreviousRelease.supported()

    def test_the_workspace_is_removed_on_exit(self) -> None:
        with PreviousRelease.workspace() as directory:
            (directory / "f").write_bytes(b"x")
            assert directory.is_dir()
        assert not directory.exists()
