"""How a declared dependency is resolved to a release and read from an archive (`cli/dependency_payload.py`)."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from cordon_scanner.cli import dependency_payload
from cordon_scanner.cli.dependency_payload import DependencyPayload, EcosystemDependencies
from cordon_scanner.intel.base import PackageArchive
from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources
from cordon_scanner.intel.registries.registry_client import RegistryError


class _Base:
    @staticmethod
    def tar(path: Path, members: dict[str, bytes]) -> Path:
        with tarfile.open(path, "w:gz") as archive:
            for name, data in members.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
        return path

    @staticmethod
    def archive(version: str = "2.0.0") -> PackageArchive:
        return PackageArchive("npm", "left", version, "left-2.0.0.tgz", b"payload")


class TestAdmitted(_Base):
    def test_no_declared_range_admits_every_version(self) -> None:
        assert EcosystemDependencies.admitted("npm", "", ["1.0.0", "2.0.0"]) == ["1.0.0", "2.0.0"]

    def test_a_range_admits_only_the_versions_inside_it(self) -> None:
        assert EcosystemDependencies.admitted("npm", "^1.0.0", ["1.2.0", "2.0.0"]) == ["1.2.0"]


class TestResolveFromTheRegistry(_Base):
    def test_a_registry_that_cannot_list_versions_resolves_to_nothing(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        def fail(ecosystem: str, name: str) -> list[str]:
            raise RegistryError("unreachable")

        monkeypatch.setattr(ArchiveSources, "versions", staticmethod(fail))
        assert EcosystemDependencies.resolve("npm", "left", "^1", None, tmp_path) is None

    def test_the_highest_admitted_release_is_fetched_into_the_work_folder(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        asked: list[str] = []
        monkeypatch.setattr(
            ArchiveSources, "versions", staticmethod(lambda e, n: ["1.0.0", "1.5.0", "2.0.0"])
        )

        def fetch(ecosystem: str, name: str, version: str) -> PackageArchive:
            asked.append(version)
            return self.archive(version)

        monkeypatch.setattr(ArchiveSources, "package_archive", staticmethod(fetch))
        found = EcosystemDependencies.resolve("npm", "left", "^1.0.0", None, tmp_path)
        assert found is not None
        assert asked == ["1.5.0"]
        assert found.version == "1.5.0"
        assert found.path.parent == tmp_path
        assert found.path.read_bytes() == b"payload"

    def test_a_release_the_source_cannot_deliver_resolves_to_nothing(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        def fail(ecosystem: str, name: str, version: str) -> PackageArchive:
            raise RegistryError("HTTP 404")

        monkeypatch.setattr(ArchiveSources, "versions", staticmethod(lambda e, n: ["1.0.0"]))
        monkeypatch.setattr(ArchiveSources, "package_archive", staticmethod(fail))
        assert EcosystemDependencies.resolve("npm", "left", "", None, tmp_path) is None
        assert list(tmp_path.iterdir()) == []


class TestDeclaredFromAnArchive(_Base):
    def test_the_package_json_of_a_tarball_names_its_dependencies_without_its_own_name(
        self, tmp_path: Path
    ) -> None:
        manifest = {
            "name": "app",
            "dependencies": {"left": "^1", "app": "1", "bad": 3},
            "optionalDependencies": {"fsevents": "2"},
        }
        target = self.tar(
            tmp_path / "a.tgz", {"package/package.json": json.dumps(manifest).encode()}
        )
        assert DependencyPayload.declared(target) == (
            "npm",
            {"fsevents": "2", "left": "^1"},
        )

    def test_a_manifest_over_the_size_limit_is_not_read(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(dependency_payload, "MAX_MANIFEST_BYTES", 10)
        target = self.tar(
            tmp_path / "a.tgz",
            {"package/package.json": b'{"dependencies": {"left": "^1"}}'},
        )
        assert DependencyPayload.declared(target) == ("npm", {})

    def test_a_tarball_with_no_package_json_declares_nothing(self, tmp_path: Path) -> None:
        target = self.tar(tmp_path / "a.tgz", {"package/index.js": b"x"})
        assert DependencyPayload.declared(target) == ("npm", {})

    def test_a_file_that_is_not_a_tarball_declares_nothing(self, tmp_path: Path) -> None:
        target = tmp_path / "a.tgz"
        target.write_bytes(b"not a tar")
        assert DependencyPayload.declared(target) == ("npm", {})

    def test_a_manifest_that_is_not_json_declares_nothing(self, tmp_path: Path) -> None:
        target = self.tar(tmp_path / "a.tgz", {"package/package.json": b"{nope"})
        assert DependencyPayload.declared(target) == ("npm", {})
