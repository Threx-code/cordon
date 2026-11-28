"""Project.toml, Manifest.toml and Artifacts.toml on the shapes written less often (`ecosystems/packages/julia.py`)."""

from __future__ import annotations

from typing import Any

from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits

UUID = "7876af07-990d-54b4-ab0e-23690620f79a"
OTHER = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["julia"]

    @staticmethod
    def project(text: str) -> Any:
        return _Kit.adapter().parse_manifest(_Kit.fc("Project.toml", text))

    @staticmethod
    def lock(path: str, text: str) -> Any:
        return _Kit.adapter().parse_lockfile(_Kit.fc(path, text))


class TestProject:
    def test_a_dependency_whose_value_is_not_a_uuid_is_refused(self) -> None:
        manifest = _Kit.project('[deps]\nExample = "not-a-uuid"\n')
        assert manifest.parse_error == "a [deps] entry whose value is not a UUID"

    def test_a_dependency_with_a_local_path_source_names_the_path(self) -> None:
        text = f'[deps]\nLocal = "{UUID}"\n\n[sources]\nLocal = {{path = "../local"}}\n'
        assert [(d.name, d.spec) for d in _Kit.project(text).dependencies] == [
            ("Local", "path:../local")
        ]

    def test_an_extra_that_is_already_a_dependency_is_not_declared_twice(self) -> None:
        text = f'[deps]\nTestA = "{UUID}"\n\n[extras]\nTestA = "{UUID}"\nTestB = "{OTHER}"\n'
        names = [d.name for d in _Kit.project(text).dependencies]
        assert names.count("TestA") == 1 and "TestB" in names


class TestManifest:
    def test_a_manifest_format_this_reader_does_not_know_is_refused(self) -> None:
        graph = _Kit.lock("Manifest.toml", 'manifest_format = "9.9"\n')
        assert graph.parse_error == "a manifest_format this reader does not know"

    def test_a_package_that_is_not_an_array_of_tables_is_refused(self) -> None:
        text = 'manifest_format = "2.0"\n\n[deps]\nExample = "text"\n'
        graph = _Kit.lock("Manifest.toml", text)
        assert graph.parse_error == "a package that is not an array of tables"

    def test_a_record_that_is_not_a_table_is_skipped_and_a_table_is_read(self) -> None:
        text = (
            'manifest_format = "2.0"\n\n[deps]\nJunk = [1, 2]\n\n'
            f'[[deps.Example]]\nuuid = "{UUID}"\nversion = "1.0.0"\n'
        )
        graph = _Kit.lock("Manifest.toml", text)
        assert [(e.name, e.version) for e in graph.entries] == [("Example", "1.0.0")]


class TestArtifacts:
    def test_an_artifact_that_is_not_a_table_is_refused(self) -> None:
        graph = _Kit.lock("Artifacts.toml", "name = 5\n")
        assert graph.parse_error == "an artifact that is not a table"

    def test_an_artifact_without_its_tree_hash_is_refused(self) -> None:
        graph = _Kit.lock("Artifacts.toml", "[data]\nlazy = true\n")
        assert graph.parse_error == "an artifact without its git-tree-sha1"

    def test_a_variant_that_is_not_a_table_is_skipped_and_one_that_is_is_read(self) -> None:
        text = 'other = [1, 2]\n\n[[data]]\ngit-tree-sha1 = "' + "a" * 40 + '"\n'
        graph = _Kit.lock("Artifacts.toml", text)
        assert not graph.parse_error
        assert [e.name for e in graph.entries] == ["artifact:data"]
