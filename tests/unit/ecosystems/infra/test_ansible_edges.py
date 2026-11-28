"""Ansible's less common documents: an execution environment's python and system lists, an inline galaxy section, role metadata entries and the refusals (`ecosystems/infra/ansible.py`)."""

from __future__ import annotations

from typing import Any

from cordon_scanner.ecosystems.infra.ansible import ExecutionEnvironment
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def read(path: str, text: str) -> Any:
        content = FileContent.from_bytes(path, text.encode("utf-8"), Limits())
        return EcosystemRegistry.BY_ID["ansible"].parse_manifest(content)


class TestExecutionEnvironment:
    PATH = "execution-environment.yml"

    def test_a_document_that_is_not_a_map_is_refused(self) -> None:
        assert "is not a map" in _Kit.read(self.PATH, "- a\n").parse_error

    def test_dependencies_that_are_not_a_map_are_refused(self) -> None:
        assert (
            "`dependencies` is not a map" in _Kit.read(self.PATH, "dependencies: [x]\n").parse_error
        )

    def test_an_inline_galaxy_section_that_cannot_be_read_is_the_files_error(self) -> None:
        text = "dependencies:\n  galaxy:\n    collections: not-a-list\n"
        assert "`collections` is not a list" in _Kit.read(self.PATH, text).parse_error

    def test_python_and_system_lists_given_as_file_names_are_named_as_sources(self) -> None:
        text = "dependencies:\n  python: requirements.txt\n  system: bindep.txt\n"
        manifest = _Kit.read(self.PATH, text)
        assert "python requirements from requirements.txt" in manifest.sources
        assert "system packages from bindep.txt" in manifest.sources

    def test_a_python_requirement_that_is_not_one_is_skipped_and_the_others_are_kept(self) -> None:
        text = "dependencies:\n  python:\n    - '!!!'\n    - requests>=2\n"
        manifest = _Kit.read(self.PATH, text)
        assert [(d.name, d.field_name) for d in manifest.dependencies] == [
            ("requests", "dependencies.python")
        ]

    def test_the_base_image_is_found_under_images_or_in_the_build_argument_defaults(self) -> None:
        assert (
            ExecutionEnvironment.base_image({"images": {"base_image": {"name": "quay.io/a/b:1"}}})
            == "quay.io/a/b:1"
        )
        assert (
            ExecutionEnvironment.base_image({"build_arg_defaults": {"EE_BASE_IMAGE": "c:2"}})
            == "c:2"
        )
        assert ExecutionEnvironment.base_image({"images": {"base_image": {}}}) is None


class TestOtherDocuments:
    def test_a_collection_runtime_that_is_not_a_map_is_refused(self) -> None:
        assert "is not a map" in _Kit.read("meta/runtime.yml", "- a\n").parse_error

    def test_a_galaxy_file_without_a_namespace_and_name_is_refused(self) -> None:
        assert "without namespace and name" in _Kit.read("galaxy.yml", "- a\n").parse_error

    def test_galaxy_dependencies_that_are_not_a_map_are_refused(self) -> None:
        text = "namespace: n\nname: c\nversion: 1.0.0\ndependencies: [x]\n"
        assert "`dependencies` is not a map" in _Kit.read("galaxy.yml", text).parse_error

    def test_a_role_meta_that_is_not_a_map_declares_nothing(self) -> None:
        manifest = _Kit.read("meta/main.yml", "- a\n")
        assert manifest.dependencies == () and not manifest.parse_error

    def test_role_dependencies_may_be_names_maps_or_urls_and_the_empty_are_skipped(self) -> None:
        text = (
            "galaxy_info:\n  author: x\n"
            "dependencies:\n"
            "  - common\n"
            "  - [nested]\n"
            "  - {src: 'https://example.invalid/org/role-repo.git', version: v1}\n"
            "  - {role: ''}\n"
        )
        names = [d.name for d in _Kit.read("meta/main.yml", text).dependencies]
        assert names == ["common", "role-repo"]


class TestRequirements:
    def test_a_single_signature_given_as_text_is_one_signature_source(self) -> None:
        text = (
            "collections:\n"
            "  - name: ns.col\n    version: 1.0.0\n    signatures: https://sigs.example.invalid/col.asc\n"
        )
        [dependency] = _Kit.read("requirements.yml", text).dependencies
        assert dependency.signature_sources == ("https://sigs.example.invalid/col.asc",)


class TestMoreAnsible:
    def test_a_collection_in_requirements_with_no_name_is_an_error(self) -> None:
        manifest = _Kit.read("requirements.yml", "collections:\n  - {version: 1.0.0}\n")
        assert manifest.parse_error == "a collections entry without a name"

    def test_a_collection_manifest_without_namespace_name_and_version_is_refused(self) -> None:
        adapter = EcosystemRegistry.BY_ID["ansible"]
        content = FileContent.from_bytes(
            "ansible_collections/ns/col/MANIFEST.json",
            b'{"collection_info": {"namespace": "ns"}}',
            Limits(),
        )
        graph = adapter.parse_lockfile(content)
        assert "without namespace, name and version" in graph.parse_error

    def test_a_manifest_too_shallow_to_have_an_info_folder_is_returned_as_read(self) -> None:
        adapter = EcosystemRegistry.BY_ID["ansible"]
        text = b'{"collection_info": {"namespace": "ns", "name": "col", "version": "1.0.0"}}'
        content = FileContent.from_bytes("MANIFEST.json", text, Limits())
        graph = adapter.parse_lockfile_in_tree(content, {"MANIFEST.json": content})
        assert [(e.name, e.version) for e in graph.entries] == [("ns.col", "1.0.0")]
