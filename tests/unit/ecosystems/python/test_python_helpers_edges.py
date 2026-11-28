"""Small helpers of the Python readers: table-valued specs, the repository a project claims, and requirement options (`ecosystems/packages/pypi.py`, `python/requirements.py`)."""

from __future__ import annotations

from typing import Any

from cordon_scanner.ecosystems.packages.pypi import PypiEcosystem
from cordon_scanner.ecosystems.packages.python.requirements import PypiManifest
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["pypi"]


class TestPoetrySpecs:
    def test_a_table_with_none_of_the_known_keys_is_any_version_and_anything_else_is_its_text(
        self,
    ) -> None:
        assert PypiEcosystem._poetry_spec({"optional": True}) == "*"
        assert PypiEcosystem._poetry_spec({"version": "^1"}) == "^1"
        assert PypiEcosystem._poetry_spec(5) == "5"

    def test_a_poetry_dependency_that_is_neither_text_a_table_nor_a_list_of_tables_is_skipped(
        self,
    ) -> None:
        text = '[tool.poetry.dependencies]\npython = "^3.9"\nflag = true\nreal = "^1.0"\n'
        manifest = _Kit.adapter().parse_manifest(_Kit.fc("pyproject.toml", text))
        assert {d.name for d in manifest.dependencies} >= {"real"}
        assert "flag" not in {d.name for d in manifest.dependencies}


class TestProjectFiles:
    def test_a_file_that_is_not_a_known_manifest_name_declares_nothing(self) -> None:
        manifest = _Kit.adapter().parse_manifest(_Kit.fc("notes.txt", "requests==2\n"))
        assert manifest.dependencies == () and not manifest.parse_error

    def test_a_published_distribution_with_no_metadata_file_declares_no_dependencies(self) -> None:
        assert _Kit.adapter().declared_dependencies([]) == frozenset()

    def test_the_repository_a_project_claims_is_none_when_it_has_no_urls_table_or_none_of_the_keys(
        self,
    ) -> None:
        assert PypiManifest._repository_of({}) is None
        assert PypiManifest._repository_of({"urls": {"Docs": "https://d.example.invalid"}}) is None
        assert PypiManifest._repository_of({"urls": {"Homepage": "https://h.example.invalid"}}) == (
            "https://h.example.invalid"
        )


class TestOptions:
    def test_a_specifier_is_cut_before_any_trailing_option(self) -> None:
        assert PypiManifest._spec_of("==1.0 --hash=sha256:abc") == "==1.0"
        assert PypiManifest._version_of("1.0 \\") == "1.0"
