"""Conda's specs, environment files, .condarc, recipes and locks on the shapes written less often (`ecosystems/packages/conda.py`)."""

from __future__ import annotations

from typing import Any

from cordon_scanner.ecosystems.packages.conda import CondaFile, Environment, MatchSpec
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["conda"]

    @staticmethod
    def manifest(path: str, text: str) -> Any:
        return _Kit.adapter().parse_manifest(_Kit.fc(path, text))

    @staticmethod
    def lock(path: str, text: str) -> Any:
        return _Kit.adapter().parse_lockfile(_Kit.fc(path, text))


class TestMatchSpec:
    def test_a_version_and_a_build_separated_by_a_space(self) -> None:
        assert MatchSpec.parse("numpy 1.26.* py312*") == ("numpy", "1.26.*", "py312*", None)

    def test_a_single_equals_is_fuzzy_and_a_double_is_exact(self) -> None:
        assert MatchSpec.parse("scipy=1.13")[1] == "1.13.*"
        assert MatchSpec.parse("scipy==1.13.0")[1] == "==1.13.0"

    def test_a_file_url_with_too_few_parts_or_no_version_names_no_package(self) -> None:
        assert CondaFile.parse("numpy.conda") is None
        assert CondaFile.parse("https://c.example.invalid/pkgs/linux-64/numpy.conda") is None
        assert CondaFile.parse(
            "https://c.example.invalid/pkgs/linux-64/numpy-1.26.4-py312_0.conda"
        ) == ("numpy", "1.26.4", "py312_0", "linux-64", "pkgs")


class TestSelectors:
    def test_the_first_hash_that_is_not_a_selector_is_part_of_the_spec(self) -> None:
        assert Environment.selector("  - numpy  # pinned # [linux]") == (
            " numpy  # pinned ",
            "linux",
        )
        assert Environment.selector("  - numpy  # just a comment") is None
        assert Environment.selector("numpy") is None


class TestEnvironmentFiles:
    def read(self, text: str) -> Any:
        return _Kit.manifest("environment.yml", text)

    def test_a_document_that_is_not_a_mapping_is_refused(self) -> None:
        assert self.read("- a\n").parse_error == "an environment file is a mapping"

    def test_dependencies_that_are_not_a_list_are_refused(self) -> None:
        assert self.read("dependencies: numpy\n").parse_error == "`dependencies` is not a list"

    def test_a_pip_requirement_that_cannot_be_read_and_entries_that_are_not_text_are_skipped(
        self,
    ) -> None:
        text = "dependencies:\n  - numpy=1.26\n  - pip:\n      - '!!!'\n      - requests>=2\n"
        names = {d.name: d.field_name for d in self.read(text).dependencies}
        assert set(names) == {"requests", "numpy", "pip"}
        assert names["requests"] == "dependencies.pip"

    def test_an_entry_that_is_neither_text_nor_a_pip_list_is_skipped(self) -> None:
        text = "dependencies:\n  - {other: x}\n  - numpy\n"
        assert [d.name for d in self.read(text).dependencies] == ["numpy"]

    def test_an_entry_that_is_no_match_spec_is_skipped(self) -> None:
        assert [
            d.name for d in self.read("dependencies:\n  - '!!!'\n  - numpy\n").dependencies
        ] == ["numpy"]


class TestCondarc:
    def test_text_that_cannot_be_read_is_an_error(self) -> None:
        assert _Kit.manifest(".condarc", "a: [unclosed\n").parse_error.startswith(
            "invalid .condarc"
        )

    def test_an_empty_file_has_nothing_and_a_list_is_not_a_map(self) -> None:
        assert not _Kit.manifest(".condarc", "").parse_error
        assert _Kit.manifest(".condarc", "- a\n").parse_error == ".condarc is not a map"

    def test_priority_given_as_false_is_said_to_be_disabled(self) -> None:
        manifest = _Kit.manifest(".condarc", "channels: [conda-forge]\nchannel_priority: false\n")
        assert "channel_priority disabled" in manifest.sources


class TestRecipes:
    def test_a_meta_yaml_that_is_not_a_conda_recipe_is_not_judged(self) -> None:
        assert not _Kit.manifest("meta.yaml", "- a\n").parse_error

    def test_a_requirement_only_jinja_could_compute_is_skipped(self) -> None:
        text = (
            "package:\n  name: p\n  version: 1\nrequirements:\n  build:\n"
            "    - zlib {{ zlib_version }}\n    - numpy\n  run:\n    - '!!!'\n"
        )
        assert [d.name for d in _Kit.manifest("meta.yaml", text).dependencies] == ["numpy"]


class TestLocksAndExports:
    def test_a_conda_lock_with_no_package_list_is_refused(self) -> None:
        assert _Kit.lock("conda-lock.yml", "version: 1\n").parse_error == "no `package` list"

    def test_a_locked_package_without_a_name_is_skipped(self) -> None:
        text = "version: 1\npackage:\n  - {version: '1'}\n"
        assert _Kit.lock("conda-lock.yml", text).entries == ()

    def test_an_explicit_export_reads_each_digest_form(self) -> None:
        base = "https://c.example.invalid/pkgs/linux-64/numpy-1.26.4-py312_0.conda"
        md5 = "a" * 32
        sha = "b" * 64
        text = f"@EXPLICIT\n{base}#{md5}\n{base}#sha256:{sha}\n{base}#{sha}\n{base}#short\n"
        integrities = [e.integrity for e in _Kit.lock("explicit.txt", text).entries]
        assert f"md5:{md5}" in integrities
        assert f"sha256:{sha}" in integrities
        assert any(i is not None and i.startswith("malformed:") for i in integrities)
