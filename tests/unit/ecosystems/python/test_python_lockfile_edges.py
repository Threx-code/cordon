"""The Python lockfiles on the shapes they write less often: Poetry groups and git sources, uv and PDM groups and wheel hashes, and Pipfile entries by path, file or git (`ecosystems/packages/python/lockfiles.py`)."""

from __future__ import annotations

import json
from typing import Any

from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits
from cordon_scanner.foundation.models import Scope


class _Kit:
    @staticmethod
    def lock(path: str, text: str) -> Any:
        content = FileContent.from_bytes(path, text.encode("utf-8"), Limits())
        return EcosystemRegistry.BY_ID["pypi"].parse_lockfile(content)


class TestPoetry:
    TEXT = (
        '[[package]]\nname = "app-lib"\nversion = "1.0"\ngroups = ["main", "dev"]\n\n'
        '[[package]]\nname = "tool"\nversion = "2.0"\ngroups = ["dev"]\n\n'
        '[[package]]\nname = "extra"\nversion = "3.0"\noptional = true\ngroups = ["main"]\n\n'
        '[[package]]\nname = "forked"\nversion = "4.0"\n'
        '[package.source]\ntype = "git"\nurl = "https://example.invalid/f.git"\n'
        'reference = "main"\nresolved_reference = "abc123"\n\n'
        '[[package]]\nversion = "9.9"\n'
    )

    def test_a_package_in_the_main_group_is_runtime_and_one_in_no_runtime_group_is_dev(
        self,
    ) -> None:
        by_name = {e.name: e for e in _Kit.lock("poetry.lock", self.TEXT).entries}
        assert by_name["app-lib"].scope is Scope.RUNTIME
        assert by_name["tool"].scope is Scope.DEV

    def test_an_optional_runtime_package_is_optional(self) -> None:
        by_name = {e.name: e for e in _Kit.lock("poetry.lock", self.TEXT).entries}
        assert by_name["extra"].scope is Scope.OPTIONAL

    def test_a_git_source_names_its_url_and_the_commit_it_resolved_to(self) -> None:
        by_name = {e.name: e for e in _Kit.lock("poetry.lock", self.TEXT).entries}
        assert by_name["forked"].resolved_from == "git+https://example.invalid/f.git#abc123"

    def test_a_package_without_a_name_is_not_an_entry(self) -> None:
        assert "9.9" not in {e.version for e in _Kit.lock("poetry.lock", self.TEXT).entries}


class TestPepStyle:
    def test_a_uv_manifest_that_groups_dev_dependencies_marks_only_those_names_dev(self) -> None:
        text = (
            "version = 1\nrevision = 2\n\n"
            '[manifest.dev-dependencies]\ntest = ["pytest>=8"]\nlint = ["ruff"]\n\n'
            '[[package]]\nname = "pytest"\nversion = "8.0"\n'
            '[package.sdist]\nhash = "sha256:' + "a" * 64 + '"\n\n'
            '[[package]]\nname = "requests"\nversion = "2.0"\n'
            '[[package.wheels]]\nhash = "sha256:' + "b" * 64 + '"\n'
        )
        by_name = {e.name: e for e in _Kit.lock("uv.lock", text).entries}
        assert by_name["pytest"].scope is Scope.DEV
        assert by_name["requests"].scope is Scope.RUNTIME
        assert by_name["requests"].integrity == "sha256:" + "b" * 64
        assert by_name["pytest"].integrity == "sha256:" + "a" * 64

    def test_a_pdm_package_in_no_default_group_is_dev_and_a_non_table_package_is_ignored(
        self,
    ) -> None:
        text = (
            '[metadata]\nlock_version = "4.5.0"\n\n'
            '[[package]]\nname = "pytest"\nversion = "8.0"\ngroups = ["dev"]\n\n'
            '[[package]]\nname = "idna"\nversion = "3.0"\ngroups = ["default"]\n'
        )
        by_name = {e.name: e for e in _Kit.lock("pdm.lock", text).entries}
        assert by_name["pytest"].scope is Scope.DEV
        assert by_name["idna"].scope is Scope.RUNTIME

    def test_a_uv_lock_with_only_the_header_has_no_entries_and_no_error(self) -> None:
        graph = _Kit.lock("uv.lock", 'version = 1\nrequires-python = ">=3.9"\n')
        assert graph.entries == () and not graph.parse_error

    def test_the_same_header_in_a_pdm_lock_is_not_taken_for_a_uv_header(self) -> None:
        graph = _Kit.lock("pdm.lock", 'version = 1\nrequires-python = ">=3.9"\n')
        assert graph.entries == ()


class TestPipfileLock:
    def test_entries_by_git_path_and_file_and_a_non_table_entry(self) -> None:
        data = {
            "default": {
                "a": {"git": "https://example.invalid/a.git", "ref": "abc", "version": "==1"},
                "b": {"path": "./libs/b", "version": "==2"},
                "c": {"file": "https://example.invalid/c.whl", "version": "==3"},
                "d": "not a table",
            },
            "develop": {"e": {"version": "==4", "markers": "python_version < '3.9'"}},
        }
        by_name = {e.name: e for e in _Kit.lock("Pipfile.lock", json.dumps(data)).entries}
        assert set(by_name) == {"a", "b", "c", "e"}
        assert by_name["a"].resolved_from == "git+https://example.invalid/a.git#abc"
        assert by_name["b"].resolved_from == "./libs/b" and by_name["b"].local is True
        assert by_name["c"].resolved_from == "https://example.invalid/c.whl"
        assert by_name["e"].scope is Scope.DEV
        assert by_name["e"].platform == ("python_version < '3.9'",)


class TestRequirementsLines:
    def test_a_hash_continued_onto_a_last_line_with_no_end_is_still_read(self) -> None:
        text = "requests==2.0.0 \\\n    --hash=sha256:" + "c" * 64 + " \\\n"
        [entry] = _Kit.lock("requirements.txt", text).entries
        assert (entry.name, entry.version) == ("requests", "2.0.0")
        assert entry.hashes == ("sha256:" + "c" * 64,)

    def test_a_package_that_is_not_a_table_is_ignored_when_finding_dev_groups(self) -> None:
        text = 'package = ["junk"]\n[manifest]\ndev-dependencies = ["pytest"]\n'
        assert _Kit.lock("uv.lock", text).entries == ()
