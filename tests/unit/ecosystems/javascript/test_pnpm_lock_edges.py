"""pnpm lockfiles on the shapes they write less often: two documents, git and optional packages, aliases and entries that are not tables (`ecosystems/packages/javascript/pnpm.py`)."""

from __future__ import annotations

from typing import Any

from cordon_scanner.ecosystems.packages.javascript.pnpm import PnpmLock
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits
from cordon_scanner.foundation.models import Scope


class _Kit:
    @staticmethod
    def lock(text: str) -> Any:
        content = FileContent.from_bytes("pnpm-lock.yaml", text.encode("utf-8"), Limits())
        return EcosystemRegistry.BY_ID["npm"].parse_lockfile(content)


LOCK = """\
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a: {specifier: ^1, version: 1.0.0}
      bad: not-a-table
  other: not-a-table
packages:
  a@1.0.0:
    resolution: {integrity: sha512-aaaa}
  g@1.0.0:
    resolution: {type: git, repo: https://example.invalid/g.git, commit: abc123}
  o@1.0.0:
    resolution: {integrity: sha512-oooo}
    optional: true
  real@2.0.0:
    resolution: {integrity: sha512-rrrr}
  weird@1.0.0: ~
snapshots:
  a@1.0.0:
    dependencies: {g: 1.0.0, missing: 9.9.9, ali: real@2.0.0}
    optionalDependencies: {o: 1.0.0}
  g@1.0.0: {}
  o@1.0.0:
    optional: true
  weird@1.0.0: ~
"""


class TestEntries:
    def test_a_git_package_names_its_repository_and_commit(self) -> None:
        by_name = {e.name: e for e in _Kit.lock(LOCK).entries}
        assert by_name["g"].resolved_from == "git+https://example.invalid/g.git#abc123"

    def test_a_package_only_optional_dependencies_reach_is_optional(self) -> None:
        by_name = {e.name: e for e in _Kit.lock(LOCK).entries}
        assert by_name["o"].scope is Scope.OPTIONAL
        assert by_name["a"].scope is Scope.RUNTIME

    def test_a_dependency_under_another_name_is_an_edge_to_the_real_package(self) -> None:
        by_name = {e.name: e for e in _Kit.lock(LOCK).entries}
        assert "real" in by_name
        assert by_name["real"].alias == "ali"

    def test_a_top_level_that_is_not_a_mapping_is_refused(self) -> None:
        assert _Kit.lock("- a\n").parse_error == "top level is not a mapping"


class TestKeys:
    def test_an_empty_key_is_not_a_package(self) -> None:
        assert PnpmLock.split_key("  ''  ") is None
        assert PnpmLock.split_key("lodash@4.17.21") == ("lodash", "4.17.21")


class TestTwoDocuments:
    def test_the_second_documents_importers_and_packages_are_merged_into_the_project(self) -> None:
        text = (
            "importers:\n  .:\n    dependencies:\n      a: {specifier: '1', version: 1.0.0}\n"
            "packages:\n  a@1.0.0:\n    resolution: {integrity: sha512-aaaa}\n"
            "---\n"
            "importers:\n  sub:\n    dependencies:\n      b: {specifier: '1', version: 1.0.0}\n"
            "packages:\n  b@1.0.0:\n    resolution: {integrity: sha512-bbbb}\n"
        )
        assert {e.name for e in _Kit.lock(text).entries} == {"a", "b"}
