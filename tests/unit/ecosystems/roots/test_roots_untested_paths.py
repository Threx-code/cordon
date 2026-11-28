"""Paths of the ecosystem package's root modules that no other test reached.

Each test says what the module answers (a name, a verdict, a membership) for the input that sends it
down a branch the main suites leave out: a workspace declared as a mapping, a pnpm list with
a following key, an archive whose manifest cannot be read, a registry without npm.
"""

from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

from cordon_scanner.ecosystems.archive_shapes import ArchiveLevels, NpmRenamedArchive
from cordon_scanner.ecosystems.base import (
    WORKSPACE_INHERITED,
    BaseEcosystem,
    Coordinate,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    ProjectDefaults,
    ReleaseIdentityDefaults,
)
from cordon_scanner.ecosystems.contract import Contracts
from cordon_scanner.ecosystems.own_names import OwnNameReaders
from cordon_scanner.ecosystems.published_manifests import PublishedManifests
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.ecosystems.workspace_members import NpmWorkspaces, WorkspaceMembers
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class RootsHelpers:
    @staticmethod
    def fc(path: str, text: str | bytes) -> FileContent:
        raw = text.encode("utf-8") if isinstance(text, str) else text
        return FileContent.from_bytes(path, raw, Limits())


class TestWorkspaceMembers:
    def test_the_container_answers_for_a_key_it_holds(self) -> None:
        members = WorkspaceMembers({("npm", "a"): ("1.0.0",)})
        assert ("npm", "a") in members
        assert ("npm", "b") not in members
        assert "a" not in members

    def test_yarn_workspaces_as_a_mapping_name_the_members(self) -> None:
        files = {
            "package.json": RootsHelpers.fc(
                "package.json", '{"workspaces": {"packages": ["pkgs/*"]}}'
            ),
            "pkgs/a/package.json": RootsHelpers.fc("pkgs/a/package.json", "{}"),
            "other/b/package.json": RootsHelpers.fc("other/b/package.json", "{}"),
        }
        assert NpmWorkspaces.defines("pkgs/a/package.json", files)
        assert not NpmWorkspaces.defines("other/b/package.json", files)

    def test_a_pnpm_list_stops_at_the_next_top_level_key(self) -> None:
        yaml = "packages:\n  - 'apps/*'\n  - \"libs/**\"\nonlyBuiltDependencies:\n  - 'ignored/*'\n"
        files = {
            "package.json": RootsHelpers.fc("package.json", "{}"),
            "pnpm-workspace.yaml": RootsHelpers.fc("pnpm-workspace.yaml", yaml),
            "apps/x/package.json": RootsHelpers.fc("apps/x/package.json", "{}"),
            "libs/deep/er/package.json": RootsHelpers.fc("libs/deep/er/package.json", "{}"),
            "ignored/y/package.json": RootsHelpers.fc("ignored/y/package.json", "{}"),
        }
        assert NpmWorkspaces.defines("apps/x/package.json", files)
        assert NpmWorkspaces.defines("libs/deep/er/package.json", files)
        assert not NpmWorkspaces.defines("ignored/y/package.json", files)

    def test_an_excluded_pattern_removes_a_member(self) -> None:
        files = {
            "package.json": RootsHelpers.fc("package.json", '{"workspaces": ["p/*", "!p/skip"]}'),
            "p/keep/package.json": RootsHelpers.fc("p/keep/package.json", "{}"),
            "p/skip/package.json": RootsHelpers.fc("p/skip/package.json", "{}"),
        }
        assert NpmWorkspaces.defines("p/keep/package.json", files)
        assert not NpmWorkspaces.defines("p/skip/package.json", files)

    def test_a_manifest_that_is_not_json_declares_no_members(self) -> None:
        files = {
            "package.json": RootsHelpers.fc("package.json", "{not json"),
            "p/a/package.json": RootsHelpers.fc("p/a/package.json", "{}"),
        }
        assert not NpmWorkspaces.defines("p/a/package.json", files)


class TestArchiveShapes:
    def test_a_member_whose_text_cannot_be_read_is_empty(self) -> None:
        class Broken:
            @property
            def text(self) -> str:
                raise ValueError("not text")

        unit = SimpleNamespace(path="a.tgz!package/x", content=Broken())
        levels = ArchiveLevels(
            units=[unit], top=frozenset(), roots={}, members=frozenset({"package/x"})
        )
        assert levels.text("package/x") == ""
        assert levels.text("missing") == ""

    def test_a_renamed_directory_in_a_zip_is_not_an_npm_tarball(self) -> None:
        text = '{"name": "p", "version": "1.0.0"}'
        unit = SimpleNamespace(path="p.zip!pkg/package.json", content=RootsHelpers.fc("x", text))
        levels = ArchiveLevels(
            units=[unit],
            top=frozenset({"pkg/package.json"}),
            roots={"pkg": frozenset({"package.json"})},
            members=frozenset({"pkg/package.json"}),
        )
        assert not NpmRenamedArchive().matches(levels)
        tgz = SimpleNamespace(path="p.tgz!pkg/package.json", content=RootsHelpers.fc("x", text))
        assert NpmRenamedArchive().matches(
            ArchiveLevels(units=[tgz], top=levels.top, roots=levels.roots, members=levels.members)
        )


class TestContractsAndNames:
    def test_a_contract_is_found_by_ecosystem_id(self) -> None:
        found = Contracts.get("npm")
        assert found is not None
        assert found.id == "npm"
        assert Contracts.get("no-such-ecosystem") is None

    def test_an_image_config_titled_by_its_publisher_is_named_so(self) -> None:
        blob = '{"rootfs": {}, "config": {"Labels": {"org.opencontainers.image.title": " web "}}}'
        assert OwnNameReaders.image_config("blobs/x", RootsHelpers.fc("blobs/x", blob)) == "web"

    def test_an_image_config_without_labels_has_no_name(self) -> None:
        blob = '{"rootfs": {}, "config": {"Cmd": ["x"]}}'
        assert OwnNameReaders.image_config("blobs/x", RootsHelpers.fc("blobs/x", blob)) is None

    def test_an_image_config_falls_back_to_the_source_repository(self) -> None:
        blob = '{"rootfs": {}, "config": {"Labels": {"org.opencontainers.image.source": "https://h.example/o/app.git"}}}'
        assert OwnNameReaders.image_config("blobs/x", RootsHelpers.fc("blobs/x", blob)) == "app"

    def test_a_nuspec_without_an_id_has_no_name(self) -> None:
        assert (
            OwnNameReaders.nuspec_id("a.nuspec", RootsHelpers.fc("a.nuspec", "<package/>")) is None
        )
        assert (
            OwnNameReaders.nuspec_id("a.nuspec", RootsHelpers.fc("a.nuspec", "<id> Foo.Bar </id>"))
            == "Foo.Bar"
        )

    def test_an_erlang_term_file_without_the_key_gives_none(self) -> None:
        content = RootsHelpers.fc("metadata.config", '{<<"name">>,<<"jason">>}.\n')
        assert OwnNameReaders.erlang_term(content, "name") == "jason"
        assert OwnNameReaders.erlang_term(content, "version") is None


class TestPublishedManifests:
    def test_a_nix_package_names_itself_and_its_build_inputs(self) -> None:
        text = 'pname = "tool";\n buildInputs = [ zlib openssl ];\n nativeBuildInputs = [ pkg-config ];'
        manifest = PublishedManifests.nix_manifest(
            "nix", "pkgs/tool/package.nix", RootsHelpers.fc("package.nix", text)
        )
        assert manifest.ecosystem == "nix"
        assert {d.name for d in manifest.dependencies} >= {"zlib", "openssl", "pkg-config"}

    def test_an_extension_manifest_without_npm_registered_is_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(EcosystemRegistry, "get", staticmethod(lambda _eco: None))
        manifest = PublishedManifests.extension_package(
            "vscode",
            "extension/package.json",
            RootsHelpers.fc("p", '{"name": "a", "publisher": "b"}'),
        )
        assert manifest.name is None
        assert not manifest.dependencies


class TestBaseDefaults:
    def test_a_blank_digest_is_none_and_an_odd_one_is_marked_malformed(self) -> None:
        assert Coordinate.integrity("   ") is None
        assert Coordinate.integrity(None) is None
        odd = Coordinate.integrity("not a digest")
        assert odd is not None
        assert odd.startswith(Coordinate.MALFORMED)

    @pytest.mark.parametrize(
        ("spec", "unpinned"),
        [
            ("", True),
            ("*", True),
            ("latest", True),
            ("any", True),
            ("^1.2.0", True),
            ("~1.2", True),
            (">=1", True),
            ("1.2.3", False),
            ("==1.2.3", False),
            (">=1,==1.2", False),
            (WORKSPACE_INHERITED, False),
        ],
    )
    def test_a_range_is_unpinned_and_an_exact_or_inherited_version_is_not(
        self, spec: str, unpinned: bool
    ) -> None:
        assert DeclaredDependency(name="x", spec=spec).is_unpinned is unpinned

    def test_a_lock_graph_counts_its_entries(self) -> None:
        entry = LockEntry(name="a", version="1")
        assert len(LockGraph(path="l", ecosystem="npm", entries=(entry, entry))) == 2
        assert len(LockGraph(path="l", ecosystem="npm")) == 0

    def test_a_table_spec_without_a_version_is_any_and_a_bare_value_is_its_text(self) -> None:
        assert BaseEcosystem._table_spec({"features": ["x"]}) == "*"
        assert BaseEcosystem._table_spec({"workspace": True}) == WORKSPACE_INHERITED
        assert BaseEcosystem._table_spec(3) == "3"

    def test_an_ecosystem_with_no_project_writes_none(self) -> None:
        defaults = ProjectDefaults()
        assert defaults.pinned_project([("a", "1")]) is None
        assert defaults.loose_project(["a"]) is None

    def test_an_ecosystem_names_no_release_member_unless_it_says_so(self) -> None:
        defaults = ReleaseIdentityDefaults()
        assert defaults.release_manifest() is None
        assert defaults.release_identity("p", "t", re.match("p", "p")) is None  # type: ignore[arg-type]

    def test_the_base_adapter_lower_cases_names_and_has_no_parser(self) -> None:
        base = BaseEcosystem()
        assert base.normalize_name("  MiXed ") == "mixed"
        with pytest.raises(NotImplementedError):
            base.parse_manifest(RootsHelpers.fc("x", ""))
