"""Stack, cabal.project and cabal.freeze files in the shapes the main tests leave out: extra
dependencies by URL or git, compilers, package indices, and lock files that cannot be trusted."""

from __future__ import annotations

import pytest

from cordon_scanner.ecosystems.packages.haskell.cabal import CabalDeps, CabalLayout
from cordon_scanner.ecosystems.packages.haskell.cabal_project import CabalFreeze, CabalProject
from cordon_scanner.ecosystems.packages.haskell.stack import StackLock, StackProject
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())


fc = _Kit.fc


class TestStackProject:
    def test_a_file_that_is_not_a_mapping_is_an_error(self) -> None:
        manifest = StackProject.parse(fc("stack.yaml", "- a\n- b\n"), "hackage")
        assert "invalid stack.yaml" in str(manifest.parse_error)

    def test_a_snapshot_given_as_a_url_mapping_is_read(self) -> None:
        text = "snapshot:\n  url: https://h.example/snap.yaml\n"
        manifest = StackProject.parse(fc("stack.yaml", text), "hackage")
        assert manifest.parse_error is None
        assert "snapshot https://h.example/snap.yaml" in manifest.sources

    def test_a_file_without_a_snapshot_is_an_error(self) -> None:
        manifest = StackProject.parse(fc("stack.yaml", "packages: [.]\n"), "hackage")
        assert "without a snapshot" in str(manifest.parse_error)

    def test_extra_dependencies_by_url_git_and_archive_are_routed_to_their_source(self) -> None:
        text = """resolver: lts-22.0
extra-deps:
  - acme-1.2.3@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,100
  - https://h.example/dl/widget-0.4.tar.gz
  - 7
  - git: https://h.example/org/repo.git
    commit: deadbeef
    subdirs:
      - one
      - two
  - github: org/other
  - url: https://h.example/dl/gadget-2.0.zip
flags:
  acme:
    fast: true
    slow: false
compiler: ghc-9.6.4
package-indices:
  - name: mine
    download-prefix: https://idx.example/
  - http: https://idx2.example/
  - plain
"""
        manifest = StackProject.parse(fc("stack.yaml", text), "hackage")
        assert manifest.parse_error is None
        assert manifest.overrides == {"acme": "==1.2.3"}
        assert manifest.source_patterns["widget"] == "https://h.example/dl/widget-0.4.tar.gz"
        assert manifest.source_patterns["one"] == "git+https://h.example/org/repo.git#deadbeef"
        assert manifest.source_patterns["two"] == "git+https://h.example/org/repo.git#deadbeef"
        assert manifest.source_patterns["other"] == "git+https://github.com/org/other"
        assert manifest.source_patterns["gadget"] == "https://h.example/dl/gadget-2.0.zip"
        assert "flags acme: +fast -slow" in manifest.sources
        assert "repository mine https://idx.example/" in manifest.sources
        assert "repository package-index https://idx2.example/" in manifest.sources
        (compiler,) = manifest.dependencies
        assert (compiler.name, compiler.spec) == ("ghc", "9.6.4")

    def test_a_compiler_that_is_not_versioned_is_kept_as_written(self) -> None:
        manifest = StackProject.parse(
            fc("stack.yaml", "resolver: nightly\ncompiler: custom-build\n"), "hackage"
        )
        (compiler,) = manifest.dependencies
        assert (compiler.name, compiler.spec) == ("ghc", "custom-build")

    def test_a_single_package_index_mapping_is_read(self) -> None:
        text = "resolver: lts-22.0\npackage-index:\n  name: solo\n  http: https://solo.example/\n"
        manifest = StackProject.parse(fc("stack.yaml", text), "hackage")
        assert "repository solo https://solo.example/" in manifest.sources


class TestStackLock:
    def test_a_lock_that_is_not_a_mapping_or_lacks_snapshots_is_an_error(self) -> None:
        assert "invalid stack.yaml.lock" in str(
            StackLock.parse(fc("stack.yaml.lock", "- a\n"), "hackage").parse_error
        )
        assert "without `snapshots`" in str(
            StackLock.parse(fc("stack.yaml.lock", "packages: []\n"), "hackage").parse_error
        )

    def test_packages_that_is_not_a_list_is_an_error(self) -> None:
        graph = StackLock.parse(fc("stack.yaml.lock", "snapshots: []\npackages: x\n"), "hackage")
        assert graph.parse_error == "`packages` is not a list"

    def test_each_kind_of_completed_package_becomes_an_entry_and_the_rest_is_skipped(self) -> None:
        digest = "a" * 64
        text = f"""snapshots: []
packages:
  - completed:
      hackage: acme-1.2.3@sha256:{digest},100
  - completed:
      name: gitpkg
      version: 0.1
      git: https://h.example/g.git
      commit: c0ffee
  - completed:
      name: urlpkg
      version: 0.2
      url: https://h.example/u.tgz
      sha256: {digest}
  - completed:
      name: nameonly
  - completed: not-a-mapping
  - plain
"""
        graph = StackLock.parse(fc("stack.yaml.lock", text), "hackage")
        by_name = {e.name: e for e in graph.entries}
        assert set(by_name) == {"acme", "gitpkg", "urlpkg"}
        assert by_name["acme"].integrity == f"sha256:{digest}"
        assert by_name["gitpkg"].resolved_from == "git+https://h.example/g.git#c0ffee"
        assert by_name["urlpkg"].resolved_from == "https://h.example/u.tgz"
        assert by_name["urlpkg"].integrity == f"sha256:{digest}"

    def test_a_hackage_entry_in_another_form_is_an_error(self) -> None:
        text = "snapshots: []\npackages:\n  - completed:\n      hackage: not a package\n"
        assert "Hackage entry" in str(
            StackLock.parse(fc("stack.yaml.lock", text), "hackage").parse_error
        )


class TestCabalProject:
    def test_a_git_source_with_a_tag_and_subdirectories_names_each_package(self) -> None:
        text = """packages: .

source-repository-package
  type: git
  location: https://h.example/org/mono.git
  tag: v1
  subdir: a b/
"""
        manifest = CabalProject.parse(fc("cabal.project", text), "hackage")
        assert manifest.source_patterns["a"] == "git+https://h.example/org/mono.git#v1"
        assert manifest.source_patterns["b"] == "git+https://h.example/org/mono.git#v1"

    def test_extra_packages_and_constraints_are_declared(self) -> None:
        text = """packages: .
extra-packages: foo ==1.0, bar
constraints: any.baz ==2.0, qux +flag -other, nonsense
with-compiler: ghc-9.4
"""
        manifest = CabalProject.parse(fc("cabal.project", text), "hackage")
        assert manifest.parse_error is None
        names = {d.name for d in manifest.dependencies}
        assert {"foo", "bar"} <= names


class TestCabalFreeze:
    def test_a_freeze_with_only_an_index_state_pins_nothing_and_is_not_an_error(self) -> None:
        graph = CabalFreeze.parse(
            fc("cabal.project.freeze", "index-state: hackage 2026-01-01\n"), "hackage"
        )
        assert graph.parse_error is None
        assert graph.entries == ()

    def test_a_freeze_without_constraints_is_an_error(self) -> None:
        graph = CabalFreeze.parse(fc("cabal.project.freeze", "packages: .\n"), "hackage")
        assert "no `constraints`" in str(graph.parse_error)

    def test_a_freeze_cut_short_is_an_error(self) -> None:
        graph = CabalFreeze.parse(fc("cabal.project.freeze", "constraints: any.a ==1.0"), "hackage")
        assert "does not end where" in str(graph.parse_error)

    def test_pins_flags_and_installed_markers_are_read_and_a_stray_constraint_is_an_error(
        self,
    ) -> None:
        good = "constraints: any.a ==1.0,\n             any.base installed,\n             b +x -y\n"
        graph = CabalFreeze.parse(fc("cabal.project.freeze", good), "hackage")
        assert graph.parse_error is None
        assert {e.name for e in graph.entries} >= {"a"}
        bad = CabalFreeze.parse(fc("cabal.project.freeze", "constraints: any.a >=1.0\n"), "hackage")
        assert "neither a pin nor a flag" in str(bad.parse_error)


class TestCabalLayout:
    def test_sections_nested_past_the_limit_are_refused(self) -> None:
        text = "".join(" " * i + "s\n" for i in range(CabalLayout.MAX_DEPTH + 3))
        with pytest.raises(ValueError, match="nested deeper"):
            CabalLayout.parse(text)

    def test_a_comma_inside_braces_does_not_split_a_dependency_list(self) -> None:
        assert list(CabalDeps.split("a {x, y}, b")) == ["a {x, y}", "b"]

    def test_a_dependency_entry_that_is_not_a_package_is_refused(self) -> None:
        with pytest.raises(ValueError, match="build-depends entry"):
            list(CabalDeps.entries("!!"))
