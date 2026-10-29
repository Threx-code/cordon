"""The dependency inventory reads, for a scan target, the files that decide what gets installed."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from cordon_scanner.engine.pipeline.dependency_scope import DependencyScope


@dataclass
class Unit:
    """Only the path, which is all the scope reads."""

    path: str


class Paths:
    NPM = "x-1.0.0.tgz!package/"
    PACKAGE: ClassVar[list[str]] = [
        NPM + "package.json",
        NPM + "package-lock.json",
        NPM + "test/fixtures/broken/package.json",
        NPM + "node_modules/dep/package.json",
        NPM + ".github/workflows/ci.yml",
        NPM + "packages/member/package.json",
        NPM + "Dockerfile",
    ]
    REPOSITORY: ClassVar[list[str]] = [
        "repo-HEAD.tar.gz!repo/package.json",
        "repo-HEAD.tar.gz!repo/.github/workflows/ci.yml",
        "repo-HEAD.tar.gz!repo/tests/fixture/package.json",
        "repo-HEAD.tar.gz!repo/node_modules/dep/package.json",
        "repo-HEAD.tar.gz!repo/.venv/lib/requirements.txt",
    ]

    @staticmethod
    def units(paths: list[str]) -> list[Unit]:
        return [Unit(p) for p in paths]


class TestDependencyScope:
    def test_a_directory_on_disk_reads_every_file_the_walk_found(self) -> None:
        scope = DependencyScope.of(Paths.units(Paths.REPOSITORY), published="", archive=False)
        assert all(scope.reads(p) for p in Paths.REPOSITORY + Paths.PACKAGE)

    def test_a_repository_snapshot_is_read_as_the_tree_on_disk(self) -> None:
        scope = DependencyScope.of(Paths.units(Paths.REPOSITORY), published="", archive=True)
        read = [p for p in Paths.REPOSITORY if scope.reads(p)]
        # Its CI and its test manifests count; the walker's pruned directories do not.
        assert read == Paths.REPOSITORY[:3]

    def test_a_published_package_reads_its_root_manifest_and_lockfile(self) -> None:
        scope = DependencyScope.of(Paths.units(Paths.PACKAGE), published="npm", archive=True)
        assert scope.root == "x-1.0.0.tgz!package"
        # And its own node_modules: npm installs a tarball's bundled dependencies with it.
        assert [p for p in Paths.PACKAGE if scope.reads(p)] == [
            *Paths.PACKAGE[:2],
            Paths.PACKAGE[3],
        ]

    def test_only_the_ecosystems_own_bundled_paths_are_installed(self) -> None:
        scope = DependencyScope.of(Paths.units(Paths.PACKAGE), published="npm", archive=True)
        assert scope.reads(Paths.NPM + "node_modules/@scope/dep/package.json")
        assert scope.reads(Paths.NPM + "node_modules/dep/node_modules/inner/package.json")
        # A manifest under a bundled dependency's tests is not one npm installs.
        assert not scope.reads(Paths.NPM + "node_modules/dep/test/fixture/package.json")
        # And a pruned directory elsewhere still is not read.
        assert not scope.reads(Paths.NPM + "ui/node_modules/dep/package.json")

    def test_a_published_package_reads_the_members_its_root_lockfile_declares(self) -> None:
        scope = DependencyScope.of(Paths.units(Paths.PACKAGE), published="npm", archive=True)
        member = Paths.NPM + "packages/member/package.json"
        assert not scope.reads(member)
        scope.note_members([("x-1.0.0.tgz!package/packages/member", "npm")])
        assert scope.reads(member)
        # A manifest below the member is still not one.
        assert not scope.reads(Paths.NPM + "packages/member/test/package.json")

    def test_a_published_package_never_reads_its_ci_or_container_files(self) -> None:
        scope = DependencyScope.of(
            Paths.units([*Paths.PACKAGE, Paths.NPM + "docker-compose.yml"]),
            published="npm",
            archive=True,
        )
        assert not scope.reads(Paths.NPM + "Dockerfile")
        assert not scope.reads(Paths.NPM + "docker-compose.yml")

    def test_a_published_package_is_read_root_first(self) -> None:
        units = Paths.units(list(reversed(Paths.PACKAGE)))
        scope = DependencyScope.of(units, published="npm", archive=True)
        first = scope.ordered(units)[:3]
        assert {u.path for u in first} == {
            Paths.NPM + "package.json",
            Paths.NPM + "package-lock.json",
            Paths.NPM + "Dockerfile",
        }

    def test_any_other_target_keeps_its_order(self) -> None:
        units = Paths.units(Paths.REPOSITORY)
        assert DependencyScope.of(units, published="", archive=True).ordered(units) == units
