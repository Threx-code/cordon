"""go.mod and go.work on the directives and blocks written less often (`ecosystems/packages/go.py`)."""

from __future__ import annotations

from typing import Any

from cordon_scanner.ecosystems.packages.go import GoModFile
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["gomod"]

    @staticmethod
    def manifest(text: str, path: str = "go.mod") -> Any:
        return _Kit.adapter().parse_manifest(_Kit.fc(path, text))


HEAD = "module example.invalid/app\n\ngo 1.22\n"


class TestDirectives:
    def test_toolchain_default_is_ignored(self) -> None:
        manifest = _Kit.manifest(HEAD + "toolchain default\n")
        assert not manifest.parse_error

    def test_a_block_opened_by_an_unknown_directive_is_an_error_naming_the_line_only(self) -> None:
        manifest = _Kit.manifest(HEAD + "frobnicate (\n  x\n)\n")
        assert "line 4: a block opened by an unknown directive" in manifest.parse_error
        assert "frobnicate" not in manifest.parse_error

    def test_retract_and_godebug_blocks_are_read_and_a_bad_entry_is_named(self) -> None:
        good = HEAD + "retract (\n  v1.0.0\n  [v1.1.0, v1.2.0]\n)\ngodebug (\n  default=go1.21\n)\n"
        assert not _Kit.manifest(good).parse_error
        bad = HEAD + "retract (\n  nonsense\n)\ngodebug (\n  not-a-setting\n)\n"
        assert "malformed retract entry" in _Kit.manifest(bad).parse_error

    def test_a_block_that_never_closes_is_named(self) -> None:
        assert (
            "require block is never closed"
            in _Kit.manifest(HEAD + "require (\n  a.b/c v1.0.0\n").parse_error
        )


class TestLanguageVersion:
    def test_before_1_17_only_direct_modules_are_listed_and_with_no_go_line_too(self) -> None:
        assert GoModFile.lists_direct_only("1.16") is True
        assert GoModFile.lists_direct_only("1.17") is False
        assert GoModFile.lists_direct_only(None) is True

    def test_a_language_version_that_is_not_a_number_is_not_before_1_17(self) -> None:
        assert GoModFile.lists_direct_only("1.x") is False


class TestExcludes:
    TEXT = HEAD + "require (\n  a.b/c v1.0.0\n  d.e/f v2.0.0\n)\nexclude a.b/c v1.0.0\n"

    def test_an_excluded_version_is_not_declared_or_locked(self) -> None:
        manifest = _Kit.manifest(self.TEXT)
        names = {d.name for d in manifest.dependencies}
        assert "d.e/f" in names and "a.b/c" not in names
        graph = _Kit.adapter().parse_lockfile(_Kit.fc("go.mod", self.TEXT))
        locked = {e.name for e in graph.entries}
        assert "d.e/f" in locked and "a.b/c" not in locked


class TestWorkspaces:
    def test_a_single_line_use_names_a_directory_and_a_block_names_several(self) -> None:
        text = "go 1.22\nuse ./a\nuse (\n  ./b\n  ./c\n)\n"
        manifest = _Kit.manifest(text, "go.work")
        assert not manifest.parse_error
        assert [d.name for d in manifest.dependencies] == ["go"]
