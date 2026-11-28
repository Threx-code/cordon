"""DESCRIPTION, renv.lock and repository index files on the shapes written less often (`ecosystems/packages/cran.py`)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from cordon_scanner.ecosystems.packages.cran import Dcf, Description
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["cran"]

    @staticmethod
    def lock(data: Any) -> Any:
        text = data if isinstance(data, str) else json.dumps(data)
        return _Kit.adapter().parse_lockfile(_Kit.fc("renv.lock", text))


class TestDcf:
    def test_a_continuation_with_no_field_before_it_is_refused(self) -> None:
        with pytest.raises(ValueError, match="a continuation with no field before it"):
            Dcf.records("  orphan\n")

    def test_a_line_that_is_neither_a_field_nor_a_continuation_is_refused(self) -> None:
        with pytest.raises(ValueError, match="not a `Field: value` line"):
            Dcf.records("not a field\n")


class TestRemotes:
    def test_each_remote_kind_is_a_source_spec(self) -> None:
        remotes = Description.remotes(
            "git::https://git.example.invalid/a.git, url::https://x.example.invalid/b.tar.gz, "
            "local::../c, bioc::release/d, owner/e@v1, , gitlab::g/h"
        )
        assert remotes == {
            "a": "git+https://git.example.invalid/a.git",
            "b.tar.gz": "https://x.example.invalid/b.tar.gz",
            "c": "path:../c",
            "d": "registry:bioconductor",
            "e": "git+https://github.com/owner/e#v1",
            "h": "git+https://gitlab.com/g/h",
        }


class TestSourceFolders:
    def test_a_package_with_a_src_folder_and_no_other_hook_says_it_compiles_on_install(
        self,
    ) -> None:
        description = _Kit.fc(
            "pkg/DESCRIPTION", "Package: p\nVersion: 1.0\nLicense: MIT\nTitle: T\nDescription: D\n"
        )
        files = {
            "pkg/DESCRIPTION": description,
            "pkg/src/x.c": _Kit.fc("pkg/src/x.c", "int x;"),
        }
        manifest = Description.with_install_scripts(
            _Kit.adapter().parse_manifest(description), list(files)
        )
        assert manifest.parse_error is None, manifest.parse_error
        assert [h.command for h in manifest.hooks] == ["R CMD INSTALL compiles src/"]


class TestRenv:
    def test_a_lock_that_is_not_json_even_with_na_fixed_is_refused(self) -> None:
        assert _Kit.lock("{nope").parse_error.startswith("invalid JSON")

    def test_a_lock_without_a_packages_object_is_refused(self) -> None:
        assert _Kit.lock({"R": {}}).parse_error == "no `Packages` object"

    def test_a_package_that_is_not_an_object_is_skipped_and_a_git_source_names_url_and_commit(
        self,
    ) -> None:
        graph = _Kit.lock(
            {
                "Packages": {
                    "junk": "text",
                    "dev": {
                        "Package": "dev",
                        "Version": "1.0",
                        "Source": "Git",
                        "RemoteUrl": "https://git.example.invalid/dev.git",
                        "RemoteSha": "abc123",
                    },
                }
            }
        )
        assert [(e.name, e.resolved_from) for e in graph.entries] == [
            ("dev", "git+https://git.example.invalid/dev.git#abc123")
        ]

    def test_renv_settings_that_are_not_json_are_refused_and_a_repository_index_is_counted(
        self,
    ) -> None:
        bad = _Kit.adapter().parse_manifest(_Kit.fc("renv/settings.json", "{nope"))
        assert bad.parse_error.startswith("invalid JSON")
        index = _Kit.adapter().parse_manifest(
            _Kit.fc("src/contrib/PACKAGES", "Package: a\nVersion: 1\n\nPackage: b\nVersion: 2\n")
        )
        assert "repository index serving 2 package(s)" in index.sources
        assert (
            _Kit.adapter().parse_manifest(_Kit.fc("src/contrib/PACKAGES", "not a field\n")).sources
            == ()
        )
        assert (
            _Kit.adapter().parse_manifest(_Kit.fc("src/contrib/PACKAGES", "Other: x\n")).sources
            == ()
        )
