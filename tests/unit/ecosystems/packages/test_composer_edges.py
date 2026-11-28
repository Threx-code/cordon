"""Composer manifests, locks and plugin hooks on the shapes that are odd, broken or restricted (`ecosystems/packages/composer.py`)."""

from __future__ import annotations

import json
from typing import Any, ClassVar

from cordon_scanner.ecosystems.packages.composer import ComposerLock, ComposerManifest
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["composer"]

    @staticmethod
    def manifest(data: Any, path: str = "composer.json") -> Any:
        return _Kit.adapter().parse_manifest(_Kit.fc(path, json.dumps(data)))

    @staticmethod
    def lock(data: Any) -> Any:
        return _Kit.adapter().parse_lockfile(_Kit.fc("composer.lock", json.dumps(data)))


class TestManifest:
    def test_a_require_section_that_is_not_an_object_is_refused(self) -> None:
        assert _Kit.manifest({"require": []}).parse_error == "`require` is not an object"

    def test_packagist_disabled_by_either_spelling_or_as_a_bare_false_is_said(self) -> None:
        for repositories in (
            [{"packagist.org": False}],
            [{"packagist": False}],
            [False],
            {"packagist.org": False},
        ):
            manifest = _Kit.manifest({"repositories": repositories})
            assert "repository packagist.org: disabled" in manifest.sources

    def test_a_repository_with_a_type_and_url_is_named(self) -> None:
        manifest = _Kit.manifest(
            {"repositories": [{"type": "composer", "url": "https://repo.example.invalid"}]}
        )
        assert "repository composer: https://repo.example.invalid" in manifest.sources


class TestPluginPermission:
    def test_true_and_false_allow_or_refuse_every_plugin(self) -> None:
        assert ComposerManifest.plugin_allowed("a/b", True) is True
        assert ComposerManifest.plugin_allowed("a/b", False) is False

    def test_a_pattern_table_allows_what_it_matches_and_refuses_what_it_does_not(self) -> None:
        assert ComposerManifest.plugin_allowed("a/b", {"a/*": True}) is True
        assert ComposerManifest.plugin_allowed("a/b", {"a/*": False}) is False
        assert ComposerManifest.plugin_allowed("c/d", {"a/*": True}) is False

    def test_no_setting_says_nothing(self) -> None:
        assert ComposerManifest.plugin_allowed("a/b", None) is None


class TestLock:
    def test_a_lock_without_packages_is_refused(self) -> None:
        assert _Kit.lock({"content-hash": "x"}).parse_error == "no `packages` list"

    def test_a_section_that_is_not_a_list_is_refused(self) -> None:
        assert _Kit.lock({"packages": {}}).parse_error == "`packages` is not a list"

    def test_an_entry_without_a_name_is_skipped_and_an_abandoned_package_is_marked(self) -> None:
        graph = _Kit.lock(
            {
                "packages": [
                    {"version": "1.0"},
                    "text",
                    {"name": "a/b", "version": "1.0", "abandoned": True},
                    {"name": "c/d", "version": "2.0", "abandoned": "e/f"},
                ],
                "packages-dev": [],
            }
        )
        assert {e.name: e.deprecated for e in graph.entries} == {
            "a/b": "abandoned",
            "c/d": "abandoned; use e/f instead",
        }


class TestPluginHooks:
    LOCK: ClassVar[dict[str, Any]] = {
        "packages": [
            {
                "name": "a/plug",
                "version": "1",
                "type": "composer-plugin",
                "extra": {"class": "A\\P"},
            },
            {
                "name": "b/plug",
                "version": "1",
                "type": "composer-plugin",
                "extra": {"class": "B\\P"},
            },
        ],
        "packages-dev": [],
    }

    def hooks(self, manifest: Any) -> list[str]:
        files = {"composer.lock": _Kit.fc("composer.lock", json.dumps(self.LOCK))}
        if manifest is not None:
            files["composer.json"] = _Kit.fc("composer.json", manifest)
        result = _Kit.adapter().parse_in_tree(files["composer.lock"], files)
        return [h.name for h in result.hooks]

    def test_with_no_composer_json_every_plugin_is_reported(self) -> None:
        assert self.hooks(None) == ["a/plug", "b/plug"]

    def test_a_plugin_the_config_refuses_is_not_a_hook(self) -> None:
        text = json.dumps({"config": {"allow-plugins": {"a/*": True}}})
        assert self.hooks(text) == ["a/plug"]

    def test_a_composer_json_that_cannot_be_read_leaves_every_plugin_reported(self) -> None:
        assert self.hooks("{nope") == ["a/plug", "b/plug"]


class TestPluginList:
    def test_a_lock_that_is_not_json_lists_no_plugins(self) -> None:
        assert ComposerLock.plugins(_Kit.fc("composer.lock", "{nope")) == []


class TestOtherFiles:
    def test_an_auth_json_that_is_not_json_is_an_error_that_does_not_quote_it(self) -> None:
        manifest = _Kit.adapter().parse_manifest(_Kit.fc("auth.json", "{secret-token"))
        assert manifest.parse_error == "not valid JSON"

    def test_a_lock_that_is_not_json_is_an_error_as_a_manifest(self) -> None:
        files = {"composer.lock": _Kit.fc("composer.lock", "{nope")}
        result = _Kit.adapter().parse_in_tree(files["composer.lock"], files)
        assert result.parse_error.startswith("invalid JSON")
