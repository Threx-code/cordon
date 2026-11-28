"""Cargo manifests, locks, features and config files on the shapes written less often (`ecosystems/packages/cargo.py`)."""

from __future__ import annotations

from typing import Any

from cordon_scanner.ecosystems.packages.cargo import CargoFeatures
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["cargo"]


class TestManifest:
    def test_a_target_table_that_is_not_a_table_is_skipped_and_one_that_is_names_its_condition(
        self,
    ) -> None:
        text = (
            '[package]\nname = "p"\nversion = "0.1.0"\n\n'
            "[target]\nweird = 5\n\n"
            "[target.'cfg(windows)'.dependencies]\nwinapi = \"0.3\"\n"
        )
        manifest = _Kit.adapter().parse_manifest(_Kit.fc("Cargo.toml", text))
        [dependency] = manifest.dependencies
        assert dependency.name == "winapi"
        assert any("cfg(windows)" in p for p in dependency.platform)


class TestLock:
    def test_packages_none_of_which_has_a_name_are_refused(self) -> None:
        graph = _Kit.adapter().parse_lockfile(_Kit.fc("Cargo.lock", '[[package]]\nversion = "1"\n'))
        assert graph.parse_error == "no [[package]] could be read"


class TestFeatures:
    def test_a_feature_that_enables_itself_is_followed_once(self) -> None:
        from cordon_scanner.ecosystems.base import DeclaredDependency
        from cordon_scanner.foundation.models import Scope

        declared = [
            DeclaredDependency(name="x", spec="1", scope=Scope.OPTIONAL, field_name="dependencies")
        ]
        features = {"default": ["a"], "a": ["default", "dep:x"]}
        [annotated] = CargoFeatures.annotate(declared, features)
        assert "feature a (enabled by default)" in annotated.platform


class TestConfig:
    def test_a_config_that_is_not_toml_is_an_error(self) -> None:
        manifest = _Kit.adapter().parse_manifest(_Kit.fc(".cargo/config.toml", "[source"))
        assert manifest.parse_error.startswith("invalid TOML")

    def test_a_source_replacement_that_is_not_a_table_is_skipped(self) -> None:
        text = '[source]\njunk = 5\n\n[source.crates-io]\nreplace-with = "mirror"\n'
        manifest = _Kit.adapter().parse_manifest(_Kit.fc(".cargo/config.toml", text))
        assert "source crates-io replaced with mirror" in manifest.sources
