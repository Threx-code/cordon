"""Gradle lock files, verification metadata and version catalogs on the shapes written less often (`ecosystems/packages/jvm/gradle.py`)."""

from __future__ import annotations

from typing import Any

import pytest

from cordon_scanner.ecosystems.packages.jvm.gradle import GradleLock
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits
from cordon_scanner.foundation.models import Scope


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["gradle"]

    @staticmethod
    def lock(path: str, text: str) -> Any:
        return _Kit.adapter().parse_lockfile(_Kit.fc(path, text))


class TestScope:
    @pytest.mark.parametrize(
        ("configurations", "scope"),
        [
            (["runtimeClasspath"], Scope.RUNTIME),
            (["compileClasspath"], Scope.BUILD),
            (["annotationProcessor"], Scope.BUILD),
            (["customConfiguration"], Scope.RUNTIME),
            (["testRuntimeClasspath"], Scope.TEST),
        ],
    )
    def test_the_configurations_a_module_resolved_in_decide_its_scope(
        self, configurations: list[str], scope: Scope
    ) -> None:
        assert GradleLock.scope(configurations, buildscript=False) is scope

    def test_a_buildscript_lock_is_tooling(self) -> None:
        assert GradleLock.scope(["classpath"], buildscript=True) is Scope.TOOL


class TestLockFiles:
    def test_a_file_where_no_line_is_a_module_is_refused_with_the_count(self) -> None:
        graph = _Kit.lock("gradle.lockfile", "this is not\nnor this\n")
        assert graph.parse_error == "2 line(s) are not 'group:name:version=configurations'"


class TestVerificationMetadata:
    def test_text_that_is_not_xml_or_the_wrong_document_is_refused(self) -> None:
        bad = _Kit.lock("gradle/verification-metadata.xml", "<verification-metadata>")
        assert bad.parse_error.startswith("not readable verification metadata")
        other = _Kit.lock("gradle/verification-metadata.xml", "<other/>")
        assert other.parse_error == "not a <verification-metadata> document"

    def test_a_component_without_group_name_and_version_is_skipped(self) -> None:
        text = (
            "<verification-metadata><components>"
            '<component group="g" name="n"><artifact name="n-1.jar"><sha256 value="'
            + "a"
            * 64
            + '"/></artifact></component>'
            "</components></verification-metadata>"
        )
        assert _Kit.lock("gradle/verification-metadata.xml", text).entries == ()


class TestCatalogs:
    def test_a_catalog_names_what_its_libraries_resolve_to(self) -> None:
        text = '[versions]\nguava = "33.0"\n[libraries]\nguava = {module = "com.google.guava:guava", version.ref = "guava"}\n'
        manifest = _Kit.adapter().parse_manifest(_Kit.fc("gradle/libs.versions.toml", text))
        assert not manifest.parse_error
        assert "33.0" in manifest.shared_specs.values()

    def test_a_catalog_that_is_not_toml_is_refused(self) -> None:
        manifest = _Kit.adapter().parse_manifest(
            _Kit.fc("gradle/libs.versions.toml", "[versions\n")
        )
        assert manifest.parse_error.startswith("invalid TOML")

    def test_the_release_identity_of_a_gradle_jar_is_its_pom_properties(self) -> None:
        adapter = _Kit.adapter()
        path = "lib-1.0.jar!META-INF/maven/g/lib/pom.properties"
        found = adapter.release_manifest().search(path)
        assert adapter.release_identity(
            path, "groupId=g\nartifactId=lib\nversion=1.0\n", found
        ) == (
            "g:lib",
            "1.0",
        )


class TestInheritedProperties:
    def test_a_build_nested_past_the_walk_limit_inherits_nothing_and_stops(self) -> None:
        from cordon_scanner.ecosystems.packages.jvm.gradle import GradleEcosystem

        deep = "/".join(["d"] * 40) + "/build.gradle"
        assert GradleEcosystem._inherited_extras(deep, "elsewhere", {}) == {}
