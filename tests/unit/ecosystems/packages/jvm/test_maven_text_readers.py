"""Maven's less common inputs: BOM imports through a parent, dependency:tree output, checksum summaries and a jar's pom.properties (`ecosystems/packages/jvm/maven.py`)."""

from __future__ import annotations

from typing import Any

import pytest

from cordon_scanner.ecosystems.packages.jvm.maven import (
    MavenChecksums,
    MavenEcosystem,
    MavenTree,
    MavenWrapper,
)
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["maven"]

    @staticmethod
    def pom(artifact: str, body: str = "", parent: str = "") -> str:
        return (
            '<project xmlns="http://maven.apache.org/POM/4.0.0">'
            f"{parent}<groupId>g</groupId><artifactId>{artifact}</artifactId>"
            f"<version>1</version>{body}</project>"
        )


class TestBomImportThroughAParent:
    BOM = _Kit.pom(
        "bom",
        "<dependencyManagement><dependencies><dependency><groupId>g</groupId>"
        "<artifactId>lib</artifactId><version>1.0</version></dependency></dependencies>"
        "</dependencyManagement>",
    )

    @staticmethod
    def importing(*boms: str) -> str:
        imports = "".join(
            f"<dependency><groupId>g</groupId><artifactId>{bom}</artifactId><version>1</version>"
            "<type>pom</type><scope>import</scope></dependency>"
            for bom in boms
        )
        return _Kit.pom(
            "other",
            f"<dependencyManagement><dependencies>{imports}</dependencies></dependencyManagement>",
        )

    APP = _Kit.pom(
        "app",
        "<dependencies><dependency><groupId>g</groupId><artifactId>lib</artifactId>"
        "</dependency></dependencies>",
        parent="<parent><groupId>g</groupId><artifactId>other</artifactId><version>1</version>"
        "<relativePath>../other</relativePath></parent>",
    )

    def declared(self, other: str) -> Any:
        files = {
            "bom/pom.xml": _Kit.fc("bom/pom.xml", self.BOM),
            "sub/other/pom.xml": _Kit.fc("sub/other/pom.xml", other),
            "sub/app/pom.xml": _Kit.fc("sub/app/pom.xml", self.APP),
        }
        return _Kit.adapter().parse_in_tree(files["sub/app/pom.xml"], files)

    def test_a_version_the_parent_imports_from_a_bom_in_the_tree_is_the_one_used(self) -> None:
        manifest = self.declared(self.importing("bom"))
        assert [(d.name, d.spec) for d in manifest.dependencies] == [("g:lib", "1.0")]

    def test_a_bom_that_is_not_in_the_tree_is_named_as_unavailable_not_guessed(self) -> None:
        manifest = self.declared(self.importing("elsewhere"))
        assert [d.name for d in manifest.dependencies] == ["g:lib"]
        assert any(
            "g:elsewhere:1" in str(note)
            for note in (manifest.sources, manifest.dependencies[0].note)
        )


class TestTree:
    def parse(self, text: str):
        return MavenTree.parse(_Kit.fc("dependency-tree.txt", text), "maven")

    def test_an_empty_file_has_no_entries_and_no_error(self) -> None:
        graph = self.parse("")
        assert graph.entries == () and not graph.parse_error

    def test_text_that_is_not_tree_output_is_refused_with_how_many_lines(self) -> None:
        assert (
            "2 line(s) are not dependency:tree output"
            in self.parse("a:b:jar:1\nnot a line\nnor this").parse_error
        )

    def test_each_line_becomes_an_entry_with_its_scope_classifier_and_type(self) -> None:
        graph = self.parse(
            "g:app:jar:1\n"
            "+- g:lib:jar:2:compile\n"
            "|  \\- g:deep:war:3:runtime\n"
            "+- g:native:jar:linux:4:compile\n"
            "+- g:omitted:jar:5:compile (omitted for duplicate)\n"
            "+- g:opt:jar:6:compile (optional)\n"
            "+- g:short:jar:1\n"
        )
        seen = {e.name: e for e in graph.entries}
        assert set(seen) == {"g:lib", "g:deep", "g:native", "g:opt"}
        assert "type war" in seen["g:deep"].platform
        assert "classifier linux" in seen["g:native"].platform
        assert seen["g:lib"].dependencies == ("g:deep@3",)
        assert seen["g:opt"].scope.value == "optional"


class TestChecksums:
    def parse(self, name: str, text: str):
        return MavenChecksums.parse(_Kit.fc(name, text), "maven")

    def test_a_file_that_is_not_a_checksum_summary_is_refused(self) -> None:
        assert "not a checksum summary" in self.parse("notes.txt", "x").parse_error

    def test_the_plain_jar_wins_over_a_classified_jar_and_a_pom(self) -> None:
        text = (
            "# comment\n\n"
            + "c" * 40
            + "  g/lib/1.0/lib-1.0.pom\n"
            + "b" * 40
            + "  g/lib/1.0/lib-1.0-sources.jar\n"
            + "a" * 40
            + "  g/lib/1.0/lib-1.0.jar\n"
            + "d" * 40
            + "  g/lib/1.0/lib-1.0.module\n"
        )
        [entry] = self.parse("SHA1SUMS.sha1", text).entries
        assert (entry.name, entry.version, entry.integrity) == ("g:lib", "1.0", "sha1:" + "a" * 40)

    def test_lines_that_are_not_a_digest_and_a_repository_path_are_counted_not_guessed(
        self,
    ) -> None:
        text = (
            "onlyone\n"
            + "a" * 40
            + "  short/path.jar\n"
            + "a" * 40
            + "  g/../x/1.0/x-1.0.jar\n"
            + "a" * 40
            + "  g/lib/1.0/other-1.0.jar\n"
        )
        assert "4 line(s) are not" in self.parse("x.sha1", text).parse_error


class TestPomProperties:
    def identity(self, path: str, text: str):
        return MavenEcosystem.pom_identity(path, text)

    def test_a_jar_is_named_by_the_pom_it_was_published_as(self) -> None:
        text = "groupId=g\nartifactId=lib\nversion=1.0\n"
        assert self.identity("lib-1.0.jar!META-INF/maven/g/lib/pom.properties", text) == (
            "g:lib",
            "1.0",
        )

    def test_a_pom_of_something_the_jar_bundles_does_not_name_the_jar(self) -> None:
        text = "groupId=g\nartifactId=bundled\nversion=9\n"
        assert self.identity("lib-1.0.jar!META-INF/maven/g/bundled/pom.properties", text) is None

    @pytest.mark.parametrize("missing", ["groupId=g\n", "groupId=g\nartifactId=lib\n"])
    def test_a_pom_properties_without_all_three_names_nothing(self, missing: str) -> None:
        assert self.identity("lib-1.0.jar!META-INF/maven/g/lib/pom.properties", missing) is None

    def test_the_release_manifest_is_the_pom_properties_inside_a_jar(self) -> None:
        pattern = _Kit.adapter().release_manifest()
        assert pattern.search("lib-1.0.jar!META-INF/maven/g/lib/pom.properties")


class TestPomsInATree:
    def test_a_sibling_pom_that_cannot_be_read_does_not_stop_this_one(self) -> None:
        good = _Kit.fc("a/pom.xml", _Kit.pom("a"))
        broken = _Kit.fc("b/pom.xml", "<project>")
        manifest = _Kit.adapter().parse_in_tree(good, {"a/pom.xml": good, "b/pom.xml": broken})
        assert not manifest.parse_error

    def test_this_pom_when_it_cannot_be_read_is_an_error_naming_why(self) -> None:
        broken = _Kit.fc("a/pom.xml", "<project>")
        manifest = _Kit.adapter().parse_in_tree(broken, {"a/pom.xml": broken})
        assert manifest.parse_error.startswith("not a readable POM")

    def test_a_plugin_listed_twice_or_with_no_artifact_is_declared_once_or_not_at_all(self) -> None:
        plugin = (
            "<plugin><groupId>g</groupId><artifactId>p</artifactId><version>1</version></plugin>"
        )
        nameless = "<plugin><groupId>g</groupId><version>1</version></plugin>"
        text = _Kit.pom("a", f"<build><plugins>{plugin}{plugin}{nameless}</plugins></build>")
        content = _Kit.fc("pom.xml", text)
        manifest = _Kit.adapter().parse_in_tree(content, {"pom.xml": content})
        assert [d.name for d in manifest.dependencies] == ["g:p"]


class TestWrapper:
    def parse(self, text: str):
        return MavenWrapper.parse(_Kit.fc(".mvn/wrapper/maven-wrapper.properties", text), "maven")

    def test_comments_and_lines_without_a_value_are_ignored_and_the_distribution_is_named(
        self,
    ) -> None:
        manifest = self.parse(
            "# a comment\n! another\n\nnot a pair\n"
            "distributionUrl=https\\://repo.example.invalid/apache-maven/3.9.6/apache-maven-3.9.6-bin.zip\n"
        )
        assert [(d.name, d.spec) for d in manifest.dependencies] == [
            ("org.apache.maven:apache-maven", "3.9.6")
        ]

    def test_a_wrapper_that_names_no_distribution_is_an_error_not_an_empty_build(self) -> None:
        assert "no distributionUrl" in self.parse("# nothing\n").parse_error


class TestMoreMaven:
    def test_a_pom_without_a_parent_has_no_parent_in_the_tree(self) -> None:
        from cordon_scanner.ecosystems.packages.jvm.maven import MavenBuild, MavenPom
        from cordon_scanner.foundation.formats.safexml import SafeXml

        pom = MavenPom("pom.xml", SafeXml.parse(_Kit.pom("a"), source="pom.xml"))
        assert MavenBuild({"pom.xml": pom}).parent_of(pom) is None

    def test_a_pom_that_is_not_among_the_files_given_is_not_readable(self) -> None:
        content = _Kit.fc("a/pom.xml", _Kit.pom("a"))
        manifest = _Kit.adapter().parse_in_tree(content, {})
        assert manifest.parse_error == "not a readable POM"

    def test_the_release_identity_of_a_jar_is_its_pom_properties(self) -> None:
        adapter = _Kit.adapter()
        text = "groupId=g\nartifactId=lib\nversion=1.0\n"
        path = "lib-1.0.jar!META-INF/maven/g/lib/pom.properties"
        found = adapter.release_manifest().search(path)
        assert adapter.release_identity(path, text, found) == ("g:lib", "1.0")
