"""The ecosystems and manifest shapes added after the 0.4.0 review.

Every fixture here is in the format the real tool writes, not a shape invented
to suit the parser. That distinction is the whole reason these exist: the test
this suite previously had for `uv.lock` fed it `poetry.lock` content, so it
asserted the router and proved nothing about the format, and the parser raised
`AttributeError` on the first real file it met.

Each ecosystem gets the same three questions: does a real file parse, does the
version come out, and does a file that cannot be read say so rather than
returning an empty graph that looks like a project with no dependencies.
"""

from __future__ import annotations

import pytest

from cordon_scanner.core.content import FileContent
from cordon_scanner.core.limits import Limits
from cordon_scanner.core.models import Scope
from cordon_scanner.ecosystems.others import (
    BazelEcosystem,
    ConanEcosystem,
    CondaEcosystem,
    CranEcosystem,
    GradleEcosystem,
    HexEcosystem,
    MavenEcosystem,
    NuGetEcosystem,
    SwiftEcosystem,
)
from cordon_scanner.ecosystems.registry import EcosystemRegistry


def fc(path: str, text: str) -> FileContent:
    return FileContent.from_bytes(path, text.encode("utf-8"), Limits())


class TestGradleVersionCatalog:
    """`gradle/libs.versions.toml` is where a modern Gradle build states its
    versions, and a build that uses one has nothing in `build.gradle` for the
    older regex to find."""

    CATALOG = """
[versions]
junit = "5.10.2"
spring = "6.1.6"

[libraries]
junit-api = { module = "org.junit.jupiter:junit-jupiter-api", version.ref = "junit" }
spring-core = { group = "org.springframework", name = "spring-core", version.ref = "spring" }
gson = "com.google.code.gson:gson:2.10.1"
guava = { module = "com.google.guava:guava", version = { require = "33.0.0-jre" } }
"""

    def test_every_spelling_of_a_library_resolves(self) -> None:
        manifest = GradleEcosystem().parse_manifest(fc("libs.versions.toml", self.CATALOG))
        assert manifest.parse_error is None
        assert {d.name: d.spec for d in manifest.dependencies} == {
            "org.junit.jupiter:junit-jupiter-api": "5.10.2",
            "org.springframework:spring-core": "6.1.6",
            "com.google.code.gson:gson": "2.10.1",
            "com.google.guava:guava": "33.0.0-jre",
        }

    def test_malformed_toml_reports(self) -> None:
        graph = GradleEcosystem().parse_manifest(fc("libs.versions.toml", "[versions\nbroken"))
        assert graph.parse_error

    def test_verification_metadata_carries_the_hash(self) -> None:
        """The only Gradle file that records an artefact digest, and therefore
        the only one the integrity rules can answer from."""
        xml = """
<verification-metadata>
  <components>
    <component group="com.google.guava" name="guava" version="33.0.0-jre">
      <artifact name="guava-33.0.0-jre.jar">
        <sha256 value="a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f801"/>
      </artifact>
    </component>
  </components>
</verification-metadata>
"""
        graph = GradleEcosystem().parse_lockfile(fc("verification-metadata.xml", xml))
        assert [(e.name, e.version) for e in graph.entries] == [
            ("com.google.guava:guava", "33.0.0-jre")
        ]
        assert graph.entries[0].integrity == (
            "sha256:a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f801"
        )


class TestMavenDependencyManagement:
    POM = """
<project>
  <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId>
      <version>2.0.13</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId></dependency>
  </dependencies>
</project>
"""

    def test_a_managed_version_reaches_the_dependency(self) -> None:
        """Centralising versions is the recommended Maven layout, and reading
        only `<dependencies>` left every one of them with no version -- so no
        advisory could match."""
        manifest = MavenEcosystem().parse_manifest(fc("pom.xml", self.POM))
        assert [(d.name, d.spec) for d in manifest.dependencies] == [
            ("org.slf4j:slf4j-api", "2.0.13")
        ]

    def test_the_management_block_is_not_itself_a_dependency(self) -> None:
        manifest = MavenEcosystem().parse_manifest(fc("pom.xml", self.POM))
        assert len(manifest.dependencies) == 1


class TestNuGetAssets:
    ASSETS = """
{
  "version": 3,
  "targets": { "net8.0": {
      "Newtonsoft.Json/13.0.3": { "type": "package", "dependencies": {} },
      "Serilog/3.1.1": { "type": "package", "dependencies": { "Newtonsoft.Json": "13.0.3" } } } },
  "libraries": {
    "Newtonsoft.Json/13.0.3": { "sha512": "sha512-abc==", "type": "package" },
    "Serilog/3.1.1": { "sha512": "sha512-def==", "type": "package" },
    "MyApp/1.0.0": { "type": "project" } },
  "projectFileDependencyGroups": { "net8.0": [ "Serilog >= 3.1.1" ] }
}
"""

    def test_the_restored_graph_is_read(self) -> None:
        """`packages.lock.json` exists only when a project opted into locking;
        `project.assets.json` is written by every restore."""
        graph = NuGetEcosystem().parse_lockfile(fc("project.assets.json", self.ASSETS))
        by_name = {e.name: e for e in graph.entries}
        assert set(by_name) == {"Newtonsoft.Json", "Serilog"}
        assert by_name["Serilog"].version == "3.1.1"
        assert by_name["Serilog"].direct is True
        assert by_name["Newtonsoft.Json"].direct is False
        assert by_name["Serilog"].dependencies == ("Newtonsoft.Json",)

    def test_the_project_itself_is_not_a_dependency(self) -> None:
        graph = NuGetEcosystem().parse_lockfile(fc("project.assets.json", self.ASSETS))
        assert "MyApp" not in {e.name for e in graph.entries}


class TestSwift:
    def test_a_v3_resolved_file_is_read(self) -> None:
        text = """
{ "pins": [ { "identity": "swift-nio", "kind": "remoteSourceControl",
  "location": "https://github.com/apple/swift-nio.git",
  "state": { "revision": "abc123", "version": "2.65.0" } } ], "version": 3 }
"""
        graph = SwiftEcosystem().parse_lockfile(fc("Package.resolved", text))
        assert [(e.name, e.version) for e in graph.entries] == [("apple/swift-nio", "2.65.0")]

    def test_a_v1_resolved_file_is_read_too(self) -> None:
        """Version 1 nests under `object.pins` and calls the field
        `repositoryURL`. Both spellings are still in the wild."""
        text = """
{ "object": { "pins": [ { "package": "SwiftNIO",
  "repositoryURL": "https://github.com/apple/swift-nio.git",
  "state": { "version": "2.40.0" } } ] }, "version": 1 }
"""
        graph = SwiftEcosystem().parse_lockfile(fc("Package.resolved", text))
        assert [(e.name, e.version) for e in graph.entries] == [("apple/swift-nio", "2.40.0")]

    def test_a_branch_pin_keeps_its_revision(self) -> None:
        """A branch pin has no version, and the revision is the only thing that
        says what was built."""
        text = """
{ "pins": [ { "identity": "x", "location": "https://github.com/o/x.git",
  "state": { "branch": "main", "revision": "deadbeef" } } ], "version": 3 }
"""
        graph = SwiftEcosystem().parse_lockfile(fc("Package.resolved", text))
        assert graph.entries[0].version == "deadbeef"


class TestHex:
    LOCK = """
%{
  "plug": {:hex, :plug, "1.15.3", "712976f504418f6dff0a3e554c40d705a9bcf89a7ccef92fc6a5ef8f16a30a97", [:mix], [], "hexpm", "cc4365a3c010a56af402e0809208873d113e9c38c401cabd88027ef4f5c01fd2"},
}
"""

    def test_mix_lock_gives_version_and_hash(self) -> None:
        graph = HexEcosystem().parse_lockfile(fc("mix.lock", self.LOCK))
        assert [(e.name, e.version) for e in graph.entries] == [("plug", "1.15.3")]
        assert graph.entries[0].integrity is not None
        assert graph.entries[0].integrity.startswith("sha256:")

    def test_mix_exs_declares(self) -> None:
        text = '  defp deps do\n    [{:plug, "~> 1.15"}, {:jason, "~> 1.4"}]\n  end\n'
        manifest = HexEcosystem().parse_manifest(fc("mix.exs", text))
        assert {d.name for d in manifest.dependencies} == {"plug", "jason"}


class TestCran:
    def test_renv_lock_is_read(self) -> None:
        text = """
{ "R": {"Version": "4.3.1"},
  "Packages": { "jsonlite": { "Package": "jsonlite", "Version": "1.8.7",
    "Repository": "CRAN", "Hash": "266a20443ca13c65688b2116d5220f76",
    "Requirements": ["methods"] } } }
"""
        graph = CranEcosystem().parse_lockfile(fc("renv.lock", text))
        assert [(e.name, e.version) for e in graph.entries] == [("jsonlite", "1.8.7")]
        assert graph.entries[0].dependencies == ("methods",)

    def test_description_fields_wrap_across_lines(self) -> None:
        """A DESCRIPTION field is comma-separated and wraps, and `R` itself is
        not a package anyone can install from CRAN."""
        text = (
            "Package: demo\nImports:\n    jsonlite (>= 1.8.0),\n    curl\nSuggests:\n    testthat\n"
        )
        manifest = CranEcosystem().parse_manifest(fc("DESCRIPTION", text))
        by_name = {d.name: d for d in manifest.dependencies}
        assert set(by_name) == {"jsonlite", "curl", "testthat"}
        assert by_name["testthat"].scope is Scope.DEV
        assert by_name["jsonlite"].spec == ">= 1.8.0"


class TestConan:
    def test_conanfile_txt_sections_carry_scope(self) -> None:
        text = (
            "[requires]\nzlib/1.2.13\n\n[tool_requires]\ncmake/3.27.7\n\n[generators]\nCMakeDeps\n"
        )
        manifest = ConanEcosystem().parse_manifest(fc("conanfile.txt", text))
        by_name = {d.name: d for d in manifest.dependencies}
        assert by_name["zlib"].spec == "1.2.13"
        assert by_name["zlib"].scope is Scope.RUNTIME
        assert by_name["cmake"].scope is Scope.BUILD
        assert "CMakeDeps" not in by_name

    def test_conanfile_py_is_a_build_hook(self) -> None:
        """Conan imports it during a build, which makes it arbitrary code that
        runs on every machine that builds -- the standing `setup.py` has."""
        text = 'class R(ConanFile):\n    def requirements(self):\n        self.requires("zlib/1.2.13")\n'
        manifest = ConanEcosystem().parse_manifest(fc("conanfile.py", text))
        assert [h.kind for h in manifest.hooks] == ["build"]
        assert {d.name for d in manifest.dependencies} == {"zlib"}


class TestConda:
    def test_pip_entries_are_left_to_the_pypi_adapter(self) -> None:
        """A PyPI package under a conda purl matches no advisory and names
        nothing a reader could act on."""
        text = (
            "name: demo\nchannels: [conda-forge]\ndependencies:\n"
            "  - python=3.11\n  - numpy=1.26.4\n  - pip\n  - pip:\n      - requests==2.31.0\n"
        )
        manifest = CondaEcosystem().parse_manifest(fc("environment.yml", text))
        names = {d.name for d in manifest.dependencies}
        assert "numpy" in names
        assert "requests" not in names
        assert "python" not in names


class TestBazel:
    def test_module_bazel_declares_with_scope(self) -> None:
        text = (
            'module(name = "demo", version = "1.0")\n'
            'bazel_dep(name = "rules_python", version = "0.31.0")\n'
            'bazel_dep(name = "googletest", version = "1.14.0", dev_dependency = True)\n'
        )
        manifest = BazelEcosystem().parse_manifest(fc("MODULE.bazel", text))
        by_name = {d.name: d for d in manifest.dependencies}
        assert by_name["rules_python"].spec == "0.31.0"
        assert by_name["googletest"].scope is Scope.DEV


class TestEveryNewEcosystemIsRegistered:
    """A parser the registry does not know about is a parser that never runs."""

    @pytest.mark.parametrize("ecosystem_id", ["swift", "hex", "cran", "conan", "conda", "bazel"])
    def test_it_is_in_the_registry(self, ecosystem_id: str) -> None:
        assert EcosystemRegistry.get(ecosystem_id) is not None

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("Package.resolved", "swift"),
            ("mix.lock", "hex"),
            ("renv.lock", "cran"),
            ("conan.lock", "conan"),
            ("conda-lock.yml", "conda"),
            ("MODULE.bazel.lock", "bazel"),
            ("gradle/verification-metadata.xml", "gradle"),
            ("obj/project.assets.json", "nuget"),
        ],
    )
    def test_a_lockfile_is_routed_to_its_ecosystem(self, path: str, expected: str) -> None:
        assert EcosystemRegistry.lockfile_ecosystem(path) == expected

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("Package.swift", "swift"),
            ("mix.exs", "hex"),
            ("DESCRIPTION", "cran"),
            ("conanfile.txt", "conan"),
            ("environment.yml", "conda"),
            ("MODULE.bazel", "bazel"),
            ("gradle/libs.versions.toml", "gradle"),
        ],
    )
    def test_a_manifest_is_routed_to_its_ecosystem(self, path: str, expected: str) -> None:
        assert EcosystemRegistry.manifest_ecosystem(path) == expected
