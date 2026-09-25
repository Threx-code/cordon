"""Lockfile and manifest parsers, format by format.

Parsers fail quietly. A misparse yields an empty graph, the scan succeeds, and
the result is indistinguishable from a project with no dependencies -- which is
a false negative across every package in the tree.

So each format is tested for three things: that a well-formed file yields the
expected packages, that malformed input is reported rather than swallowed, and
that an empty result is only ever produced when the file genuinely has no
entries.
"""

from __future__ import annotations

import pytest

from cordon_scanner.core.content import FileContent
from cordon_scanner.core.models import Scope
from cordon_scanner.ecosystems.npm import NpmEcosystem
from cordon_scanner.ecosystems.others import (
    CargoEcosystem,
    CocoaPodsEcosystem,
    ComposerEcosystem,
    GoEcosystem,
    GradleEcosystem,
    NuGetEcosystem,
    PubEcosystem,
    RubyGemsEcosystem,
)
from cordon_scanner.ecosystems.pypi import PypiEcosystem


def fc(path: str, text: str) -> FileContent:
    return FileContent.from_bytes(path, text.encode("utf-8"))


# ---------------------------------------------------------------------------
# Python lockfiles
# ---------------------------------------------------------------------------


POETRY_LOCK = """
[[package]]
name = "requests"
version = "2.31.0"
category = "main"
[package.dependencies]
urllib3 = ">=1.21.1"
[[package.files]]
hash = "sha256:aaa"

[[package]]
name = "pytest"
version = "8.0.0"
category = "dev"
"""

PIPFILE_LOCK = """
{"_meta":{},
 "default":{"requests":{"version":"==2.31.0","hashes":["sha256:aaa"]}},
 "develop":{"pytest":{"version":"==8.0.0","hashes":["sha256:bbb"]}}}
"""


class TestPythonLockfiles:
    def setup_method(self) -> None:
        self.eco = PypiEcosystem()

    def test_poetry_lock(self) -> None:
        graph = self.eco.parse_lockfile(fc("poetry.lock", POETRY_LOCK))
        by_name = {e.name: e for e in graph.entries}
        assert by_name["requests"].version == "2.31.0"
        assert by_name["pytest"].scope is Scope.DEV
        assert "urllib3" in by_name["requests"].dependencies

    def test_poetry_lock_records_hashes(self) -> None:
        graph = self.eco.parse_lockfile(fc("poetry.lock", POETRY_LOCK))
        assert {e.name: e.integrity for e in graph.entries}["requests"] == "sha256:aaa"

    def test_pipfile_lock(self) -> None:
        graph = self.eco.parse_lockfile(fc("Pipfile.lock", PIPFILE_LOCK))
        by_name = {e.name: e for e in graph.entries}
        assert by_name["requests"].version == "2.31.0"
        assert by_name["pytest"].scope is Scope.DEV

    def test_uv_lock_is_read_in_its_own_shape(self) -> None:
        """`uv.lock` shares poetry's `[[package]]` table and nothing inside it.

        Reading it as a poetry lockfile raised `AttributeError` on the first
        package -- `dependencies` is an array of tables here, not a mapping --
        and the engine reported a parser failure for every uv-locked project,
        so none of them had a dependency graph, an advisory match or an SBOM.
        """
        graph = self.eco.parse_lockfile(fc("uv.lock", UV_LOCK))
        assert graph.parse_error is None
        by_name = {e.name: e for e in graph.entries}
        assert by_name["django"].version == "1.2.1"
        assert by_name["django"].integrity == "sha256:aaaa"
        assert by_name["django"].dependencies == ("sqlparse",)
        assert by_name["pytest"].scope is Scope.DEV
        assert by_name["sqlparse"].scope is Scope.RUNTIME

    def test_pdm_lock_is_read_in_its_own_shape(self) -> None:
        """PDM writes requirement *strings* where uv writes tables, and records
        group membership on the package."""
        graph = self.eco.parse_lockfile(fc("pdm.lock", PDM_LOCK))
        assert graph.parse_error is None
        by_name = {e.name: e for e in graph.entries}
        assert by_name["jinja2"].version == "2.10"
        assert by_name["jinja2"].dependencies == ("MarkupSafe",)
        assert by_name["pytest"].scope is Scope.DEV

    def test_a_lockfile_with_no_package_tables_reports_rather_than_empties(self) -> None:
        graph = self.eco.parse_lockfile(fc("uv.lock", "version = 1\n"))
        assert graph.parse_error

    @pytest.mark.parametrize(
        ("path", "text"),
        [
            ("poetry.lock", "[[package]\nbroken"),
            ("Pipfile.lock", "{not json"),
        ],
    )
    def test_malformed_lockfiles_report_rather_than_swallow(self, path: str, text: str) -> None:
        """An empty graph and an unparseable file must not look the same."""
        graph = self.eco.parse_lockfile(fc(path, text))
        assert graph.parse_error
        assert graph.entries == ()

    def test_an_unsupported_name_is_marked_unsupported(self) -> None:
        graph = self.eco.parse_lockfile(fc("something.lock", ""))
        assert graph.parse_error and "unsupported" in graph.parse_error


class TestPythonManifests:
    def setup_method(self) -> None:
        self.eco = PypiEcosystem()

    def test_pipfile(self) -> None:
        manifest = self.eco.parse_manifest(
            fc(
                "Pipfile",
                '[packages]\nrequests = "*"\n[dev-packages]\npytest = ">=8"\n',
            )
        )
        by_name = {d.name: d for d in manifest.dependencies}
        assert by_name["pytest"].scope is Scope.DEV

    def test_poetry_style_pyproject(self) -> None:
        manifest = self.eco.parse_manifest(
            fc(
                "pyproject.toml",
                '[tool.poetry]\nname = "d"\nversion = "1.0"\n'
                '[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "^2.31"\n'
                '[tool.poetry.dev-dependencies]\npytest = "^8.0"\n',
            )
        )
        names = {d.name for d in manifest.dependencies}
        assert "requests" in names
        assert "python" not in names, "the interpreter is not a dependency"

    def test_a_table_valued_dependency_spec(self) -> None:
        manifest = self.eco.parse_manifest(
            fc(
                "pyproject.toml",
                "[tool.poetry.dependencies]\n"
                'internal = { git = "https://example.invalid/x.git" }\n',
            )
        )
        assert manifest.dependencies[0].spec.startswith("https://")
        assert manifest.dependencies[0].is_non_registry

    def test_a_local_build_backend_is_a_hook(self) -> None:
        """A build backend inside the repository runs during every build,
        including inside the packaging environment."""
        manifest = self.eco.parse_manifest(
            fc(
                "pyproject.toml",
                '[build-system]\nbuild-backend = "./local_backend"\n',
            )
        )
        assert manifest.hooks

    def test_pep508_direct_reference(self) -> None:
        manifest = self.eco.parse_manifest(
            fc("requirements.txt", "mypkg @ https://example.invalid/mypkg.whl\n")
        )
        assert manifest.dependencies[0].name == "mypkg"
        assert manifest.dependencies[0].is_non_registry

    def test_environment_markers_are_stripped(self) -> None:
        manifest = self.eco.parse_manifest(
            fc("requirements.txt", 'requests>=2.0; python_version < "3.12"\n')
        )
        assert manifest.dependencies[0].name == "requests"

    def test_extras_are_stripped_from_the_name(self) -> None:
        manifest = self.eco.parse_manifest(fc("requirements.txt", "requests[security]>=2.0\n"))
        assert manifest.dependencies[0].name == "requests"

    def test_option_lines_are_ignored(self) -> None:
        manifest = self.eco.parse_manifest(
            fc(
                "requirements.txt",
                "--index-url https://example.invalid/simple\n-r other.txt\nrequests==2.31.0\n",
            )
        )
        assert [d.name for d in manifest.dependencies] == ["requests"]

    def test_malformed_toml_is_reported(self) -> None:
        manifest = self.eco.parse_manifest(fc("pyproject.toml", "[broken"))
        assert manifest.parse_error


# ---------------------------------------------------------------------------
# Other ecosystems
# ---------------------------------------------------------------------------


class TestOtherLockfiles:
    def test_composer_lock(self) -> None:
        graph = ComposerEcosystem().parse_lockfile(
            fc(
                "composer.lock",
                '{"packages":[{"name":"a/b","version":"1.0.0",'
                '"dist":{"shasum":"abc","url":"https://repo.packagist.org/x.zip"},'
                '"require":{"c/d":"^1.0"}}],'
                '"packages-dev":[{"name":"e/f","version":"2.0.0"}]}',
            )
        )
        by_name = {e.name: e for e in graph.entries}
        assert by_name["a/b"].integrity == "abc"
        assert by_name["e/f"].scope is Scope.DEV
        assert "c/d" in by_name["a/b"].dependencies

    def test_composer_lock_malformed(self) -> None:
        graph = ComposerEcosystem().parse_lockfile(fc("composer.lock", "{bad"))
        assert graph.parse_error

    def test_gemfile_lock(self) -> None:
        graph = RubyGemsEcosystem().parse_lockfile(
            fc(
                "Gemfile.lock",
                "GEM\n  remote: https://rubygems.org/\n  specs:\n"
                "    rails (7.1.0)\n    puma (6.4.0)\n",
            )
        )
        assert {e.name for e in graph.entries} == {"rails", "puma"}

    def test_podfile_lock(self) -> None:
        graph = CocoaPodsEcosystem().parse_lockfile(
            fc("Podfile.lock", "PODS:\n  - Alamofire (5.8.1)\n  - SwiftyJSON (5.0.1)\n")
        )
        assert {e.name for e in graph.entries} == {"Alamofire", "SwiftyJSON"}

    def test_podfile_manifest(self) -> None:
        manifest = CocoaPodsEcosystem().parse_manifest(
            fc("Podfile", "target 'App' do\n  pod 'Alamofire', '~> 5.8'\n  pod 'SnapKit'\nend\n")
        )
        assert {d.name for d in manifest.dependencies} == {"Alamofire", "SnapKit"}

    def test_pubspec(self) -> None:
        manifest = PubEcosystem().parse_manifest(
            fc(
                "pubspec.yaml",
                "name: demo\nversion: 1.0.0\n"
                "dependencies:\n  http: ^1.1.0\n"
                "dev_dependencies:\n  test: ^1.24.0\n",
            )
        )
        by_name = {d.name: d for d in manifest.dependencies}
        assert by_name["test"].scope is Scope.DEV
        assert manifest.name == "demo"

    def test_pubspec_lock(self) -> None:
        graph = PubEcosystem().parse_lockfile(
            fc(
                "pubspec.lock",
                "packages:\n"
                "  http:\n"
                "    dependency: 'direct main'\n"
                "    version: '1.1.0'\n"
                "  meta:\n"
                "    dependency: transitive\n"
                "    version: '1.9.1'\n",
            )
        )
        by_name = {e.name: e for e in graph.entries}
        assert by_name["http"].direct is True
        assert by_name["meta"].direct is False

    def test_gradle_lockfile(self) -> None:
        graph = GradleEcosystem().parse_lockfile(
            fc(
                "gradle.lockfile",
                "# ignored comment\n"
                "com.google.guava:guava:32.1.3=compileClasspath\n"
                "org.slf4j:slf4j-api:2.0.9=runtimeClasspath\n",
            )
        )
        assert {e.name for e in graph.entries} == {
            "com.google.guava:guava",
            "org.slf4j:slf4j-api",
        }

    def test_gradle_build_file_is_always_a_hook(self) -> None:
        """A Gradle build file is executable code evaluated on every build."""
        manifest = GradleEcosystem().parse_manifest(
            fc("build.gradle", "dependencies {\n  implementation 'a:b:1.0'\n}\n")
        )
        assert manifest.hooks
        assert manifest.dependencies[0].name == "a:b"

    def test_nuget_packages_lock(self) -> None:
        graph = NuGetEcosystem().parse_lockfile(
            fc(
                "packages.lock.json",
                '{"dependencies":{"net8.0":{'
                '"Newtonsoft.Json":{"type":"Direct","resolved":"13.0.3",'
                '"contentHash":"abc"}}}}',
            )
        )
        assert graph.entries[0].direct is True
        assert graph.entries[0].integrity == "abc"

    def test_nuget_packages_config(self) -> None:
        manifest = NuGetEcosystem().parse_manifest(
            fc(
                "packages.config",
                '<packages><package id="Serilog" version="3.1.1" /></packages>',
            )
        )
        assert manifest.dependencies[0].name == "Serilog"

    def test_cargo_lock_records_dependencies(self) -> None:
        graph = CargoEcosystem().parse_lockfile(
            fc(
                "Cargo.lock",
                '[[package]]\nname = "a"\nversion = "1.0.0"\n'
                'checksum = "abc"\ndependencies = ["b 1.0.0"]\n'
                '[[package]]\nname = "b"\nversion = "1.0.0"\n',
            )
        )
        by_name = {e.name: e for e in graph.entries}
        assert "b" in by_name["a"].dependencies

    def test_cargo_lock_malformed(self) -> None:
        graph = CargoEcosystem().parse_lockfile(fc("Cargo.lock", "[[package\nbad"))
        assert graph.parse_error

    def test_maven_has_no_lockfile(self) -> None:
        """Stated explicitly rather than returning silence, so the absence is a
        known property rather than a suspected parser failure."""
        from cordon_scanner.ecosystems.others import MavenEcosystem

        graph = MavenEcosystem().parse_lockfile(fc("pom.xml", "<project/>"))
        assert graph.parse_error and "no standard lockfile" in graph.parse_error


class TestGraphConstruction:
    def test_depth_is_derived_by_walking_from_direct_dependencies(self) -> None:
        """Depth feeds the risk score, and a lockfile is attacker-controlled
        input, so it is computed rather than trusted."""
        eco = CargoEcosystem()
        graph = eco.parse_lockfile(
            fc(
                "Cargo.lock",
                '[[package]]\nname = "root"\nversion = "1"\ndependencies = ["mid 1"]\n'
                '[[package]]\nname = "mid"\nversion = "1"\ndependencies = ["leaf 1"]\n'
                '[[package]]\nname = "leaf"\nversion = "1"\n',
            )
        )
        deps = {d.name: d for d in eco.to_dependencies(graph)}
        assert deps["leaf"].depth >= deps["mid"].depth

    def test_parents_are_recorded(self) -> None:
        eco = CargoEcosystem()
        graph = eco.parse_lockfile(
            fc(
                "Cargo.lock",
                '[[package]]\nname = "root"\nversion = "1"\ndependencies = ["leaf 1"]\n'
                '[[package]]\nname = "leaf"\nversion = "1"\n',
            )
        )
        deps = {d.name: d for d in eco.to_dependencies(graph)}
        assert "root" in deps["leaf"].parents

    def test_output_is_sorted_and_deterministic(self) -> None:
        eco = CargoEcosystem()
        graph = eco.parse_lockfile(
            fc(
                "Cargo.lock",
                '[[package]]\nname = "z"\nversion = "1"\n[[package]]\nname = "a"\nversion = "1"\n',
            )
        )
        names = [d.name for d in eco.to_dependencies(graph)]
        assert names == sorted(names)

    def test_a_purl_is_built_for_every_dependency(self) -> None:
        eco = GoEcosystem()
        graph = eco.parse_lockfile(fc("go.sum", "github.com/pkg/errors v0.9.1 h1:abc=\n"))
        deps = eco.to_dependencies(graph)
        assert deps[0].purl.startswith("pkg:golang/")

    def test_an_empty_lockfile_yields_no_dependencies(self) -> None:
        eco = CargoEcosystem()
        graph = eco.parse_lockfile(fc("Cargo.lock", ""))
        assert eco.to_dependencies(graph) == ()


class TestPnpmKeyShapes:
    """pnpm has written its package key three ways, and one of them was unread.

    Lockfile 5 separates the name from the version with a slash and leads with
    one; 6 and 9 separate with `@`. Splitting on the last `@` alone resolved
    every version-5 key to an empty name, so the whole file produced nothing --
    and an empty graph is indistinguishable from a project with no
    dependencies, so the scan reported `complete: true` and said nothing.
    """

    eco = NpmEcosystem()

    V5 = (
        "lockfileVersion: 5.4\n"
        "\npackages:\n"
        "\n  /lodash/4.17.21:\n"
        "    resolution: {integrity: sha512-aaa}\n"
        "    dev: false\n"
        "\n  /@babel/core/7.21.0:\n"
        "    resolution: {integrity: sha512-bbb}\n"
        "    dev: true\n"
    )
    V6 = (
        "lockfileVersion: '6.0'\n"
        "\npackages:\n"
        "\n  /lodash@4.17.21:\n"
        "    resolution: {integrity: sha512-aaa}\n"
        "\n  /@babel/core@7.21.0:\n"
        "    resolution: {integrity: sha512-bbb}\n"
    )
    V9 = (
        "lockfileVersion: '9.0'\n"
        "\npackages:\n"
        "\n  lodash@4.17.21:\n"
        "    resolution: {integrity: sha512-aaa}\n"
        "\n  '@babel/core@7.21.0':\n"
        "    resolution: {integrity: sha512-bbb}\n"
    )

    @pytest.mark.parametrize("text", [V5, V6, V9], ids=["v5", "v6", "v9"])
    def test_every_key_shape_resolves_name_and_version(self, text: str) -> None:
        graph = self.eco.parse_lockfile(fc("pnpm-lock.yaml", text))
        assert graph.parse_error is None
        assert {(e.name, e.version) for e in graph.entries} == {
            ("lodash", "4.17.21"),
            ("@babel/core", "7.21.0"),
        }

    def test_version_five_carries_its_dev_flag(self) -> None:
        graph = self.eco.parse_lockfile(fc("pnpm-lock.yaml", self.V5))
        by_name = {e.name: e for e in graph.entries}
        assert by_name["@babel/core"].scope is Scope.DEV
        assert by_name["lodash"].scope is Scope.RUNTIME

    def test_a_peer_suffix_is_not_part_of_the_version(self) -> None:
        text = (
            "lockfileVersion: '9.0'\n\npackages:\n"
            "\n  foo@1.0.0(bar@2.0.0):\n    resolution: {integrity: sha512-a}\n"
        )
        graph = self.eco.parse_lockfile(fc("pnpm-lock.yaml", text))
        assert [(e.name, e.version) for e in graph.entries] == [("foo", "1.0.0")]

    def test_keys_none_of_which_parse_report_rather_than_empty(self) -> None:
        """An unread lockfile and a project with no dependencies must not
        produce the same empty graph."""
        text = "lockfileVersion: '9.0'\n\npackages:\n\n  nonsense:\n    resolution: {}\n"
        graph = self.eco.parse_lockfile(fc("pnpm-lock.yaml", text))
        assert graph.parse_error


# ---------------------------------------------------------------------------
# Whole-class guard
# ---------------------------------------------------------------------------


MULTI_ENTRY_LOCKFILES = [
    (
        "package-lock.json",
        '{"lockfileVersion":3,"packages":{"":{"name":"d"},'
        '"node_modules/a":{"version":"1.0.0","integrity":"sha512-a"},'
        '"node_modules/b":{"version":"2.0.0","integrity":"sha512-b"},'
        '"node_modules/c":{"version":"3.0.0","integrity":"sha512-c"}}}',
    ),
    (
        "yarn.lock",
        'a@^1.0.0:\n  version "1.0.0"\n  integrity sha512-a\n\n'
        'b@^2.0.0:\n  version "2.0.0"\n  integrity sha512-b\n\n'
        'c@^3.0.0:\n  version "3.0.0"\n  integrity sha512-c\n',
    ),
    (
        "pnpm-lock.yaml",
        "lockfileVersion: '6.0'\npackages:\n"
        "  /a@1.0.0:\n    resolution: {integrity: sha512-a}\n"
        "  /b@2.0.0:\n    resolution: {integrity: sha512-b}\n"
        "  /c@3.0.0:\n    resolution: {integrity: sha512-c}\n",
    ),
    (
        "Cargo.lock",
        '[[package]]\nname = "a"\nversion = "1.0.0"\n\n'
        '[[package]]\nname = "b"\nversion = "2.0.0"\n\n'
        '[[package]]\nname = "c"\nversion = "3.0.0"\n',
    ),
    (
        "go.sum",
        "example.com/a v1.0.0 h1:aaa=\n"
        "example.com/b v2.0.0 h1:bbb=\n"
        "example.com/c v3.0.0 h1:ccc=\n",
    ),
    (
        "Gemfile.lock",
        "GEM\n  specs:\n    a (1.0.0)\n    b (2.0.0)\n    c (3.0.0)\n",
    ),
    (
        "Podfile.lock",
        "PODS:\n  - A (1.0.0)\n  - B (2.0.0)\n  - C (3.0.0)\n",
    ),
    (
        "gradle.lockfile",
        "g:a:1.0.0=compileClasspath\ng:b:2.0.0=compileClasspath\ng:c:3.0.0=compileClasspath\n",
    ),
    (
        "composer.lock",
        '{"packages":[{"name":"x/a","version":"1.0.0"},'
        '{"name":"x/b","version":"2.0.0"},{"name":"x/c","version":"3.0.0"}]}',
    ),
    (
        "requirements.txt",
        "a==1.0.0\nb==2.0.0\nc==3.0.0\n",
    ),
    (
        "poetry.lock",
        '[[package]]\nname = "a"\nversion = "1.0.0"\n\n'
        '[[package]]\nname = "b"\nversion = "2.0.0"\n\n'
        '[[package]]\nname = "c"\nversion = "3.0.0"\n',
    ),
    (
        "packages.lock.json",
        '{"dependencies":{"net8.0":{'
        '"A":{"type":"Direct","resolved":"1.0.0"},'
        '"B":{"type":"Direct","resolved":"2.0.0"},'
        '"C":{"type":"Direct","resolved":"3.0.0"}}}}',
    ),
    (
        "pubspec.lock",
        "packages:\n  a:\n    version: '1.0.0'\n"
        "  b:\n    version: '2.0.0'\n  c:\n    version: '3.0.0'\n",
    ),
]


@pytest.mark.parametrize(
    ("filename", "text"),
    MULTI_ENTRY_LOCKFILES,
    ids=lambda x: x if isinstance(x, str) and "\n" not in x else "",
)
def test_every_lockfile_parser_reads_beyond_the_first_entry(filename: str, text: str) -> None:
    """A guard against a whole class of silent parser failure.

    An anchored pattern compiled without MULTILINE matches only at the start of
    the file. The parser then returns one entry or none, the scan succeeds, and
    the result is indistinguishable from a project with no dependencies. Two
    parsers shipped with exactly that bug and neither raised anything.

    Every format is therefore given three entries and required to find all
    three.
    """
    from cordon_scanner.ecosystems.registry import EcosystemRegistry

    ecosystem_id = EcosystemRegistry.lockfile_ecosystem(filename)
    assert ecosystem_id, f"no ecosystem claims {filename}"

    ecosystem = EcosystemRegistry.get(ecosystem_id)
    assert ecosystem is not None

    graph = ecosystem.parse_lockfile(fc(filename, text))
    assert not graph.parse_error, graph.parse_error
    assert len(graph.entries) >= 3, (
        f"{filename}: parsed {len(graph.entries)} of 3 entries ({[e.name for e in graph.entries]})"
    )


UV_LOCK = """
version = 1
requires-python = ">=3.11"

[manifest]
dev-dependencies = ["pytest>=8.0"]

[[package]]
name = "django"
version = "1.2.1"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "sqlparse" },
]
sdist = { url = "https://files.pythonhosted.org/x.tar.gz", hash = "sha256:aaaa", size = 1 }
wheels = [
    { url = "https://files.pythonhosted.org/x.whl", hash = "sha256:bbbb", size = 1 },
]

[[package]]
name = "sqlparse"
version = "0.4.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }
"""

PDM_LOCK = """
[metadata]
groups = ["default", "dev"]
lock_version = "4.4"

[[package]]
name = "jinja2"
version = "2.10"
groups = ["default"]
dependencies = [
    "MarkupSafe>=0.23",
]
files = [
    {file = "Jinja2-2.10.tar.gz", hash = "sha256:f84be1bb"},
]

[[package]]
name = "pytest"
version = "8.0.0"
groups = ["dev"]
"""


class TestRequirementsDirectoryIsALockfile:
    """`requirements/base.txt` carries hashes, and they have to be read.

    `pip-compile` writes a `requirements/` directory holding `base.txt`, `dev.txt` and
    friends for anything larger than a toy project, and each entry carries its `--hash=`
    continuations. `manifest_globs` matched both that layout and the flat `requirements.txt`
    from the start; `lockfile_globs` and `parse_lockfile` matched only the flat one.

    So the directory layout was parsed as a manifest and never as a lockfile.
    `_parse_pinned_requirements` reads the hashes correctly and was simply never reached, and
    `POLICY.DEPENDENCY.INTEGRITY.001` then reported every dependency in the file as carrying
    no hash. The accusation was the inverse of the truth, and it landed hardest on the
    projects big enough to have split their requirements AND done the work to pin by hash.
    """

    PINNED = (
        "amqp==5.3.1 \\\n"
        "    --hash=sha256:43b3319e1b4e7d1251833a93d6b17c1c3ecd8c3de4e4e0e0e0e0e0e0e0e0e0e0 \\\n"
        "    --hash=sha256:9d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d\n"
        "    # via kombu\n"
        "django==5.1.2 \\\n"
        "    --hash=sha256:1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a\n"
    )

    @pytest.mark.parametrize(
        "path",
        [
            "requirements.txt",
            "requirements-dev.txt",
            "requirements/base.txt",
            "requirements/security.txt",
            "backend/requirements/prod.txt",
        ],
    )
    def test_every_spelling_reaches_the_pinned_parser(self, path: str) -> None:
        graph = PypiEcosystem().parse_lockfile(fc(path, self.PINNED))

        assert graph.parse_error is None, f"{path} was not recognised as a lockfile"
        assert len(graph.entries) == 2
        assert all(e.integrity for e in graph.entries), (
            f"{path} parsed but carried no integrity hashes"
        )

    def test_the_first_hash_of_a_multi_hash_entry_is_recorded(self) -> None:
        graph = PypiEcosystem().parse_lockfile(fc("requirements/base.txt", self.PINNED))
        amqp = next(e for e in graph.entries if e.name == "amqp")

        assert amqp.version == "5.3.1"
        assert amqp.integrity == (
            "sha256:43b3319e1b4e7d1251833a93d6b17c1c3ecd8c3de4e4e0e0e0e0e0e0e0e0e0e0"
        )

    def test_an_unhashed_entry_is_still_reported_as_unhashed(self) -> None:
        # The complement, so the fix cannot become "assume everything is hashed": a genuinely
        # unpinned entry must still reach `POLICY.DEPENDENCY.INTEGRITY.001`.
        graph = PypiEcosystem().parse_lockfile(fc("requirements/base.txt", "django==5.1.2\n"))

        assert len(graph.entries) == 1
        assert not graph.entries[0].integrity

    def test_the_directory_is_not_mistaken_for_any_txt_file(self) -> None:
        # `docs/notes.txt` is not a lockfile. The match is on the `requirements/` directory or
        # a `requirements` prefix, not on the extension.
        graph = PypiEcosystem().parse_lockfile(fc("docs/notes.txt", self.PINNED))
        assert graph.parse_error is not None


class TestRealWorldPythonLayoutsResolve:
    """Every layout a real Python project uses reaches the right parser.

    The bug this guards was not a parser that was wrong; it was a parser that was never
    reached. `_parse_pinned_requirements` read `--hash=` continuations correctly the whole
    time, behind a dispatch that could not see `requirements/base.txt` - so a scan of a
    hash-pinned project reported every dependency as unhashed, and the report was the exact
    inverse of the truth.

    A table rather than a handful of cases, because the failure mode is silence: an
    unrecognised path yields no ecosystem, no parse, no error, and a clean result that looks
    identical to a project with no dependencies. Nothing complains. So the layouts a project
    might plausibly use are asserted by name.

    `.in` is manifest-only on purpose. It is pip-compile's input: ranges, no hashes. Treating
    one as a lockfile would report a resolved dependency the file never claimed.
    """

    @pytest.mark.parametrize(
        ("path", "manifest", "lockfile"),
        [
            # Flat, the layout every tutorial shows.
            ("requirements.txt", "pypi", "pypi"),
            ("requirements-dev.txt", "pypi", "pypi"),
            ("requirements_test.txt", "pypi", "pypi"),
            ("requirements.in", "pypi", None),
            ("requirements-dev.in", "pypi", None),
            # Split by environment, which is what pip-compile produces past a toy project.
            ("requirements/base.txt", "pypi", "pypi"),
            ("requirements/dev.txt", "pypi", "pypi"),
            ("requirements/security.txt", "pypi", "pypi"),
            ("requirements/base.in", "pypi", None),
            # The same, one level down, which is every monorepo.
            ("backend/requirements/base.txt", "pypi", "pypi"),
            ("services/api/requirements/prod.txt", "pypi", "pypi"),
            ("backend/requirements/base.in", "pypi", None),
            # The other Python formats, unaffected but asserted so a glob edit cannot
            # quietly trade one for another.
            ("pyproject.toml", "pypi", None),
            ("poetry.lock", None, "pypi"),
            ("uv.lock", None, "pypi"),
            # Not Python. A `.txt` is only a manifest inside a `requirements` context - the
            # match must not widen to every text file in the repository.
            ("docs/notes.txt", None, None),
            ("docs/notes.in", None, None),
            ("LICENSE.txt", None, None),
        ],
    )
    def test_the_registry_routes_it(
        self, path: str, manifest: str | None, lockfile: str | None
    ) -> None:
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        assert EcosystemRegistry.manifest_ecosystem(path) == manifest, f"manifest routing: {path}"
        assert EcosystemRegistry.lockfile_ecosystem(path) == lockfile, f"lockfile routing: {path}"

    def test_the_fast_index_agrees_with_the_reference_scan(self) -> None:
        # `_GlobIndex` is an optimisation over a linear glob scan, and the two are only
        # equivalent by construction. A new pattern with structure in it is exactly what could
        # separate them, and `**/requirements/*.in` is one.
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        for path in (
            "requirements/base.in",
            "requirements/base.txt",
            "backend/requirements/prod.txt",
            "docs/notes.txt",
        ):
            assert EcosystemRegistry.manifest_ecosystem(
                path
            ) == EcosystemRegistry.manifest_ecosystem_scan(path), path
            assert EcosystemRegistry.lockfile_ecosystem(
                path
            ) == EcosystemRegistry.lockfile_ecosystem_scan(path), path
