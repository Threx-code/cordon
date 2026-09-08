"""Ecosystem parsers and dependency analysis.

Two properties dominate these tests.

**Parsers must not be defeated by formatting.** A manifest reader that assumes
pretty-printed input is blinded by any tool that rewrites the file, and that is
an accident rather than an exotic evasion. Every parser is tested against
minified input.

**Name normalisation must match each registry's own rules.** Typosquat
detection and advisory matching both depend on knowing when two names are the
same package, and each ecosystem answers that differently.
"""

from __future__ import annotations

import pytest

from cordon.core.content import FileContent
from cordon.core.models import Scope
from cordon.detect.dependency import (
    _damerau_levenshtein,
    _is_plausible_slip,
)
from cordon.ecosystems.npm import NpmEcosystem
from cordon.ecosystems.others import (
    CargoEcosystem,
    ComposerEcosystem,
    GoEcosystem,
    MavenEcosystem,
    NuGetEcosystem,
    RubyGemsEcosystem,
)
from cordon.ecosystems.pypi import PypiEcosystem
from cordon.ecosystems.registry import EcosystemRegistry


def fc(path: str, text: str) -> FileContent:
    return FileContent.from_bytes(path, text.encode("utf-8"))


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------


PACKAGE_JSON = """
{
  "name": "demo",
  "version": "1.0.0",
  "scripts": {
    "test": "jest",
    "build": "tsc",
    "postinstall": "node scripts/setup.js"
  },
  "dependencies": {"express": "^4.18.0", "left-pad": "1.3.0"},
  "devDependencies": {"jest": "^29.0.0"},
  "overrides": {"minimist": "^1.2.8"}
}
"""


class TestNpmManifest:
    def setup_method(self) -> None:
        self.eco = NpmEcosystem()

    def test_parses_dependencies_with_scopes(self) -> None:
        manifest = self.eco.parse_manifest(fc("package.json", PACKAGE_JSON))
        by_name = {d.name: d for d in manifest.dependencies}
        assert by_name["express"].scope is Scope.RUNTIME
        assert by_name["jest"].scope is Scope.DEV
        assert manifest.name == "demo"

    def test_only_lifecycle_scripts_become_hooks(self) -> None:
        """A `test` script runs when somebody chooses to run tests. A
        `postinstall` script runs whether they wanted it to or not."""
        manifest = self.eco.parse_manifest(fc("package.json", PACKAGE_JSON))
        names = {h.name for h in manifest.hooks}
        assert names == {"postinstall"}

    def test_minified_manifest_is_parsed_identically(self) -> None:
        """The failure this prevents: a line-oriented reader assumes
        pretty-printed JSON, and any tool that rewrites the file onto one line
        blinds it while a postinstall script sits in plain sight."""
        import json

        minified = json.dumps(json.loads(PACKAGE_JSON), separators=(",", ":"))
        pretty = self.eco.parse_manifest(fc("package.json", PACKAGE_JSON))
        flat = self.eco.parse_manifest(fc("package.json", minified))
        assert {h.name for h in flat.hooks} == {h.name for h in pretty.hooks}
        assert len(flat.dependencies) == len(pretty.dependencies)

    def test_invalid_json_reports_rather_than_raises(self) -> None:
        manifest = self.eco.parse_manifest(fc("package.json", "{not json"))
        assert manifest.parse_error
        assert manifest.dependencies == ()

    def test_reads_overrides(self) -> None:
        manifest = self.eco.parse_manifest(fc("package.json", PACKAGE_JSON))
        assert manifest.overrides["minimist"] == "^1.2.8"


class TestNpmLockfiles:
    def setup_method(self) -> None:
        self.eco = NpmEcosystem()

    def test_lockfile_v3(self) -> None:
        text = """
        {"name":"d","lockfileVersion":3,"packages":{
          "":{"name":"d"},
          "node_modules/express":{"version":"4.18.2","integrity":"sha512-aaa",
            "resolved":"https://registry.npmjs.org/express/-/express-4.18.2.tgz"},
          "node_modules/express/node_modules/debug":{"version":"2.6.9","integrity":"sha512-bbb"}
        }}
        """
        graph = self.eco.parse_lockfile(fc("package-lock.json", text))
        by_name = {e.name: e for e in graph.entries}
        assert by_name["express"].direct is True
        assert by_name["debug"].direct is False
        assert by_name["express"].integrity == "sha512-aaa"

    def test_lockfile_v1(self) -> None:
        text = """
        {"lockfileVersion":1,"dependencies":{
          "express":{"version":"4.18.2","integrity":"sha512-aaa",
                     "dependencies":{"debug":{"version":"2.6.9"}}}
        }}
        """
        graph = self.eco.parse_lockfile(fc("package-lock.json", text))
        assert {e.name for e in graph.entries} == {"express", "debug"}

    def test_yarn_lock(self) -> None:
        text = (
            "express@^4.18.0:\n"
            '  version "4.18.2"\n'
            '  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"\n'
            "  integrity sha512-aaa\n"
        )
        graph = self.eco.parse_lockfile(fc("yarn.lock", text))
        assert len(graph.entries) == 1
        assert graph.entries[0].name == "express"
        assert graph.entries[0].version == "4.18.2"

    def test_pnpm_lock(self) -> None:
        text = (
            "lockfileVersion: '6.0'\n"
            "packages:\n"
            "  /express@4.18.2:\n"
            "    resolution: {integrity: sha512-aaa}\n"
            "    dev: false\n"
            "  /jest@29.0.0:\n"
            "    resolution: {integrity: sha512-bbb}\n"
            "    dev: true\n"
        )
        graph = self.eco.parse_lockfile(fc("pnpm-lock.yaml", text))
        by_name = {e.name: e for e in graph.entries}
        assert by_name["express"].version == "4.18.2"
        assert by_name["jest"].scope is Scope.DEV


# ---------------------------------------------------------------------------
# PyPI
# ---------------------------------------------------------------------------


class TestPypi:
    def setup_method(self) -> None:
        self.eco = PypiEcosystem()

    @pytest.mark.parametrize(
        ("written", "canonical"),
        [
            ("zope.interface", "zope-interface"),
            ("Zope_Interface", "zope-interface"),
            ("ZOPE--INTERFACE", "zope-interface"),
            ("Flask", "flask"),
        ],
    )
    def test_pep503_normalisation(self, written: str, canonical: str) -> None:
        """Without this, three spellings of one package look like three
        packages, which breaks advisory matching and typosquat detection in
        opposite directions."""
        assert self.eco.normalize_name(written) == canonical

    def test_setup_py_is_parsed_not_executed(self) -> None:
        """The rule the whole module rests on. Importing a setup script to read
        its metadata would run exactly the code the scanner exists to inspect.
        """
        hostile = (
            "import os\n"
            "raise SystemExit('this must never run')\n"
            "from setuptools import setup\n"
            "setup(name='demo', version='2.0', install_requires=['requests>=2.0'])\n"
        )
        manifest = self.eco.parse_manifest(fc("setup.py", hostile))
        assert manifest.name == "demo"
        assert manifest.version == "2.0"
        assert [d.name for d in manifest.dependencies] == ["requests"]

    def test_setup_py_is_always_a_build_hook(self) -> None:
        """Its mere existence means arbitrary Python runs at install time."""
        manifest = self.eco.parse_manifest(fc("setup.py", "print(1)"))
        assert [h.kind for h in manifest.hooks] == ["build"]

    def test_setup_py_ignores_computed_values(self) -> None:
        """Only literals are read. Anything computed is skipped rather than
        evaluated, because evaluating it is the attack."""
        text = (
            "from setuptools import setup\n"
            "deps = [chr(114) + 'equests']\n"
            "setup(name='x', install_requires=deps)\n"
        )
        manifest = self.eco.parse_manifest(fc("setup.py", text))
        assert manifest.dependencies == ()

    def test_syntax_error_reports_and_still_records_the_hook(self) -> None:
        manifest = self.eco.parse_manifest(fc("setup.py", "def broken("))
        assert manifest.parse_error
        assert manifest.hooks

    def test_pyproject(self) -> None:
        text = (
            '[project]\nname = "demo"\nversion = "1.0"\n'
            'dependencies = ["requests>=2.0", "click"]\n'
            '[project.optional-dependencies]\ndev = ["pytest"]\n'
        )
        manifest = self.eco.parse_manifest(fc("pyproject.toml", text))
        names = {d.name for d in manifest.dependencies}
        assert names == {"requests", "click", "pytest"}

    def test_requirements_with_hashes(self) -> None:
        text = (
            "requests==2.31.0 \\\n    --hash=sha256:aaa\nclick==8.1.7\n# a comment\n-r other.txt\n"
        )
        graph = self.eco.parse_lockfile(fc("requirements.txt", text))
        by_name = {e.name: e for e in graph.entries}
        assert by_name["requests"].version == "2.31.0"
        assert by_name["requests"].integrity == "sha256:aaa"
        assert by_name["click"].integrity is None

    def test_unpinned_requirements_are_not_treated_as_resolved(self) -> None:
        """A range is a declaration of intent, not a record of what installed.
        Reporting one as resolved would claim a precision the file lacks."""
        graph = self.eco.parse_lockfile(fc("requirements.txt", "requests>=2.0\n"))
        assert graph.entries == ()


# ---------------------------------------------------------------------------
# Other ecosystems
# ---------------------------------------------------------------------------


class TestOtherEcosystems:
    def test_cargo_folds_underscore_and_hyphen(self) -> None:
        """crates.io treats them as equivalent when rejecting a conflicting
        name, so they must fold together or every crate has a free typosquat."""
        eco = CargoEcosystem()
        assert eco.normalize_name("serde_json") == eco.normalize_name("serde-json")

    def test_cargo_manifest_and_lock(self) -> None:
        eco = CargoEcosystem()
        manifest = eco.parse_manifest(
            fc(
                "Cargo.toml",
                '[package]\nname = "d"\nversion = "0.1.0"\nbuild = "build.rs"\n'
                '[dependencies]\nserde = "1.0"\n[dev-dependencies]\ncriterion = "0.5"\n',
            )
        )
        assert {d.name for d in manifest.dependencies} == {"serde", "criterion"}
        assert [h.name for h in manifest.hooks] == ["build"]

        graph = eco.parse_lockfile(
            fc(
                "Cargo.lock",
                '[[package]]\nname = "serde"\nversion = "1.0.0"\nchecksum = "abc"\n',
            )
        )
        assert graph.entries[0].integrity == "abc"

    def test_go_mod_and_replace(self) -> None:
        eco = GoEcosystem()
        manifest = eco.parse_manifest(
            fc(
                "go.mod",
                "module example.com/demo\n\n"
                "require (\n"
                "\tgithub.com/pkg/errors v0.9.1\n"
                "\tgithub.com/spf13/cobra v1.8.0 // indirect\n"
                ")\n\n"
                "replace github.com/pkg/errors => ../local-errors\n",
            )
        )
        assert manifest.name == "example.com/demo"
        fields = {d.field_name for d in manifest.dependencies}
        assert "replace" in fields, "a replace directive must be recorded"

    def test_go_sum(self) -> None:
        eco = GoEcosystem()
        graph = eco.parse_lockfile(
            fc(
                "go.sum",
                "github.com/pkg/errors v0.9.1 h1:abc=\n"
                "github.com/pkg/errors v0.9.1/go.mod h1:def=\n",
            )
        )
        assert len(graph.entries) == 1
        assert graph.entries[0].integrity

    def test_maven_pom_without_an_xml_parser(self) -> None:
        """Python's XML parsers carry documented hazards on untrusted input, and
        a POM is attacker-controlled like everything else in the target."""
        eco = MavenEcosystem()
        manifest = eco.parse_manifest(
            fc(
                "pom.xml",
                "<project><dependencies>"
                "<dependency><groupId>org.slf4j</groupId>"
                "<artifactId>slf4j-api</artifactId><version>2.0.9</version></dependency>"
                "<dependency><groupId>junit</groupId><artifactId>junit</artifactId>"
                "<version>4.13</version><scope>test</scope></dependency>"
                "</dependencies></project>",
            )
        )
        by_name = {d.name: d for d in manifest.dependencies}
        assert by_name["org.slf4j:slf4j-api"].spec == "2.0.9"
        assert by_name["junit:junit"].scope is Scope.TEST

    def test_maven_xml_bomb_is_not_expanded(self) -> None:
        """A billion-laughs entity expansion is inert against pattern
        extraction, which is the point of not using an XML parser."""
        eco = MavenEcosystem()
        bomb = (
            '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
            '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
            "]><project>&lol2;</project>"
        )
        manifest = eco.parse_manifest(fc("pom.xml", bomb))
        assert manifest.dependencies == ()

    def test_composer_lifecycle_scripts(self) -> None:
        eco = ComposerEcosystem()
        manifest = eco.parse_manifest(
            fc(
                "composer.json",
                '{"name":"a/b","require":{"php":">=8.0","monolog/monolog":"^3.0"},'
                '"scripts":{"post-install-cmd":["echo hi"],"test":"phpunit"}}',
            )
        )
        assert [d.name for d in manifest.dependencies] == ["monolog/monolog"]
        assert [h.name for h in manifest.hooks] == ["post-install-cmd"]

    def test_rubygems(self) -> None:
        eco = RubyGemsEcosystem()
        manifest = eco.parse_manifest(
            fc("Gemfile", "source 'https://rubygems.org'\ngem 'rails', '7.1.0'\ngem 'puma'\n")
        )
        assert {d.name for d in manifest.dependencies} == {"rails", "puma"}

    def test_nuget(self) -> None:
        eco = NuGetEcosystem()
        manifest = eco.parse_manifest(
            fc(
                "app.csproj",
                "<Project><ItemGroup>"
                '<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />'
                "</ItemGroup></Project>",
            )
        )
        assert manifest.dependencies[0].name == "Newtonsoft.Json"


# ---------------------------------------------------------------------------
# Registry resolution
# ---------------------------------------------------------------------------


class TestRegistryHostDetection:
    @pytest.mark.parametrize(
        ("url", "is_registry"),
        [
            ("https://registry.npmjs.org/express/-/express-4.18.2.tgz", True),
            ("https://user:pw@registry.npmjs.org/x.tgz", True),
            ("git+ssh://git@github.com/acme/x.git", False),
            ("git+https://github.com/acme/x.git", False),
            ("git@github.com:acme/x.git", False),
            ("https://evil.example.net/pkg.tgz", False),
            ("file:../local", False),
            ("link:../sibling", False),
            (None, True),
            ("express", True),
            ("", True),
        ],
    )
    def test_scheme_handling(self, url: str | None, is_registry: bool) -> None:
        """Checking only for `http://` classified `git+ssh://` as "not a URL,
        therefore the registry", which is exactly backwards and silently
        disabled the provenance check for the clearest case of all."""
        assert NpmEcosystem().is_registry_host(url) is is_registry


class TestEcosystemRegistry:
    @pytest.mark.parametrize(
        ("path", "ecosystem"),
        [
            ("package.json", "npm"),
            ("app/package.json", "npm"),
            ("pyproject.toml", "pypi"),
            ("setup.py", "pypi"),
            ("Cargo.toml", "cargo"),
            ("go.mod", "gomod"),
            ("pom.xml", "maven"),
            ("composer.json", "composer"),
            ("Gemfile", "rubygems"),
            ("src/main.py", None),
        ],
    )
    def test_manifest_matching(self, path: str, ecosystem: str | None) -> None:
        assert EcosystemRegistry.manifest_ecosystem(path) == ecosystem

    def test_every_ecosystem_has_a_unique_id(self) -> None:
        ids = [e.id for e in EcosystemRegistry.all_ecosystems()]
        assert len(ids) == len(set(ids))

    def test_every_ecosystem_normalises_names(self) -> None:
        for eco in EcosystemRegistry.all_ecosystems():
            assert eco.normalize_name("  MixedCase  ") == eco.normalize_name("mixedcase")


# ---------------------------------------------------------------------------
# Typosquat similarity
# ---------------------------------------------------------------------------


class TestNameSimilarity:
    def test_transposition_counts_as_one_edit(self) -> None:
        """Plain Levenshtein counts a transposition as two edits, which pushes
        real slips outside a distance-2 threshold."""
        assert _damerau_levenshtein("recieve", "receive", 2) == 1

    def test_distance_is_bounded(self) -> None:
        assert _damerau_levenshtein("a" * 50, "b" * 50, 2) == 3

    @pytest.mark.parametrize(
        ("typo", "target"),
        [
            ("expres", "express"),  # dropped character
            ("exppress", "express"),  # doubled character
            ("lodahs", "lodash"),  # transposition
            ("reqeusts", "requests"),  # transposition
            ("l0dash", "lodash"),  # homoglyph
            ("lodash-es", "lodash_es"),  # separator swap
        ],
    )
    def test_recognised_slips(self, typo: str, target: str) -> None:
        assert _is_plausible_slip(typo, target)

    @pytest.mark.parametrize(
        "name",
        ["preact", "colorette", "lodash-es", "requests-oauthlib", "pytest-cov"],
    )
    def test_real_packages_are_never_reported_as_squats(self, name: str) -> None:
        """The guarantee that matters, asserted against the detector rather than
        against the similarity helper.

        These are real, distinct projects that sit close to a popular name. A
        check that cannot tell them from a squat gets the whole detector
        disabled, at which point recall is zero.
        """
        from cordon.detect.dependency import DependencyDetector
        from cordon.ecosystems.registry import EcosystemRegistry

        detector = DependencyDetector()
        for ecosystem_id in ("npm", "pypi"):
            eco = EcosystemRegistry.get(ecosystem_id)
            assert eco is not None
            normalized = eco.normalize_name(name)
            from cordon.intel.popular import PackageIntel

            if PackageIntel.is_known_package(ecosystem_id, normalized):
                continue  # excluded before similarity is ever considered
            target = detector._typosquat_target(ecosystem_id, normalized)
            assert target is None, f"{name} wrongly matched {target} in {ecosystem_id}"

    @pytest.mark.parametrize(
        ("typo", "ecosystem", "expected"),
        [
            ("lodahs", "npm", "lodash"),
            ("expres", "npm", "express"),
            ("reqeusts", "pypi", "requests"),
            ("numpyy", "pypi", "numpy"),
        ],
    )
    def test_real_squats_are_detected(self, typo: str, ecosystem: str, expected: str) -> None:
        from cordon.detect.dependency import DependencyDetector

        assert DependencyDetector()._typosquat_target(ecosystem, typo) == expected
