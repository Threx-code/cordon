"""The name a package gives itself, read for every ecosystem from the file of that ecosystem that states it (`OwnName`), and the
finding for a name that is a slip of a popular one (`SUSPECT.TYPOSQUAT.PACKAGE_NAME.001`).

The files are real bytes: published package metadata fetched on 2026-11-27 (`own_name_captures/CAPTURES.md`, one file per
ecosystem, each with its source and licence), the manifests of a real project (cdxgen's package.json and pyproject.toml), a signed
.nupkg's own .nuspec (`intel/provenance/nuget`), and the real-project cases of the conformance suite for Gradle and RubyGems."""

from __future__ import annotations

import io
import json
import zipfile
from dataclasses import dataclass

import pytest

from cordon_scanner.detect.base import FileUnit, ScanContext
from cordon_scanner.detect.supply.dependency import DependencyDetector
from cordon_scanner.detect.supply.manifests.detector import ManifestDetector
from cordon_scanner.detect.supply.manifests.identity_findings import IdentityFindings
from cordon_scanner.ecosystems.own_names import NoOwnName, OwnName
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.rules.loader import RuleSet
from support import ROOT

CAPTURES = ROOT / "tests" / "unit" / "detect" / "supply" / "own_name_captures"
CONFORMANCE = ROOT / "tests" / "conformance" / "cases"
NUPKG = (
    ROOT
    / "tests"
    / "unit"
    / "intel"
    / "provenance"
    / "nuget"
    / "microsoft.netcore.targets.5.0.0.nupkg"
)
RECORDS = (
    ROOT / "tests" / "unit" / "intel" / "advisories" / "upstream" / "charts_images_records.json"
)
RULE = "SUSPECT.TYPOSQUAT.PACKAGE_NAME.001"


@dataclass(frozen=True)
class Real:
    ecosystem: str
    #: Where the file sits in a published package or a repository.
    path: str
    #: The name the ecosystem's own file gives the package.
    name: str
    #: The part of the name that is cut to make a slip of it (the slip is that part with its last letter gone).
    cut: str
    capture: str = ""

    def raw(self) -> bytes:
        if self.capture == "nupkg":
            with zipfile.ZipFile(io.BytesIO(NUPKG.read_bytes())) as archive:
                member = next(n for n in archive.namelist() if n.endswith(".nuspec"))
                return archive.read(member)
        if self.capture == "traefik-config":
            # The real image config blob (its OCI labels) of traefik 3.0.4, as the registry served it.
            records = json.loads(RECORDS.read_text(encoding="utf-8"))
            return json.dumps(records["image"]["config"], indent=1).encode()
        if self.capture.startswith("conformance/"):
            return (CONFORMANCE / self.capture.removeprefix("conformance/")).read_bytes()
        return (CAPTURES / self.capture).read_bytes()


CASES = [
    Real("ansible", "MANIFEST.json", "ansible.eda", "eda", "ansible-eda-2.13.0-MANIFEST.json"),
    Real("bazel", "MODULE.bazel", "rules_go", "rules_go", "rules_go-MODULE.bazel"),
    Real("cargo", "Cargo.toml", "serde", "serde", "serde-Cargo.toml"),
    Real(
        "cocoapods",
        "Alamofire.podspec.json",
        "Alamofire",
        "Alamofire",
        "Alamofire-5.9.1.podspec.json",
    ),
    Real(
        "composer",
        "composer.json",
        "monolog/monolog",
        "monolog",
        "monolog-3.9.0-composer.json",
    ),
    Real("conan", "conanfile.py", "zlib", "zlib", "zlib-conanfile.py"),
    Real("conda", "info/index.json", "six", "six", "six-1.17.0-conda-index.json"),
    Real("cran", "DESCRIPTION", "jsonlite", "jsonlite", "jsonlite-2.0.0-DESCRIPTION"),
    Real("gomod", "go.mod", "github.com/google/uuid", "uuid", "google-uuid-v1.6.0.mod"),
    Real(
        "gradle",
        "settings.gradle.kts",
        "conformance",
        "conformance",
        "conformance/gradle/real-multiproject/settings.gradle.kts",
    ),
    Real("hackage", "aeson.cabal", "aeson", "aeson", "aeson-2.2.3.0.cabal"),
    Real("helm", "Chart.yaml", "redis", "redis", "redis-Chart.yaml"),
    Real("hex", "metadata.config", "jason", "jason", "jason-1.4.4-metadata.config"),
    Real("homebrew", "Formula/j/jq.rb", "jq", "jq", "jq.rb"),
    Real("image", "blobs/sha256/" + "ab" * 32, "Traefik", "Traefik", "traefik-config"),
    Real("julia", "Project.toml", "DataFrames", "DataFrames", "DataFrames-Project.toml"),
    Real(
        "maven",
        "META-INF/maven/com.google.code.gson/gson/pom.xml",
        "com.google.code.gson:gson",
        "gson",
        "gson-2.11.0.pom",
    ),
    Real("nix", "pkgs/by-name/he/hello/package.nix", "hello", "hello", "hello-package.nix"),
    Real("npm", "package.json", "@cdxgen/cdxgen", "cdxgen", "cdxgen-package.json"),
    Real(
        "nuget", "Microsoft.NETCore.Targets.nuspec", "Microsoft.NETCore.Targets", "Targets", "nupkg"
    ),
    Real("opam", "packages/dune/dune.3.15.3/opam", "dune", "dune", "opam-dune.3.15.3-opam"),
    Real("pub", "pubspec.yaml", "http", "http", "http-1.2.2-pubspec.yaml"),
    Real("pypi", "pyproject.toml", "cdxgen", "cdxgen", "cdxgen-pyproject.toml"),
    Real(
        "rubygems",
        "conformance.gemspec",
        "conformance",
        "conformance",
        "conformance/rubygems/real-bundler/conformance.gemspec",
    ),
    Real(
        "swift",
        "Package.swift",
        "swift-argument-parser",
        "swift-argument-parser",
        "swift-argument-parser-Package.swift",
    ),
    Real("vcpkg", "ports/zlib/vcpkg.json", "zlib", "zlib", "zlib-vcpkg.json"),
    Real(
        "vscode",
        "extension/package.json",
        "vscjava.vscode-java-pack",
        "vscode-java-pack",
        "vscode-java-pack-0.31.2-package.json",
    ),
]


IDS = [c.ecosystem for c in CASES]


class TestEveryEcosystemStatesHowItsOwnNameIsRead:
    def test_each_ecosystem_declares_a_file_or_a_reason(self) -> None:
        for ecosystem in EcosystemRegistry.all_ecosystems():
            declared = ecosystem.own_name
            assert isinstance(declared, OwnName | NoOwnName), ecosystem.id
            if isinstance(declared, NoOwnName):
                assert len(declared.reason.split()) >= 12, ecosystem.id
            else:
                assert declared.files, ecosystem.id

    def test_a_real_file_is_held_for_every_ecosystem_that_reads_one(self) -> None:
        reads = {
            e.id for e in EcosystemRegistry.all_ecosystems() if isinstance(e.own_name, OwnName)
        }
        assert set(IDS) == reads

    def test_the_ecosystems_with_no_file_are_the_ones_whose_files_do_not_name_the_package(
        self,
    ) -> None:
        none = {
            e.id for e in EcosystemRegistry.all_ecosystems() if isinstance(e.own_name, NoOwnName)
        }
        assert none == {"actions", "terraform"}

    def test_only_the_formats_it_was_measured_on_may_block(self) -> None:
        assert IdentityFindings.own_name_measured_on() == {"npm", "pypi"}


class TestTheRealFilesGiveTheirName:
    @pytest.mark.parametrize("case", CASES, ids=IDS)
    def test_the_ecosystem_that_owns_the_file_reads_the_name(self, case: Real) -> None:
        raw = case.raw()
        speaking = EcosystemRegistry.own_name_ecosystems(case.path)
        assert speaking and speaking[0].id == case.ecosystem
        read = speaking[0].own_name_of(
            case.path, FileContent(case.path, raw, len(raw)), [case.path]
        )
        assert read == case.name

    def test_an_extension_manifest_is_the_editors_and_a_package_json_is_npms(self) -> None:
        assert EcosystemRegistry.own_name_ecosystems("extension/package.json")[0].id == "vscode"
        assert EcosystemRegistry.own_name_ecosystems("package.json")[0].id == "npm"
        assert (
            EcosystemRegistry.own_name_ecosystems("a.vsix!extension/package.json", "vscode")[0].id
            == "vscode"
        )

    def test_a_bazel_module_is_named_by_its_own_call_not_by_an_extension_tag_after_it(self) -> None:
        # The real rules_go file: `go_deps.module(path = ..., version = "v1.2.5")` follows `module(name = "rules_go")`.
        raw = (CAPTURES / "rules_go-MODULE.bazel").read_bytes()
        manifest = EcosystemRegistry.get("bazel").parse_manifest(
            FileContent("MODULE.bazel", raw, len(raw))
        )
        assert (manifest.name, manifest.version) == ("rules_go", "")


class TestASlipOfAPopularNameIsFoundInEveryEcosystem:
    @staticmethod
    def found(
        case: Real, monkeypatch: pytest.MonkeyPatch, *, path: str = "", distribution: str = ""
    ):
        """What the manifest detector says of the real file with its name cut by a letter, the popular package standing
        in as the name it is a slip of; and the (ecosystem, name) the popular names were asked about."""
        slip = case.cut[:-1]
        slipped = case.name.replace(case.cut, slip)
        member = (path or case.path).replace(case.cut, slip)
        asked: list[tuple[str, str]] = []

        def popular(cls, ecosystem: str, name: str) -> str | None:
            asked.append((ecosystem, name))
            same = name == EcosystemRegistry.get(ecosystem).normalize_name(slipped)
            return case.name.lower() if same else None

        monkeypatch.setattr(DependencyDetector, "_typosquat_target", classmethod(popular))
        unit = FileUnit(
            content=FileContent.from_bytes(
                member, case.raw().replace(case.cut.encode(), slip.encode())
            )
        )
        ctx = ScanContext(config=Config.default(), rules=RuleSet(()), distribution=distribution)
        findings = [f for f in ManifestDetector().inspect(unit, ctx) if f.rule_id == RULE]
        return slipped, asked, findings

    @pytest.mark.parametrize("case", CASES, ids=IDS)
    def test_the_finding_names_the_popular_package(
        self, case: Real, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        slipped, asked, found = self.found(case, monkeypatch)
        assert len(found) == 1, (asked, found)
        assert found[0].severity.name == "MEDIUM"
        assert slipped in found[0].message and case.name.lower() in found[0].message
        # (a .nuspec is also read as a release's own metadata, so the name may be asked twice)
        assert set(asked) == {
            (case.ecosystem, EcosystemRegistry.get(case.ecosystem).normalize_name(slipped))
        }

    def test_in_a_published_package_of_a_measured_format_it_may_block(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        case = next(c for c in CASES if c.ecosystem == "npm")
        assert self.found(case, monkeypatch, distribution="npm")[2][0].severity.name == "HIGH"

    def test_in_a_format_it_was_not_measured_on_it_stays_below_the_gate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        case = next(c for c in CASES if c.ecosystem == "pub")
        assert self.found(case, monkeypatch, distribution="pub")[2][0].severity.name == "MEDIUM"
