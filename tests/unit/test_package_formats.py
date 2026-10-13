"""Published-package formats beyond Python and npm (review 98, FP-11 / FP-12).

A lockfile inside a published package is its maintainers' environment in every format whose
installer resolves from declared metadata, not only in an sdist or an npm tarball. What else is
lowered depends on what that format's installer runs.
"""

from __future__ import annotations

import io
import tarfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_exploited import ExploitedHelpers

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.core.engine import HONOURED_PINS, Engine
from cordon_scanner.core.models import Severity
from cordon_scanner.detect.advisory import EXPLOITED_RULE, VULNERABLE_RULE, AdvisoryDetector
from cordon_scanner.intel import exploited
from cordon_scanner.intel.advisories import Advisory, AdvisoryDatabase

CARGO_LOCK = """version = 3

[[package]]
name = "smallvec"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"
"""


class PackageFormatHelpers:
    @staticmethod
    def units(*members: str) -> list[SimpleNamespace]:
        return [SimpleNamespace(path=f"target.ext!{m}") for m in members]

    @staticmethod
    def archive(tmp_path: Path, name: str, files: dict[str, str]) -> Path:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for member, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo(member)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / name
        target.write_bytes(buffer.getvalue())
        return target

    @staticmethod
    def scan(target: Path, advisory: Advisory):
        config = Config.default().with_overrides(use_cache=False)
        detectors = (AdvisoryDetector(AdvisoryDatabase((advisory,))),)
        return Scanner(config, detectors=detectors).scan(target)

    @staticmethod
    def smallvec(**overrides) -> Advisory:
        return ExploitedHelpers._advisory(
            ecosystem="cargo", name="smallvec", severity="critical", **overrides
        )


class TestTheFormatIsRecognised:
    @pytest.mark.parametrize(
        ("expected", "members"),
        [
            ("pypi", ["app-1.0.0/PKG-INFO", "app-1.0.0/setup.py"]),
            ("pypi", ["app-1.0.0.dist-info/METADATA", "app/__init__.py"]),
            ("npm", ["package/package.json", "package/index.js"]),
            (
                "cargo",
                ["app-1.0.0/Cargo.toml", "app-1.0.0/Cargo.toml.orig", "app-1.0.0/src/lib.rs"],
            ),
            ("rubygems", ["metadata.gz", "checksums.yaml.gz"]),
            ("nuget", ["[Content_Types].xml", "App.nuspec", "lib/net8.0/App.dll"]),
            ("hex", ["VERSION", "CHECKSUM", "metadata.config"]),
            ("maven", ["META-INF/MANIFEST.MF", "com/example/App.class"]),
            ("conda", ["info/index.json", "info/paths.json", "lib/app.so"]),
            ("hackage", ["AVar-0.0.5.1/AVar.cabal", "AVar-0.0.5.1/Setup.lhs"]),
            ("cran", ["AID/DESCRIPTION", "AID/MD5", "AID/R/aid.R"]),
            ("galaxy", ["MANIFEST.json", "FILES.json", "plugins/modules/x.py"]),
            ("gomod", ["github.com/a/b@v1.2.3/go.mod", "github.com/a/b@v1.2.3/b.go"]),
        ],
    )
    def test_by_the_metadata_its_packaging_tool_writes(self, expected, members) -> None:
        assert Engine._distribution_format(PackageFormatHelpers.units(*members)) == expected

    @pytest.mark.parametrize(
        "members",
        [
            # A repository snapshot: Packagist and Helm archives look exactly like this.
            ["app-main/composer.json", "app-main/composer.lock"],
            ["chart/Chart.yaml", "chart/Chart.lock"],
            # A cabal file whose folder is not `<name>-<version>`.
            ["src/AVar.cabal"],
            # DESCRIPTION alone is any R project; R CMD build adds MD5.
            ["AID/DESCRIPTION"],
        ],
    )
    def test_a_repository_snapshot_is_not_one(self, members) -> None:
        assert Engine._distribution_format(PackageFormatHelpers.units(*members)) == ""

    def test_a_repository_that_vendors_a_package_is_still_a_repository(self) -> None:
        units = [
            SimpleNamespace(path="repo.tar.gz!repo/Cargo.lock"),
            SimpleNamespace(path="repo.tar.gz!repo/vendor/dep-1.0.0.tgz!package/package.json"),
            SimpleNamespace(path="repo.tar.gz!repo/vendor/x-1.0.crate!x-1.0/Cargo.toml.orig"),
        ]
        assert Engine._distribution_format(units) == ""


class TestALockfileInAPublishedCrate:
    def test_is_its_maintainers_environment(self, tmp_path) -> None:
        crate = PackageFormatHelpers.archive(
            tmp_path,
            "app-1.0.0.crate",
            {
                "app-1.0.0/Cargo.toml": '[package]\nname = "app"\nversion = "1.0.0"\n',
                "app-1.0.0/Cargo.toml.orig": '[package]\nname = "app"\nversion = "1.0.0"\n',
                "app-1.0.0/Cargo.lock": CARGO_LOCK,
            },
        )
        result = PackageFormatHelpers.scan(crate, PackageFormatHelpers.smallvec())
        [finding] = [f for f in result.findings if f.rule_id == VULNERABLE_RULE]
        assert finding.severity is Severity.LOW
        assert "maintainers' development environment" in finding.message

    def test_keeps_its_rating_in_a_repository(self, tmp_path) -> None:
        (tmp_path / "Cargo.toml").write_text(
            '[package]\nname = "app"\nversion = "1.0.0"\n', encoding="utf-8"
        )
        (tmp_path / "Cargo.lock").write_text(CARGO_LOCK, encoding="utf-8")
        result = PackageFormatHelpers.scan(tmp_path, PackageFormatHelpers.smallvec())
        [finding] = [f for f in result.findings if f.rule_id == VULNERABLE_RULE]
        assert finding.severity is Severity.CRITICAL

    def test_a_malicious_release_is_never_lowered(self, tmp_path) -> None:
        crate = PackageFormatHelpers.archive(
            tmp_path,
            "app-1.0.0.crate",
            {
                "app-1.0.0/Cargo.toml.orig": '[package]\nname = "app"\nversion = "1.0.0"\n',
                "app-1.0.0/Cargo.lock": CARGO_LOCK,
            },
        )
        advisory = PackageFormatHelpers.smallvec(malicious=True, identifier="MAL-2026-1")
        result = PackageFormatHelpers.scan(crate, advisory)
        [finding] = [f for f in result.findings if f.rule_id == "MALWARE.DEPENDENCY.KNOWN.001"]
        assert finding.severity is Severity.CRITICAL


class TestAPinTheInstallerHonours:
    def test_npm_shrinkwrap_keeps_its_rating(self, tmp_path) -> None:
        tarball = PackageFormatHelpers.archive(
            tmp_path,
            "app-1.0.0.tgz",
            {
                "package/package.json": '{"name":"app","version":"1.0.0"}',
                "package/npm-shrinkwrap.json": ExploitedHelpers._lockfile("left-pad", "1.0.0"),
            },
        )
        result = PackageFormatHelpers.scan(tarball, ExploitedHelpers._advisory(severity="critical"))
        [finding] = [f for f in result.findings if f.rule_id == VULNERABLE_RULE]
        assert finding.severity is Severity.CRITICAL

    def test_npm_package_lock_is_still_lowered(self, tmp_path) -> None:
        tarball = PackageFormatHelpers.archive(
            tmp_path,
            "app-1.0.0.tgz",
            {
                "package/package.json": '{"name":"app","version":"1.0.0"}',
                "package/package-lock.json": ExploitedHelpers._lockfile("left-pad", "1.0.0"),
            },
        )
        result = PackageFormatHelpers.scan(tarball, ExploitedHelpers._advisory(severity="critical"))
        [finding] = [f for f in result.findings if f.rule_id == VULNERABLE_RULE]
        assert finding.severity is Severity.LOW

    @pytest.mark.parametrize(
        ("distribution", "path", "honoured"),
        [
            ("maven", "a.jar!META-INF/maven/com.example/app/pom.xml", True),
            ("maven", "a.jar!src/test/resources/pom.xml", False),
            ("nuget", "a.nupkg!App.nuspec", True),
            ("nuget", "a.nupkg!content/packages.lock.json", False),
            ("gomod", "m.zip!github.com/a/b@v1.2.3/go.mod", True),
            ("gomod", "m.zip!github.com/a/b@v1.2.3/tools/go.mod", False),
            ("gomod", "m.zip!github.com/a/b@v1.2.3/go.sum", False),
        ],
    )
    def test_by_format(self, distribution, path, honoured) -> None:
        assert bool(HONOURED_PINS[distribution].search(path)) is honoured


class TestWhatTheInstallerRuns:
    """The author-time ceiling, applied to a real finding moved onto each kind of file."""

    @pytest.fixture
    def finding(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name":"app","version":"1.0.0"}', encoding="utf-8")
        (tmp_path / "package-lock.json").write_text(
            ExploitedHelpers._lockfile("left-pad", "1.0.0"), encoding="utf-8"
        )
        result = PackageFormatHelpers.scan(
            tmp_path, ExploitedHelpers._advisory(severity="critical")
        )
        [finding] = [f for f in result.findings if f.rule_id == VULNERABLE_RULE]
        assert finding.severity is Severity.CRITICAL
        return finding

    @staticmethod
    def ceiling(finding, path: str, distribution: str) -> Severity:
        moved = replace(finding, location=replace(finding.location, path=path))
        [out] = Engine._author_time_ceiling([moved], [], distribution)
        return out.severity

    def test_rust_source_in_a_crate_is_the_program(self, finding) -> None:
        assert self.ceiling(finding, "a.crate!a-1.0/src/lib.rs", "cargo") is Severity.CRITICAL

    def test_compiled_source_in_an_sdist_is_not_run(self, finding) -> None:
        assert self.ceiling(finding, "a.tar.gz!a-1.0/src/ext.c", "pypi") is Severity.MEDIUM

    @pytest.mark.parametrize("distribution", ["cran", "hex", "rubygems", "hackage"])
    def test_a_makefile_runs_where_install_runs_make(self, finding, distribution) -> None:
        assert self.ceiling(finding, "p.tgz!p/src/Makefile", distribution) is Severity.CRITICAL

    @pytest.mark.parametrize("distribution", ["cargo", "gomod", "maven", "pypi", "npm"])
    def test_a_makefile_is_the_maintainers_elsewhere(self, finding, distribution) -> None:
        assert self.ceiling(finding, "p.tgz!p/Makefile", distribution) is Severity.MEDIUM

    @pytest.mark.parametrize("distribution", ["cargo", "gomod", "maven", "nuget", "cran"])
    def test_ci_workflows_never_run_for_a_consumer(self, finding, distribution) -> None:
        path = "p.tgz!p/.github/workflows/release.yml"
        assert self.ceiling(finding, path, distribution) is Severity.MEDIUM


class TestAPublishersSecret:
    """A credential inside a published package is its publisher's to rotate, not an attack."""

    COVERALLS = "service_name: travis-pro\nrepo_token: 7Hq2LmZx9VbN4kPd1RtYw8sGcE5fJuAo3\n"

    @staticmethod
    def secret_findings(target: Path):
        config = Config.default().with_overrides(use_cache=False)
        result = Scanner(config).scan(target)
        return [f for f in result.findings if f.rule_id.startswith("SECRET.")]

    def test_is_reported_below_the_gate(self, tmp_path) -> None:
        tarball = PackageFormatHelpers.archive(
            tmp_path,
            "app-1.0.0.tgz",
            {
                "package/package.json": '{"name":"app","version":"1.0.0"}',
                "package/.coveralls.yml": self.COVERALLS,
            },
        )
        findings = self.secret_findings(tarball)
        assert findings
        assert all(f.severity <= Severity.MEDIUM for f in findings)
        assert all("publisher's" in f.message for f in findings)

    def test_in_a_repository_it_keeps_its_grade(self, tmp_path) -> None:
        (tmp_path / "package.json").write_text('{"name":"app","version":"1.0.0"}', encoding="utf-8")
        (tmp_path / ".coveralls.yml").write_text(self.COVERALLS, encoding="utf-8")
        findings = self.secret_findings(tmp_path)
        assert any(f.severity >= Severity.HIGH for f in findings)

    def test_a_drop_point_keeps_its_grade(self, tmp_path) -> None:
        (tmp_path / ".coveralls.yml").write_text(self.COVERALLS, encoding="utf-8")
        [finding, *_] = [f for f in self.secret_findings(tmp_path) if f.severity >= Severity.HIGH]
        bot = replace(finding, rule_id="SECRET.TELEGRAM.BOT_TOKEN.001")
        leaked = replace(finding, rule_id="SECRET.GENERIC.ASSIGNMENT.001")
        out = {f.rule_id: f.severity for f in Engine._publisher_secrets([bot, leaked])}
        assert out["SECRET.TELEGRAM.BOT_TOKEN.001"] is finding.severity
        assert out["SECRET.GENERIC.ASSIGNMENT.001"] is Severity.MEDIUM


class TestAGoModulesMinimumVersion:
    """FP-11: a published module's `go.mod` require is a minimum, not what a build selects."""

    GO_MOD = "module github.com/a/b\n\ngo 1.21\n\nrequire golang.org/x/net v0.1.0\n"

    @staticmethod
    def module(tmp_path: Path) -> Path:
        import zipfile

        target = tmp_path / "github.com_a_b-v1.0.0.zip"
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr("github.com/a/b@v1.0.0/go.mod", TestAGoModulesMinimumVersion.GO_MOD)
            archive.writestr("github.com/a/b@v1.0.0/b.go", "package b\n")
        return target

    @staticmethod
    def advisory(**overrides) -> Advisory:
        return ExploitedHelpers._advisory(
            ecosystem="gomod", name="golang.org/x/net", versions=("v0.1.0", "0.1.0"), **overrides
        )

    def test_is_reported_at_medium(self, tmp_path) -> None:
        advisory = self.advisory(severity="critical")
        result = PackageFormatHelpers.scan(self.module(tmp_path), advisory)
        [finding] = [f for f in result.findings if f.rule_id == VULNERABLE_RULE]
        assert finding.severity is Severity.MEDIUM
        assert "may select a newer one" in finding.message

    def test_an_exploited_one_is_reported_and_named(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(
            exploited.ExploitedCatalogue,
            "catalogue",
            lambda: ExploitedHelpers._catalogue("CVE-2023-2222"),
        )
        advisory = self.advisory(severity="critical", aliases=("CVE-2023-2222",))
        result = PackageFormatHelpers.scan(self.module(tmp_path), advisory)
        [finding] = [f for f in result.findings if f.rule_id == EXPLOITED_RULE]
        assert finding.severity is Severity.MEDIUM
        assert "exploited" in finding.message.lower()

    def test_in_a_repository_it_keeps_its_rating(self, tmp_path) -> None:
        (tmp_path / "go.mod").write_text(self.GO_MOD, encoding="utf-8")
        result = PackageFormatHelpers.scan(tmp_path, self.advisory(severity="critical"))
        [finding] = [f for f in result.findings if f.rule_id == VULNERABLE_RULE]
        assert finding.severity is Severity.CRITICAL
