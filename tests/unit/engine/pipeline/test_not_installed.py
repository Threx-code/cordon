"""A published package's nested and vendored dependency records are kept, marked not installed.

The inventory's scope is what installing the package installs (`DependencyScope`); what only a file
outside it records -- a lockfile of the maintainers' environment, a bundled UI's own lockfile -- is
reported with `installed=False`, its advisories under their own rules (a vulnerability at info, a
known-malicious release at high), and it can neither gate as an install-set finding nor leave the
scan incomplete.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.detect.supply.advisories.detector import AdvisoryDetector
from cordon_scanner.detect.supply.advisories.findings import (
    BUNDLED_MALWARE_RULE,
    BUNDLED_RULE,
    VULNERABLE_RULE,
)
from cordon_scanner.detect.supply.dependency import DependencyDetector
from cordon_scanner.detect.supply.dependency_rules import SOURCE_BUNDLED_RULE
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Severity
from cordon_scanner.intel.advisories.advisories import Advisory, AdvisoryDatabase


class Tarball:
    """An npm package tarball, written member by member."""

    @staticmethod
    def lock(**packages: str) -> str:
        entries = {"": {"name": "x", "version": "1.0.0", "dependencies": dict(packages)}}
        entries.update({f"node_modules/{n}": {"version": v} for n, v in packages.items()})
        return json.dumps(
            {"name": "x", "version": "1.0.0", "lockfileVersion": 3, "packages": entries}
        )

    @staticmethod
    def write(where: Path, members: dict[str, str]) -> Path:
        path = where / "x-1.0.0.tgz"
        with tarfile.open(path, "w:gz") as archive:
            for name, text in members.items():
                data = text.encode()
                info = tarfile.TarInfo(f"package/{name}")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return path

    @staticmethod
    def package(
        where: Path, *, root_lock: str | None = None, nested_lock: str | None = None
    ) -> Path:
        manifest = {"name": "x", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}}
        members = {"package.json": json.dumps(manifest), "index.js": "module.exports = 1;\n"}
        members["package-lock.json"] = (
            root_lock if root_lock is not None else Tarball.lock(lodash="4.17.20")
        )
        members["ui/package-lock.json"] = (
            nested_lock
            if nested_lock is not None
            else Tarball.lock(minimist="1.2.0", evilpkg="1.0.0")
        )
        return Tarball.write(where, members)

    @staticmethod
    def scan(path: Path):
        records = (
            Advisory(
                ecosystem="npm",
                name="lodash",
                versions=("4.17.20",),
                summary="s",
                identifier="GHSA-lodash",
            ),
            Advisory(
                ecosystem="npm",
                name="minimist",
                versions=("1.2.0",),
                summary="s",
                identifier="GHSA-minimist",
            ),
            Advisory(
                ecosystem="npm",
                name="evilpkg",
                versions=("1.0.0",),
                malicious=True,
                summary="s",
                identifier="MAL-evilpkg",
            ),
        )
        # Info shown: by default the report hides info findings, as it hides every info finding.
        config = Config.default().with_overrides(use_cache=False, severity_threshold=Severity.INFO)
        return Scanner(config, detectors=(AdvisoryDetector(AdvisoryDatabase(records)),)).scan(path)


class TestNotInstalled:
    def test_nested_records_are_kept_and_marked_not_installed(self, tmp_path: Path) -> None:
        result = Tarball.scan(Tarball.package(tmp_path))
        installed = {d.name: d.installed for d in result.dependencies}
        assert installed["lodash"] is True
        assert installed["minimist"] is False
        assert installed["evilpkg"] is False

    def test_their_advisories_have_their_own_rules_and_never_the_install_set_rule(
        self, tmp_path: Path
    ) -> None:
        result = Tarball.scan(Tarball.package(tmp_path))
        by_package = {
            (f.rule_id, str(f.severity))
            for f in result.findings
            if f.rule_id.endswith((".KNOWN.001", ".BUNDLED.001"))
        }
        assert (VULNERABLE_RULE, "high") in by_package or any(
            r == VULNERABLE_RULE for r, _ in by_package
        )
        assert (BUNDLED_RULE, "info") in by_package
        assert (BUNDLED_MALWARE_RULE, "high") in by_package
        vulnerable = [f for f in result.findings if f.rule_id == VULNERABLE_RULE]
        assert {f.location.package for f in vulnerable} == {"pkg:npm/lodash@4.17.20"}

    def test_an_unparsed_nested_lockfile_leaves_the_scan_complete(self, tmp_path: Path) -> None:
        assert Tarball.scan(Tarball.package(tmp_path, nested_lock="{ not json")).complete is True

    def test_an_unparsed_root_lockfile_leaves_it_incomplete(self, tmp_path: Path) -> None:
        assert Tarball.scan(Tarball.package(tmp_path, root_lock="{ not json")).complete is False


class TestBundledDependencies:
    """npm installs a tarball's own node_modules with it, as shipped: they are the install set."""

    @staticmethod
    def tarball(where: Path) -> Path:
        manifest = {
            "name": "x",
            "version": "1.0.0",
            "dependencies": {"evil": "1.0.0"},
            "bundleDependencies": ["evil"],
        }
        inner = {"name": "evil", "version": "1.0.0", "dependencies": {"inner": "2.0.0"}}
        return Tarball.write(
            where,
            {
                "package.json": json.dumps(manifest),
                "index.js": "require('evil');\n",
                "node_modules/evil/package.json": json.dumps(inner),
                "node_modules/evil/index.js": "module.exports = 1;\n",
                "node_modules/evil/node_modules/inner/package.json": json.dumps(
                    {"name": "inner", "version": "2.0.0"}
                ),
            },
        )

    def test_a_bundled_dependency_is_installed_and_a_malicious_one_is_the_normal_finding(
        self, tmp_path: Path
    ) -> None:
        records = (
            Advisory(
                ecosystem="npm",
                name="inner",
                versions=("2.0.0",),
                malicious=True,
                summary="s",
                identifier="MAL-inner",
            ),
        )
        config = Config.default().with_overrides(use_cache=False, severity_threshold=Severity.INFO)
        result = Scanner(config, detectors=(AdvisoryDetector(AdvisoryDatabase(records)),)).scan(
            TestBundledDependencies.tarball(tmp_path)
        )
        assert {d.name: d.installed for d in result.dependencies}["inner"] is True
        malware = [f for f in result.findings if f.location.package == "pkg:npm/inner@2.0.0"]
        assert [(f.rule_id, f.severity) for f in malware] == [
            ("MALWARE.DEPENDENCY.KNOWN.001", Severity.CRITICAL)
        ]


class TestNotInstalledSources:
    """A not-installed record's own risks stay visible at info: a source outside the registry, and
    an ecosystem no bundled database covers."""

    @staticmethod
    def scan(where: Path, nested_lock: str):
        manifest = {"name": "x", "version": "1.0.0"}
        path = Tarball.write(
            where,
            {
                "package.json": json.dumps(manifest),
                "index.js": "1;\n",
                "ui/package-lock.json": nested_lock,
            },
        )
        config = Config.default().with_overrides(use_cache=False, severity_threshold=Severity.INFO)
        return Scanner(
            config, detectors=(AdvisoryDetector(AdvisoryDatabase(())), DependencyDetector())
        ).scan(path)

    def test_a_source_outside_the_registry_is_its_own_info_rule(self, tmp_path: Path) -> None:
        lock = {
            "name": "ui",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "ui", "version": "1.0.0", "dependencies": {"left": "1.0.0"}},
                "node_modules/left": {
                    "version": "1.0.0",
                    "resolved": "https://code.example/left-1.0.0.tgz",
                },
            },
        }
        result = TestNotInstalledSources.scan(tmp_path, json.dumps(lock))
        rules = {(f.rule_id, f.severity) for f in result.findings if "SOURCE" in f.rule_id}
        assert rules == {(SOURCE_BUNDLED_RULE, Severity.INFO)}

    def test_an_uncovered_ecosystem_is_named_at_info_and_coverage_stays_complete(
        self, tmp_path: Path
    ) -> None:
        result = TestNotInstalledSources.scan(tmp_path, Tarball.lock(minimist="1.2.0"))
        notes = [f for f in result.findings if f.rule_id == "OPERATIONAL.ADVISORY.NO_FEED.001"]
        assert len(notes) == 1
        assert notes[0].message.startswith("Not installed with this package")
        assert result.advisory_complete is True
