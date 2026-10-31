"""A nested project the package's own install script installs is installed: what it declares is
the package's dependencies, not its maintainers' (`engine/pipeline/install_scripts.py`)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.detect.supply.advisories.detector import AdvisoryDetector
from cordon_scanner.detect.supply.advisories.findings import BUNDLED_RULE, VULNERABLE_RULE
from cordon_scanner.engine.pipeline.install_scripts import InstallScripts
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Severity
from cordon_scanner.intel.advisories.advisories import Advisory, AdvisoryDatabase
from unit.engine.pipeline.test_not_installed import Tarball


class Manifest:
    @staticmethod
    def scripts(**scripts: str) -> bytes:
        return json.dumps({"name": "x", "version": "1.0.0", "scripts": scripts}).encode()


class TestInstallScripts:
    @pytest.mark.parametrize(
        ("script", "directories"),
        [
            ("cd app && npm install", {"app"}),
            ("cd ./examples/app && npm ci", {"examples/app"}),
            ("npm install --prefix app", {"app"}),
            ("npm --prefix=app i", {"app"}),
            ("yarn --cwd ui install", {"ui"}),
            ("yarn --cwd ui", {"ui"}),
            ("pnpm -C web install", {"web"}),
            ("pnpm --dir web i", {"web"}),
            ("bun install --cwd srv", {"srv"}),
            ("cd a && cd b && npm install", {"a/b"}),
            ("cd a; npm install; cd ..; cd c && yarn", {"a", "c"}),
            ("node scripts/build.js && npm install --prefix 'my app'", {"my app"}),
        ],
    )
    def test_the_directories_an_install_runs_in(self, script: str, directories: set[str]) -> None:
        found = InstallScripts.of(Manifest.scripts(postinstall=script))
        assert (found.directories, found.unresolved) == (directories, False)

    @pytest.mark.parametrize(
        "script",
        [
            "node build.js",
            "npm run build",
            "npm install",
            "cd .. && npm install",
            "echo npm install --prefix app",
            "tsc -p .",
        ],
    )
    def test_no_nested_install(self, script: str) -> None:
        found = InstallScripts.of(Manifest.scripts(postinstall=script))
        assert (found.directories, found.unresolved) == (set(), False)

    @pytest.mark.parametrize(
        "script",
        ["npm install --prefix $DIR", "cd $(node where.js) && npm i", "cd `pwd`/app && yarn"],
    )
    def test_an_install_somewhere_unnamed_is_unresolved(self, script: str) -> None:
        assert InstallScripts.of(Manifest.scripts(install=script)).unresolved

    def test_only_install_time_scripts_count(self) -> None:
        found = InstallScripts.of(
            Manifest.scripts(
                prepare="cd app && npm i", test="cd t && npm i", build="npm i --prefix b"
            )
        )
        assert (found.directories, found.unresolved) == (set(), False)

    @pytest.mark.parametrize("manifest", [b"", b"[]", b'{"scripts": 3}', b"\xff\xfe not json"])
    def test_a_manifest_that_says_nothing_installs_nothing(self, manifest: bytes) -> None:
        assert InstallScripts.of(manifest) == InstallScripts()


class TestScriptedInstalls:
    @staticmethod
    def rules(tmp_path: Path, postinstall: str | None) -> set[str]:
        root: dict[str, object] = {"name": "x", "version": "1.0.0"}
        if postinstall is not None:
            root["scripts"] = {"postinstall": postinstall}
        members = {
            "package.json": json.dumps(root),
            "app/package.json": json.dumps({"name": "app", "version": "1.0.0"}),
            "app/package-lock.json": Tarball.lock(minimist="1.2.5"),
        }
        records = (
            Advisory(
                ecosystem="npm",
                name="minimist",
                versions=("1.2.5",),
                severity="high",
                summary="s",
                identifier="GHSA-minimist",
            ),
        )
        config = Config.default().with_overrides(use_cache=False, severity_threshold=Severity.INFO)
        result = Scanner(config, detectors=(AdvisoryDetector(AdvisoryDatabase(records)),)).scan(
            Tarball.write(tmp_path, members)
        )
        return {f.rule_id for f in result.findings if f.rule_id in (VULNERABLE_RULE, BUNDLED_RULE)}

    def test_a_nested_project_nothing_installs_stays_not_installed(self, tmp_path: Path) -> None:
        assert self.rules(tmp_path, None) == {BUNDLED_RULE}

    def test_a_nested_project_the_install_script_installs_is_installed(
        self, tmp_path: Path
    ) -> None:
        assert self.rules(tmp_path, "cd app && npm install") == {VULNERABLE_RULE}

    def test_an_install_somewhere_unnamed_counts_every_nested_project(self, tmp_path: Path) -> None:
        assert self.rules(tmp_path, "npm install --prefix $TARGET") == {VULNERABLE_RULE}
