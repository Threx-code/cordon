"""A Composer dist's own `composer.lock` is the maintainers' environment, not what installing the package brings in: the package is installed
from its `composer.json` requirements, so the lock's entries are graded as development ones (`VULNERABLE.DEPENDENCY.BUNDLED.001` at info).
That demotion must not hide a malicious release: a requirement whose range admits a recorded malicious release still blocks.

The dist, its two files and the advisory record are synthetic (every real name in the repository's Composer captures is on the
established-package list, whose declared ranges are never flagged: a compromised release of a popular package is pulled within hours). The
requirement is for a package outside that list; the lock pins the release the maintainers had, as Composer 2 writes it (the shape of the real
`conformance/cases/composer/real-application/composer.lock`). The test is about the grading, not about the data."""

from __future__ import annotations

import io
import json
import tarfile
import zipfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.detect.supply.advisories.detector import AdvisoryDetector
from cordon_scanner.detect.supply.advisories.findings import MALICIOUS_RULE
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Severity
from cordon_scanner.intel.advisories.advisories import Advisory, AdvisoryDatabase

NAME = "zeta-ledger/ledger-core"
MANIFEST = {"name": "zeta/app", "require": {"php": ">=8.1", NAME: "^1.2"}}
LOCK = {
    "packages": [{"name": NAME, "version": "1.2.0", "type": "library"}],
    "packages-dev": [],
}


class Dist:
    @staticmethod
    def make(folder: Path, lock: bool = True) -> Path:
        path = folder / "zeta-app-1.0.0.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("zeta-app-4b1f/composer.json", json.dumps(MANIFEST))
            if lock:
                archive.writestr("zeta-app-4b1f/composer.lock", json.dumps(LOCK))
        return path

    @staticmethod
    def scan(path: Path, release: str):
        record = Advisory(
            ecosystem="composer",
            name=NAME,
            versions=(release,),
            malicious=True,
            summary="s",
            identifier="MAL-1",
        )
        config = Config.default().with_overrides(use_cache=False, severity_threshold=Severity.INFO)
        return Scanner(config, detectors=(AdvisoryDetector(AdvisoryDatabase((record,))),)).scan(
            path
        )


class NpmTarball:
    """An npm package whose tarball ships a `package-lock.json` (its maintainers' own; npm installs only an `npm-shrinkwrap.json`)."""

    NAME = "zeta-ledger-core"

    @staticmethod
    def make(folder: Path, lock_name: str) -> Path:
        manifest = {
            "name": "zeta-app",
            "version": "1.0.0",
            "dependencies": {NpmTarball.NAME: "^1.2.0"},
        }
        lock = {
            "name": "zeta-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "zeta-app",
                    "version": "1.0.0",
                    "dependencies": {NpmTarball.NAME: "^1.2.0"},
                },
                f"node_modules/{NpmTarball.NAME}": {"version": "1.2.0"},
            },
        }
        path = folder / "zeta-app-1.0.0.tgz"
        with tarfile.open(path, "w:gz") as tar:
            for name, document in (("package.json", manifest), (lock_name, lock)):
                data = json.dumps(document).encode()
                info = tarfile.TarInfo(f"package/{name}")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return path

    @staticmethod
    def scan(path: Path):
        record = Advisory(
            ecosystem="npm",
            name=NpmTarball.NAME,
            versions=("1.9.9",),
            malicious=True,
            summary="s",
            identifier="MAL-2",
        )
        config = Config.default().with_overrides(use_cache=False, severity_threshold=Severity.INFO)
        return Scanner(config, detectors=(AdvisoryDetector(AdvisoryDatabase((record,))),)).scan(
            path
        )


class TestADemotedLockDoesNotHideAMaliciousRelease:
    def test_an_npm_packages_own_lock_does_not_hide_a_range_that_admits_one(
        self, tmp_path: Path
    ) -> None:
        result = NpmTarball.scan(NpmTarball.make(tmp_path, "package-lock.json"))
        assert [f for f in result.findings if f.rule_id == MALICIOUS_RULE]

    def test_a_range_that_admits_a_malicious_release_blocks(self, tmp_path: Path) -> None:
        result = Dist.scan(Dist.make(tmp_path), "1.9.9")
        found = [f for f in result.findings if f.rule_id == MALICIOUS_RULE]
        assert found, "the declared range ^1.2 admits 1.9.9"
        assert max(f.severity for f in found) >= Severity.HIGH

    def test_a_dist_without_a_lock_blocks_the_same_way(self, tmp_path: Path) -> None:
        result = Dist.scan(Dist.make(tmp_path, lock=False), "1.9.9")
        assert [f for f in result.findings if f.rule_id == MALICIOUS_RULE]

    def test_a_malicious_release_outside_every_declared_range_is_not_reported(
        self, tmp_path: Path
    ) -> None:
        result = Dist.scan(Dist.make(tmp_path), "0.5.0")
        assert [f for f in result.findings if f.rule_id == MALICIOUS_RULE] == []
