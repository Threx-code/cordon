"""An action runs what its tarball ships: the packages its lock marks runtime keep their rating, the dev ones stay capped.

GitHub's runner downloads, for `uses: owner/repo@ref`, the repository's tarball and runs the action as shipped; its `dist/` is compiled
(ncc) from the runtime entries of its `package-lock.json`. So a vulnerable runtime package there is what runs, and a dev package
(eslint, jest) never reaches a workflow. (A Composer dist is the opposite: its `composer.lock` is ignored when the package is a
dependency, and stays `VULNERABLE.DEPENDENCY.BUNDLED.001` at info.) The tarball is the real `actions/checkout` v4.2.2; the advisory
records are synthetic and name packages its lock pins, so the test is about the grading, not the advisory data.
"""

from __future__ import annotations

from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.detect.supply.advisories.detector import AdvisoryDetector
from cordon_scanner.detect.supply.advisories.findings import BUNDLED_RULE, VULNERABLE_RULE
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Severity
from cordon_scanner.intel.advisories.advisories import Advisory, AdvisoryDatabase
from support import ROOT

TARBALL = (
    ROOT
    / "tests"
    / "unit"
    / "detect"
    / "supply"
    / "advisories"
    / "action_captures"
    / "actions-checkout-v4.2.2.tar.gz"
)


class Checkout:
    @staticmethod
    def scan(path: Path):
        records = (
            Advisory(
                ecosystem="npm",
                name="@actions/core",
                versions=("1.10.1",),
                summary="s",
                identifier="GHSA-core",
                severity="high",
            ),
            Advisory(
                ecosystem="npm",
                name="eslint",
                versions=("8.57.0",),
                summary="s",
                identifier="GHSA-eslint",
                severity="high",
            ),
        )
        config = Config.default().with_overrides(use_cache=False, severity_threshold=Severity.INFO)
        return Scanner(config, detectors=(AdvisoryDetector(AdvisoryDatabase(records)),)).scan(path)

    @staticmethod
    def graded(result, package: str) -> set[tuple[str, str]]:
        return {
            (f.rule_id, str(f.severity)) for f in result.findings if f.location.package == package
        }


class TestAnActionRunsWhatItShips:
    def test_a_runtime_package_in_its_lock_keeps_its_rule_and_severity(self) -> None:
        graded = Checkout.graded(Checkout.scan(TARBALL), "pkg:npm/@actions/core@1.10.1")
        assert (VULNERABLE_RULE, "high") in graded
        assert all(rule != BUNDLED_RULE for rule, _ in graded)

    def test_a_dev_package_in_its_lock_is_still_capped_at_low(self) -> None:
        graded = Checkout.graded(Checkout.scan(TARBALL), "pkg:npm/eslint@8.57.0")
        assert graded == {(VULNERABLE_RULE, "low")}

    def test_the_lock_scopes_are_read_as_npm_wrote_them(self) -> None:
        scopes = {d.name: str(d.scope) for d in Checkout.scan(TARBALL).dependencies}
        assert (scopes["@actions/core"], scopes["uuid"], scopes["eslint"]) == (
            "runtime",
            "runtime",
            "dev",
        )
