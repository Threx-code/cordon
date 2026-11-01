"""Detection in supervised workers (item 28, phase (a)): a detector that kills its worker on one file
costs that file and nothing else; the template every worker is forked from is forked before any
scanned byte is read; a detector given to the Scanner runs in the workers, its failures and gaps
coming back as the parent's; and a scan whose workers cannot start is a scanner error, never a pass."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap

import pytest

from cordon_scanner import Config, Scanner
from cordon_scanner.detect.base import DetectorRequirements, ScanContext
from cordon_scanner.engine.isolation.template import Template
from cordon_scanner.foundation.models import (
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
from support import ROOT

pytestmark = pytest.mark.skipif(not Template.available(), reason="no fork on this platform")


class Planted:
    """A detector given to the Scanner, as a third party's would be."""

    id = "planted-isolation"
    version = "1.0.0"
    categories = frozenset({Category.SUSPICIOUS})
    requires = DetectorRequirements(content=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def inspect(self, unit, ctx):
        name = unit.path.rsplit("/", 1)[-1]
        if name == "kills.txt":
            os._exit(9)  # the worker dies on this file, as a memory kill would end it
        if name == "raises.txt":
            raise RuntimeError("planted: a detector that fails on this file")
        yield Finding(
            rule_id="PLANTED.SEEN.001",
            category=Category.SUSPICIOUS,
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            message=f"seen in process {os.getpid()}",
            location=Location(path=unit.path),
            evidence=Evidence(
                kind=EvidenceKind.METADATA, match_hash="sha256:x", redaction=RedactionMode.NONE
            ),
            remediation="n/a",
            explanation=Explanation(summary="s", matched_rule="PLANTED.SEEN.001"),
            risk=RiskScore(value=0, base=0, confidence_multiplier=1.0),
            detector="planted-isolation",
        )


class Tree:
    @staticmethod
    def make(root, names: list[str]):
        root.mkdir(parents=True, exist_ok=True)
        for name in names:
            # each its own bytes: identical files are reported once, naming every place
            (root / name).write_text(f"plain text of {name}\n", encoding="utf-8")
        return root


class TestADetectorThatKillsItsWorker:
    SCRIPT = textwrap.dedent(
        """
        import json, sys
        from cordon_scanner import Config, Scanner
        from cordon_scanner.engine.registry import Registry
        sys.path[:0] = [sys.argv[2], sys.argv[3]]  # the test module, and tests/ for its support
        from test_isolated_detection import Planted
        detectors = (*Registry.default_detectors(), Planted())
        result = Scanner(Config.default().with_overrides(use_cache=False), detectors=detectors).scan(sys.argv[1])
        print(json.dumps({"complete": result.complete, "rules": sorted({(f.rule_id, f.location.path) for f in result.findings})}))
        """
    )

    def test_it_costs_that_file_and_the_scan_reports(self, tmp_path) -> None:
        root = Tree.make(tmp_path / "pkg", ["a.txt", "kills.txt", "b.txt"])
        tests_dir = str(ROOT / "tests" / "unit" / "engine" / "isolation")
        support_dir = str(ROOT / "tests")
        run = subprocess.run(
            [sys.executable, "-c", self.SCRIPT, str(root), tests_dir, support_dir],
            capture_output=True, text=True, timeout=600, check=False,
        )  # fmt: skip
        # before: the in-parent fallback inspected the file in the scanning process, which died
        assert run.returncode == 0, run.stderr[-800:]
        out = json.loads(run.stdout.strip().splitlines()[-1])
        rules = {tuple(r) for r in out["rules"]}
        assert ("OPERATIONAL.FILE.WORKER_DIED", "kills.txt") in rules
        assert {("PLANTED.SEEN.001", "a.txt"), ("PLANTED.SEEN.001", "b.txt")} <= rules
        assert out["complete"] is False


class TestTheTemplateHoldsNoScannedByte:
    def test_no_file_content_exists_when_the_template_forks(self, tmp_path, monkeypatch) -> None:
        from cordon_scanner.engine import engine as engine_module
        from cordon_scanner.foundation.content import FileContent

        made: list[int] = []
        at_fork: list[int] = []
        real_init = FileContent.__init__
        real_start = engine_module.Engine._start_template

        def counted(self, *a, **k):
            made.append(1)
            real_init(self, *a, **k)

        def start(self):
            at_fork.append(len(made))
            return real_start(self)

        monkeypatch.setattr(FileContent, "__init__", counted)
        monkeypatch.setattr(engine_module.Engine, "_start_template", start)
        Scanner(Config.default().with_overrides(use_cache=False)).scan(
            Tree.make(tmp_path / "pkg", ["a.txt"])
        )
        assert at_fork == [0]
        assert made, "the scan read its files after the fork"


class TestADetectorGivenToTheScannerRunsInTheWorkers:
    def test_its_findings_come_from_a_worker_and_its_failure_is_a_gap(self, tmp_path) -> None:
        from cordon_scanner.engine.registry import Registry

        root = Tree.make(tmp_path / "pkg", ["a.txt", "raises.txt"])
        config = Config.default().with_overrides(use_cache=False)
        result = Scanner(config, detectors=(*Registry.default_detectors(), Planted())).scan(root)
        seen = [f for f in result.findings if f.rule_id == "PLANTED.SEEN.001"]
        assert seen and all(f"process {os.getpid()}" not in f.message for f in seen)  # not here
        failed = [f for f in result.findings if f.rule_id == "OPERATIONAL.DETECTOR.FAILED"]
        assert [f.location.path for f in failed] == ["raises.txt"]
        assert result.complete is False


class TestNoWorkerCanStart:
    def test_it_is_a_scanner_error(self, tmp_path, monkeypatch) -> None:
        from cordon_scanner.engine import engine as engine_module
        from cordon_scanner.engine.isolation.supervisor import IsolationUnavailable
        from cordon_scanner.foundation.errors import ExitCode

        def broken(self):
            return Template.start(lambda sock: os._exit(3))  # every worker ends before it is ready

        monkeypatch.setattr(engine_module.Engine, "_start_template", broken)
        with pytest.raises(IsolationUnavailable) as raised:
            Scanner(Config.default().with_overrides(use_cache=False)).scan(
                Tree.make(tmp_path / "pkg", ["a.txt"])
            )
        assert raised.value.exit_code == ExitCode.SCANNER_ERROR
