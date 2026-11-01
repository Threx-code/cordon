"""Detection in supervised workers (item 28, phase (a)): a detector that kills its worker on one file
costs that file and nothing else; the template every worker is forked from is forked before any
scanned byte is read; a detector given to the Scanner runs in the workers, its failures and gaps
coming back as the parent's; and a scan whose workers cannot start is a scanner error, never a pass."""

from __future__ import annotations

import json
import os
import re
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


class Seen:
    """Where a planted finding was made, read exactly from its message (item 55): the check was a
    substring match, so a worker whose pid begins with this process's digits (1234 against 12) read
    as this process, and the gate's load, many processes, made such pids likely."""

    PID = re.compile(r"seen in process (\d+)$")

    @staticmethod
    def pid(message: str) -> int | None:
        found = Seen.PID.search(message)
        return int(found.group(1)) if found else None

    @staticmethod
    def here(findings) -> list[tuple[str, int | None]]:
        """The planted findings made in this process (or whose pid can't be read), by path and pid."""
        return [
            (f.location.path, Seen.pid(f.message))
            for f in findings
            if f.rule_id == "PLANTED.SEEN.001" and Seen.pid(f.message) in (None, os.getpid())
        ]


class TestTheCheckReadsThePidExactly:
    def test_a_worker_pid_that_begins_with_this_one_is_not_this_one(self) -> None:
        worker = int(f"{os.getpid()}34")
        assert Seen.pid(f"seen in process {worker}") == worker != os.getpid()
        assert Seen.pid(f"seen in process {os.getpid()}") == os.getpid()


class TestADetectorGivenToTheScannerRunsInTheWorkers:
    def test_its_findings_come_from_a_worker_and_its_failure_is_a_gap(self, tmp_path) -> None:
        from cordon_scanner.engine.registry import Registry

        root = Tree.make(tmp_path / "pkg", ["a.txt", "raises.txt"])
        config = Config.default().with_overrides(use_cache=False)
        result = Scanner(config, detectors=(*Registry.default_detectors(), Planted())).scan(root)
        seen = [f for f in result.findings if f.rule_id == "PLANTED.SEEN.001"]
        assert seen
        assert not Seen.here(seen), f"made in this process {os.getpid()}: {Seen.here(seen)}"
        failed = [f for f in result.findings if f.rule_id == "OPERATIONAL.DETECTOR.FAILED"]
        assert [f.location.path for f in failed] == ["raises.txt"]
        assert result.complete is False

    def test_an_archive_s_members_are_read_in_the_workers_too(self, tmp_path) -> None:
        """No member of an archive is inspected in this process: the loop left for that was deleted
        (item 55), and this keeps one from coming back unnoticed."""
        import io
        import tarfile

        from cordon_scanner.engine.registry import Registry

        target = tmp_path / "pkg-1.0.0.tgz"
        with tarfile.open(target, "w:gz") as tar:
            for name in ("package/package.json", "package/a.txt", "package/b.txt"):
                # distinct bytes: byte-identical copies fold into one finding (item 28)
                data = (
                    b'{"name":"pkg","version":"1.0.0"}' if name.endswith(".json") else name.encode()
                )
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        config = Config.default().with_overrides(use_cache=False)
        result = Scanner(config, detectors=(*Registry.default_detectors(), Planted())).scan(target)
        seen = [f for f in result.findings if f.rule_id == "PLANTED.SEEN.001"]
        assert {f.location.path.rsplit("!", 1)[-1] for f in seen} >= {
            "package/a.txt",
            "package/b.txt",
        }
        assert not Seen.here(seen), f"made in this process {os.getpid()}: {Seen.here(seen)}"


class TestAWorkerStartsNoProcessOfItsOwn:
    """The binary rule pool spreads one large file over processes of its own. Inside a supervised
    worker those would be outside its bounds, its kill and its reaping, and outlive it; a plainly
    forked worker has no `parent_process()`, so that check alone let every worker start one."""

    def test_a_large_file_under_a_large_collection_starts_no_rule_pool(
        self, tmp_path, monkeypatch
    ) -> None:
        from cordon_scanner.detect.binary import rule_pool

        rules = tmp_path / "operator.yar"
        rules.write_text(
            "\n".join(
                f"rule f{i} {{ strings: $a = {{ {i // 256:02X} {i % 256:02X} EE {i % 251:02X} 7A }}"
                " condition: $a }"
                for i in range(rule_pool.RulePool.MIN_RULES + 50)
            ),
            encoding="utf-8",
        )
        root = tmp_path / "pkg"
        root.mkdir()
        (root / "blob.bin").write_bytes(bytes(range(256)) * (rule_pool.RulePool.LARGE // 128))
        starts = tmp_path / "pool-starts.txt"  # written in the worker, read here
        real = rule_pool.RulePool.executor

        def recorded(self):
            with starts.open("a", encoding="utf-8") as out:
                out.write(f"{os.getpid()}\n")
            return real(self)

        monkeypatch.setattr(rule_pool.RulePool, "executor", recorded)
        config = Config.default().with_overrides(use_cache=False, rule_file=str(rules))
        Scanner(config.with_overrides(limits=config.limits.merged(max_workers=2))).scan(root)
        # before: each forked worker started its own pool (S/proofs-item28/pool/pool250-native.txt)
        assert not starts.exists(), starts.read_text(encoding="utf-8")


class TestNothingOutlivesTheScan:
    def test_the_engine_the_workers_came_from_is_released(self, tmp_path) -> None:
        from cordon_scanner.engine.parallel import ParallelScanner

        Scanner(Config.default().with_overrides(use_cache=False)).scan(
            Tree.make(tmp_path / "pkg", ["a.txt"])
        )
        # before: it still held the scan's engine, its rules and config, in this process
        assert ParallelScanner._template_engine is None


class TestALossOfAnyKindBlocks:
    def test_a_reason_the_table_does_not_list_still_names_the_file_and_blocks(self) -> None:
        from cordon_scanner.decide.policy import PolicyGate
        from cordon_scanner.detect.base import FileUnit
        from cordon_scanner.engine.pipeline.accumulator import Accumulator
        from cordon_scanner.engine.pipeline.detection import Detection
        from cordon_scanner.foundation.content import FileContent
        from cordon_scanner.foundation.errors import ExitCode
        from cordon_scanner.foundation.results import ScanResult

        unit = FileUnit(content=FileContent(path="x.py", raw=b"x = 1\n", size=6))
        acc = Accumulator()
        lost = Detection.worker_lost(unit, "unheard-of: a reason no table lists", acc)
        assert (lost.rule_id, lost.location.path) == ("OPERATIONAL.FILE.WORKER_DIED", "x.py")
        assert ("OPERATIONAL.FILE.WORKER_DIED", "x.py") in acc.content_gaps
        result = ScanResult(findings=(lost,), **acc.coverage())
        policy = Config.default().policy
        assert not policy.fail_on_incomplete
        assert PolicyGate.evaluate(result, policy).exit_code is not ExitCode.CLEAN


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


class Slow(Planted):
    """A detector that reaches its own time limit on one file and breaks on another (item 58)."""

    id = "planted-slow"

    def inspect(self, unit, ctx):
        name = unit.path.rsplit("/", 1)[-1]
        if name == "slow.txt":
            raise TimeoutError("matching took longer than the time allowed")
        if name == "broken.txt":
            raise ValueError("planted: a detector that breaks on this file")
        return ()


class TestATimeLimitIsNotACrash:
    """A detector's own time limit on a file is a time budget, reported as one: a host stall had made
    the rule engine's match timeout read as OPERATIONAL.DETECTOR.FAILED on two benign units."""

    def test_a_timeout_is_a_file_timeout_gap_and_a_crash_stays_a_failure(self, tmp_path) -> None:
        from cordon_scanner.engine.registry import Registry

        root = Tree.make(tmp_path / "pkg", ["slow.txt", "broken.txt", "fine.txt"])
        config = Config.default().with_overrides(use_cache=False)
        result = Scanner(config, detectors=(*Registry.default_detectors(), Slow())).scan(root)
        by_rule = {}
        for f in result.findings:
            if f.rule_id in ("OPERATIONAL.FILE.TIMEOUT", "OPERATIONAL.DETECTOR.FAILED"):
                by_rule.setdefault(f.rule_id, set()).add(f.location.path)
        assert by_rule == {
            "OPERATIONAL.FILE.TIMEOUT": {"slow.txt"},
            "OPERATIONAL.DETECTOR.FAILED": {"broken.txt"},
        }
        gaps = dict(result.content_gaps)
        assert gaps.get("OPERATIONAL.FILE.TIMEOUT") == "slow.txt"
        assert result.content_complete is False
