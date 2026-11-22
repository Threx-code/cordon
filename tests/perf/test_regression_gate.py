"""The push regression gate: a fixed, hashed corpus whose p99 scan time and peak memory may not regress.

The corpus is every project under tests/conformance/cases (the real, edge, regression and adversarial cases), pinned
by one sha256 over each file's path and bytes, so it cannot change without the baseline being re-recorded on purpose.
Each project is scanned whole with one job and no wall-clock budget, in a fresh child process so that what other perf
tests ran before cannot raise the memory peak. Time is CPU time (the child and the workers it reaps), judged as a ratio
to a calibration scan made in the same run: a slower machine moves both and the ratio stays. Memory is the largest
resident size of the child or any worker. Re-record only on purpose, with the change that justifies it:

    CORDON_PERF_REBASELINE=1 pytest -q -m perf tests/perf/test_regression_gate.py
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import ClassVar

import pytest

from support import ROOT as REPO

pytestmark = pytest.mark.perf


class RegressionCorpus:
    """The corpus, its pin, and the measurement run in a child process."""

    ROOT: ClassVar[Path] = REPO / "tests" / "conformance" / "cases"
    BASELINE: ClassVar[Path] = REPO / "tests" / "perf" / "regression_baseline.json"
    SELF: ClassVar[Path] = REPO / "tests" / "perf" / "test_regression_gate.py"
    CONFIG: ClassVar[str] = (
        "version: 1\nscan:\n  limits:\n    per_file_timeout: 0\n    total_timeout: 0\n"
    )
    #: How far the measurement may move before the push fails: time is noisier than memory.
    TIME_TOLERANCE: ClassVar[float] = 1.5
    MEMORY_TOLERANCE: ClassVar[float] = 1.25
    CALIBRATION_RUNS: ClassVar[int] = 3

    @classmethod
    def projects(cls) -> list[Path]:
        return sorted(p for p in cls.ROOT.glob("*/*") if p.is_dir())

    @classmethod
    def pin(cls) -> str:
        """sha256 over every corpus file's relative path and bytes, in a fixed order."""
        digest = hashlib.sha256()
        for path in sorted(p for p in cls.ROOT.rglob("*") if p.is_file()):
            digest.update(path.relative_to(cls.ROOT).as_posix().encode("utf-8") + b"\0")
            digest.update(hashlib.sha256(path.read_bytes()).digest())
        return digest.hexdigest()

    @staticmethod
    def spent() -> float:
        import resource  # POSIX: the perf suite runs on Linux

        own = resource.getrusage(resource.RUSAGE_SELF)
        children = resource.getrusage(resource.RUSAGE_CHILDREN)
        return own.ru_utime + own.ru_stime + children.ru_utime + children.ru_stime

    @staticmethod
    def peak_kb() -> int:
        import resource

        return max(
            resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
        )

    @classmethod
    def scan(cls, project: Path, work: Path) -> float:
        from cordon_scanner.cli.main import CommandLine

        config = work / "gate.config.yaml"
        config.write_text(cls.CONFIG, encoding="utf-8")
        out = work / f"{project.parent.name}-{project.name}.json"
        args = [
            "scan",
            str(project),
            "--offline",
            "--no-cache",
            "--no-color",
            "--quiet",
            "--jobs",
            "1",
        ]
        args += ["--format", "json", "--output", str(out), "--config", str(config)]
        started = cls.spent()
        with redirect_stdout(io.StringIO()):
            code = CommandLine.run(args)
        took = cls.spent() - started
        if code == 2:
            raise RuntimeError(f"the scan failed to run on {project}")
        return took

    @classmethod
    def measure(cls, work: Path) -> dict[str, float | int]:
        """Run in the child: calibration scans, then every project; p99 as a ratio, and the peak."""
        projects = cls.projects()
        cls.scan(projects[0], work)  # warm: the first scan of a process pays one-off loads
        calibration = sorted(cls.scan(projects[0], work) for _ in range(cls.CALIBRATION_RUNS))[1]
        times = sorted(cls.scan(project, work) for project in projects)
        p99 = times[min(len(times) - 1, round(0.99 * (len(times) - 1)))]
        return {
            "cases": len(projects),
            "p99_ratio": round(p99 / max(calibration, 1e-6), 3),
            "peak_rss_mb": round(cls.peak_kb() / 1024, 1),
        }

    @classmethod
    def run_child(cls, work: Path) -> dict[str, float | int]:
        """The measurement in a fresh interpreter, so earlier tests' workers cannot raise its peak."""
        env = dict(os.environ)
        paths = (str(REPO / "src"), str(REPO / "tests"), env.get("PYTHONPATH", ""))
        env["PYTHONPATH"] = os.pathsep.join(p for p in paths if p)
        done = subprocess.run(
            [sys.executable, str(cls.SELF), "--measure", str(work)],
            capture_output=True,
            text=True,
            env=env,
            timeout=3600,
            check=False,
        )
        assert done.returncode == 0, f"the measurement failed:\n{done.stderr[-4000:]}"
        return json.loads(done.stdout.strip().splitlines()[-1])


class TestRegressionGate:
    def test_the_corpus_is_the_pinned_one(self) -> None:
        recorded = json.loads(RegressionCorpus.BASELINE.read_text(encoding="utf-8"))
        assert RegressionCorpus.pin() == recorded["corpus_sha256"], (
            "the corpus changed: re-record the baseline on purpose (CORDON_PERF_REBASELINE=1), with the change"
        )

    def test_p99_time_and_peak_memory_do_not_regress(self, tmp_path: Path) -> None:
        measured = RegressionCorpus.run_child(tmp_path)
        print(f"regression gate: {measured}")
        if os.environ.get("CORDON_PERF_REBASELINE") == "1":
            record = {"corpus_sha256": RegressionCorpus.pin(), **measured}
            RegressionCorpus.BASELINE.write_text(
                json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8"
            )
            pytest.skip(f"baseline re-recorded: {record}")
        recorded = json.loads(RegressionCorpus.BASELINE.read_text(encoding="utf-8"))
        assert measured["cases"] == recorded["cases"], "the corpus's project count changed"
        assert measured["p99_ratio"] <= recorded["p99_ratio"] * RegressionCorpus.TIME_TOLERANCE, (
            f"p99 scan time regressed: {measured['p99_ratio']} against {recorded['p99_ratio']} "
            f"(x{RegressionCorpus.TIME_TOLERANCE} allowed)"
        )
        assert (
            measured["peak_rss_mb"] <= recorded["peak_rss_mb"] * RegressionCorpus.MEMORY_TOLERANCE
        ), (
            f"peak memory regressed: {measured['peak_rss_mb']} MB against {recorded['peak_rss_mb']} MB "
            f"(x{RegressionCorpus.MEMORY_TOLERANCE} allowed)"
        )


if __name__ == "__main__" and sys.argv[1:2] == ["--measure"]:
    print(json.dumps(RegressionCorpus.measure(Path(sys.argv[2]))))
