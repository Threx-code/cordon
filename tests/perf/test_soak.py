"""Many scans in one process hold no more memory than a few do.

In a process that scans unit after unit (the Python API, an editor integration, a harness), caches
that kept each scan's files held about 0.2 MB a unit: one new project per scan, each with a 200 KB
Python and a 200 KB JavaScript file at paths no scan saw before, took 00578d7e from 98 MB after 25
scans to 149 MB after 150 and 164 MB after 300, still rising. With those caches emptied after every
scan (`foundation.collector.ScanCaches`) the same scans hold 85 MB from the 25th to the 150th.

So the soak scans that shape, and after a warm-up its resident memory may grow by at most GROWTH. The
warm-up takes the one-off loads and the allocator's first high water; what grows after it is what the
process keeps. The MCP server's warm helper is held to the same, over the same scans as tool calls:
it forks a child per call, so nothing a call reads can stay in it.
"""

from __future__ import annotations

import gc
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

pytestmark = pytest.mark.perf

#: Scans after the warm-up, and the growth they may add (measured: 00578d7e +50 MB from scan 25 to
#: 150, emptied 0 MB). CORDON_SOAK_SCANS raises the count for the release soak (1,000).
WARM = 25
SCANS = max(int(os.environ.get("CORDON_SOAK_SCANS", "150")), WARM + 1)
#: The warm helper's calls: fewer by default, since each is a fork and a whole CLI scan (about 4 s)
#: and the fork leaves nothing behind by construction; the release soak runs it at SCANS too.
CALLS = SCANS if "CORDON_SOAK_SCANS" in os.environ else 50
GROWTH_MB = 15


class SoakKit:
    PY = (
        '"""A module."""\nimport os\n\ndef run(value):\n    """Run."""\n    return os.getenv(value)\n'
        * 3_000
    )[:200_000]
    JS = (
        "/* a block comment\n * spanning lines */\nconst cp = require('child_process'); cp.exec(x);\n"
        * 2_500
    )[:200_000]

    @staticmethod
    def project(work: Path, index: int) -> Path:
        """A project no earlier scan saw: its own paths, and two 200 KB sources."""
        root = work / f"unit{index:05d}"
        package = root / "src" / f"pkg{index}"
        package.mkdir(parents=True)
        for k in range(30):
            (package / f"module_{index}_{k}.py").write_text(
                f"VALUE_{k} = {index}\n", encoding="utf-8"
            )
        (root / f"big_{index}.py").write_text(SoakKit.PY, encoding="utf-8")
        (root / f"big_{index}.js").write_text(SoakKit.JS, encoding="utf-8")
        return root

    @staticmethod
    def rss_mb(pid: int | str = "self") -> float:
        for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
        raise AssertionError("no VmRSS")


@pytest.mark.skipif(
    not Path("/proc/self/status").exists(), reason="reads resident memory from /proc"
)
class TestSoak:
    def test_scans_in_one_process_hold_no_more_after_a_warm_up(self, tmp_path: Path) -> None:
        scanner = Scanner(
            Config.default().with_overrides(
                use_cache=False, limits=Config.default().limits.merged(max_workers=1)
            )
        )
        readings: dict[int, float] = {}
        for index in range(1, SCANS + 1):
            root = SoakKit.project(tmp_path, index)
            scanner.scan(root)
            shutil.rmtree(root)
            if index in (WARM, SCANS):
                gc.collect()
                readings[index] = SoakKit.rss_mb()
        grown = readings[SCANS] - readings[WARM]
        assert grown <= GROWTH_MB, f"{grown:.0f} MB kept from scan {WARM} to {SCANS}: {readings}"

    @pytest.mark.skipif(
        os.name != "posix", reason="the warm helper forks, so it runs on POSIX only"
    )
    def test_the_mcp_warm_helper_holds_no_more_after_a_warm_up(self, tmp_path: Path) -> None:
        from cordon_scanner.mcp.runner import CancelToken, Runner

        runner = Runner(offline=True, environment=dict(os.environ))
        runner.start_warm()
        try:
            deadline = time.monotonic() + 600
            while not (runner.warm and runner.warm.ready):
                assert time.monotonic() < deadline, "the warm helper never became ready"
                time.sleep(0.1)
            pid = runner.warm._process.pid  # type: ignore[union-attr]
            readings: dict[int, float] = {}
            for index in range(1, CALLS + 1):
                root = SoakKit.project(tmp_path, index)
                runner.run(
                    ["scan", str(root), "--offline", "--format", "json"],
                    timeout=600,
                    token=CancelToken(),
                )
                shutil.rmtree(root)
                assert runner.warm is not None and runner.warm.ready, (
                    f"the helper died at call {index}"
                )
                if index in (WARM, CALLS):
                    readings[index] = SoakKit.rss_mb(pid)
        finally:
            runner.close()
        grown = readings[CALLS] - readings[WARM]
        assert grown <= GROWTH_MB, (
            f"the helper kept {grown:.0f} MB from call {WARM} to {CALLS}: {readings}"
        )


class TestStatementWindowMemory:
    """D1: an oversized Python module is read in statement windows, each window's tree released
    before the next, so its peak memory does not grow with the module's length, and the windows add
    little over what the first pass already holds."""

    LIMIT = 3 * 1024 * 1024
    ADDED_MB = 100
    """The most the statement windows may add over the first pass's peak (measured: 62 MB at 2.9 windows of 3 MiB)."""

    CHILD = """
import json, sys
from pathlib import Path
from cordon_scanner import Scanner
from cordon_scanner.engine import window_pass
from cordon_scanner.foundation.config.settings import Config
def hwm():
    with open("/proc/self/status") as status:
        return next(int(line.split()[1]) for line in status if line.startswith("VmHWM"))
target, size = Path(sys.argv[1]), int(sys.argv[2])
body, n = [], 0
while sum(map(len, body)) < size:
    body.append(f"class C{n}:\\n    @property\\n    def v(self):\\n        return {n}\\n\\n")
    n += 1
target.mkdir()
(target / "generated.py").write_text("".join(body), encoding="utf-8")
before = {}
read = window_pass.WindowPass._read
def reading(*args, release=False, **kwargs):
    if release and "aligned" not in before:
        before["aligned"] = hwm()
    return read(*args, release=release, **kwargs)
window_pass.WindowPass._read = staticmethod(reading)
base = Config.default()
limits = base.limits.merged(max_file_bytes=int(sys.argv[3]), per_file_timeout=0.0, total_timeout=0.0)
Scanner(base.with_overrides(limits=limits, use_cache=False)).scan(target)
print(json.dumps({"peak_kb": hwm(), "before_aligned_kb": before.get("aligned", 0)}))
"""

    @classmethod
    def peaks(cls, work: Path, windows: float) -> dict[str, int]:
        import json

        environment = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
        run = subprocess.run(
            [
                sys.executable,
                "-c",
                cls.CHILD,
                str(work),
                str(int(cls.LIMIT * windows)),
                str(cls.LIMIT),
            ],
            capture_output=True,
            text=True,
            env=environment,
            timeout=1800,
            check=False,
        )
        assert run.returncode == 0, run.stderr[-2000:]
        result: dict[str, int] = json.loads(run.stdout.strip().splitlines()[-1])
        return result

    @pytest.mark.skipif(not Path("/proc/self/status").exists(), reason="reads VmHWM from /proc")
    def test_a_longer_module_holds_no_more(self, tmp_path: Path) -> None:
        three = self.peaks(tmp_path / "three", 2.9)["peak_kb"]
        six = self.peaks(tmp_path / "six", 5.9)["peak_kb"]
        assert six <= 1.1 * three, (
            f"{six / 1024:.0f} MB at 5.9 windows, {three / 1024:.0f} MB at 2.9"
        )

    @pytest.mark.skipif(not Path("/proc/self/status").exists(), reason="reads VmHWM from /proc")
    def test_the_statement_windows_add_little_over_the_first_pass(self, tmp_path: Path) -> None:
        measured = self.peaks(tmp_path / "three", 2.9)
        added = (measured["peak_kb"] - measured["before_aligned_kb"]) / 1024
        assert measured["before_aligned_kb"] > 0, "the statement windows did not run"
        assert added <= self.ADDED_MB, f"the statement windows added {added:.0f} MB"
