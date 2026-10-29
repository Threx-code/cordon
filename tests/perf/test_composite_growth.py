"""A setup.py of many spawns costs the scan time that grows with the file, not faster.

A composite capability rule with a proximity, past 400 capability hits, is searched one window per
hit. Each window was counted afresh, so a setup.py of 2,048 `x = "..." ; os.system(x)` lines cost 50 s
of CPU and four times the file nearly nineteen times as much (review 98, 27-PERFORMANCE, 7); the
window now slides. The file is scanned whole, in this process and with one job, with the wall-clock
budgets off (a budget would cut the slow detector and hide it), and timed in CPU time. Its size doubles
until the small scan costs half a second, so a moment's interruption cannot decide the ratio; the small
scan runs before and after the large one, four times its size, and the two are averaged. A linear scan
costs up to four times as much, a quadratic one sixteen; more than ten fails.

Marked `perf`: it runs in the prepush performance step.
"""

from __future__ import annotations

import io
import time
from contextlib import redirect_stdout
from pathlib import Path

import pytest

pytestmark = pytest.mark.perf


class Growth:
    """The setup.py shape, and a whole scan of it timed in CPU seconds."""

    CONFIG = "version: 1\nscan:\n  limits:\n    per_file_timeout: 0\n    total_timeout: 0\n"
    FLOOR = 0.5
    START = 64
    LARGEST = 1 << 16
    BOUND = 10.0
    LINE = 'x{i} = "aGVsbG8gd29ybGQ" + "QUFBQUFBQUFBQUFBQUFBQQ==" ; import os ; os.system(x{i})\n'

    @staticmethod
    def project(root: Path, n: int) -> Path:
        root.mkdir(parents=True)
        lines = "".join(Growth.LINE.format(i=i) for i in range(n))
        (root / "setup.py").write_text(
            "from setuptools import setup\n"
            + lines
            + "setup(name='growth-probe', version='1.0.0')\n",
            encoding="utf-8",
        )
        return root

    @staticmethod
    def cpu(root: Path) -> float:
        from cordon_scanner.cli.main import CommandLine

        config = root.parent / f"{root.name}.config.yaml"
        config.write_text(Growth.CONFIG, encoding="utf-8")
        args = [
            "scan",
            str(root),
            "--offline",
            "--no-cache",
            "--no-color",
            "--quiet",
            "--jobs",
            "1",
        ]
        args += ["--format", "json", "--output", str(root.parent / f"{root.name}.json")]
        args += ["--config", str(config)]
        started = time.process_time()
        with redirect_stdout(io.StringIO()):
            code = CommandLine.run(args)
        took = time.process_time() - started
        assert code != 2, f"the scan failed to run on {root}"
        return took


class TestCompositeGrowth:
    def test_four_times_the_spawns_cost_at_most_ten_times_as_much(self, tmp_path: Path) -> None:
        Growth.cpu(Growth.project(tmp_path / "warm", Growth.START))
        n = Growth.START
        while True:
            before = Growth.cpu(Growth.project(tmp_path / f"size-{n}", n))
            if before >= Growth.FLOOR or n >= Growth.LARGEST:
                break
            n *= 2
        large = Growth.cpu(Growth.project(tmp_path / f"large-{n}", 4 * n))
        after = Growth.cpu(Growth.project(tmp_path / f"after-{n}", n))
        small = (before + after) / 2
        print(
            f"setup.py: n={n} small {before:.2f}/{after:.2f}s, 4n {large:.2f}s, {large / small:.1f}x"
        )
        assert large < small * Growth.BOUND, (
            f"{4 * n} lines {large:.1f}s of CPU against {n} in {before:.1f}s and {after:.1f}s:"
            f" {large / small:.1f} times"
        )
