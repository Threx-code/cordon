"""The §1.1 latency budgets, measured.

Latency is a security property here, not an efficiency concern. A commit-time
guard that costs noticeably more than a second gets bypassed, and a CI stage
slow enough to be resented acquires an exemption. Both end in a control that
does not run.

The budgets were written in `docs/04-OPERATIONS.md` and never measured, which
is the same failure in a different place: a number nobody checks is a number
nobody meets. These assert the **hard ceilings**, not the targets. A ceiling is
the point at which behaviour changes -- people start passing `--no-verify` --
and it is stable enough to assert on shared CI hardware. The targets are
tracked by reporting the measurement, so a regression is visible in the log
before it reaches a ceiling.

Marked `perf` and deselected by default: generating fifty thousand files is not
something to do on every `pytest` run.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.perf

BODY = "\n".join(f"export function f{i}(a) {{ return a + {i}; }}" for i in range(60))


class BudgetsHelpers:
    """Helpers for test_budgets.py."""

    @staticmethod
    def populate(root: Path, count: int, per_dir: int = 1000) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        for index in range(count):
            directory = root / f"pkg{index // per_dir:03d}" / "src"
            directory.mkdir(parents=True, exist_ok=True)
            (directory / f"m{index % per_dir:04d}.js").write_text(BODY, encoding="utf-8")
        return root

    @staticmethod
    def scan(target: Path, *args: str) -> float:
        started = time.monotonic()
        subprocess.run(
            [
                sys.executable,
                "-m",
                "cordon_scanner",
                "scan",
                str(target),
                "--format",
                "json",
                "--output",
                str(target.parent / "r.json"),
                *args,
            ],
            capture_output=True,
            check=False,
        )
        return time.monotonic() - started

    @staticmethod
    def scan_timed(target: Path, *args: str) -> tuple[float, float]:
        """`scan`'s wall time, and the CPU time the scan's processes used (the child and every
        worker it waited for), which neighbouring load does not stretch. POSIX only, as the
        `resource` module is."""
        import resource

        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        wall = BudgetsHelpers.scan(target, *args)
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        return wall, (after.ru_utime + after.ru_stime) - (before.ru_utime + before.ru_stime)

    @staticmethod
    def report(name: str, seconds: float, target: float, ceiling: float) -> None:
        """Print the measurement against the published budget, which is for what every install
        runs -- Cordon's own JavaScript and TypeScript tier included; only a shared runner's
        allowance (`CORDON_PERF_ALLOWANCE`) moves the ceiling it is judged against."""
        here_target = target
        here_ceiling = ceiling * ALLOWANCE
        verdict = (
            "OK"
            if seconds < here_target
            else "over target"
            if seconds < here_ceiling
            else "OVER CEILING"
        )
        note = f", {here_ceiling:.1f}s here" if abs(here_ceiling - ceiling) > 0.01 else ""
        print(
            f"\n  {name}: {seconds:.2f}s (target <{target}s, ceiling {ceiling}s{note}) -- {verdict}"
        )


ALLOWANCE = float(os.environ.get("CORDON_PERF_ALLOWANCE", "1"))
"""Multiplier applied to the asserted ceiling, not to the reported one.

The targets and ceilings in `docs/04-OPERATIONS.md` are product commitments
measured on a reference machine. A shared CI runner is neither reference nor
consistent -- the 50,000-file incremental scan takes 5.5s on the reference
machine and 27s on a GitHub runner, a five-fold spread that has nothing to do
with the code.

Asserting the real ceiling there would fail constantly, and a check that fails
constantly is one people re-run rather than read. Inflating the documented
ceilings to match the slowest runner would be worse: it would quietly weaken a
commitment to users in order to make a test pass.

So CI asserts a multiple of the ceiling and the multiplier is visible in the
workflow. What is printed is always the true target and ceiling, so the numbers
a reader sees are the real ones and the regression guard is separate from
them.
"""


class TestBudgets:
    def test_one_thousand_files_cold(self, tmp_path: Path) -> None:
        root = BudgetsHelpers.populate(tmp_path / "repo", 1000)
        elapsed = BudgetsHelpers.scan(root, "--no-cache")
        BudgetsHelpers.report("1,000-file cold", elapsed, 2.0, 5.0)
        assert elapsed < 5.0 * ALLOWANCE

    def test_fifty_thousand_files_cold(self, tmp_path: Path) -> None:
        root = BudgetsHelpers.populate(tmp_path / "repo", 50_000)
        elapsed = BudgetsHelpers.scan(root, "--no-cache")
        BudgetsHelpers.report("50,000-file cold", elapsed, 45.0, 180.0)
        assert elapsed < 180.0 * ALLOWANCE

    def test_fifty_thousand_files_incremental(self, tmp_path: Path) -> None:
        """The one budget the tool does not meet, and the reason is structural.

        A warm scan still opens every file, because the cache is addressed by
        content hash and computing one means reading the bytes. The obvious
        shortcut -- trust `(size, mtime)` and skip the read -- is a blinding
        vector: an attacker who edits a file can pad it to its former size and
        restore its mtime with one call, and the scan would then reuse the
        clean result it cached for the original. That is precisely the failure
        this tool exists to prevent, so the read stays.

        On the reference machine that floor is 1.2s of reading and hashing plus
        1.7s of reading cache entries, against a 3s target: the budget is
        roughly the I/O floor itself. It is asserted at its 10s ceiling, which
        is met with room, and the target is recorded as not met in the
        operations guide rather than quietly dropped.
        """
        root = BudgetsHelpers.populate(tmp_path / "repo", 50_000)
        BudgetsHelpers.scan(root)
        elapsed = BudgetsHelpers.scan(root)
        BudgetsHelpers.report("50,000-file incremental", elapsed, 3.0, 10.0)
        assert elapsed < 10.0 * ALLOWANCE

    @pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
    def test_precommit_realistic_commit(self, tmp_path: Path) -> None:
        """The budget that decides whether a developer keeps the hook.

        A large repository and a small commit, which is what a pre-commit hook
        actually meets. The 2,000-file version below is the pathological case,
        kept because it is where `git show` per file was found.
        """
        root = BudgetsHelpers.populate(tmp_path / "repo", 5000)
        self.init(root)
        subprocess.run(
            [shutil.which("git"), "add", "-A"], cwd=root, check=True, capture_output=True
        )
        subprocess.run(
            [shutil.which("git"), "commit", "-qm", "base"],
            cwd=root,
            check=True,
            capture_output=True,
        )
        for index in range(8):
            (root / "pkg000" / "src" / f"m{index:04d}.js").write_text(
                BODY + f"\n// edit {index}\n", encoding="utf-8"
            )
        subprocess.run(
            [shutil.which("git"), "add", "-A"], cwd=root, check=True, capture_output=True
        )
        elapsed = BudgetsHelpers.scan(root, "--staged")
        BudgetsHelpers.report("pre-commit, 8 of 5,000 staged", elapsed, 0.3, 1.0)
        assert elapsed < 1.0 * ALLOWANCE

    @staticmethod
    def init(root: Path) -> None:
        for command in (
            ["init", "-q", "-b", "main"],
            ["config", "user.email", "t@example.invalid"],
            ["config", "user.name", "T"],
        ):
            subprocess.run(
                [shutil.which("git"), *command], cwd=root, check=True, capture_output=True
            )

    @pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
    def test_precommit_two_thousand_staged(self, tmp_path: Path) -> None:
        """The pathological commit. `git show` per file made this eleven
        seconds; one batched process makes it half of one."""
        root = BudgetsHelpers.populate(tmp_path / "repo", 2000)
        for command in (
            ["init", "-q", "-b", "main"],
            ["config", "user.email", "t@example.invalid"],
            ["config", "user.name", "T"],
            ["add", "-A"],
        ):
            subprocess.run(
                [shutil.which("git"), *command], cwd=root, check=True, capture_output=True
            )
        elapsed, cpu = BudgetsHelpers.scan_timed(root, "--staged")
        # A different budget from the realistic case above, because this is not
        # a commit anybody makes: two thousand files staged at once. It is here
        # because it is where one git process per file was found, and it is
        # asserted so that regression cannot come back unnoticed.
        BudgetsHelpers.report("pre-commit, 2,000 staged", elapsed, 1.0, 3.0)
        # Asserted on CPU time, not wall time: beside other load the wall clock measured the
        # neighbours (22 s against this ceiling of 15 s with the shared allowance, while the same
        # scan alone took 6.5 s on the release and on the change alike). Measured alone, ABBA by
        # process: CPU median 2.49 s on 00578d7e, 2.70 s on 289c55cb; the bound is three times
        # that, and a process per file, the regression this guards, costs far more.
        print(f"  pre-commit, 2,000 staged: {cpu:.2f}s CPU (ceiling {7.5 * ALLOWANCE:.1f}s)")
        assert cpu < 7.5 * ALLOWANCE
