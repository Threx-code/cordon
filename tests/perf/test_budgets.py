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

import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.perf

BODY = "\n".join(f"export function f{i}(a) {{ return a + {i}; }}" for i in range(60))


def populate(root: Path, count: int, per_dir: int = 1000) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for index in range(count):
        directory = root / f"pkg{index // per_dir:03d}" / "src"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"m{index % per_dir:04d}.js").write_text(BODY, encoding="utf-8")
    return root


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


def report(name: str, seconds: float, target: float, ceiling: float) -> None:
    verdict = "OK" if seconds < target else "over target" if seconds < ceiling else "OVER CEILING"
    print(f"\n  {name}: {seconds:.2f}s (target <{target}s, ceiling {ceiling}s) -- {verdict}")


class TestBudgets:
    def test_one_thousand_files_cold(self, tmp_path: Path) -> None:
        root = populate(tmp_path / "repo", 1000)
        elapsed = scan(root, "--no-cache")
        report("1,000-file cold", elapsed, 2.0, 5.0)
        assert elapsed < 5.0

    def test_fifty_thousand_files_cold(self, tmp_path: Path) -> None:
        root = populate(tmp_path / "repo", 50_000)
        elapsed = scan(root, "--no-cache")
        report("50,000-file cold", elapsed, 45.0, 180.0)
        assert elapsed < 180.0

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
        root = populate(tmp_path / "repo", 50_000)
        scan(root)
        elapsed = scan(root)
        report("50,000-file incremental", elapsed, 3.0, 10.0)
        assert elapsed < 10.0

    @pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
    def test_precommit_realistic_commit(self, tmp_path: Path) -> None:
        """The budget that decides whether a developer keeps the hook.

        A large repository and a small commit, which is what a pre-commit hook
        actually meets. The 2,000-file version below is the pathological case,
        kept because it is where `git show` per file was found.
        """
        root = populate(tmp_path / "repo", 5000)
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
        elapsed = scan(root, "--staged")
        report("pre-commit, 8 of 5,000 staged", elapsed, 0.3, 1.0)
        assert elapsed < 1.0

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
        root = populate(tmp_path / "repo", 2000)
        for command in (
            ["init", "-q", "-b", "main"],
            ["config", "user.email", "t@example.invalid"],
            ["config", "user.name", "T"],
            ["add", "-A"],
        ):
            subprocess.run(
                [shutil.which("git"), *command], cwd=root, check=True, capture_output=True
            )
        elapsed = scan(root, "--staged")
        # A different budget from the realistic case above, because this is not
        # a commit anybody makes: two thousand files staged at once. It is here
        # because it is where one git process per file was found, and it is
        # asserted so that regression cannot come back unnoticed.
        report("pre-commit, 2,000 staged", elapsed, 1.0, 3.0)
        assert elapsed < 3.0
