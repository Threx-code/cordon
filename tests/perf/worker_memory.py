"""Each scan worker's own memory, the part no other process shares, recorded per worker.

A worker is forked from a template that has already imported the scanner, so most of its resident set is pages it
shares with the template and its siblings. What one more worker costs is its unique set: the private pages
(`Private_Clean` + `Private_Dirty` in `/proc/<pid>/smaps_rollup`). This runs one scan with a fixed number of
workers over the pinned conformance corpus, samples every descendant process of the scan while it runs, and
records each one's peak resident set, peak unique set and peak proportional set (`Pss`, its fair share of shared
pages).

    PYTHONPATH=tests python tests/perf/worker_memory.py OUT.json [--jobs N]

Linux only (it reads /proc). Run it in a container with the source mounted read-only; the corpus is the
repository's own benign test cases, copied to a temporary directory so the scan reads them as a plain tree.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import ClassVar

from support import ROOT


class WorkerMemory:
    CASES: ClassVar[Path] = ROOT / "tests" / "conformance" / "cases"
    INTERVAL: ClassVar[float] = 0.05

    @staticmethod
    def children(pid: int) -> list[int]:
        """Every descendant of `pid`, read from /proc."""
        parents: dict[int, list[int]] = {}
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                fields = (entry / "stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()
            except OSError:
                continue
            parents.setdefault(int(fields[1]), []).append(int(entry.name))
        out, frontier = [], [pid]
        while frontier:
            current = frontier.pop()
            for child in parents.get(current, []):
                out.append(child)
                frontier.append(child)
        return out

    @staticmethod
    def rollup(pid: int) -> dict[str, int] | None:
        """Rss, Pss and the unique set (private clean + private dirty) of one process, in kB."""
        try:
            text = Path(f"/proc/{pid}/smaps_rollup").read_text(encoding="ascii")
        except OSError:
            return None
        values = {}
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].endswith(":") and parts[1].isdigit():
                values[parts[0][:-1]] = int(parts[1])
        return {
            "rss_kb": values.get("Rss", 0),
            "pss_kb": values.get("Pss", 0),
            "uss_kb": values.get("Private_Clean", 0) + values.get("Private_Dirty", 0),
        }

    @staticmethod
    def name(pid: int) -> str:
        try:
            return (
                Path(f"/proc/{pid}/cmdline")
                .read_bytes()
                .replace(b"\0", b" ")
                .decode(errors="replace")[:80]
            )
        except OSError:
            return ""

    @classmethod
    def measure(cls, jobs: int) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "tree"
            shutil.copytree(cls.CASES, tree)
            env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
            command = [
                sys.executable,
                "-m",
                "cordon_scanner",
                "scan",
                str(tree),
                "--jobs",
                str(jobs),
                "--offline",
                "--format",
                "json",
                "--no-color",
            ]
            started = time.monotonic()
            scan = subprocess.Popen(
                command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            peaks: dict[int, dict] = {}
            while scan.poll() is None:
                for pid in [scan.pid, *cls.children(scan.pid)]:
                    now = cls.rollup(pid)
                    if now is None:
                        continue
                    seen = peaks.setdefault(
                        pid, {"command": cls.name(pid), "rss_kb": 0, "pss_kb": 0, "uss_kb": 0}
                    )
                    for key, value in now.items():
                        seen[key] = max(seen[key], value)
                time.sleep(cls.INTERVAL)
            elapsed = time.monotonic() - started
        parent = peaks.pop(scan.pid, {})
        workers = sorted(peaks.values(), key=lambda w: -w["uss_kb"])
        return {
            "jobs": jobs,
            "exit": scan.returncode,
            "seconds": round(elapsed, 1),
            "corpus": "tests/conformance/cases",
            "parent": parent,
            "processes": len(workers),
            "workers": workers,
            "uss_mb_max": round(max((w["uss_kb"] for w in workers), default=0) / 1024, 1),
            "rss_mb_max": round(max((w["rss_kb"] for w in workers), default=0) / 1024, 1),
        }


if __name__ == "__main__":
    jobs = int(sys.argv[sys.argv.index("--jobs") + 1]) if "--jobs" in sys.argv else 4
    result = WorkerMemory.measure(jobs)
    Path(sys.argv[1]).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(
        f"processes {result['processes']}; peak unique {result['uss_mb_max']} MB; peak resident {result['rss_mb_max']} MB"
    )
