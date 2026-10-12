#!/usr/bin/env python3
"""Scan every archive the fetcher queues, record what Cordon reports, delete the archive.

Run with no network. Cordon's rules, detectors and advisories are loaded once (as the MCP warm
scanner does, `cordon_scanner/mcp/warm.py`) and each archive is scanned in a forked child with
`--offline`, so a sample costs its scan, not an interpreter start. Nothing is executed.

    docker run --rm --network none --cap-drop ALL -v cordon-corpus-q:/q \
      -v "$PWD/src:/src:ro" -e PYTHONPATH=/src -v "$PWD/bench:/tools:ro" \
      -v "$PWD/bench/longtail:/out" python:3.12-slim python /tools/longtail_scan.py

Output: /out/scans.jsonl -- per archive: file, exit code, completeness, and per finding the rule,
severity, confidence, category and path inside the archive (no content). Resumable.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import sys
import tempfile
import time
from pathlib import Path

TIMEOUT = 300


class LongtailScan:
    @staticmethod
    def warm():
        from cordon_scanner.mcp.warm import WarmHelper

        WarmHelper.warm()

    @staticmethod
    def child(path: str, out: str) -> int:
        os.setsid()
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        null = os.open(os.devnull, os.O_RDWR)
        os.dup2(null, 0)
        os.dup2(fd, 1)
        os.dup2(null, 2)
        sys.stdout = open(1, "w", encoding="utf-8", closefd=False)  # noqa: SIM115 - the child's stdout for its life
        from cordon_scanner.cli.main import CommandLine

        try:
            code = CommandLine.main(
                ["scan", path, "--offline", "--no-color", "--quiet", "--format", "json"]
            )
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 1
        except BaseException:
            code = 70
        sys.stdout.flush()
        return int(code or 0)

    @staticmethod
    def record(rel: str, code, out: Path, seconds: float) -> dict:
        rec = {"file": rel, "exit": code, "seconds": round(seconds, 2)}
        try:
            text = out.read_text(encoding="utf-8", errors="replace")
            rep = json.loads(text[text.index("{") :])
            rec["complete"] = rep.get("complete")
            rec["findings"] = [
                [
                    f["rule_id"],
                    f.get("severity"),
                    f.get("confidence"),
                    f.get("category"),
                    ((f.get("location") or {}).get("path") or "").split("!", 1)[-1][-160:],
                ]
                for f in rep.get("findings", [])
            ]
        except Exception as e:
            rec["parse_error"] = repr(e)[:120]
        return rec

    @staticmethod
    def main():
        ap = argparse.ArgumentParser()
        ap.add_argument("--queue", type=Path, default=Path("/q"))
        ap.add_argument("--out", type=Path, default=Path("/out"))
        ap.add_argument("--workers", type=int, default=10)
        ap.add_argument("--keep", action="store_true", help="do not delete archives after scanning")
        a = ap.parse_args()
        a.out.mkdir(parents=True, exist_ok=True)
        results = a.out / "scans.jsonl"
        done = set()
        if results.exists():
            done = {
                json.loads(x)["file"] for x in results.read_text(encoding="utf-8").splitlines() if x
            }
        LongtailScan.warm()
        tmp = Path(tempfile.mkdtemp(prefix="scan-"))
        running: dict[int, tuple[str, Path, float]] = {}
        fh = results.open("a", encoding="utf-8")
        idle_since = time.monotonic()
        while True:
            # Reap finished or overdue children.
            for pid, (rel, out, started) in list(running.items()):
                try:
                    got, status = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    got, status = pid, 0
                if got == 0 and time.monotonic() - started > TIMEOUT:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
                    got, status = pid, None
                if got:
                    code = "timeout" if status is None else os.waitstatus_to_exitcode(status)
                    fh.write(
                        json.dumps(LongtailScan.record(rel, code, out, time.monotonic() - started))
                        + "\n"
                    )
                    fh.flush()
                    out.unlink(missing_ok=True)
                    if not a.keep:
                        (a.queue / rel).unlink(missing_ok=True)
                    del running[pid]
            # Start new ones.
            if len(running) < a.workers:
                busy = {r for r, _, _ in running.values()}
                # Oldest first, so every registry the fetcher interleaves is scanned in the same
                # proportion, and the queue is listed only when a worker is free.
                found = []
                for root, _, files in os.walk(a.queue):
                    for name in files:
                        if name.endswith(".part") or name.startswith("."):
                            continue
                        p = Path(root, name)
                        if p.relative_to(a.queue).as_posix() in busy:
                            continue
                        with contextlib.suppress(FileNotFoundError):
                            found.append((p.stat().st_mtime, p))
                todo = [p for _, p in sorted(found)[: a.workers * 4]]
                for p in todo:
                    if len(running) >= a.workers:
                        break
                    rel = p.relative_to(a.queue).as_posix()
                    if rel in done:
                        if not a.keep:
                            p.unlink(missing_ok=True)
                        continue
                    out = tmp / f"{len(done)}-{os.getpid()}-{time.monotonic_ns()}.json"
                    pid = os.fork()
                    if pid == 0:
                        os._exit(LongtailScan.child(str(p), str(out)))
                    running[pid] = (rel, out, time.monotonic())
                    done.add(rel)
                if todo:
                    idle_since = time.monotonic()
            if (
                not running
                and (a.queue / ".fetch-done").exists()
                and time.monotonic() - idle_since > 30
            ):
                break
            time.sleep(0.05 if len(running) < a.workers else 0.2)
        fh.close()


if __name__ == "__main__":
    LongtailScan.main()
