#!/usr/bin/env python3
"""Scan every archive the fetcher queues, record what Cordon reports, delete the archive.

Run with no network. Cordon's rules, detectors and advisories are loaded once (as the MCP warm
scanner does, `cordon_scanner/mcp/warm.py`) and each archive is scanned in a forked child with
`--offline`, so a sample costs its scan, not an interpreter start. Nothing is executed.

Cordon must run as an INSTALLED package: its output formats and detectors are found through
package entry points, which a bare `PYTHONPATH=src` does not provide (every scan then exits 2;
`BrokenScanner` stops such a run). Build the wheel once with network, then scan without it:

    docker run --rm -v "$PWD:/repo:ro" -v cordon-wheel:/w python:3.12-slim \
      sh -c "cp -r /repo /tmp/r && pip wheel -q --no-deps -w /w /tmp/r"
    docker run --rm --network none --cap-drop ALL -v cordon-corpus-q:/q -v cordon-wheel:/w:ro \
      -v "$PWD/bench:/tools:ro" -v "$PWD/bench/longtail:/out" python:3.12-slim \
      sh -c "pip install -q --no-index --no-deps /w/cordon_scanner-*.whl && python /tools/longtail_scan.py --keep"

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
LIST_EVERY = 15.0
MARKERS = frozenset({".fetch-done"})
"""The queue's own control files. Only these are skipped by name: a package may legitimately be
named with a leading dot (RubyGems has `.omghi`), and skipping every dot-file dropped it silently."""


class BrokenScanner:
    """Stops a run whose first results say the scanner itself is broken.

    From a clean checkout, Cordon's plugins are missing unless the package metadata is generated,
    and every scan exits 2 ("unknown output format 'json'"). A benchmark that counted blocks would
    record each of those as "not blocked": a broken scanner reported as a perfectly quiet one. So
    after the first CHECK_AFTER results, a run where at least BROKEN_SHARE of them are scanner
    errors (exit 2, or output that does not parse) stops with exit 3 instead of continuing.
    """

    CHECK_AFTER = 50
    BROKEN_SHARE = 0.9

    def __init__(self) -> None:
        self.seen = 0
        self.errors = 0
        self.checked = False

    def observe(self, rec: dict) -> bool:
        """Record one result; True when the run should stop."""
        if self.checked:
            return False
        self.seen += 1
        if rec.get("exit") == 2 or "parse_error" in rec:
            self.errors += 1
        if self.seen < self.CHECK_AFTER:
            return False
        self.checked = True
        return self.errors >= self.BROKEN_SHARE * self.seen

    def reason(self) -> str:
        return (
            f"stopping: {self.errors} of the first {self.seen} scans failed with a scanner error "
            "(exit 2 or unparseable output). The scanner is broken, not the packages: from a clean "
            "checkout, generate the package metadata (pip install -e .) before scanning."
        )


class LongtailScan:
    @staticmethod
    def queued(name: str) -> bool:
        """Whether a file in the queue is an archive to scan (not a marker, not mid-write)."""
        return not name.endswith(".part") and name not in MARKERS

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
            # One process per scan: this harness already runs a scan per worker, and the engine's
            # own pool inside each started ~10 more, so 8 workers ran ~80 processes on 8 CPUs and
            # the corpus moved at ~7 archives a minute instead of ~75 (review 98).
            code = CommandLine.main(
                [
                    "scan",
                    path,
                    "--offline",
                    "--no-color",
                    "--quiet",
                    "--format",
                    "json",
                    "--jobs",
                    "1",
                ]
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
            # Kept apart: an offline scan has no fresh advisory data by design, which says
            # nothing about whether the package's content was examined. A result whose content
            # was not fully examined must never be scored as a clean one (review 98, phase 0).
            rec["content_complete"] = rep.get("content_complete")
            rec["advisory_complete"] = rep.get("advisory_complete")
            # The package verdict's features and score, read by the same code that produced them:
            # the training data for `core/verdict.py` is what scans report.
            rec["verdict"] = rep.get("verdict")
            rec["findings"] = [
                [
                    f["rule_id"],
                    f.get("severity"),
                    f.get("confidence"),
                    f.get("category"),
                    ((f.get("location") or {}).get("path") or "").split("!", 1)[-1][-160:],
                    # Where in the file: what region-level analyses (a release diff, a shared
                    # idiom) compare. Appended, so every reader of the first five keeps working.
                    (f.get("location") or {}).get("line"),
                    # Which detector made it: what tells a content block from an intel one
                    # (`bench/tools/content.py`). Appended, like the line.
                    f.get("detector"),
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
        guard = BrokenScanner()
        pending: list[Path] = []
        listed_at = 0.0
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
                    rec = LongtailScan.record(rel, code, out, time.monotonic() - started)
                    fh.write(json.dumps(rec) + "\n")
                    fh.flush()
                    if guard.observe(rec):
                        print(guard.reason(), file=sys.stderr, flush=True)
                        for other in running:
                            if other != pid:
                                with contextlib.suppress(ProcessLookupError):
                                    os.killpg(other, signal.SIGKILL)
                        fh.close()
                        raise SystemExit(3)
                    out.unlink(missing_ok=True)
                    if not a.keep:
                        (a.queue / rel).unlink(missing_ok=True)
                    del running[pid]
            # Start new ones.
            if len(running) < a.workers:
                busy = {r for r, _, _ in running.values()}
                # With --keep the queue grows to every archive (200,000), so it is listed at most
                # every LIST_EVERY seconds or when the pending list runs dry, and archives already
                # scanned are left out of the list: picking the oldest N files, as before, picks
                # the same scanned ones forever once they are kept. Oldest first, so registries the
                # fetcher interleaves are scanned in the same proportion.
                now = time.monotonic()
                if not pending or now - listed_at > LIST_EVERY:
                    listed_at = now
                    found = []
                    for root, _, files in os.walk(a.queue):
                        for name in files:
                            if not LongtailScan.queued(name):
                                continue
                            p = Path(root, name)
                            rel = p.relative_to(a.queue).as_posix()
                            if rel in done:
                                if not a.keep:  # scanned before a restart, never deleted
                                    p.unlink(missing_ok=True)
                                continue
                            with contextlib.suppress(FileNotFoundError):
                                found.append((p.stat().st_mtime, p))
                    pending[:] = [p for _, p in sorted(found)]
                started_any = False
                while pending and len(running) < a.workers:
                    p = pending.pop(0)
                    rel = p.relative_to(a.queue).as_posix()
                    if rel in done or rel in busy or not p.exists():
                        continue
                    out = tmp / f"{len(done)}-{os.getpid()}-{time.monotonic_ns()}.json"
                    pid = os.fork()
                    if pid == 0:
                        os._exit(LongtailScan.child(str(p), str(out)))
                    running[pid] = (rel, out, time.monotonic())
                    done.add(rel)
                    started_any = True
                # Idle means nothing new was started: with --keep the queue is never empty.
                if started_any:
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
