#!/usr/bin/env python3
"""Unknown-attack recall: content only, on malware published after the rules were written (MEAS-3).

```
  DataDog dataset @ FROZEN (the snapshot every rule was developed against)
        │
        │   samples added after it: never read by anyone working on the rules
        ▼
  partial clone (history, no contents) ──► only the added sample blobs fetched
        │
        ▼
  cordon scan --offline --advisories empty.json    (no intel: content alone)
        │
        ▼
  content recall = blocked / payload-bearing, with a 95% Wilson interval
```

The held-out set is MEASURED, NEVER STUDIED. A miss in it is not read to write a rule: once one is,
that sample is development data and leaves the set (record it in `STUDIED` with the date). Cordon's
first commit is from September 2026 and the snapshot's newest sample from June 2026, so no earlier
cut is held out -- the split starts at the snapshot.

    docker volume create cordon-bench-fresh
    docker run --rm -v cordon-bench-fresh:/f -v "$PWD:/s:ro" --entrypoint python \\
      cordon-prepush:<tag> /s/bench/timesplit.py fetch --into /f
    docker run --rm --network none -v cordon-bench-fresh:/f:ro -v "$PWD:/s:ro" -v OUT:/out \\
      --entrypoint sh cordon-prepush:<tag> -c 'cp -r /s /tmp/w && PYTHONPATH=/tmp/w/src \\
      python /tmp/w/bench/timesplit.py scan --from /f --out /out'

(`scan` calls `cordon-scanner`; put it on PATH as `run.py`'s docstring does.)

`fetch` needs the network and git; `scan` runs with none. Nothing in a sample is executed.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "suites"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from run import Harness, Levels, Wilson

DATASET = "https://github.com/DataDog/malicious-software-packages-dataset.git"
FROZEN = "805fcd72db525244cae8dd32056efbd50b8b0e19"
"""The DataDog commit the rules were developed against (2026-10-09). Everything added after it is
held out."""
STUDIED: dict[str, str] = {}
"""Held-out samples later read to develop a rule, with the date: they leave the set."""


class TimeSplit:
    @staticmethod
    def git(*args: str, cwd: Path) -> str:
        return subprocess.run(
            ["git", "-c", "safe.directory=*", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True,
        ).stdout

    @classmethod
    def fetch(cls, into: Path) -> list[str]:
        """Clone history without contents, then fetch only the samples added after FROZEN."""
        clone = into / "dd"
        if not clone.exists():
            subprocess.run(
                ["git", "clone", "-q", "--filter=blob:none", "--no-checkout", DATASET, str(clone)],
                check=True,
            )
        cls.git("fetch", "-q", "origin", cwd=clone)
        head = cls.git("rev-parse", "origin/main", cwd=clone).strip()
        added = [
            line
            for line in cls.git(
                "diff", "--name-only", "--diff-filter=A", FROZEN, head, "--", "samples", cwd=clone
            ).splitlines()
            if line.endswith((".zip", ".vsix"))
        ]
        if added:
            cls.git("checkout", head, "--", *added, cwd=clone)
        (into / "added.json").write_text(
            json.dumps({"frozen": FROZEN, "head": head, "added": added}, indent=1), encoding="utf-8"
        )
        return added

    @staticmethod
    def scan_one(root: Path, relative: str, empty: Path) -> dict[str, object]:
        archive = root / "dd" / relative
        with tempfile.TemporaryDirectory(prefix="ts-") as work:
            target: Path | None = archive
            if archive.suffix != ".vsix":
                try:
                    target = Harness._unzip_datadog(archive, Path(work))
                except Exception as exc:  # noqa: BLE001
                    return {"sample": relative, "level": "error", "error": type(exc).__name__}
            if target is None:
                return {"sample": relative, "level": "error", "error": "empty"}
            code, out, _ = Harness.run(
                [
                    "cordon-scanner",
                    "scan",
                    str(target),
                    "--offline",
                    "--advisories",
                    str(empty),
                    "--no-color",
                    "--quiet",
                    "--format",
                    "json",
                ]
            )
        findings: list[list[str]] = []
        try:
            report = json.loads(out[out.index("{") :])
            findings = [
                [
                    str(f.get("rule_id")),
                    str(f.get("severity")),
                    str(f.get("confidence")),
                    str(f.get("category")),
                    "",
                    "",
                    # Which detector made it: what tells a content block from an intel one.
                    str(f.get("detector", "")),
                ]
                for f in report.get("findings", [])
            ]
        except (ValueError, TypeError, AttributeError):
            pass
        return {"sample": relative, "level": Levels.of(code, findings), "findings": findings}

    @staticmethod
    def summary(listing: dict[str, object], rows: list[dict[str, object]]) -> dict[str, object]:
        """The recalls over the scanned rows (each row's `level` from `Levels.of`)."""
        seen = Counter(str(r["level"]) for r in rows)
        answered = len(rows) - seen["error"]
        # A release the shipped advisories already name is intel, not content: it counts only in
        # the recall with intel, and so does a block intel alone made (`bench/tools/content.py`).
        # Content recall is a lower bound -- a known release whose content would also have been
        # blocked is not credited to content. Both recalls are over EVERY sample: a scan that
        # failed or timed out is a sample not caught, so errors can only lower them. The
        # `*_answered` figures, which leave failed scans out, are kept beside them, labelled.
        caught = seen["blocked"] + seen["known"] + seen["intel"]
        total = len(rows)
        return {
            "frozen": listing["frozen"],
            "head": listing["head"],
            "samples": total,
            "levels": dict(seen),
            "errors": seen["error"],
            "content_recall": round(seen["blocked"] / max(total, 1), 4),
            "content_recall_95": list(Wilson.interval(seen["blocked"], total)),
            "recall_with_intel": round(caught / max(total, 1), 4),
            "content_recall_answered": round(seen["blocked"] / max(answered, 1), 4),
            "recall_with_intel_answered": round(caught / max(answered, 1), 4),
            "enough_for_a_98_claim": total >= 650,
        }

    @classmethod
    def scan(cls, root: Path, out: Path, workers: int) -> dict[str, object]:
        listing = json.loads((root / "added.json").read_text(encoding="utf-8"))
        samples = [s for s in listing["added"] if s not in STUDIED]
        empty = Path(tempfile.mkdtemp()) / "no-advisories.json"
        empty.write_text("[]", encoding="utf-8")
        # Processes, not threads: decrypting DataDog's password-protected zips is pure Python and
        # holds the GIL, so nine threads unpacked one sample at a time and left one scan running.
        with ProcessPoolExecutor(workers) as pool:
            rows = list(pool.map(partial(cls.scan_one, root, empty=empty), samples))
        summary = cls.summary(listing, rows)
        out.mkdir(parents=True, exist_ok=True)
        (out / "timesplit.json").write_text(
            json.dumps({"summary": summary, "rows": rows}, indent=1), encoding="utf-8"
        )
        return summary

    @classmethod
    def main(cls) -> int:
        parser = argparse.ArgumentParser(
            description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
        )
        sub = parser.add_subparsers(dest="command", required=True)
        fetch = sub.add_parser("fetch")
        fetch.add_argument("--into", type=Path, default=Path("/f"))
        scan = sub.add_parser("scan")
        scan.add_argument("--from", dest="root", type=Path, default=Path("/f"))
        scan.add_argument("--out", type=Path, default=Path("/out"))
        scan.add_argument("--workers", type=int, default=4)
        args = parser.parse_args()
        if args.command == "fetch":
            print(f"{len(cls.fetch(args.into))} samples added after {FROZEN[:12]}")
            return 0
        if shutil.which("cordon-scanner") is None:
            raise SystemExit("cordon-scanner is not on PATH: every sample would score as an error")
        print(json.dumps(cls.scan(args.root, args.out, args.workers), indent=1))
        return 0


if __name__ == "__main__":
    raise SystemExit(TimeSplit.main())
