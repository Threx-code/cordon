#!/usr/bin/env python3
"""GuardDog on every malware sample, in batches, merged with Cordon's full run.

`run.py malware` scans every sample with Cordon. GuardDog is slower by an order of magnitude, so
this runs it separately, `--batch-size` samples at a time, writing each batch as it finishes:

    python /bench/compare.py --batch 0          # samples 0..4999
    python /bench/compare.py --batch 1          # 5000..9999
    python /bench/compare.py --all              # every batch not yet written
    python /bench/compare.py --merge            # the side-by-side table, over every sample

A batch already written is skipped, so a stopped run resumes where it stopped. The merge reads
Cordon's verdicts from `results.json` and reports both tools on exactly the samples both answered.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run as harness


class GuardDogComparison:
    """GuardDog over every malware sample in batches, merged with Cordon's run."""

    @staticmethod
    def batch(data: Path, results: Path, index: int, size: int, workers: int) -> Path:
        out = results / f"guarddog-batch-{index:02d}.json"
        if out.exists():
            print(f"batch {index}: already written", flush=True)
            return out
        samples = harness.Harness.malware_samples(data)[index * size : (index + 1) * size]

        def one(sample: tuple[str, Path, str]) -> dict[str, object]:
            name, archive, ecosystem = sample
            with tempfile.TemporaryDirectory(prefix="gd-") as work:
                if name.startswith("datadog/"):
                    try:
                        target = harness.Harness._unzip_datadog(archive, Path(work))
                    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
                        return {"sample": name, "blocked": None, "detail": f"unzip: {exc}"}
                    if target is None:
                        return {"sample": name, "blocked": None, "detail": "empty"}
                else:
                    target = archive
                verdict = harness.Harness.guarddog(target, name, ecosystem)
                return {"sample": name, "blocked": verdict.blocked, "detail": verdict.detail}

        with ThreadPoolExecutor(max_workers=workers) as pool:
            rows = list(pool.map(one, samples))
        partial = out.with_suffix(".partial")
        partial.write_text(json.dumps(rows), encoding="utf-8")
        partial.rename(out)
        print(f"batch {index}: {len(rows)} samples written", flush=True)
        return out

    @staticmethod
    def merge(results: Path) -> int:
        cordon_rows = json.loads((results / "results.json").read_text(encoding="utf-8"))["malware"][
            "verdicts"
        ]
        cordon = {
            v["sample"]: (v["blocked"], v.get("detail", ""))
            for v in cordon_rows
            if v["tool"] == "cordon"
        }
        guarddog: dict[str, bool | None] = {}
        for path in sorted(results.glob("guarddog-batch-*.json")):
            for row in json.loads(path.read_text(encoding="utf-8")):
                guarddog[str(row["sample"])] = row["blocked"]  # type: ignore[assignment]
        both = [
            s
            for s in guarddog
            if guarddog[s] is not None and cordon.get(s, (None, ""))[0] is not None
        ]
        if not both:
            print("no samples answered by both tools yet")
            return 1
        cordon_blocked = sum(1 for s in both if cordon[s][0])
        content_blocked = sum(1 for s in both if cordon[s][0] and cordon[s][1] != "identity-only")
        guarddog_blocked = sum(1 for s in both if guarddog[s])
        total = len(both)
        print(f"samples answered by both tools: {total} (of {len(cordon)} Cordon scanned)")
        print(
            f"  Cordon, with known-malware lookup  {cordon_blocked:6}  {cordon_blocked / total:.1%}"
        )
        print(
            f"  Cordon, content only               {content_blocked:6}  {content_blocked / total:.1%}"
        )
        print(
            f"  GuardDog                           {guarddog_blocked:6}  {guarddog_blocked / total:.1%}"
        )
        by_source: dict[str, list[str]] = {}
        for s in both:
            key = "/".join(s.split("/")[:2]) if s.startswith("datadog/") else "malregistry"
            by_source.setdefault(key, []).append(s)
        for key, names in sorted(by_source.items()):
            n = len(names)
            print(
                f"  {key:24} {n:6}  Cordon {sum(1 for s in names if cordon[s][0]) / n:.1%}"
                f"  content {sum(1 for s in names if cordon[s][0] and cordon[s][1] != 'identity-only') / n:.1%}"
                f"  GuardDog {sum(1 for s in names if guarddog[s]) / n:.1%}"
            )
        (results / "comparison.json").write_text(
            json.dumps(
                {
                    "samples": total,
                    "cordon": cordon_blocked,
                    "cordon_content_only": content_blocked,
                    "guarddog": guarddog_blocked,
                },
                indent=1,
            ),
            encoding="utf-8",
        )
        return 0

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--data", type=Path, default=Path("/data"))
        parser.add_argument("--results", type=Path, default=Path("/results"))
        parser.add_argument("--batch", type=int)
        parser.add_argument("--all", action="store_true", help="every batch not yet written")
        parser.add_argument("--batch-size", type=int, default=5000)
        parser.add_argument("--workers", type=int, default=6)
        parser.add_argument("--merge", action="store_true")
        args = parser.parse_args()
        if args.merge:
            return GuardDogComparison.merge(args.results)
        if args.batch is not None:
            GuardDogComparison.batch(
                args.data, args.results, args.batch, args.batch_size, args.workers
            )
            return 0
        if args.all:
            total = len(harness.Harness.malware_samples(args.data))
            for index in range((total + args.batch_size - 1) // args.batch_size):
                GuardDogComparison.batch(
                    args.data, args.results, index, args.batch_size, args.workers
                )
            return GuardDogComparison.merge(args.results)
        parser.error("give --batch N, --all or --merge")
        return 2


if __name__ == "__main__":
    sys.exit(GuardDogComparison.main())
