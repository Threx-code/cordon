"""Score archived scans into scorecard entries, by group, with the gate's own definitions.

    python -m bench.cdi.score --scans RUN.jsonl --kind malware|benign [--groups GROUPS.jsonl]
        [--prefix q/] --id-prefix skills.public --set "..." --split "..." --scanner b00d203

Malware is blocked when the scan's exit is a block (`Gate.blocked`); a failed scan is a miss.
Legitimate software is blocked as malware by `Gate.malware_class_block` (a block for a leaked
secret alone is policy, counted apart). Each group's k and n are written as one scorecard metric;
the report's build computes the percentages and intervals, so this never rounds anything.
`--groups` maps units to groups: JSON lines with a `group` and a `file` (or `sha256` and
`filename`, as the PyPI held-out lists have). Without it, every unit is one group, `all`.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from bench.cdi.gate import Gate


class Score:
    @staticmethod
    def groups(path: Path | None) -> dict[str, str]:
        if path is None:
            return {}
        out = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line:
                continue
            row = json.loads(line)
            key = row.get("file") or f"{row['sha256'][:2]}/{row['filename']}"
            out[key] = row["group"]
        return out

    @staticmethod
    def tally(
        scans: Path, kind: str, groups: dict[str, str], prefix: str = ""
    ) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = defaultdict(
            lambda: {"k": 0, "n": 0, "failed": 0, "secret_only": 0}
        )
        for line in scans.read_text(encoding="utf-8").splitlines():
            if not line:
                continue
            row = json.loads(line)
            unit = (
                row["file"][len(prefix) :]
                if prefix and row["file"].startswith(prefix)
                else row["file"]
            )
            group = groups.get(unit, "all") if groups else "all"
            tally = out[group]
            tally["n"] += 1
            failed = row.get("exit") not in (0, 1)
            tally["failed"] += failed
            if kind == "malware":
                tally["k"] += Gate.blocked(row)
            elif Gate.malware_class_block(row):
                tally["k"] += 1
            elif Gate.blocked(row):
                tally["secret_only"] += 1
        return dict(out)

    @staticmethod
    def metrics(tallies: dict[str, dict[str, int]], args: argparse.Namespace) -> dict[str, Any]:
        out = {}
        for group, t in sorted(tallies.items()):
            out[f"{args.id_prefix}.{group}"] = {
                "label": f"{args.label} ({group})",
                "area": args.area,
                "kind": "recall" if args.kind == "malware" else "benign_rate",
                "k": t["k"],
                "n": t["n"],
                "target": 0.98 if args.kind == "malware" else 0.005,
                "set": args.set,
                "split": args.split,
                "scanner": args.scanner,
                "date": args.date,
                "status": "validated",
                "evidence": f"{Path(args.scans).name}, sha256 {Gate.file_digest(str(args.scans))[:16]}",
                "note": f"scan failures {t['failed']}"
                + (
                    f"; blocked for a leaked secret only {t['secret_only']}"
                    if args.kind == "benign"
                    else ""
                ),
            }
        return out

    @staticmethod
    def main(argv: list[str] | None = None) -> int:
        p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
        p.add_argument("--scans", required=True, type=Path)
        p.add_argument("--kind", required=True, choices=("malware", "benign"))
        p.add_argument("--groups", type=Path)
        p.add_argument("--prefix", default="")
        p.add_argument("--id-prefix", required=True)
        p.add_argument("--label", required=True)
        p.add_argument("--area", required=True)
        p.add_argument("--set", required=True)
        p.add_argument("--split", required=True)
        p.add_argument("--scanner", required=True)
        p.add_argument("--date", required=True)
        args = p.parse_args(argv)
        tallies = Score.tally(args.scans, args.kind, Score.groups(args.groups), args.prefix)
        print(json.dumps(Score.metrics(tallies, args), indent=1))
        return 0


if __name__ == "__main__":
    sys.exit(Score.main())
