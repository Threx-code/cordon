"""Live capture into the CDI loop: the Cloud's retained, labelled releases in, a loop run out.

    manage.py retained_export --out DIR --labelled-only        (the Cloud, platform side)
    python -m bench.cdi.capture --export DIR --root /c --prefix x/ --tools /tools \\
        --benign-set NAME=OFF.jsonl:PREFIX --discovery-benign LIST --pack-id ID --work OUT

Registries delete malware within hours, so outside npm, PyPI and the skills datasets the only
held-out malware is what the analyser fleet kept at analysis time and a label later named. This turns
that export into the loop's input without a person choosing samples:

1. Intake: a release counts as malware only when its label in the label store is
   `confirmed_malicious` at tier `confirmed` or `corroborated`. Silver (one automated signal) and
   unlabelled releases never enter: an attacker's upload cannot label itself.
2. Split by content hash before anything is scanned or read: a fixed hash of the sha256 sends each
   release to dev or sealed, so the split cannot follow what the scanner does.
3. Baseline: every captured release is scanned with the current scanner (network off), recorded.
4. Misses: dev releases the scanner does not block. Only these reach discovery; the sealed half is
   measured by the gate and never learned from.
5. The loop (`bench/cdi/loop.py`) runs with the sealed half, the dev half and the standing benign
   sets, and writes a signed bundle or a recorded rejection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from bench.cdi.gate import Gate
from bench.cdi.loop import CdiLoop

USABLE_TIERS = ("confirmed", "corroborated")
#: Fixed: changing it would move releases between halves after one was studied.
SPLIT_SALT = b"cdi-capture-split-v1"


class CaptureIntake:
    @staticmethod
    def labelled(manifest: Path) -> list[dict[str, Any]]:
        """Export rows the label store calls malicious with a usable tier, one per sha256."""
        rows, seen = [], set()
        for line in manifest.read_text(encoding="utf-8").splitlines():
            if not line:
                continue
            row = json.loads(line)
            if row.get("state") != "confirmed_malicious" or row.get("tier") not in USABLE_TIERS:
                continue
            if row["sha256"] in seen:
                continue
            seen.add(row["sha256"])
            rows.append(row)
        return rows

    @staticmethod
    def half(sha256: str) -> str:
        digest = hashlib.sha256(SPLIT_SALT + sha256.encode("ascii")).digest()
        return "dev" if digest[0] % 2 == 0 else "sealed"

    @staticmethod
    def split(rows: list[dict[str, Any]]) -> dict[str, list[str]]:
        halves: dict[str, list[str]] = {"dev": [], "sealed": []}
        for row in sorted(rows, key=lambda r: r["sha256"]):
            halves[CaptureIntake.half(row["sha256"])].append(row["file"])
        return halves

    @staticmethod
    def misses(records: Path, units: list[str]) -> list[str]:
        scans = Gate.read_scans(str(records))
        return [unit for unit in units if not Gate.blocked(scans.get(unit))]

    @staticmethod
    def listing(path: Path, units: list[str]) -> str:
        text = "".join(f"{u}\n" for u in units)
        path.write_text(text, encoding="utf-8")
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @staticmethod
    def run(
        *,
        export: Path,
        root: Path,
        prefix: str,
        tools: Path,
        benign_sets: list[dict[str, str]],
        discovery_benign: Path,
        pack_id: str,
        work: Path,
        sign_key: Path | None,
        workers: int = 4,
    ) -> dict[str, Any]:
        work.mkdir(parents=True, exist_ok=True)
        rows = CaptureIntake.labelled(export / "manifest.jsonl")
        halves = CaptureIntake.split(rows)
        record: dict[str, Any] = {
            "kind": "CaptureIntake",
            "export_manifest_sha256": Gate.file_digest(str(export / "manifest.jsonl")),
            "labelled": len(rows),
            "by_ecosystem": {},
        }
        for row in rows:
            record["by_ecosystem"][row["ecosystem"]] = (
                record["by_ecosystem"].get(row["ecosystem"], 0) + 1
            )
        sets = []
        for name, units in halves.items():
            record[f"{name}_list_sha256"] = CaptureIntake.listing(
                work / f"captured-{name}.txt", units
            )
            baseline = work / f"captured-{name}.baseline.jsonl"
            CdiLoop.rescan(tools, root, [prefix + u for u in units], None, baseline, workers)
            # Records name units as the scan saw them (<prefix><unit>); the sets name them unprefixed.
            off = work / f"captured-{name}.off.jsonl"
            off.write_text(
                "".join(
                    json.dumps({**r, "file": r["file"][len(prefix) :]}) + "\n"
                    for r in Gate.read_scans(str(baseline)).values()
                ),
                encoding="utf-8",
            )
            blocked = len(units) - len(CaptureIntake.misses(off, units))
            record[name] = {"units": len(units), "blocked": blocked}
            sets.append(
                {
                    "name": f"captured-{name}",
                    "kind": "malware",
                    "area": "live-capture",
                    "split": "held" if name == "sealed" else "dev",
                    "prefix": prefix,
                    "off": str(off),
                }
            )
        dev_misses = CaptureIntake.misses(work / "captured-dev.off.jsonl", halves["dev"])
        record["dev_misses"] = len(dev_misses)
        CaptureIntake.listing(work / "dev-misses.txt", [prefix + u for u in dev_misses])
        (work / "capture_intake.json").write_text(
            json.dumps(record, indent=1, sort_keys=True), encoding="utf-8"
        )
        if not dev_misses:
            return {"outcome": "no_misses", "intake": record}
        config = {
            "root": str(root),
            "tools": str(tools),
            "workers": workers,
            "misses": str(work / "dev-misses.txt"),
            "discovery_benign": str(discovery_benign),
            "pack_id": pack_id,
            "reference": f"Cloud live capture, export manifest {record['export_manifest_sha256'][:12]}",
            "paths": [],
            "sets": [*sets, *benign_sets],
        }
        (work / "loop-config.json").write_text(json.dumps(config, indent=1), encoding="utf-8")
        result = CdiLoop.run(config, work / "loop", sign_key)
        return {**result, "intake": record}

    @staticmethod
    def benign_set(spec: str) -> dict[str, str]:
        """NAME=OFF.jsonl:PREFIX -- a standing benign set and where its units are mounted."""
        name, rest = spec.split("=", 1)
        off, _, prefix = rest.partition(":")
        return {
            "name": name,
            "kind": "benign",
            "area": "live-capture",
            "split": "work",
            "prefix": prefix,
            "off": off,
        }

    @staticmethod
    def main(argv: list[str] | None = None) -> int:
        parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
        parser.add_argument(
            "--export", required=True, help="a `manage.py retained_export` directory"
        )
        parser.add_argument("--root", required=True, help="where the scan tool resolves units")
        parser.add_argument("--prefix", default="", help="the export's mount point under --root")
        parser.add_argument("--tools", required=True)
        parser.add_argument("--benign-set", action="append", default=[], required=True)
        parser.add_argument("--discovery-benign", required=True)
        parser.add_argument("--pack-id", required=True)
        parser.add_argument("--work", required=True)
        parser.add_argument("--sign-key")
        parser.add_argument("--workers", type=int, default=4)
        args = parser.parse_args(argv)
        result = CaptureIntake.run(
            export=Path(args.export),
            root=Path(args.root),
            prefix=args.prefix,
            tools=Path(args.tools),
            benign_sets=[CaptureIntake.benign_set(s) for s in args.benign_set],
            discovery_benign=Path(args.discovery_benign),
            pack_id=args.pack_id,
            work=Path(args.work),
            sign_key=Path(args.sign_key) if args.sign_key else None,
            workers=args.workers,
        )
        print(json.dumps(result, indent=1))
        return 0 if result["outcome"] not in ("reject", "no_candidate") else 1


if __name__ == "__main__":
    sys.exit(CaptureIntake.main())
