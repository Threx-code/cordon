#!/usr/bin/env python3
"""Scan every `.vsix` under a directory and count what blocks: the extension measurement.

Each package is scanned as it is published (`cordon-scanner scan x.vsix --offline`), never
installed or run. Blocked means the scan's exit status was 1, the default gate. Reported: how many
blocked, which rules blocked them, and, for the legitimate corpus, each blocked extension by name so
a false alarm is read, not just counted.

    docker run --rm --network none -v "$PWD:/s:ro" -v cordon-bench-ext:/ext:ro \\
      -e PYTHONPATH=/s/src cordon-bench:dev python /s/bench/extensions_measure.py /ext/vsix --out /tmp/legit.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

GATE_EXIT = 1


class ExtensionMeasure:
    @staticmethod
    def scan(vsix: Path) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as scratch:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "cordon_scanner",
                    "scan",
                    str(vsix),
                    "--offline",
                    "--format",
                    "json",
                ],
                capture_output=True,
                cwd=scratch,
                timeout=600,
                check=False,
            )
        try:
            findings = json.loads(result.stdout)["findings"]
        except (ValueError, KeyError):
            return {"path": str(vsix), "exit": result.returncode, "error": True, "rules": []}
        blocking = sorted({f["rule_id"] for f in findings if f["severity"] in ("high", "critical")})
        return {"path": str(vsix), "exit": result.returncode, "error": False, "rules": blocking}

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("root", type=Path)
        parser.add_argument("--out", type=Path, required=True)
        parser.add_argument("--workers", type=int, default=6)
        args = parser.parse_args()
        packages = sorted(args.root.rglob("*.vsix"))
        with ThreadPoolExecutor(args.workers) as pool:
            rows = list(pool.map(ExtensionMeasure.scan, packages))
        blocked = [r for r in rows if r["exit"] == GATE_EXIT]
        errors = [r for r in rows if r["error"] or r["exit"] not in (0, GATE_EXIT)]
        by_rule = Counter(rule for r in blocked for rule in r["rules"])
        print(
            f"{len(rows)} extensions; blocked {len(blocked)} ({len(blocked) / max(1, len(rows)):.2%}); errors {len(errors)}"
        )
        for rule, count in by_rule.most_common():
            print(f"  {count:5d}  {rule}")
        args.out.write_text(json.dumps(rows, indent=1), encoding="utf-8")
        return 0


if __name__ == "__main__":
    sys.exit(ExtensionMeasure.main())
