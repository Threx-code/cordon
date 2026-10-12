#!/usr/bin/env python3
"""Cordon's own rules over the random ordinary packages: the false alarms the model is added to.

The baseline (`bench/run.py`) measured the rules on the top 2,000 packages only. A combined verdict
(rules or model) blocks what either blocks, so its false-alarm rate needs the rules' verdict on the
long tail too. Each package is scanned exactly as the baseline scans a sample (`Harness.cordon`),
offline, in the same image.

    docker run --rm --network none -v cordon-bench-random:/random:ro -v "$PWD/bench:/bench:ro" \\
      -v cordon-model-work:/work cordon-bench:dev python /bench/model/rules_random.py
"""

from __future__ import annotations

import json
import sys
from multiprocessing import Pool
from pathlib import Path

sys.path.insert(0, "/bench")
from run import Harness


class RulesOnRandom:
    @staticmethod
    def one(entry: dict[str, str]) -> tuple[str, bool | None, str]:
        path = Path("/random") / entry["file"]
        verdict = Harness.cordon(path, entry["file"])
        return entry["file"], verdict.blocked, verdict.detail

    @staticmethod
    def main() -> int:
        out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/work/rules_random.json")
        entries = json.loads(Path("/random/manifest.json").read_text(encoding="utf-8"))
        with Pool(8) as pool:
            results = pool.map(RulesOnRandom.one, entries, chunksize=16)
        out = {path: {"blocked": blocked, "detail": detail} for path, blocked, detail in results}
        out_path.write_text(json.dumps(out), encoding="utf-8")
        blocked = sum(1 for v in out.values() if v["blocked"])
        errors = sum(1 for v in out.values() if v["blocked"] is None)
        print(f"{len(out)} packages; blocked {blocked}; no answer {errors}")
        return 0


if __name__ == "__main__":
    sys.exit(RulesOnRandom.main())
