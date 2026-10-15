#!/usr/bin/env python3
"""Train the package verdict (`core/verdict.py`) from what scans reported, and measure it held out.

```
  benign rows (long-tail rescan)  ┐                       work half ──► monotone trees
  malware rows (as published)     ├─► result.verdict ───►            ──► block / warn thresholds
  adjudication (not malicious,    ┘   features              holdout ──► the figures this prints
  no payload: excluded)
```

Every row's features are the ones the scanner itself reported (`result.verdict`), so what is
trained is what is scored. Halves are fixed by a hash: a benign unit by its name, a malware sample
by its package (every version of one package on one side). Thresholds are chosen on the work half
only -- `block` the lowest score at which no ecosystem blocks more than `--block-share` of its units,
`warn` the lowest at which every ecosystem stays at or above `--quiet` with no warning -- and the
holdout half is scored once with them.

    docker run --rm --network none -v OUT:/o -v DATA:/r:ro -v "$PWD:/s:ro" -e PYTHONPATH=/s/src \\
      cordon-model:next python /s/bench/model/verdict_train.py --benign /o/benign.jsonl \\
      --malware /o/malware-scans.jsonl --corpus /r/d0d8ea9/scans.jsonl --noisy /o/noisy.txt \\
      --adjudication /r/adjudication-malware.jsonl /r/adjudication-malware-supplement.jsonl \\
      --out /o/verdict.json.gz
"""

from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
import math
from pathlib import Path

from cordon_scanner.core.models import Severity
from cordon_scanner.core.verdict import VerdictFeatures, VerdictModel


class VerdictTrain:
    @staticmethod
    def half(key: str) -> str:
        return "holdout" if hashlib.sha256(key.encode()).digest()[0] % 2 else "work"

    @staticmethod
    def group(name: str) -> str:
        parts = name.split("/")
        return "/".join(parts[:4]) if parts[0] == "datadog" else "/".join(parts[:2])

    @staticmethod
    def rows(path: Path):
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                yield json.loads(line)
            except ValueError:
                continue

    @staticmethod
    def export(clf, vocab: list[str], block: float, warn: float, trained_on: dict) -> dict:
        """sklearn's HistGradientBoosting trees as `VerdictModel.score` walks them."""
        trees = []
        for predictors in clf._predictors:
            nodes = predictors[0].nodes
            tree = []
            for n in nodes:
                tree.append(
                    {"leaf": True, "value": float(n["value"])}
                    if n["is_leaf"]
                    else {
                        "leaf": False,
                        "feature": int(n["feature_idx"]),
                        "threshold": float(n["num_threshold"]),
                        "left": int(n["left"]),
                        "right": int(n["right"]),
                        "missing_left": bool(n["missing_go_to_left"]),
                    }
                )
            trees.append(tree)
        return {
            "version": trained_on.get("version", ""),
            "vocab": vocab,
            "package": list(VerdictFeatures.PACKAGE),
            "baseline": float(clf._baseline_prediction.ravel()[0]),
            "trees": trees,
            "thresholds": {"block": block, "warn": warn},
            "trained_on": trained_on,
        }

    @classmethod
    def main(cls) -> None:
        import numpy as np
        from sklearn.ensemble import HistGradientBoostingClassifier

        p = argparse.ArgumentParser()
        p.add_argument("--benign", type=Path, required=True)
        p.add_argument("--malware", type=Path, required=True)
        p.add_argument(
            "--corpus", type=Path, required=True, help="full-corpus scans: ecosystem sizes"
        )
        p.add_argument("--noisy", type=Path, required=True)
        p.add_argument("--adjudication", type=Path, nargs="*", default=[])
        p.add_argument("--out", type=Path)
        p.add_argument("--block-share", type=float, default=0.4)
        p.add_argument("--quiet", type=float, default=98.3)
        a = p.parse_args()

        excluded = set()
        for path in a.adjudication:
            for r in cls.rows(path):
                if r.get("verdict") in ("not-malicious", "no-payload", "vulnerable-fixture", "empty-template"):
                    excluded.add(r["file"])
        noisy = set(a.noisy.read_text(encoding="utf-8").split())
        total = {"work": collections.Counter(), "holdout": collections.Counter()}
        for r in cls.rows(a.corpus):
            total[cls.half(r["file"])][r["file"].split("/")[0]] += 1

        data = []
        for r in cls.rows(a.benign):
            if r["file"] in noisy and r.get("verdict"):
                data.append((r, 0, cls.half(r["file"])))
        for r in cls.rows(a.malware):
            if r["file"] not in excluded and r.get("verdict"):
                data.append((r, 1, cls.half(cls.group(r["file"]))))
        vocab = sorted({k for r, _, _ in data for k in r["verdict"]["rules"]})
        model_stub = {"vocab": vocab}

        def vec(r):
            v = r["verdict"]
            return VerdictModel.vector(model_stub, v["rules"], v["package"])

        X = {h: [] for h in ("work", "holdout")}
        Y = {h: [] for h in X}
        M = {h: [] for h in X}
        for r, y, h in data:
            X[h].append(vec(r))
            Y[h].append(y)
            M[h].append(r)
        mono = [1] * len(vocab) + [0] * len(VerdictFeatures.PACKAGE) + [1, 1, 0]
        clf = HistGradientBoostingClassifier(
            max_iter=300, learning_rate=0.08, max_leaf_nodes=31, monotonic_cst=mono, random_state=7
        )
        clf.fit(np.array(X["work"]), np.array(Y["work"]))
        prob = {h: clf.predict_proba(np.array(X[h]))[:, 1] for h in X}

        def strong(f) -> bool:
            return (
                f[0].startswith("MALWARE.")
                and ".KNOWN" not in f[0]
                and f[2] in ("high", "confirmed")
                and Severity[f[1].upper()] >= Severity.HIGH
            )

        # The floor: MALWARE.* rules that never fired on a benign unit of the WORK half and caught
        # malware there. A rule that misfired is weighed by the model until its precision is fixed.
        benign_hits = collections.Counter()
        malware_hits = collections.Counter()
        for r, y, h in data:
            if h != "work":
                continue
            for rule in {f[0] for f in r.get("findings", []) if strong(f)}:
                (malware_hits if y else benign_hits)[rule] += 1
        floor = sorted(r for r in malware_hits if malware_hits[r] >= 3 and not benign_hits[r])

        def floored(r) -> bool:
            return any(strong(f) and f[0] in floor for f in r.get("findings", []))

        def score(h, block, warn):
            blocked_b = collections.Counter()
            warned_b = collections.Counter()
            caught = n = 0
            for r, y, s in zip(M[h], Y[h], prob[h], strict=True):
                rules = r["verdict"]["rules"]
                if not rules:
                    continue
                blocked = s >= block or floored(r)
                if y:
                    n += 1
                    caught += blocked
                    continue
                eco = r["file"].split("/")[0]
                blocked_b[eco] += blocked
                medium = any(v >= int(Severity.MEDIUM) for v in rules.values())
                warned_b[eco] += blocked or (medium and s >= warn)
            ecos = total[h]
            block_rate = {e: 100 * blocked_b[e] / max(ecos[e], 1) for e in ecos}
            quiet = {e: 100 - 100 * warned_b[e] / max(ecos[e], 1) for e in ecos}
            return caught, max(n, 1), block_rate, quiet

        block = next(
            (
                t
                for t in np.linspace(0.02, 0.99, 98)
                if max(score("work", t, 1.0)[2].values()) <= a.block_share
            ),
            0.99,
        )
        warn = next(
            (
                t
                for t in np.linspace(0.001, block, 300)
                if min(score("work", block, t)[3].values()) >= a.quiet
            ),
            block,
        )
        report = {}
        for h in ("work", "holdout"):
            caught, n, block_rate, quiet = score(h, block, warn)
            z = 1.96
            p_hat = caught / n
            centre = p_hat + z * z / (2 * n)
            margin = z * math.sqrt(p_hat * (1 - p_hat) / n + z * z / (4 * n * n))
            report[h] = {
                "malware": f"{caught}/{n}",
                "recall": round(100 * p_hat, 2),
                "recall_ci95_low": round(100 * (centre - margin) / (1 + z * z / n), 2),
                "ecosystems_block_ok": sum(v <= 0.5 for v in block_rate.values()),
                "ecosystems_quiet_ok": sum(v >= 98 for v in quiet.values()),
                "ecosystems": len(block_rate),
                "worst_block": sorted(block_rate.items(), key=lambda x: -x[1])[:5],
                "worst_quiet": sorted(quiet.items(), key=lambda x: x[1])[:5],
            }
        print(json.dumps({"block": block, "warn": warn, "floor": floor, **report}, indent=1))
        if a.out:
            model = cls.export(
                clf,
                vocab,
                float(block),
                float(warn),
                {
                    "benign": len(Y["work"]) - sum(Y["work"]),
                    "malware": sum(Y["work"]),
                    "half": "work",
                },
            )
            model["floor"] = floor
            with gzip.open(a.out, "wt", encoding="utf-8") as handle:
                json.dump(model, handle, separators=(",", ":"))


if __name__ == "__main__":
    VerdictTrain.main()
