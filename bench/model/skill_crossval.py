#!/usr/bin/env python3
"""Held-out recall of the skill model across the two public malicious-skill benchmarks.

Each benchmark writes its attacks in its own style, and a model trained on one and scored on the
other is the only number that says how it reads attacks it has not seen written that way:

```
  fold no-malskill   train on MaliciousSkillBench + public skills; score MalSkillBench
  fold no-asb        train on MalSkillBench + public skills; score MaliciousSkillBench
  fold all           train on both (what would ship); report the calibration only
```

Thresholds per fold as the shipped model sets them: on public skills from repositories held out
of training, at `--block` and `--warn` of them. DataDog's ai-skills set is scored by the scanner
itself (`bench/run.py`), never here: no fold trains on it.

    docker run --rm --network none -v "$PWD:/s:ro" -v DEV:/o -e PYTHONPATH=/s/src \\
      --entrypoint python cordon-model:next /s/bench/model/skill_crossval.py /o/skills.jsonl --out /o/folds
"""

from __future__ import annotations

import argparse
import gzip
import json
import random
from collections import Counter
from pathlib import Path

from cordon_scanner.detect.agents.mcp_model import BUCKETS, SKILL_MODEL


class SkillCrossVal:
    @staticmethod
    def matrix(rows: list[dict]):
        """Rows as a sparse matrix, built in compact typed arrays: Python lists of the hundreds of
        millions of n-gram entries a public-skill sample produces did not fit in 9 GB."""
        from array import array

        import numpy as np
        from scipy.sparse import csr_matrix

        data = array("f")
        indices = array("i")
        indptr = array("q", [0])
        for row in rows:
            features = SKILL_MODEL.features(row["text"], "skill")
            indices.extend(features.keys())
            data.extend(features.values())
            indptr.append(len(indices))
        return csr_matrix(
            (
                np.frombuffer(data, dtype=np.float32),
                np.frombuffer(indices, dtype=np.int32),
                np.frombuffer(indptr, dtype=np.int64),
            ),
            shape=(len(rows), BUCKETS),
        )

    @staticmethod
    def threshold(scores, share: float) -> float:
        ordered = sorted((float(s) for s in scores), reverse=True)
        return ordered[max(0, int(len(ordered) * share) - 1)] if ordered else 1.0

    @classmethod
    def fold(cls, name, train, test, calibrate, args) -> None:
        import numpy as np
        from sklearn.linear_model import LogisticRegression

        clf = LogisticRegression(C=4.0, class_weight={0: 1, 1: args.positive_weight}, max_iter=4000)
        clf.fit(cls.matrix(train), np.array([r["label"] for r in train]))
        calibration = clf.predict_proba(cls.matrix(calibrate))[:, 1]
        block, warn = cls.threshold(calibration, args.block), cls.threshold(calibration, args.warn)
        report: dict = {
            "fold": name,
            "train": len(train),
            "block": float(block),
            "warn": float(warn),
        }
        if test:
            scores = clf.predict_proba(cls.matrix(test))[:, 1]
            by: dict[str, Counter] = {}
            for row, score in zip(test, scores, strict=True):
                c = by.setdefault(row["source"], Counter())
                c["n"] += 1
                c["blocked"] += int(score >= block)
                c["warned_or_blocked"] += int(score >= warn)
            report["test"] = {k: dict(v) for k, v in sorted(by.items())}
        if args.out:
            args.out.mkdir(parents=True, exist_ok=True)
            model = {
                "bias": float(clf.intercept_[0]),
                "weights": {
                    str(i): round(float(w), 5) for i, w in enumerate(clf.coef_[0]) if abs(w) > 1e-3
                },
                "thresholds": {"skill": [block, warn]},
                "calibration": {"fold": name},
                "trained_on": sorted({r["source"] for r in train}),
                "features": "word 1-3 grams + channel, crc32 mod 2^18, L2 (detect/mcp_model.py)",
            }
            with gzip.open(args.out / f"skill-{name}.json.gz", "wt", encoding="utf-8") as handle:
                json.dump(model, handle, separators=(",", ":"), sort_keys=True)
        print(json.dumps(report), flush=True)

    @classmethod
    def main(cls) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument("devset", type=Path)
        parser.add_argument("--out", type=Path)
        parser.add_argument("--block", type=float, default=0.003)
        parser.add_argument("--warn", type=float, default=0.02)
        parser.add_argument("--positive-weight", type=float, default=60.0)
        parser.add_argument("--corpus-train", type=int, default=30_000)
        parser.add_argument("--corpus-calibrate", type=int, default=15_000)
        parser.add_argument("--folds", default="no-malskill,no-asb,all")
        args = parser.parse_args()
        # Streamed: the public skills are 1.5 GB of text, and only a sample of each half is used.
        # Reservoir sampling keeps the sample independent of the file's order.
        rng = random.Random(20261015)  # noqa: S311  (a reproducible sample, not a secret)
        work: list[dict] = []
        calibrate: list[dict] = []
        seen = {"work": 0, "holdout": 0}
        limits = {"work": args.corpus_train, "holdout": args.corpus_calibrate}
        malskill: list[dict] = []
        asb: list[dict] = []
        with args.devset.open(encoding="utf-8") as handle:
            for line in handle:
                row = json.loads(line)
                if row["dataset"] == "malskillbench":
                    malskill.append(row)
                elif row["dataset"] == "maliciousskillbench":
                    asb.append(row)
                else:
                    half = row["half"]
                    pool = work if half == "work" else calibrate
                    seen[half] += 1
                    if len(pool) < limits[half]:
                        pool.append(row)
                    else:
                        slot = rng.randrange(seen[half])
                        if slot < limits[half]:
                            pool[slot] = row
        wanted = set(args.folds.split(","))
        if "no-malskill" in wanted:
            cls.fold("no-malskill", work + asb, malskill, calibrate, args)
        if "no-asb" in wanted:
            cls.fold("no-asb", work + malskill, asb, calibrate, args)
        if "all" in wanted:
            cls.fold("all", work + malskill + asb, [], calibrate, args)


if __name__ == "__main__":
    SkillCrossVal.main()
