#!/usr/bin/env python3
"""Held-out recall of the MCP description model, by MCP-SafetyBench domain and by dataset.

`bench/mcp_model_train.py` reports a held-out rate on a hash split, and MCP-SafetyBench builds
every attack from its own servers' descriptions: a task family's attacks share that family's
vocabulary (ticker, Yahoo Finance, geocode). A hash split puts the same family on both sides, so
the model can score the family's words rather than the attack's. Measured that way, the shipped
model blocked the benchmark's own unmodified `yahoo_finance` descriptions at 0.86-0.99 (review 98).

So the figure that can be published is the one where the family was never seen:

```
  fold msb:<domain>   train on everything except MCP-SafetyBench (attacks and its benign
                      servers); score that one domain's attack units
  fold no-msb         the same with every domain held out at once (cross-dataset)
  fold no-mcptox      train without MCPTox; score MCPTox's attacks and its legitimate tools
```

Thresholds are set per fold the trainer's way: on real servers held out of training (the corpus
`holdout` half), per server, at `--block-servers` and `--warn-servers` of them. A unit (one task,
one server) is blocked when its highest-scoring text reaches `block`.

    docker run --rm --network none -v "$PWD:/s:ro" -v DEV:/o -e PYTHONPATH=/s/src \\
      cordon-model:next python /s/bench/model/mcp_crossval.py /o/devset.jsonl --out /o/folds
"""

from __future__ import annotations

import argparse
import gzip
import json
from collections import defaultdict
from pathlib import Path

from cordon_scanner.detect.mcp_model import BUCKETS, McpDescriptionModel


class McpCrossVal:
    @staticmethod
    def matrix(rows: list[dict]):
        import numpy as np
        from scipy.sparse import csr_matrix

        data: list[float] = []
        indices: list[int] = []
        indptr = [0]
        for row in rows:
            features = McpDescriptionModel.features(row["text"], row["channel"])
            indices.extend(features)
            data.extend(features.values())
            indptr.append(len(indices))
        return csr_matrix(
            (np.array(data, dtype=np.float32), indices, indptr), shape=(len(rows), BUCKETS)
        )

    @staticmethod
    def threshold(scores: list[float], share: float) -> float:
        ordered = sorted(scores, reverse=True)
        index = max(0, int(len(ordered) * share) - 1)
        return ordered[index] if ordered else 1.0

    @staticmethod
    def per_group(rows: list[dict], scores) -> dict[str, float]:
        best: dict[str, float] = defaultdict(float)
        for row, score in zip(rows, scores, strict=True):
            key = row["group"]
            best[key] = max(best[key], float(score))
        return best

    @classmethod
    def fold(
        cls, name: str, train: list[dict], test: list[dict], calibrate: list[dict], args
    ) -> dict:
        import numpy as np
        from sklearn.linear_model import LogisticRegression

        y = np.array([r["label"] for r in train])
        clf = LogisticRegression(C=4.0, class_weight={0: 1, 1: args.positive_weight}, max_iter=4000)
        clf.fit(cls.matrix(train), y)
        report: dict = {"fold": name, "train": len(train)}
        thresholds: dict[str, tuple[float, float]] = {}
        for channel in ("description", "return"):
            rows = [r for r in calibrate if r["channel"] == channel]
            if not rows:
                continue
            servers = list(cls.per_group(rows, clf.predict_proba(cls.matrix(rows))[:, 1]).values())
            thresholds[channel] = (
                cls.threshold(servers, args.block_servers),
                cls.threshold(servers, args.warn_servers),
            )
        report["thresholds"] = thresholds
        scores = clf.predict_proba(cls.matrix(test))[:, 1] if test else []
        units: dict[tuple[int, str], list[tuple[str, float]]] = defaultdict(list)
        for row, score in zip(test, scores, strict=True):
            units[(row["label"], row["group"])].append((row["channel"], float(score)))
        for label in (1, 0):
            mine = {k: v for k, v in units.items() if k[0] == label}
            blocked = sum(
                any(s >= thresholds[c][0] for c, s in texts if c in thresholds)
                for texts in mine.values()
            )
            warned = sum(
                any(s >= thresholds[c][1] for c, s in texts if c in thresholds)
                for texts in mine.values()
            )
            key = "attack" if label else "benign"
            report[key] = {"units": len(mine), "blocked": blocked, "warned_or_blocked": warned}
        if args.out:
            args.out.mkdir(parents=True, exist_ok=True)
            weights = {
                str(i): round(float(w), 5) for i, w in enumerate(clf.coef_[0]) if abs(w) > 1e-3
            }
            model = {
                "bias": float(clf.intercept_[0]),
                "weights": weights,
                "thresholds": {k: list(v) for k, v in thresholds.items()},
                "calibration": {"fold": name},
                "trained_on": sorted({r["source"] for r in train}),
                "features": "word 1-3 grams + channel, crc32 mod 2^18, L2 (detect/mcp_model.py)",
            }
            with gzip.open(
                args.out / f"{name.replace(':', '-')}.json.gz", "wt", encoding="utf-8"
            ) as handle:
                json.dump(model, handle, separators=(",", ":"), sort_keys=True)
        print(json.dumps(report), flush=True)
        return report

    @classmethod
    def main(cls) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument("devset", type=Path)
        parser.add_argument("--out", type=Path)
        parser.add_argument("--block-servers", type=float, default=0.002)
        parser.add_argument("--warn-servers", type=float, default=0.02)
        parser.add_argument("--positive-weight", type=float, default=60.0)
        args = parser.parse_args()
        rows = [json.loads(line) for line in args.devset.read_text(encoding="utf-8").splitlines()]
        corpus_work = [r for r in rows if r["dataset"] == "corpus" and r["half"] == "work"]
        calibrate = [r for r in rows if r["dataset"] == "corpus" and r["half"] == "holdout"]
        msb = [r for r in rows if r["dataset"] == "mcpsafetybench"]
        mcptox = [r for r in rows if r["dataset"] == "mcptox"]
        domains = sorted({r["domain"] for r in msb if r["label"] == 1 and r["domain"]})
        for domain in domains:
            test = [r for r in msb if r["label"] == 1 and r["domain"] == domain]
            cls.fold(f"msb:{domain}", corpus_work + mcptox, test, calibrate, args)
        cls.fold("no-msb", corpus_work + mcptox, msb, calibrate, args)
        cls.fold("no-mcptox", corpus_work + msb, mcptox, calibrate, args)


if __name__ == "__main__":
    McpCrossVal.main()
