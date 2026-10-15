#!/usr/bin/env python3
"""Train and calibrate the MCP tool-description model (`detect/mcp_model.py`).

```
  devset.jsonl   label, source, group (server or package), half (work|holdout), text
        │  features: McpDescriptionModel.features -- the scanner's own, imported, not copied
        ▼
  logistic regression on the WORK half (attacks: MCPTox, MCP-SafetyBench; benign: 85K real
  descriptions from 1,694 MCP servers + MCPTox's legitimate tools)
        │
        ▼  calibrated on the HOLDOUT half, per server: a server's score is its highest description
  block = the score above which <= --block-servers of held-out benign servers fall
  warn  = the same at --warn-servers
        │
        ▼
  src/cordon_scanner/detect/data/mcp-descriptions.json.gz   (the work-trained model ships, so the
                                                              numbers printed are what ships)
```

    docker run --rm -v "$PWD:/s:ro" -v <devset dir>:/o -v <out>:/out python:3.12-slim sh -c \\
      'pip -q install scikit-learn==1.5.2 numpy==2.1.2 scipy==1.14.1 && \\
       PYTHONPATH=/s/src python /s/bench/mcp_model_train.py /o/devset.jsonl --out /out'
"""

from __future__ import annotations

import argparse
import gzip
import json
from collections import defaultdict
from pathlib import Path


class McpModelTrainer:
    KIND = "mcp"
    """Which model: `mcp` (descriptions and returns) or `skill` (a skill's instructions)."""

    @staticmethod
    def matrix(rows: list[dict]):
        import numpy as np
        from scipy.sparse import csr_matrix, vstack

        from cordon_scanner.detect import mcp_model

        model = mcp_model.SKILL_MODEL if McpModelTrainer.KIND == "skill" else mcp_model.MCP_MODEL
        # In chunks, as float32 arrays: half a million rows of n-gram features held as Python
        # lists took more than 10 GB.
        chunks = []
        for start in range(0, len(rows), 20_000):
            data, indices, pointers = [], [], [0]
            for r in rows[start : start + 20_000]:
                for k, v in model.features(r["text"], r.get("channel", "description")).items():
                    indices.append(k)
                    data.append(v)
                pointers.append(len(indices))
            chunks.append(
                csr_matrix(
                    (
                        np.asarray(data, dtype=np.float32),
                        np.asarray(indices, dtype=np.int32),
                        np.asarray(pointers, dtype=np.int64),
                    ),
                    shape=(len(pointers) - 1, mcp_model.FEATURES),
                )
            )
        return vstack(chunks, format="csr") if chunks else csr_matrix((0, mcp_model.FEATURES))

    @staticmethod
    def per_group(rows: list[dict], scores) -> list[float]:
        best: dict[str, float] = defaultdict(float)
        for r, s in zip(rows, scores, strict=True):
            key = f"{r['source']}:{r['group']}"
            best[key] = max(best[key], float(s))
        return sorted(best.values())

    @staticmethod
    def threshold(sorted_scores: list[float], share: float) -> float:
        index = min(len(sorted_scores) - 1, int(len(sorted_scores) * (1 - share)))
        return sorted_scores[index] + 1e-9

    @classmethod
    def main(cls) -> None:
        import numpy as np
        from sklearn.linear_model import LogisticRegression

        ap = argparse.ArgumentParser()
        ap.add_argument("devset", type=Path)
        ap.add_argument("--out", type=Path, default=Path())
        ap.add_argument("--block-servers", type=float, default=0.002)
        ap.add_argument("--warn-servers", type=float, default=0.02)
        ap.add_argument("--positive-weight", type=float, default=60.0)
        ap.add_argument("--calibrate-on", default="corpus,mcptox-legit,msb-legit")
        ap.add_argument("--calibrate-returns-on", default="corpus-return,msb-legit-return")
        ap.add_argument("--kind", choices=("mcp", "skill"), default="mcp")
        ap.add_argument("--calibrate-skills-on", default="corpus-skill")
        args = ap.parse_args()
        McpModelTrainer.KIND = args.kind
        rows = [json.loads(line) for line in args.devset.read_text(encoding="utf-8").splitlines()]
        work = [r for r in rows if r["half"] == "work"]
        hold = [r for r in rows if r["half"] == "holdout"]
        y = np.array([r["label"] for r in work])
        clf = LogisticRegression(
            C=4.0, class_weight={0: 1, 1: args.positive_weight}, max_iter=4000
        ).fit(cls.matrix(work), y)
        scores = clf.predict_proba(cls.matrix(hold))[:, 1]
        # Calibrated on REAL servers only, per channel. Hard negatives written to sit beside attacks
        # (ATR's benign cases) train the model; counting them as servers would set the bar by a
        # test suite.
        real = (
            {"skill": set(args.calibrate_skills_on.split(","))}
            if args.kind == "skill"
            else {
                "description": set(args.calibrate_on.split(",")),
                "return": set(args.calibrate_returns_on.split(",")),
            }
        )
        thresholds: dict[str, list[float]] = {}
        report: dict = {}
        for channel, sources in real.items():
            pairs = [
                (r, s)
                for r, s in zip(hold, scores, strict=True)
                if r["label"] == 0
                and r["source"] in sources
                and r.get("channel", "description") == channel
            ]
            if not pairs:
                continue
            servers = cls.per_group([r for r, _ in pairs], [s for _, s in pairs])
            block = cls.threshold(servers, args.block_servers)
            warn = cls.threshold(servers, args.warn_servers)
            thresholds[channel] = [block, warn]
            report[channel] = {
                "benign_servers_held_out": len(servers),
                "block": block,
                "warn": warn,
                "benign_texts_flagged_at_warn": round(
                    sum(s >= warn for _, s in pairs) / len(pairs), 5
                ),
            }
        by_source: dict[tuple[str, str], list[float]] = defaultdict(list)
        for r, s in zip(hold, scores, strict=True):
            if r["label"] == 1:
                by_source[(r.get("channel", "description"), r["source"])].append(float(s))
        for (channel, source), values in sorted(by_source.items()):
            if channel not in thresholds:
                continue
            block, warn = thresholds[channel]
            report[f"{channel}:{source}"] = {
                "n": len(values),
                "blocked": round(sum(v >= block for v in values) / len(values), 4),
                "warned_or_blocked": round(sum(v >= warn for v in values) / len(values), 4),
            }
        weights = {str(i): round(float(w), 5) for i, w in enumerate(clf.coef_[0]) if abs(w) > 1e-3}
        model = {
            "bias": float(clf.intercept_[0]),
            "weights": weights,
            "thresholds": thresholds,
            "calibration": report,
            "trained_on": sorted({f"{r['source']}" for r in work}),
            "features": "word 1-3 grams + channel, crc32 mod 2^18, L2 (detect/mcp_model.py)",
        }
        args.out.mkdir(parents=True, exist_ok=True)
        name = "skill-instructions.json.gz" if args.kind == "skill" else "mcp-descriptions.json.gz"
        with gzip.open(args.out / name, "wt", encoding="utf-8") as handle:
            json.dump(model, handle, separators=(",", ":"), sort_keys=True)
        print(json.dumps(report, indent=2), f"\nweights kept: {len(weights)}")


if __name__ == "__main__":
    McpModelTrainer.main()
