#!/usr/bin/env python3
"""Re-set the MCP model's block and warn lines on a larger benign pool, the weights untouched.

The lines were set on 900 held-out servers (descriptions) and 726 (results): the held-out half of
the 1,694 real servers the model was trained beside. The development half of the MCP benchmark has
about 3,700 more real servers the weights never saw. This sets the lines again by the trainer's own
rule on that larger pool, and changes nothing else.

```
  shipped model (weights, bias)  +  devset.jsonl (label, channel, source, group, half, text)
      pool    = the held-out half of the sources the lines were first set on,
                plus every row of a source the weights never saw (`NEVER_TRAINED`)
      line    = the score above which at most `--block-servers` / `--warn-servers` of the pool's
                servers fall; a server scores as its highest text (`McpModelTrainer`)
      written = the same weights, bias and trained_on; new thresholds; a calibration that records
                the pool, the old lines and a digest of the weights it was set on
```

    docker run --rm --network none -v "$PWD:/s:ro" -v DEVSET:/d:ro -v OUT:/o -e PYTHONPATH=/s/src \\
      python:3.12-slim python /s/bench/model/mcp_recalibrate.py /d/devset.jsonl --out /o
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, ClassVar

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp_model_train import McpModelTrainer

from cordon_scanner.detect.agents.mcp_servers.description_model import (
    MAX_TEXT,
    MODEL_PATH,
    LinearTextModel,
)


class McpRecalibrate:
    SOURCES: ClassVar[dict[str, tuple[str, ...]]] = {
        "description": ("corpus", "mcptox-legit", "msb-legit", "census"),
        "return": ("corpus-return", "msb-legit-return", "census-return"),
    }
    """The real servers (and MCPTox's and MCP-SafetyBench's legitimate tools) that set a line."""
    NEVER_TRAINED = frozenset({"census", "census-return"})
    """Sources the shipped weights never saw: every row counts, not only the held-out half."""
    ATTACKS = ("mcptox", "mcpsafetybench", "mcpsafetybench-return")

    @classmethod
    def pool(cls, rows: list[dict[str, Any]], channel: str) -> list[dict[str, Any]]:
        return [
            r
            for r in rows
            if r["label"] == 0
            and r["channel"] == channel
            and r["source"] in cls.SOURCES[channel]
            and (r["half"] == "holdout" or r["source"] in cls.NEVER_TRAINED)
        ]

    @staticmethod
    def lines(
        rows: list[dict[str, Any]], scores: list[float], block: float, warn: float
    ) -> tuple[float, float, int]:
        servers = McpModelTrainer.per_group(rows, scores)
        return (
            McpModelTrainer.threshold(servers, block),
            McpModelTrainer.threshold(servers, warn),
            len(servers),
        )

    @staticmethod
    def weights_digest(weights: dict[str, float]) -> str:
        text = json.dumps(weights, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @classmethod
    def recalibrated(
        cls,
        model: dict[str, Any],
        rows: list[dict[str, Any]],
        scores: dict[str, list[float]],
        block_share: float = 0.002,
        warn_share: float = 0.02,
    ) -> dict[str, Any]:
        """`model` with new lines. `rows` are the pool's rows and `scores[channel]` their scores,
        in the order `pool(rows, channel)` returns them."""
        out = json.loads(json.dumps(model))
        previous = {k: list(v) for k, v in model["thresholds"].items()}
        for channel in cls.SOURCES:
            chosen = cls.pool(rows, channel)
            block, warn, servers = cls.lines(chosen, scores[channel], block_share, warn_share)
            out["thresholds"][channel] = [block, warn]
            flagged = sum(s >= warn for s in scores[channel]) / max(1, len(chosen))
            out["calibration"][channel] = {
                "benign_servers_held_out": servers,
                "block": block,
                "warn": warn,
                "benign_texts_flagged_at_warn": round(flagged, 5),
            }
        for key, value in out["calibration"].items():
            if ":" in key and "lines" not in value:
                value["lines"] = "previous"
        out["calibration"]["recalibration"] = {
            "previous_lines": previous,
            "never_trained_on": sorted(cls.NEVER_TRAINED),
            "pool_sources": {k: list(v) for k, v in cls.SOURCES.items()},
            "block_share": block_share,
            "warn_share": warn_share,
            "weight_count": len(model["weights"]),
            "weights_sha256": cls.weights_digest(model["weights"]),
        }
        return out

    @classmethod
    def attacks(
        cls, model: dict[str, Any], rows: list[dict[str, Any]], scorer: LinearTextModel
    ) -> dict[str, dict[str, float]]:
        """Held-out attack rows scored with the weights, read at the new lines."""
        report: dict[str, dict[str, float]] = {}
        for source in cls.ATTACKS:
            hits = [r for r in rows if r["label"] == 1 and r["source"] == source]
            hits = [r for r in hits if r["half"] == "holdout"]
            if not hits:
                continue
            channel = hits[0]["channel"]
            block, warn = model["thresholds"][channel]
            values = [scorer.score(r["text"], channel) or 0.0 for r in hits]
            report[f"{channel}:{source}"] = {
                "n": len(values),
                "blocked": round(sum(v >= block for v in values) / len(values), 4),
                "warned_or_blocked": round(sum(v >= warn for v in values) / len(values), 4),
            }
        return report

    @classmethod
    def main(cls) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument("devset", type=Path)
        parser.add_argument("--model", type=Path, default=MODEL_PATH)
        parser.add_argument("--out", type=Path, default=Path())
        parser.add_argument("--block-servers", type=float, default=0.002)
        parser.add_argument("--warn-servers", type=float, default=0.02)
        args = parser.parse_args()
        with gzip.open(args.model, "rt", encoding="utf-8") as handle:
            model = json.load(handle)
        rows = [json.loads(line) for line in args.devset.read_text(encoding="utf-8").splitlines()]
        scorer = LinearTextModel(args.model, MAX_TEXT, semantic=True)
        chosen: list[dict[str, Any]] = []
        scores: dict[str, list[float]] = {}
        for channel in cls.SOURCES:
            pool = cls.pool(rows, channel)
            chosen += pool
            scores[channel] = [scorer.score(r["text"], channel) or 0.0 for r in pool]
        # `recalibrated` pairs each channel's pool with its own scores, so it is given the rows
        # of one channel at a time through `pool`; the flat list holds both channels' rows.
        new = cls.recalibrated(model, chosen, scores, args.block_servers, args.warn_servers)
        new["calibration"].update(cls.attacks(new, rows, scorer))
        args.out.mkdir(parents=True, exist_ok=True)
        with gzip.open(args.out / MODEL_PATH.name, "wt", encoding="utf-8") as handle:
            json.dump(new, handle, separators=(",", ":"), sort_keys=True)
        print(json.dumps(new["calibration"], indent=2, sort_keys=True))


if __name__ == "__main__":
    McpRecalibrate.main()
