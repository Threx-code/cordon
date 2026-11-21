#!/usr/bin/env python3
"""Give one channel of the MCP model its own weights and lines, and leave the others as they were.

The description and return channels share one weight vector, so retraining on a larger benign pool
moves both. Where one channel improves and the other must not move (the retrained return channel
clears legitimate servers; the description channel still holds the only block of two malicious
units, and a larger pool raises its line past them), the model file takes an optional block:

```
  shipped model   {bias, weights, thresholds{description, return}, calibration}
  retrained model {bias, weights, thresholds{...},                 calibration}
        │  --channel return
        ▼
  merged          the shipped model, plus  channels.return = {bias, weights}  and the retrained
                  return lines and calibration; every description number byte for byte as shipped
```

`LinearTextModel.score` reads `channels[channel]` when the file has it and the top-level weights
otherwise, so a file without the block scores as before. `digest` is what the identity test pins: a
hash of everything that scores a channel, so a change to the description channel cannot pass.

    docker run --rm --network none -v "$PWD:/s:ro" -v RETRAINED:/r:ro -v OUT:/o -e PYTHONPATH=/s/src \\
      python:3.12-slim python /s/bench/model/mcp_channel_model.py /r/mcp-descriptions.json.gz \\
      --channel return --out /o
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


class McpChannelModel:
    @staticmethod
    def parameters(model: dict[str, Any], channel: str) -> tuple[dict[str, float], float]:
        """The weights and bias that score `channel`: its own block when the file has one."""
        own = model.get("channels", {}).get(channel)
        if own is not None:
            return own["weights"], float(own["bias"])
        return model["weights"], float(model["bias"])

    @classmethod
    def digest(cls, model: dict[str, Any], channel: str) -> str:
        """A hash of what scores `channel`: its weights, its bias and its lines."""
        weights, bias = cls.parameters(model, channel)
        text = json.dumps(
            {
                "bias": bias,
                "lines": list(model["thresholds"][channel]),
                "weights": {key: weights[key] for key in sorted(weights, key=int)},
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @classmethod
    def merged(
        cls, shipped: dict[str, Any], retrained: dict[str, Any], channel: str
    ) -> dict[str, Any]:
        """`shipped` with `channel` taken from `retrained`; every other channel untouched."""
        if channel not in retrained["thresholds"] or channel not in shipped["thresholds"]:
            raise ValueError(f"both models need lines for the channel {channel!r}")
        out = json.loads(json.dumps(shipped))
        before = {name: cls.digest(shipped, name) for name in shipped["thresholds"]}
        out.setdefault("channels", {})[channel] = {
            "bias": retrained["bias"],
            "weights": retrained["weights"],
        }
        out["thresholds"][channel] = list(retrained["thresholds"][channel])
        calibration = out["calibration"]
        for key in [k for k in calibration if k == channel or k.startswith(f"{channel}:")]:
            del calibration[key]
        for key, value in retrained["calibration"].items():
            if key == channel or key.startswith(f"{channel}:"):
                calibration[key] = value
        calibration.setdefault("channel_models", {})[channel] = {
            "trained_on": retrained.get("trained_on", []),
            "weight_count": len(retrained["weights"]),
            "weights_sha256": hashlib.sha256(
                json.dumps(retrained["weights"], sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "others_unchanged": {
                name: digest for name, digest in before.items() if name != channel
            },
        }
        return out

    @classmethod
    def main(cls) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument("retrained", type=Path)
        parser.add_argument("--channel", required=True)
        parser.add_argument("--shipped", type=Path, default=None)
        parser.add_argument("--out", type=Path, default=Path())
        args = parser.parse_args()
        if args.shipped is None:
            from cordon_scanner.detect.agents.mcp_servers.description_model import MODEL_PATH

            args.shipped = MODEL_PATH
        with gzip.open(args.shipped, "rt", encoding="utf-8") as handle:
            shipped = json.load(handle)
        with gzip.open(args.retrained, "rt", encoding="utf-8") as handle:
            retrained = json.load(handle)
        out = cls.merged(shipped, retrained, args.channel)
        for name in shipped["thresholds"]:
            if name != args.channel and cls.digest(out, name) != cls.digest(shipped, name):
                sys.exit(f"refused: the {name!r} channel changed")
        args.out.mkdir(parents=True, exist_ok=True)
        with gzip.open(args.out / "mcp-descriptions.json.gz", "wt", encoding="utf-8") as handle:
            json.dump(out, handle, separators=(",", ":"), sort_keys=True)
        print(
            json.dumps(
                {name: cls.digest(out, name) for name in out["thresholds"]},
                indent=2,
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    McpChannelModel.main()
