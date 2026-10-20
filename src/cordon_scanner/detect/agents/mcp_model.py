"""A learned reading of MCP tool descriptions: steering the agent, as against describing the tool.

Hand-written phrase rules caught 6 to 10% of the poisoned tools in MCPTox and MCP-SafetyBench
(review 98): poisoning reads like professional prose -- "Before using `read_file`, a mandatory
pre-authorization check requires calling `write_file` ..." -- and every rule narrow enough to stay
quiet on 85,003 real descriptions missed most of it. This is a linear model over hashed word
n-grams, trained on those attack sets against those real descriptions (`bench/mcp_model_train.py`),
shipped as data and scored here: offline, deterministic, no dependency.

```
  description -> lower-cased words -> 1..3-grams -> crc32 mod 2^18 -> counts, L2-normalised
              -> w . x + b -> logistic -> probability
  per server: the highest-scoring text decides; each channel (a description, a returned string)
  has its own `block` and `warn`, set on real servers held out of training (`calibration`)
```

`features` is the one definition of a feature: the trainer imports it, so what was trained is
exactly what is scored.
"""

from __future__ import annotations

import functools
import gzip
import json
import math
import re
import zlib
from pathlib import Path
from typing import Any, ClassVar, Final

from cordon_scanner.foundation.paths import PackagePaths

MODEL_PATH: Final = PackagePaths.data("detect") / "mcp-descriptions.json.gz"
SKILL_MODEL_PATH: Final = PackagePaths.data("detect") / "skill-instructions.json.gz"
BUCKETS: Final = 1 << 18
FEATURES: Final = BUCKETS + 64
"""Word buckets, then reserved slots for `agent_semantics` (it uses fewer than 64)."""
MAX_TEXT: Final = 8_000
"""A description longer than this is scored on its first part: none in either corpus is."""
MAX_SKILL_TEXT: Final = 40_000
"""A skill's instructions are longer. Text past either limit is scored in windows of the limit's
size (`LinearTextModel.score`), so an instruction placed past it is still read."""
MAX_WINDOWS: Final = 24
"""Windows scored per text. At the skill limit and half-window steps that is about half a megabyte
of instructions; past it the text is not scored, and `windows_unread` says so."""

WORD: Final = re.compile(r"\w[\w'-]{0,60}")


class LinearTextModel:
    """Hashed word n-grams and a logistic model shipped as data. One definition of a feature, for
    the scanner and for `bench/mcp_model_train.py`, so what was trained is what is scored."""

    NGRAMS: ClassVar[tuple[int, ...]] = (1, 2, 3)

    def __init__(self, path: Path, limit: int, *, semantic: bool = False) -> None:
        self.path = path
        self.limit = limit
        # Tool text also carries what it asks the agent to do (`agent_semantics`), in fixed slots
        # after the word buckets. Skill instructions are orders to the agent by design, so the
        # skill model does not read them this way.
        self.semantic = semantic

    def features(self, text: str, channel: str) -> dict[int, float]:
        """Hashed, L2-normalised counts of the text's word 1- to 3-grams, and its channel."""
        words = WORD.findall(text[: self.limit].lower())
        counts: dict[int, float] = {zlib.crc32(f"\x00channel:{channel}".encode()) % BUCKETS: 1.0}
        for n in self.NGRAMS:
            for i in range(len(words) - n + 1):
                gram = " ".join(words[i : i + n])
                index = zlib.crc32(gram.encode("utf-8")) % BUCKETS
                counts[index] = counts.get(index, 0.0) + 1.0
        norm = math.sqrt(sum(v * v for v in counts.values())) or 1.0
        features = {k: v / norm for k, v in counts.items()}
        if self.semantic:
            from cordon_scanner.detect.agents.agent_semantics import SCALE, AgentSemantics

            for slot, value in enumerate(AgentSemantics.vector(text[: self.limit])):
                if value:
                    features[BUCKETS + slot] = value * SCALE
        return features

    @functools.cached_property
    def model(self) -> dict[str, Any] | None:
        """The shipped weights, or None when they are absent (a source checkout without data)."""
        try:
            with gzip.open(self.path, "rt", encoding="utf-8") as handle:
                data = json.load(handle)
        except OSError:
            return None
        data["weights"] = {int(k): float(v) for k, v in data["weights"].items()}
        return data

    def windows(self, text: str) -> list[str]:
        """The text as the model reads it: whole when it fits the limit it was trained on, else
        overlapping windows of that size, half a window apart, so a passage that straddles one
        boundary sits whole inside the next window. A long skill was scored on its first 40,000
        characters only -- an instruction after them was never read (review 98, `13` STEP 2b)."""
        if len(text) <= self.limit:
            return [text]
        step = max(1, self.limit // 2)
        starts = range(0, len(text) - self.limit + step, step)
        return [text[start : start + self.limit] for start in list(starts)[:MAX_WINDOWS]]

    def windows_unread(self, text: str) -> int:
        """Characters past the last window scored (0 when the whole text was read)."""
        if len(text) <= self.limit:
            return 0
        step = max(1, self.limit // 2)
        return max(0, len(text) - ((MAX_WINDOWS - 1) * step + self.limit))

    def score(self, text: str, channel: str) -> float | None:
        """The probability that this text steers the agent, or None without a model: the highest
        over the text's windows (`windows`). The text a whole score would average away -- one
        order inside a long manual -- is what a window keeps."""
        model = self.model
        if model is None or not text.strip():
            return None
        weights = model["weights"]
        best = -60.0
        for window in self.windows(text):
            z = model["bias"] + sum(
                weights.get(index, 0.0) * value
                for index, value in self.features(window, channel).items()
            )
            best = max(best, z)
        return 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, best))))

    def thresholds(self, channel: str) -> tuple[float, float] | None:
        """(block, warn) for the channel, set on held-out real servers or skills."""
        model = self.model
        if model is None or channel not in model.get("thresholds", {}):
            return None
        block, warn = model["thresholds"][channel]
        return float(block), float(warn)


MCP_MODEL: Final = LinearTextModel(MODEL_PATH, MAX_TEXT, semantic=True)
SKILL_MODEL: Final = LinearTextModel(SKILL_MODEL_PATH, MAX_SKILL_TEXT)


class McpDescriptionModel:
    CHANNELS: ClassVar[tuple[str, ...]] = ("description", "return")
    """Where the text reaches the agent: a tool's description, or what the tool returns."""

    @staticmethod
    def features(text: str, channel: str = "description") -> dict[int, float]:
        return MCP_MODEL.features(text, channel)

    @staticmethod
    def model() -> dict[str, Any] | None:
        return MCP_MODEL.model

    @staticmethod
    def score(text: str, channel: str = "description") -> float | None:
        return MCP_MODEL.score(text, channel)

    @staticmethod
    def thresholds(channel: str = "description") -> tuple[float, float] | None:
        return MCP_MODEL.thresholds(channel)
