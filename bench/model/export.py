"""The exporter: what `train.py` fitted, written as the gzip-JSON tree model the scanner and the feed read.

A model that is published is data a scanner walks, never a program a scanner loads. So the only thing that leaves training for the
feed is this: `features`, `baseline`, `trees` (a flat list of nodes for each tree: a leaf has its value, a split has its feature,
threshold, children and which side a missing value takes), and the `schema` and `fold` of the features and a `version`
(`YYYY-MM-DD-<12 hex>`) that names the training list, and the two sections a scan reads when it applies the model: `areas` (the
block line of each area, with a `package` entry that every area without a line of its own falls back to) and `floor` (the rule ids
that are never re-graded). No pickle, no joblib file and no booster text file is ever published; the
exporter checks that the exported trees score exactly as the fitted model does before it writes anything."""

from __future__ import annotations

import gzip
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, ClassVar, Final

VERSION: Final = re.compile(r"\d{4}-\d{2}-\d{2}-[0-9a-f]{12}")
TOLERANCE: Final = 1e-6


class ExportRefused(ValueError):
    """The exported trees do not score as the fitted model does, or the model cannot be described by this format."""


class ModelExport:
    FORMAT: ClassVar[int] = 3

    @staticmethod
    def version(day: str, list_sha: str) -> str:
        """`YYYY-MM-DD-<12 hex of the training list's hash>`: the same list on the same day is the same version."""
        digest = list_sha.removeprefix("sha256:")
        out = f"{day}-{digest[:12]}"
        if not VERSION.fullmatch(out):
            raise ExportRefused(f"{out!r} is not a model version")
        return out

    @classmethod
    def lightgbm_trees(cls, booster: Any) -> list[list[dict[str, Any]]]:
        """A LightGBM booster's trees as flat node lists. Only numerical `<=` splits are described; anything else is refused."""
        trees = []
        for info in booster.dump_model()["tree_info"]:
            nodes: list[dict[str, Any]] = []

            def walk(node: Mapping[str, Any]) -> int:
                index = len(nodes)
                nodes.append({})
                if "leaf_value" in node:
                    nodes[index] = {"leaf": True, "value": float(node["leaf_value"])}
                    return index
                if node.get("decision_type") != "<=":
                    raise ExportRefused("a split that is not a numerical <= split cannot be exported")
                left, right = walk(node["left_child"]), walk(node["right_child"])
                nodes[index] = {
                    "leaf": False,
                    "feature": int(node["split_feature"]),
                    "threshold": float(node["threshold"]),
                    "left": left,
                    "right": right,
                    "missing_left": bool(node.get("default_left", True)),
                }
                return index

            walk(info["tree_structure"])
            trees.append(nodes)
        return trees

    @staticmethod
    def score(model: Mapping[str, Any], values: Sequence[float]) -> float:
        """The probability the scanner's walk gives: the baseline plus each tree's leaf, through the logistic."""
        raw = float(model["baseline"])
        for tree in model["trees"]:
            node = 0
            while not tree[node]["leaf"]:
                n = tree[node]
                x = values[n["feature"]]
                go_left = n["missing_left"] if math.isnan(x) else x <= n["threshold"]
                node = n["left"] if go_left else n["right"]
            raw += tree[node]["value"]
        return 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, raw))))

    @classmethod
    def from_lightgbm(
        cls,
        booster: Any,
        names: list[str],
        *,
        schema: str,
        fold: str,
        version: str,
        rows: Sequence[Sequence[float]],
        predict: Callable[[Sequence[Sequence[float]]], Sequence[float]],
        line: float | Callable[[dict[str, Any]], float],
        floor: Sequence[str] = (),
    ) -> dict[str, Any]:
        """The model as data. Refused when the exported trees do not score `rows` as `predict` (the fitted model) does.

        `line` is the score above which the package area blocks (or a function of the exported trees that gives it, so a line
        taken from the trees' own scores is the scanner's own); `floor` the rule ids a scan never re-grades."""
        if not VERSION.fullmatch(version):
            raise ExportRefused(f"{version!r} is not a model version")
        model = {
            "format": cls.FORMAT,
            "features": list(names),
            "baseline": 0.0,
            "trees": cls.lightgbm_trees(booster),
            "areas": {},
            "floor": [str(rule) for rule in floor],
            "schema": schema,
            "fold": fold,
            "version": version,
        }
        fitted = predict(rows)
        worst = max((abs(cls.score(model, row) - float(want)) for row, want in zip(rows, fitted, strict=True)), default=0.0)
        if worst > TOLERANCE:
            raise ExportRefused(f"the exported trees differ from the fitted model by {worst:.2e}: not written")
        package_line = float(line(model) if callable(line) else line)
        if not 0.0 < package_line < 1.0:
            raise ExportRefused("the package line is a probability between 0 and 1")
        model["areas"] = {"package": package_line}
        return model

    @staticmethod
    def write(model: Mapping[str, Any], path: Path) -> str:
        """The model as gzip JSON, the same bytes for the same model. Returns its file's sha256."""
        import hashlib

        body = gzip.compress(json.dumps(model, sort_keys=True).encode("utf-8"), mtime=0)
        path.write_bytes(body)
        return hashlib.sha256(body).hexdigest()
