#!/usr/bin/env python3
"""The one training entry point's contract (CDI self-improving, 01-TECHNICAL).

`train.py --area A --train LIST --seed S` is the single way every model is built -- the per-ecosystem
verdict model, the code model, the skill text model. Whichever trainer runs, these helpers write the
two artefacts the gate and the audit record need beside the model:

  training_list.sha256   the normalised-content sha of the exact training set, so the gate's lineage
                         check (train ∩ eval/held == 0) is reproducible and a model cannot silently
                         be trained on held data;
  metrics.json          a normalised summary (recall, benign rate, n, threshold, per group), so one
                         reader distils every area's result the same way.

Pure and deterministic: the same inputs give the same files. No trainer logic here -- this is the
contract the trainers fill.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any


class EntryPoint:
    """Why `train.py` is the only way in: every script that writes a model is listed here, and refuses to run unless `train.py`
    started it. A script that fits a model and is neither listed nor an evaluation-only script is a failing test."""

    ENV = "CORDON_TRAIN_ENTRY"
    #: area name -> the trainer `train.py --area <name>` runs.
    TRAINERS = {
        "verdict": "verdict_train.py",
        "skill-text": "train_text.py",
        "files": "train_files.py",
        "area-fit": "area_fit.py",
        "mcp": "mcp_model_train.py",
        "mcp-channel": "mcp_channel_model.py",
        "mcp-lines": "mcp_recalibrate.py",
    }
    #: Scripts that fit models only to measure them (cross-validation): they write no model anyone ships.
    EVALUATION_ONLY = frozenset({"mcp_crossval.py", "skill_crossval.py"})

    @classmethod
    def environment(cls) -> dict[str, str]:
        """The environment `train.py` gives the trainer it starts."""
        return {**os.environ, cls.ENV: "1"}

    @classmethod
    def require(cls, script: str) -> None:
        """Refuses to run a trainer on its own."""
        if os.environ.get(cls.ENV) != "1":
            raise SystemExit(
                f"{Path(script).name} is not an entry point: train through bench/model/train.py --area ... --train LIST --seed N"
            )


class Contract:
    """The one-entry-point contract. Stateless; call the static methods."""

    @staticmethod
    def training_list_sha(train_ids: Iterable[str]) -> str:
        """sha256 over the sorted, de-duplicated training ids. The id is the normalised-content key
        the dataset assigns (a package/version or a featureset digest), NOT a file path, so the same
        content hashes the same wherever it was trained."""
        joined = "\n".join(sorted({str(i) for i in train_ids}))
        return "sha256:" + hashlib.sha256(joined.encode("utf-8")).hexdigest()

    @staticmethod
    def file_sha(path: Path) -> str:
        """sha256 of a file's bytes -- the family-map sha recorded beside the training list."""
        return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()

    @staticmethod
    def write_contract(
        out: Path,
        *,
        area: str,
        seed: int,
        train_ids: Iterable[str],
        metrics: dict[str, Any],
    ) -> dict[str, Any]:
        """Write training_list.sha256 and metrics.json into ``out``; return the metrics body."""
        out.mkdir(parents=True, exist_ok=True)
        ids = sorted({str(i) for i in train_ids})
        sha = Contract.training_list_sha(ids)
        (out / "training_list.sha256").write_text(sha + "\n", encoding="utf-8")
        body = {
            "area": area,
            "seed": seed,
            "n_train": len(ids),
            "training_list_sha": sha,
            **metrics,
        }
        (out / "metrics.json").write_text(
            json.dumps(body, indent=1, sort_keys=True), encoding="utf-8"
        )
        return body
