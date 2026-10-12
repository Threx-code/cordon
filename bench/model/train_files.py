#!/usr/bin/env python3
"""Train the per-file model (`files.py`) and score each package by its worst file.

Which file of a malicious package is the malicious one is not labelled, so the model learns in two
rounds (multiple-instance learning): first every file of a malicious package counts as malicious;
then only each malicious package's files the first model finds most malicious stay positive, and the
model is trained again. A typosquat's copied library code stops teaching the model that ordinary
library code is malware. Compromised libraries are never trained on -- which file was injected is
exactly what is unknown -- so they are the held-out test of whether a bad file is found among
hundreds of clean ones.

The threshold is set on the training split alone: package scores from 5-fold out-of-fold models, at
the false-alarm budget over its legitimate packages.

    docker run --rm --network none -v cordon-model-work:/work -v "$PWD/bench/model:/model" \\
      cordon-model:dev python train_files.py --split time
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import lightgbm as lgb
import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

PARAMS = {
    "objective": "binary",
    "learning_rate": 0.05,
    "num_leaves": 63,
    "min_data_in_leaf": 40,
    "feature_fraction": 0.8,
    "bagging_fraction": 0.8,
    "bagging_freq": 1,
    "lambda_l2": 1.0,
    "verbose": -1,
    "num_threads": 8,
    "seed": 20261011,
}
ROUNDS = 400
#: Of a malicious package's files, those scoring at least this share of its best stay positive.
KEEP_SHARE = 0.8
KEEP_AT_MOST = 3


class FileTraining:
    @staticmethod
    def load(work: Path) -> tuple[list[dict[str, str]], np.ndarray, np.ndarray]:
        rows = [
            json.loads(x)
            for x in (work / "manifest.jsonl").read_text(encoding="utf-8").splitlines()
            if x
        ]
        return rows, np.load(work / "files" / "rows.npy"), np.load(work / "files" / "owner.npy")

    @staticmethod
    def fit(x: np.ndarray, y: np.ndarray) -> lgb.Booster:
        return lgb.train(PARAMS, lgb.Dataset(x, y, free_raw_data=True), ROUNDS)

    @staticmethod
    def package_scores(
        model: lgb.Booster, x: np.ndarray, owner: np.ndarray, packages: np.ndarray
    ) -> np.ndarray:
        """Each package's worst file; a package with no code file scores 0."""
        best = np.zeros(len(packages))
        if len(x) == 0:
            return best
        position = {p: i for i, p in enumerate(packages)}
        scores = model.predict(x)
        for o, s in zip(owner, scores, strict=True):
            i = position.get(int(o))
            if i is not None and s > best[i]:
                best[i] = s
        return best

    @staticmethod
    def train(
        rows: list[dict[str, str]], x: np.ndarray, owner: np.ndarray, packages: set[int]
    ) -> lgb.Booster:
        """Two rounds over the given training packages' files."""
        legit = {p for p in packages if int(rows[p]["label"]) == 0}
        intent = {
            p
            for p in packages
            if int(rows[p]["label"]) == 1 and rows[p]["kind"] == "malicious_intent"
        }
        use = np.array([o in legit or o in intent for o in owner])
        labels = np.array([1 if o in intent else 0 for o in owner])
        first = FileTraining.fit(x[use], labels[use])
        # Round two: of each malicious package, only its most malicious-looking files stay positive.
        scores = first.predict(x[use])
        by_package: dict[int, list[tuple[float, int]]] = defaultdict(list)
        indices = np.where(use)[0]
        for i, s in zip(indices, scores, strict=True):
            if owner[i] in intent:
                by_package[int(owner[i])].append((float(s), int(i)))
        keep = np.zeros(len(owner), dtype=bool)
        keep[[i for i in indices if owner[i] in legit]] = True
        for files in by_package.values():
            files.sort(reverse=True)
            top = files[0][0]
            for s, i in files[:KEEP_AT_MOST]:
                if s >= KEEP_SHARE * top:
                    keep[i] = True
        return FileTraining.fit(x[keep], labels[keep])

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--work", type=Path, default=Path("/work"))
        parser.add_argument("--split", choices=("hash", "time", "campaign"), default="time")
        parser.add_argument("--fpr", type=float, default=0.005)
        args = parser.parse_args()
        rows, x, owner = FileTraining.load(args.work)
        read = json.loads((args.work / "features" / "read.json").read_text(encoding="utf-8"))
        side = np.array([r[f"{args.split}_split"] for r in rows])
        labels = np.array([int(r["label"]) for r in rows])
        train = np.array([i for i in range(len(rows)) if side[i] == "train" and read[i]])
        held = np.array([i for i in range(len(rows)) if side[i] == "held" and read[i]])
        groups = np.array([r.get("campaign", i) for i, r in enumerate(rows)])
        # Out-of-fold package scores over the training split: what sets the threshold.
        oof = np.zeros(len(train))
        for fit, check in StratifiedGroupKFold(5, shuffle=True, random_state=1).split(
            train, labels[train], groups[train]
        ):
            fit_set = set(train[fit].tolist())
            mask = np.array([o in fit_set for o in owner])
            model = FileTraining.train(rows, x[mask], owner[mask], fit_set)
            check_set = set(train[check].tolist())
            cmask = np.array([o in check_set for o in owner])
            oof[check] = FileTraining.package_scores(model, x[cmask], owner[cmask], train[check])
        legit = np.sort(oof[labels[train] == 0])
        threshold = float(
            legit[min(len(legit) - 1, max(0, int(np.ceil(len(legit) * (1 - args.fpr))) - 1))]
        )
        train_set = set(train.tolist())
        mask = np.array([o in train_set for o in owner])
        model = FileTraining.train(rows, x[mask], owner[mask], train_set)
        held_set = set(held.tolist())
        hmask = np.array([o in held_set for o in owner])
        scores = FileTraining.package_scores(model, x[hmask], owner[hmask], held)
        groups_out: dict[str, list[bool]] = defaultdict(list)
        for i, s in zip(held, scores, strict=True):
            r = rows[i]
            name = (
                f"legitimate {r['source']} {r['ecosystem']}"
                if r["label"] == 0
                else f"malicious {r['source']} {r['ecosystem']} {r['kind']}"
            )
            groups_out[name].append(bool(s > threshold))
        print(
            f"files split={args.split} train={len(train)} held={len(held)} threshold={threshold:.4f}"
        )
        for name in sorted(groups_out):
            hits = groups_out[name]
            print(
                f"  {name:55s} {len(hits):6d}  {'flagged' if name.startswith('legit') else 'detected'} {sum(hits):6d} ({100 * sum(hits) / len(hits):.2f}%)"
            )
        out = args.work / f"files-{args.split}"
        out.mkdir(exist_ok=True)
        model.save_model(str(out / "model.txt"))
        (out / "scores.json").write_text(
            json.dumps(
                {
                    "threshold": threshold,
                    "held": {rows[i]["id"]: float(s) for i, s in zip(held, scores, strict=True)},
                    "train_oof": {rows[i]["id"]: float(s) for i, s in zip(train, oof, strict=True)},
                }
            ),
            encoding="utf-8",
        )
        return 0


if __name__ == "__main__":
    sys.exit(FileTraining.main())
