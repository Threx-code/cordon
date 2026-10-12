#!/usr/bin/env python3
"""Train Cordon's code model and measure it on what it never saw.

LightGBM over the dense and hashed-token features (`features.py`). The decision threshold is set
inside the training split only -- out-of-fold scores of its legitimate packages, at a false-alarm
budget -- before the held-out split is looked at, and the held-out rates are reported per group.

    --split hash   held-out packages (and every version of them) the model never trained on
    --split time   held-out: DataDog samples published from the cutoff on -- attacks that did
                   not exist when the training data ended

    docker run --rm --network none -v cordon-model-work:/work -v "$PWD/bench/model:/model" \\
      cordon-model:dev python train.py --split time --fpr 0.005
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
from scipy import sparse
from sklearn.feature_selection import chi2
from sklearn.model_selection import StratifiedGroupKFold

PARAMS = {
    "objective": "binary",
    "learning_rate": 0.05,
    "num_leaves": 63,
    "min_data_in_leaf": 20,
    "feature_fraction": 0.5,
    "bagging_fraction": 0.8,
    "bagging_freq": 1,
    "lambda_l2": 1.0,
    "verbose": -1,
    "num_threads": 8,
    "seed": 20261011,
    # Token columns are 0/1 and the dense ones counts: few bins each, which is most of the memory.
    "max_bin": 63,
    "force_col_wise": True,
}
#: The hashed-token columns kept: those most associated with the label in the training rows alone
#: (chi-squared), which never sees the held-out side. All 262,144 did not fit in memory, and hash
#: collisions put nearly every column in many packages, so frequency alone could not choose.
TOKENS_KEPT = 20_000
ROUNDS = 600


class Training:
    @staticmethod
    def load(work: Path, extra: str = "") -> tuple[list[dict[str, str]], sparse.csr_matrix]:
        rows = [
            json.loads(line)
            for line in (work / "manifest.jsonl").read_text(encoding="utf-8").splitlines()
            if line
        ]
        dense = np.load(work / "features" / "dense.npy")
        tokens = sparse.load_npz(work / "features" / "tokens.npz")
        read = json.loads((work / "features" / "read.json").read_text(encoding="utf-8"))
        if extra:
            # Extra dense columns (`embeddings.py`), placed with the dense block so token
            # selection by chi-squared leaves them alone.
            dense = np.hstack([dense, np.load(work / "features" / f"{extra}.npy")])
        matrix = sparse.hstack([sparse.csr_matrix(dense), tokens]).tocsr()
        keep = [i for i, ok in enumerate(read) if ok]
        return [rows[i] for i in keep], matrix[keep]

    @staticmethod
    def group(row: dict[str, str]) -> str:
        if row["label"] == 0:
            return f"legitimate {row['source']} {row['ecosystem']}"
        return f"malicious {row['source']} {row['ecosystem']} {row['kind']}"

    @staticmethod
    def threshold(
        matrix: sparse.csr_matrix, labels: np.ndarray, groups: np.ndarray, fpr: float
    ) -> tuple[float, np.ndarray]:
        """The score above which at most `fpr` of the training split's legitimate packages fall,
        from 5-fold out-of-fold scores -- never from a model scoring its own training rows -- and
        those scores, which `combine.py` sets joint thresholds with."""
        scores = np.zeros(len(labels))
        for fit, check in StratifiedGroupKFold(5, shuffle=True, random_state=1).split(
            matrix, labels, groups
        ):
            model = lgb.train(
                PARAMS, lgb.Dataset(matrix[fit], labels[fit], free_raw_data=True), ROUNDS
            )
            scores[check] = model.predict(matrix[check])
            del model
        legitimate = np.sort(scores[labels == 0])
        index = int(np.ceil(len(legitimate) * (1 - fpr))) - 1
        return float(legitimate[min(max(index, 0), len(legitimate) - 1)]), scores

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--work", type=Path, default=Path("/work"))
        parser.add_argument("--split", choices=("hash", "time", "campaign"), default="hash")
        parser.add_argument("--fpr", type=float, default=0.005)
        parser.add_argument("--extra", default="", help="extra dense columns: features/<name>.npy")
        args = parser.parse_args()
        rows, matrix = Training.load(args.work, args.extra)
        labels = np.array([int(r["label"]) for r in rows])
        side = np.array([r[f"{args.split}_split"] for r in rows])
        train, held = np.where(side == "train")[0], np.where(side == "held")[0]
        campaigns = np.array([r.get("campaign", i) for i, r in enumerate(rows)])
        dense_n = len(
            json.loads((args.work / "features" / "dense_names.json").read_text(encoding="utf-8"))
        ) + (
            np.load(args.work / "features" / f"{args.extra}.npy", mmap_mode="r").shape[1]
            if args.extra
            else 0
        )
        scores_chi, _ = chi2(matrix[train][:, dense_n:], labels[train])
        best = np.argsort(np.nan_to_num(scores_chi, nan=0.0))[::-1][:TOKENS_KEPT]
        columns = np.concatenate([np.arange(dense_n), dense_n + np.sort(best)])
        matrix = matrix[:, columns].tocsr()
        print(
            f"columns kept: {len(columns)} ({dense_n} dense, {len(columns) - dense_n} tokens by chi-squared on training rows)",
            flush=True,
        )
        threshold, oof = Training.threshold(
            matrix[train], labels[train], campaigns[train], args.fpr
        )
        model = lgb.train(PARAMS, lgb.Dataset(matrix[train], labels[train]), ROUNDS)
        scores = model.predict(matrix[held])
        flagged = scores > threshold
        groups: dict[str, list[bool]] = defaultdict(list)
        for i, f in zip(held, flagged, strict=True):
            groups[Training.group(rows[i])].append(bool(f))
        print(
            f"split={args.split} train={len(train)} held={len(held)} threshold={threshold:.4f} (train FPR budget {args.fpr:.2%})"
        )
        for name in sorted(groups):
            hits = groups[name]
            what = "false alarms" if name.startswith("legitimate") else "detected"
            print(
                f"  {name:55s} {len(hits):6d}  {what} {sum(hits):6d} ({100 * sum(hits) / len(hits):.2f}%)"
            )
        mal = [f for i, f in zip(held, flagged, strict=True) if labels[i] == 1]
        leg = [f for i, f in zip(held, flagged, strict=True) if labels[i] == 0]
        print(
            f"  ALL malicious detected {sum(mal)}/{len(mal)} ({100 * sum(mal) / max(len(mal), 1):.2f}%); legitimate flagged {sum(leg)}/{len(leg)} ({100 * sum(leg) / max(len(leg), 1):.2f}%)"
        )
        out = args.work / (
            f"model-{args.split}-{args.extra}" if args.extra else f"model-{args.split}"
        )
        out.mkdir(exist_ok=True)
        model.save_model(str(out / "model.txt"))
        joblib.dump(
            {
                "threshold": threshold,
                "split": args.split,
                "fpr": args.fpr,
                "columns": columns.tolist(),
            },
            out / "meta.joblib",
        )
        (out / "held_scores.json").write_text(
            json.dumps(
                [
                    {"id": rows[i]["id"], "label": int(labels[i]), "score": float(s)}
                    for i, s in zip(held, scores, strict=True)
                ]
            ),
            encoding="utf-8",
        )
        (out / "train_oof.json").write_text(
            json.dumps({rows[i]["id"]: float(s) for i, s in zip(train, oof, strict=True)}),
            encoding="utf-8",
        )
        return 0


if __name__ == "__main__":
    sys.exit(Training.main())
