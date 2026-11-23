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
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

try:  # the code and fixture areas fit here; dispatching to another area's trainer needs none of these
    import joblib
    import lightgbm as lgb
    import numpy as np
    from scipy import sparse
    from sklearn.feature_selection import chi2
    from sklearn.model_selection import StratifiedGroupKFold
except ImportError:  # pragma: no cover - a plain interpreter that only dispatches
    joblib = lgb = np = sparse = chi2 = StratifiedGroupKFold = None  # type: ignore[assignment]

try:  # run as a module (tests) or as a script from this directory
    from bench.model import area, export
except ImportError:  # pragma: no cover - script invocation
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import area
    import export

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
    "deterministic": True,
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
        area.EntryPoint.refuse_inherited()
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        # The one entry point (CDI self-improving). --area code is this trainer; verdict and
        # skill-text dispatch to their trainers. Every area writes the contract (training-list sha
        # + metrics.json) beside its model via bench.model.area.
        parser.add_argument("--area", choices=("code", "fixture", *area.EntryPoint.TRAINERS), default="code")
        parser.add_argument("--seed", type=int, default=None, help="RNG seed (overrides PARAMS)")
        parser.add_argument(
            "--train", type=Path, default=None, help="explicit training-id list, one per line"
        )
        parser.add_argument("--work", type=Path, default=Path("/work"))
        parser.add_argument("--schema", default="fs1-0000000000000000", help="the feature schema of the exported model")
        parser.add_argument("--fold", default="ff1-0000000000000000", help="the feature fold of the exported model")
        parser.add_argument("--day", default="1970-01-01", help="the day in the exported model's version")
        parser.add_argument("--split", choices=("hash", "time", "campaign"), default="hash")
        parser.add_argument("--fpr", type=float, default=0.005)
        parser.add_argument("--extra", default="", help="extra dense columns: features/<name>.npy")
        args, extra = parser.parse_known_args()
        if args.area == "fixture":
            return Training.fixture(args)
        if args.area != "code":
            return Training.dispatch(args, extra)
        if args.seed is not None:
            PARAMS["seed"] = args.seed
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
        (out / "meta.json").write_text(
            json.dumps(
                {
                    "threshold": threshold,
                    "split": args.split,
                    "fpr": args.fpr,
                    "columns": columns.tolist(),
                },
                sort_keys=True,
            ),
            encoding="utf-8",
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
        area.Contract.write_contract(
            out,
            area="code",
            seed=PARAMS["seed"],
            train_ids=[rows[i]["id"] for i in train],
            metrics={
                "split": args.split,
                "fpr": args.fpr,
                "num_threads": PARAMS["num_threads"],
                "deterministic": PARAMS["deterministic"],
                "threshold": float(threshold),
                "recall": round(sum(mal) / max(len(mal), 1), 6),
                "n_malicious_held": len(mal),
                "benign_rate": round(sum(leg) / max(len(leg), 1), 6),
                "n_legit_held": len(leg),
            },
        )
        return 0

    FIXTURE_PARAMS = {  # noqa: RUF012 -- read-only
        "objective": "binary",
        "learning_rate": 0.1,
        "num_leaves": 7,
        "min_data_in_leaf": 5,
        "verbose": -1,
        "num_threads": 1,
        "deterministic": True,
        "force_row_wise": True,
        "feature_fraction": 1.0,
        "bagging_fraction": 1.0,
    }

    @staticmethod
    def fixture_rows(ids: list[str]) -> tuple[np.ndarray, np.ndarray]:
        """Features and labels made from each id's own digest: a small, repeatable stand-in for an area's rows, so the entry point can
        be run end to end without a corpus. The same ids give the same rows, whatever the order they are listed in."""
        import hashlib

        matrix, labels = [], []
        for unit in sorted(set(ids)):
            digest = hashlib.sha256(unit.encode("utf-8")).digest()
            values = [b / 255.0 for b in digest[:8]]
            matrix.append(values)
            labels.append(int(values[0] + values[1] > 1.0))
        return np.array(matrix, dtype=np.float64), np.array(labels)

    @staticmethod
    def fixture_line(trees: dict[str, Any], matrix: np.ndarray) -> float:
        """The fixture area's block line: the midpoint of the two scores in the middle of the training rows, taken from the exported
        trees' own scores, so the line is the scanner's. A fixture has no benign budget; this puts rows on both sides of the line."""
        scores = sorted(export.ModelExport.score(trees, row.tolist()) for row in matrix)
        middle = len(scores) // 2
        return (scores[middle] + scores[middle + 1]) / 2

    @staticmethod
    def fixture(args: argparse.Namespace) -> int:
        """`--area fixture`: the whole entry point on a fixture area. Same list and seed give a byte-identical model."""
        if args.train is None or not args.train.exists():
            print("--area fixture needs --train LIST", file=sys.stderr)
            return 2
        ids = args.train.read_text(encoding="utf-8").split()
        seed = args.seed if args.seed is not None else 0
        matrix, labels = Training.fixture_rows(ids)
        params = {**Training.FIXTURE_PARAMS, "seed": seed}
        model = lgb.train(params, lgb.Dataset(matrix, labels), 20)
        out = args.work / "model-fixture"
        out.mkdir(parents=True, exist_ok=True)
        predicted = model.predict(matrix) > 0.5
        sha = area.Contract.training_list_sha(ids)
        exported = export.ModelExport.from_lightgbm(
            model,
            [f"f{i}" for i in range(matrix.shape[1])],
            schema=getattr(args, "schema", "fs1-0000000000000000"),
            fold=getattr(args, "fold", "ff1-0000000000000000"),
            version=export.ModelExport.version(getattr(args, "day", "1970-01-01"), sha),
            rows=matrix.tolist(),
            predict=lambda rows: model.predict(np.array(rows)),
            line=lambda trees: Training.fixture_line(trees, matrix),
        )
        file_sha = export.ModelExport.write(exported, out / "model.json.gz")
        area.Contract.write_contract(
            out,
            area="fixture",
            seed=seed,
            train_ids=ids,
            metrics={
                "accuracy": round(float((predicted == labels).mean()), 6),
                "n_malicious": int(labels.sum()),
                "model_file": "model.json.gz",
                "model_sha256": file_sha,
                "version": exported["version"],
                "num_threads": Training.FIXTURE_PARAMS["num_threads"],
                "deterministic": Training.FIXTURE_PARAMS["deterministic"],
            },
        )
        return 0

    @staticmethod
    def dispatch(args: argparse.Namespace, extra: list[str]) -> int:
        """Run a non-code area's trainer, then record the one-entry-point contract. The trainer owns
        the model and its own report; the contract adds the training-list sha (from --train) so every
        area is built the one way and the gate's lineage check is reproducible."""
        script = area.EntryPoint.TRAINERS[args.area]
        here = Path(__file__).resolve().parent
        extra = [a for a in extra if a != "--"]  # drop the argparse options separator
        cmd = [sys.executable, str(here / script), *extra]
        if args.seed is not None:
            cmd += ["--seed", str(args.seed)]
        print(f"area={args.area}: {' '.join(cmd)}", flush=True)
        rc = subprocess.run(cmd, check=False, env=area.EntryPoint.environment()).returncode  # our own trainer, by path
        out = Path(extra[extra.index("--out") + 1]) if "--out" in extra else None
        if rc != 0 or out is None:
            return rc
        # The training list for the contract: an explicit --train list, else the trainer's --dump
        # (the work-half rows are what was trained on). The gate's lineage check reads this sha.
        train_ids: list[str] = []
        if args.train is not None and args.train.exists():
            train_ids = args.train.read_text(encoding="utf-8").split()
        elif "--dump" in extra:
            dump = Path(extra[extra.index("--dump") + 1])
            if dump.exists():
                for line in dump.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    r = json.loads(line)
                    if r.get("half") == "work":
                        train_ids.append(r.get("file", r.get("id", "")))
        metrics: dict = {
            "dispatched_to": script,
            # The CV changed from a positional split to a family-grouped, seeded one (more correct;
            # no family leaks across folds). A retrain of any verdict model goes through the full
            # gate again -- old thresholds are never reused silently.
            "cv_scheme": "family-grouped-seeded (>=5 families; positional fallback otherwise)",
        }
        if "--family-map" in extra:
            fm = Path(extra[extra.index("--family-map") + 1])
            if fm.exists():
                metrics["family_map_sha"] = area.Contract.file_sha(fm)
        area.Contract.write_contract(
            out.parent if out.is_file() else out,
            area=args.area,
            seed=args.seed if args.seed is not None else 0,
            train_ids=train_ids,
            metrics=metrics,
        )
        return rc


if __name__ == "__main__":
    sys.exit(Training.main())
