#!/usr/bin/env python3
"""Which text representation judges agent skills best: word n-grams, static embeddings, or both.

The same measurement as `train_text.py`, for each representation: malicious skills split by
campaign into two folds, each fold scored by a model trained without it (multiple-instance learning
over passages), the threshold set on 5,000 calibrate-half real skills at the false-alarm budget, and
the false-alarm rate measured on 10,000 evaluate-half real skills. Embeddings come from a Model2Vec
static model (`--embedder`, a local directory pinned by revision and digest in PINNED.json), run on
CPU; nothing is downloaded here.

    docker run --rm --network none -v cordon-model-work:/work -v cordon-model-weights:/weights:ro \\
      -v "$PWD/bench:/bench:ro" -v "$PWD/model-server:/ms:ro" cordon-model-sem:dev \\
      python /bench/model/compare_text.py --embedder /weights/potion-base-32M
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
from scipy import sparse
from sklearn.linear_model import LogisticRegression

sys.path.insert(0, "/ms")
sys.path.insert(0, str(Path(__file__).parent))
from cordon_model_server.text import TextVectoriser
from train_text import Campaigns


class Representation:
    def __init__(self, kind: str, embedder: Path) -> None:
        self.kind = kind
        self.vectoriser = TextVectoriser()
        self.static = None
        if kind in ("embed", "both"):
            from model2vec import StaticModel

            self.static = StaticModel.from_pretrained(str(embedder))

    def fit(self, texts: list[str]) -> None:
        if self.kind in ("ngram", "both"):
            self.vectoriser.fit_idf(texts)

    def transform(self, texts: list[str]) -> sparse.csr_matrix:
        parts = []
        if self.kind in ("ngram", "both"):
            parts.append(self.vectoriser.transform(texts))
        if self.static is not None:
            normalised = [TextVectoriser.normalise(t) for t in texts]
            vectors = np.asarray(self.static.encode(normalised), dtype=np.float32)
            norms = np.linalg.norm(vectors, axis=1, keepdims=True)
            norms[norms == 0] = 1.0
            parts.append(sparse.csr_matrix(vectors / norms))
        return sparse.hstack(parts).tocsr() if len(parts) > 1 else parts[0].tocsr()


class Experiment:
    @staticmethod
    def fit(
        rep: Representation, base: list[dict], malicious: list[dict], c: float
    ) -> LogisticRegression:
        bags = [TextVectoriser.passages(s["text"]) for s in malicious]
        rep.fit([p["text"] for p in base] + [p for bag in bags for p in bag])
        x_base = rep.transform([p["text"] for p in base])
        y_base = np.array([p["label"] for p in base])
        chosen, model = bags, None
        for _ in range(3):
            positives = [p for bag in chosen for p in bag]
            x = sparse.vstack([x_base, rep.transform(positives)]) if positives else x_base
            y = np.concatenate([y_base, np.ones(len(positives), dtype=int)])
            model = LogisticRegression(
                C=c, class_weight="balanced", max_iter=3000, solver="liblinear"
            )
            model.fit(x, y)
            chosen = []
            for bag in bags:
                if bag:
                    scores = model.decision_function(rep.transform(bag))
                    chosen.append([bag[i] for i in np.argsort(-scores)[:2]])
        assert model is not None  # noqa: S101 - set by the first round
        return model

    @staticmethod
    def skill_scores(
        rep: Representation, model: LogisticRegression, texts: list[str]
    ) -> np.ndarray:
        out = []
        for text in texts:
            passages = TextVectoriser.passages(text)
            out.append(
                float(np.max(model.decision_function(rep.transform(passages))))
                if passages
                else -1e9
            )
        return np.array(out)

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--work", type=Path, default=Path("/work"))
        parser.add_argument("--embedder", type=Path, default=Path("/weights/potion-base-32M"))
        parser.add_argument("--kinds", default="ngram,embed,both")
        parser.add_argument("--fpr", type=float, default=0.005)
        parser.add_argument("--c", type=float, default=4.0)
        args = parser.parse_args()

        def jsonl(path: Path) -> list[dict]:
            return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x]

        passages = jsonl(args.work / "text" / "passages.jsonl")
        skills = jsonl(args.work / "text" / "skills.jsonl")
        base = [p for p in passages if p["split"] == "train" and p["source"] != "real-skill"]
        real = [p for p in passages if p["split"] == "train" and p["source"] == "real-skill"]
        rng = np.random.default_rng(20261011)
        base += [real[i] for i in rng.choice(len(real), size=min(80_000, len(real)), replace=False)]
        calibrate = [s for s in skills if s["half"] == "calibrate"]
        evaluate = [s for s in skills if s["half"] == "evaluate"]
        malicious = [s for s in skills if s["label"] == 1 and s["text"].strip()]
        fold = Campaigns.folds(malicious)
        adjudication = args.work / "adjudication.json"
        demonstrable = (
            {
                r["name"]
                for r in json.loads(adjudication.read_text(encoding="utf-8"))
                if r["demonstrable"]
            }
            if adjudication.exists()
            else set()
        )
        dem = [i for i, s in enumerate(malicious) if s["name"] in demonstrable]
        results = {}
        for kind in args.kinds.split(","):
            caught = np.zeros(len(malicious), dtype=bool)
            false_alarms = []
            for f in (0, 1):
                rep = Representation(kind, args.embedder)
                trained = [s for s, k in zip(malicious, fold, strict=True) if k != f]
                model = Experiment.fit(rep, base, trained, args.c)
                legit = np.sort(Experiment.skill_scores(rep, model, [s["text"] for s in calibrate]))
                threshold = float(
                    legit[min(len(legit) - 1, int(np.ceil(len(legit) * (1 - args.fpr))) - 1)]
                )
                held = [i for i, k in enumerate(fold) if k == f]
                hits = (
                    Experiment.skill_scores(rep, model, [malicious[i]["text"] for i in held])
                    > threshold
                )
                for i, hit in zip(held, hits, strict=True):
                    caught[i] = hit
                false_alarms.append(
                    float(
                        np.mean(
                            Experiment.skill_scores(rep, model, [s["text"] for s in evaluate])
                            > threshold
                        )
                    )
                )
            results[kind] = {
                "malicious": f"{int(caught.sum())}/{len(malicious)} ({caught.mean():.2%})",
                "demonstrable": f"{int(caught[dem].sum())}/{len(dem)} ({(caught[dem].mean() if dem else 0):.2%})",
                "real_flagged_per_fold": [f"{x:.2%}" for x in false_alarms],
            }
            print(kind, json.dumps(results[kind]), flush=True)
        (args.work / "compare_text.json").write_text(
            json.dumps(results, indent=1), encoding="utf-8"
        )
        return 0


if __name__ == "__main__":
    sys.exit(Experiment.main())
