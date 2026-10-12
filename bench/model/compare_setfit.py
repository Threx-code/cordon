#!/usr/bin/env python3
"""SetFit for the skills judge: a small sentence model fine-tuned on CPU, measured as the others are.

The measurement is `compare_text.py`'s: malicious skills split by campaign into two folds, each fold
scored by a model trained without it; the threshold set on 5,000 calibrate-half real skills at the
false-alarm budget; false alarms measured on 10,000 evaluate-half real skills. Within a fold, the
n-gram judge picks each training malicious skill's two worst passages (multiple-instance learning,
as `train_text.py` does), and SetFit is fine-tuned on those with ATR's attacks as positives and ATR's
benign twins and real-skill passages as negatives. Reported: SetFit alone, and averaged with the
n-gram judge. The base model is a local directory pinned in PINNED.json; nothing is downloaded.

    docker run --rm --network none -v cordon-model-work:/work -v cordon-model-weights:/weights:ro \\
      -v "$PWD/bench:/bench:ro" -v "$PWD/model-server:/ms:ro" cordon-model-setfit:dev \\
      python /bench/model/compare_setfit.py
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, "/ms")
sys.path.insert(0, str(Path(__file__).parent))
from compare_text import Experiment, Representation
from cordon_model_server.text import TextVectoriser
from train_text import Campaigns

MAX_PASSAGES = 40


class SetFitJudge:
    @staticmethod
    def passages(text: str) -> list[str]:
        return TextVectoriser.passages(text)[:MAX_PASSAGES]

    @staticmethod
    def train(base_model: Path, positives: list[str], negatives: list[str], steps: int):
        from datasets import Dataset
        from setfit import SetFitModel, Trainer, TrainingArguments

        data = Dataset.from_dict(
            {"text": positives + negatives, "label": [1] * len(positives) + [0] * len(negatives)}
        )
        model = SetFitModel.from_pretrained(str(base_model))
        # The attention memory grows with the square of the length, and pair training doubles the
        # batch: at the model's own 512 tokens one step needed more than 18 GB. Passages are cut
        # at 1,200 characters; 128 tokens keeps the start of each, where the instruction is.
        model.model_body.max_seq_length = 128
        args = TrainingArguments(
            batch_size=16, num_epochs=1, max_steps=steps, max_length=128, seed=20261012,
            show_progress_bar=False, report_to="none",
        )  # fmt: skip
        Trainer(model=model, args=args, train_dataset=data).train()
        return model

    @staticmethod
    def skill_scores(model, ngram: tuple | None, texts: list[str]) -> np.ndarray:
        """A skill's worst passage, by SetFit -- or by the mean of SetFit and the n-gram judge."""
        out = []
        for text in texts:
            passages = SetFitJudge.passages(text)
            if not passages:
                out.append(0.0)
                continue
            probability = np.asarray(model.predict_proba(passages))[:, 1]
            if ngram is not None:
                rep, judge = ngram
                logits = judge.decision_function(rep.transform(passages))
                probability = (probability + 1.0 / (1.0 + np.exp(-logits))) / 2.0
            out.append(float(probability.max()))
        return np.array(out)

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--work", type=Path, default=Path("/work"))
        parser.add_argument("--base", type=Path, default=Path("/weights/bge-small-en-v1.5"))
        parser.add_argument("--fpr", type=float, default=0.005)
        parser.add_argument("--steps", type=int, default=1500)
        args = parser.parse_args()

        def jsonl(path: Path) -> list[dict]:
            return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x]

        passages = jsonl(args.work / "text" / "passages.jsonl")
        skills = jsonl(args.work / "text" / "skills.jsonl")
        base = [p for p in passages if p["split"] == "train" and p["source"] != "real-skill"]
        real = [p for p in passages if p["split"] == "train" and p["source"] == "real-skill"]
        rng = np.random.default_rng(20261011)
        base_ngram = base + [
            real[i] for i in rng.choice(len(real), size=min(80_000, len(real)), replace=False)
        ]
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
        sampler = random.Random(20261012)  # noqa: S311 - a reproducible sample, not a secret
        attacks = [p["text"] for p in base if p["label"] == 1]
        twins = [p["text"] for p in base if p["label"] == 0]
        real_texts = [p["text"] for p in real]
        caught = {
            "setfit": np.zeros(len(malicious), dtype=bool),
            "setfit+ngram": np.zeros(len(malicious), dtype=bool),
        }
        alarms: dict[str, list[float]] = {"setfit": [], "setfit+ngram": []}
        for f in (0, 1):
            trained = [s for s, k in zip(malicious, fold, strict=True) if k != f]
            rep = Representation("ngram", Path("/unused"))
            judge = Experiment.fit(rep, base_ngram, trained, 4.0)
            chosen = []
            for skill in trained:
                bag = SetFitJudge.passages(skill["text"])
                if bag:
                    order = np.argsort(-judge.decision_function(rep.transform(bag)))[:2]
                    chosen += [bag[i] for i in order]
            positives = sampler.sample(attacks, min(1500, len(attacks))) + chosen
            negatives = sampler.sample(twins, min(1000, len(twins))) + sampler.sample(
                real_texts, 1500
            )
            model = SetFitJudge.train(args.base, positives, negatives, args.steps)
            held = [i for i, k in enumerate(fold) if k == f]
            for name, ngram in (("setfit", None), ("setfit+ngram", (rep, judge))):
                legit = np.sort(
                    SetFitJudge.skill_scores(model, ngram, [s["text"] for s in calibrate])
                )
                threshold = float(
                    legit[min(len(legit) - 1, int(np.ceil(len(legit) * (1 - args.fpr))) - 1)]
                )
                hits = (
                    SetFitJudge.skill_scores(model, ngram, [malicious[i]["text"] for i in held])
                    > threshold
                )
                for i, hit in zip(held, hits, strict=True):
                    caught[name][i] = hit
                alarms[name].append(
                    float(
                        np.mean(
                            SetFitJudge.skill_scores(model, ngram, [s["text"] for s in evaluate])
                            > threshold
                        )
                    )
                )
                print(
                    f"fold {f} {name}: held caught {int(hits.sum())}/{len(held)}; real flagged {alarms[name][-1]:.2%}",
                    flush=True,
                )
        results = {
            name: {
                "malicious": f"{int(c.sum())}/{len(malicious)} ({c.mean():.2%})",
                "demonstrable": f"{int(c[dem].sum())}/{len(dem)} ({(c[dem].mean() if dem else 0):.2%})",
                "real_flagged_per_fold": [f"{x:.2%}" for x in alarms[name]],
            }
            for name, c in caught.items()
        }
        print(json.dumps(results, indent=1))
        (args.work / "compare_setfit.json").write_text(
            json.dumps(results, indent=1), encoding="utf-8"
        )
        return 0


if __name__ == "__main__":
    sys.exit(SetFitJudge.main())
