#!/usr/bin/env python3
"""Train Cordon's judge model over agent text, and measure it on what it never saw.

Negatives: ATR's benign twins and benign corpus, and passages of 20,000 real skills (calibrate
half). Positives: ATR's attacks (train rules), and the malicious skills' own worst passages. A
malicious skill is labelled as a whole, not by passage, so its positives are found by multiple-
instance learning: every passage at first, then each skill's `TOP` highest-scoring passages,
refitted `ROUNDS` times; the rest of a malicious skill is never used as a negative.

Malicious skills come in campaigns of near-copies, so they are split by campaign: skills whose
5-word shingles overlap by Jaccard >= 0.5 share a group, and groups are dealt into two folds. Each
fold is measured by a model trained without it -- every malicious skill is scored out of fold, by a
model that saw no copy of it. The threshold is set each time on 5,000 calibrate-half real skills
at the false-alarm budget, before anything held out is read, and the false-alarm rate is measured
on 10,000 evaluate-half real skills. The shipped model is then trained on every malicious skill,
its threshold set the same way.

    docker run --rm --network none -v cordon-model-work:/work -v "$PWD/bench:/bench:ro" \\
      -v "$PWD/model-server:/ms:ro" cordon-model:next python /bench/model/train_text.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

import numpy as np
from scipy import sparse
from sklearn.linear_model import LogisticRegression

sys.path.insert(0, "/ms")
from cordon_model_server.text import TextModel, TextVectoriser

#: ATR's categories in the judge contract's words (schemas/cordon-judge-v1.schema.json).
CATEGORY: dict[str, str] = {
    "prompt-injection": "instruction-override",
    "context-exfiltration": "exfiltration",
    "tool-poisoning": "tool-poisoning",
    "agent-manipulation": "instruction-override",
    "privilege-escalation": "permission-escalation",
    "skill-compromise": "fetch-and-run",
    "excessive-autonomy": "unapproved-action",
    "model-abuse": "other",
    "data-poisoning": "other",
    "model-security": "other",
}
TOP = 2
ROUNDS = 2
SIMILAR = 0.5


class Campaigns:
    """Near-copies grouped, and groups dealt into two folds."""

    @staticmethod
    def shingles(text: str) -> set[int]:
        words = re.sub(r"\s+", " ", text.lower()).split(" ")
        return {
            int.from_bytes(
                hashlib.blake2b(" ".join(words[i : i + 5]).encode(), digest_size=8).digest()
            )
            for i in range(max(1, len(words) - 4))
        }

    @staticmethod
    def folds(skills: list[dict]) -> list[int]:
        sets = [Campaigns.shingles(s["text"]) for s in skills]
        parent = list(range(len(skills)))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for i in range(len(skills)):
            for j in range(i + 1, len(skills)):
                union = len(sets[i] | sets[j])
                if union and len(sets[i] & sets[j]) / union >= SIMILAR:
                    parent[find(i)] = find(j)
        groups: dict[int, list[int]] = {}
        for i in range(len(skills)):
            groups.setdefault(find(i), []).append(i)
        fold = [0] * len(skills)
        for members in groups.values():
            key = min(skills[i]["name"] for i in members)
            for i in members:
                fold[i] = hashlib.sha256(key.encode()).digest()[0] % 2
        return fold


class TextTraining:
    @staticmethod
    def skill_scores(model: TextModel, texts: list[str]) -> np.ndarray:
        return np.array(
            [float(np.max(model.scores(TextVectoriser.passages(t)), initial=0.0)) for t in texts]
        )

    @staticmethod
    def fit(base: list[dict], malicious: list[dict], c: float) -> TextModel:
        """The binary model by multiple-instance learning over `malicious`, and the category head
        on ATR's attacks."""
        bags = [TextVectoriser.passages(s["text"]) for s in malicious]
        vectoriser = TextVectoriser()
        vectoriser.fit_idf([p["text"] for p in base] + [p for bag in bags for p in bag])
        x_base = vectoriser.transform([p["text"] for p in base])
        y_base = np.array([p["label"] for p in base])
        chosen = bags
        model = None
        for _ in range(ROUNDS + 1):
            positives = [p for bag in chosen for p in bag]
            x = sparse.vstack([x_base, vectoriser.transform(positives)]) if positives else x_base
            y = np.concatenate([y_base, np.ones(len(positives), dtype=int)])
            binary = LogisticRegression(
                C=c, class_weight="balanced", max_iter=3000, solver="liblinear"
            )
            binary.fit(x, y)
            model = TextModel(
                vectoriser,
                binary.coef_[0].astype(np.float32),
                float(binary.intercept_[0]),
                np.zeros((1, x.shape[1]), dtype=np.float32),
                np.zeros(1, dtype=np.float32),
                ("other",),
            )
            chosen = []
            for bag in bags:
                if bag:
                    order = np.argsort(-model.scores(bag))[:TOP]
                    chosen.append([bag[i] for i in order])
        attacks = [p for p in base if p["label"] == 1]
        categories = sorted({CATEGORY[p["category"]] for p in attacks})
        multi = LogisticRegression(C=c, max_iter=3000, solver="saga")
        multi.fit(
            vectoriser.transform([p["text"] for p in attacks]),
            [CATEGORY[p["category"]] for p in attacks],
        )
        order = [list(multi.classes_).index(k) for k in categories]
        assert model is not None  # noqa: S101 - set by the first round
        model.category_weights = multi.coef_[order].astype(np.float32)
        model.category_bias = multi.intercept_[order].astype(np.float32)
        model.categories = tuple(categories)
        return model

    @staticmethod
    def threshold(model: TextModel, calibrate: list[dict], fpr: float) -> float:
        legit = np.sort(TextTraining.skill_scores(model, [s["text"] for s in calibrate]))
        return float(legit[min(len(legit) - 1, int(np.ceil(len(legit) * (1 - fpr))) - 1)])

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--work", type=Path, default=Path("/work"))
        parser.add_argument("--fpr", type=float, default=0.005)
        parser.add_argument("--c", type=float, default=4.0)
        args = parser.parse_args()
        text = args.work / "text"

        def jsonl(path: Path) -> list[dict]:
            return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x]

        passages = jsonl(text / "passages.jsonl")
        skills = jsonl(text / "skills.jsonl")
        base = [p for p in passages if p["split"] == "train" and p["source"] != "real-skill"]
        real = [p for p in passages if p["split"] == "train" and p["source"] == "real-skill"]
        # A fixed random 80,000 real-skill passages: ample negatives for a linear model, and all
        # 430,000 x 1.3 million hashed columns does not fit beside the rest of the benchmark.
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
        lines = [
            f"{len(malicious)} malicious skills, split by campaign into folds of {dict(Counter(fold))}"
        ]
        out_of_fold = np.zeros(len(malicious), dtype=bool)
        report: dict[str, object] = {"fpr_budget": args.fpr, "folds": []}
        for f in (0, 1):
            trained = [s for s, k in zip(malicious, fold, strict=True) if k != f]
            model = TextTraining.fit(base, trained, args.c)
            threshold = TextTraining.threshold(model, calibrate, args.fpr)
            held = [i for i, k in enumerate(fold) if k == f]
            caught = (
                TextTraining.skill_scores(model, [malicious[i]["text"] for i in held]) > threshold
            )
            for i, hit in zip(held, caught, strict=True):
                out_of_fold[i] = hit
            false = TextTraining.skill_scores(model, [s["text"] for s in evaluate]) > threshold
            lines.append(
                f"  fold {f}: trained on {len(trained)} malicious; held {len(held)} caught "
                f"{int(caught.sum())} ({caught.mean():.2%}); real evaluate flagged {int(false.sum())}/"
                f"{len(evaluate)} ({false.mean():.2%}); threshold {threshold:.4f}"
            )
            report["folds"].append(
                {
                    "held": len(held),
                    "caught": int(caught.sum()),
                    "real_flagged": int(false.sum()),
                    "real": len(evaluate),
                    "threshold": threshold,
                }
            )
        names = [s["name"] for s in malicious]
        dem = [i for i, n in enumerate(names) if n in demonstrable]
        lines.append(
            f"  out of fold: all malicious {int(out_of_fold.sum())}/{len(malicious)} "
            f"({out_of_fold.mean():.2%}); demonstrably malicious "
            f"{int(out_of_fold[dem].sum())}/{len(dem)} ({(out_of_fold[dem].mean() if dem else 0):.2%})"
        )
        report["out_of_fold"] = {
            "malicious": len(malicious),
            "caught": int(out_of_fold.sum()),
            "demonstrable": len(dem),
            "demonstrable_caught": int(out_of_fold[dem].sum()) if dem else 0,
            "caught_names": [n for n, hit in zip(names, out_of_fold, strict=True) if hit],
        }
        # The shipped model: every malicious skill.
        model = TextTraining.fit(base, malicious, args.c)
        threshold = TextTraining.threshold(model, calibrate, args.fpr)
        false = TextTraining.skill_scores(model, [s["text"] for s in evaluate]) > threshold
        held_atr = [p for p in passages if p["split"] == "held" and p["source"].startswith("atr")]
        scores = model.scores([p["text"] for p in held_atr])
        labels = np.array([p["label"] for p in held_atr])
        attack_recall = (
            float(np.mean(scores[labels == 1] > threshold)) if (labels == 1).any() else 0.0
        )
        twin_fpr = float(np.mean(scores[labels == 0] > threshold)) if (labels == 0).any() else 0.0
        attacks = [p for p in held_atr if p["label"] == 1][:2000]
        right = sum(model.category(p["text"]) == CATEGORY[p["category"]] for p in attacks)
        lines.append(
            f"shipped model: threshold {threshold:.4f}; real evaluate flagged {int(false.sum())}/"
            f"{len(evaluate)} ({false.mean():.2%}); ATR held rules: attacks {attack_recall:.2%}, "
            f"benign twins {twin_fpr:.2%}; category right {right}/{len(attacks)}"
        )
        report["shipped"] = {
            "threshold": threshold,
            "real_flagged": int(false.sum()),
            "real": len(evaluate),
            "atr_held_attack_recall": attack_recall,
            "atr_held_twin_fpr": twin_fpr,
            "category_right": right,
            "category_n": len(attacks),
        }
        print("\n".join(lines))
        out = args.work / "text-model"
        out.mkdir(exist_ok=True)
        model.save(out)
        (out / "meta.json").write_text(
            json.dumps({"categories": list(model.categories), "threshold": threshold, **report}),
            encoding="utf-8",
        )
        return 0


if __name__ == "__main__":
    sys.exit(TextTraining.main())
