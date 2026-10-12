#!/usr/bin/env python3
"""Train Cordon's judge model over agent text, and measure it on what it never saw.

Trained on the train split of `text_dataset.py`'s passages: ATR's attacks (by rule) against ATR's
close benign twins, its benign corpus and passages of 20,000 real skills. The skill-level
threshold -- a skill's worst passage -- is set on 5,000 other calibrate-half skills at the
false-alarm budget, before anything held out is read. Then, held out: ATR's held rules' attacks and
twins, 10,000 skills of the evaluate half, and DataDog's malicious skills by half, with the
demonstrably malicious ones (`adjudication.json`) reported apart.

    docker run --rm --network none -v cordon-model-work:/work -v "$PWD/bench:/bench:ro" \\
      -v "$PWD/model-server:/ms:ro" cordon-model:next python /bench/model/train_text.py
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
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


class TextTraining:
    @staticmethod
    def skill_scores(model: TextModel, texts: list[str]) -> np.ndarray:
        return np.array(
            [float(np.max(model.scores(TextVectoriser.passages(t)), initial=0.0)) for t in texts]
        )

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--work", type=Path, default=Path("/work"))
        parser.add_argument("--fpr", type=float, default=0.005)
        parser.add_argument("--c", type=float, default=4.0)
        args = parser.parse_args()
        text = args.work / "text"
        passages = [
            json.loads(x)
            for x in (text / "passages.jsonl").read_text(encoding="utf-8").splitlines()
            if x
        ]
        skills = [
            json.loads(x)
            for x in (text / "skills.jsonl").read_text(encoding="utf-8").splitlines()
            if x
        ]
        train = [p for p in passages if p["split"] == "train" and p["source"] != "real-skill"]
        real = [p for p in passages if p["split"] == "train" and p["source"] == "real-skill"]
        # A fixed random 80,000 of the real-skill passages: ample negatives for a linear model, and
        # 430,000 x 1.3 million hashed columns does not fit beside the rest of the benchmark.
        rng = np.random.default_rng(20261011)
        train += [
            real[i] for i in rng.choice(len(real), size=min(80_000, len(real)), replace=False)
        ]
        held = [p for p in passages if p["split"] == "held" and p["source"].startswith("atr")]
        vectoriser = TextVectoriser()
        vectoriser.fit_idf([p["text"] for p in train])
        x = vectoriser.transform([p["text"] for p in train])
        y = np.array([p["label"] for p in train])
        binary = LogisticRegression(
            C=args.c, class_weight="balanced", max_iter=3000, solver="liblinear"
        )
        binary.fit(x, y)
        attacks = [p for p in train if p["label"] == 1]
        categories = sorted({CATEGORY[p["category"]] for p in attacks})
        names = np.array([CATEGORY[p["category"]] for p in attacks])
        multi = LogisticRegression(C=args.c, max_iter=3000, solver="saga")
        multi.fit(vectoriser.transform([p["text"] for p in attacks]), names)
        order = [list(multi.classes_).index(c) for c in categories]
        model = TextModel(
            vectoriser,
            binary.coef_[0].astype(np.float32),
            float(binary.intercept_[0]),
            multi.coef_[order].astype(np.float32)
            if len(categories) > 2
            else np.vstack([-multi.coef_[0], multi.coef_[0]]),
            multi.intercept_[order].astype(np.float32)
            if len(categories) > 2
            else np.array([-multi.intercept_[0], multi.intercept_[0]]),
            tuple(categories),
        )
        calibrate = [s for s in skills if s["half"] == "calibrate"]
        legit = np.sort(TextTraining.skill_scores(model, [s["text"] for s in calibrate]))
        threshold = float(legit[min(len(legit) - 1, int(np.ceil(len(legit) * (1 - args.fpr))) - 1)])
        # Held-out passages: ATR's held rules.
        held_scores = model.scores([p["text"] for p in held])
        held_labels = np.array([p["label"] for p in held])
        passage_recall = (
            float(np.mean(held_scores[held_labels == 1] > 0.5)) if (held_labels == 1).any() else 0.0
        )
        passage_fpr = (
            float(np.mean(held_scores[held_labels == 0] > 0.5)) if (held_labels == 0).any() else 0.0
        )
        held_attacks = [p for p in held if p["label"] == 1]
        category_hits = sum(
            model.category(p["text"]) == CATEGORY[p["category"]] for p in held_attacks[:2000]
        )
        # Held-out skills.
        adjudication_path = args.work / "adjudication.json"
        demonstrable = (
            {
                r["name"]
                for r in json.loads(adjudication_path.read_text(encoding="utf-8"))
                if r["demonstrable"]
            }
            if adjudication_path.exists()
            else set()
        )
        report: dict[str, object] = {"threshold": threshold, "fpr_budget": args.fpr}
        lines = [
            f"text model: threshold {threshold:.4f} (skill-level, {args.fpr:.2%} of {len(calibrate)} calibrate-half real skills)"
        ]
        lines.append(
            f"  ATR held-out passages: attacks caught {passage_recall:.2%}, benign twins flagged {passage_fpr:.2%} (at 0.5)"
        )
        lines.append(
            f"  ATR held-out category right: {category_hits}/{min(len(held_attacks), 2000)}"
        )
        for group, chosen in (
            ("real skills, evaluate half", [s for s in skills if s["half"] == "evaluate"]),
            (
                "malicious skills, dev half",
                [s for s in skills if s["label"] == 1 and s["half"] == "dev"],
            ),
            (
                "malicious skills, held half",
                [s for s in skills if s["label"] == 1 and s["half"] == "held"],
            ),
            (
                "demonstrably malicious, held half",
                [
                    s
                    for s in skills
                    if s["label"] == 1 and s["half"] == "held" and s["name"] in demonstrable
                ],
            ),
        ):
            if not chosen:
                continue
            flagged = TextTraining.skill_scores(model, [s["text"] for s in chosen]) > threshold
            lines.append(
                f"  {group:40s} {len(chosen):6d}  flagged {int(flagged.sum()):6d} ({100 * float(flagged.mean()):.2f}%)"
            )
            report[group] = {"n": len(chosen), "flagged": int(flagged.sum())}
            if chosen[0]["label"] == 1:
                report[group + " names flagged"] = [
                    s["name"] for s, f in zip(chosen, flagged, strict=True) if f
                ]
        print("\n".join(lines))
        out = args.work / "text-model"
        out.mkdir(exist_ok=True)
        model.save(out)
        (out / "meta.json").write_text(
            json.dumps({"categories": categories, **report}), encoding="utf-8"
        )
        print("categories in training:", dict(Counter(names.tolist())))
        return 0


if __name__ == "__main__":
    sys.exit(TextTraining.main())
