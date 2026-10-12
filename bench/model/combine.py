#!/usr/bin/env python3
"""What the product would block: Cordon's rules, the package model, the file model, together.

Thresholds are chosen on the training split alone: over the out-of-fold scores of both models, the
pair that flags at most --fpr of the training split's legitimate packages (either model flagging
counts) and detects the most of its malicious ones. Those thresholds are then applied, unchanged, to
the held-out split, and every rate below is the held-out one.

The rules' verdicts come from the baseline (`bench/run.py`, the same image and offline): `content`
is what the rules block from the code itself, leaving out the known-malicious-release lookup, so it
is the fair partner of a model that has never seen a sample's name. `full` adds the lookup, which is
what a user gets on a release already reported. The random legitimate packages' rule verdicts come
from `rules_random.py`.

    docker run --rm --network none -v cordon-model-work:/work -v "$PWD/bench:/bench:ro" \\
      cordon-model:dev python /bench/model/combine.py --split time
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np


class Combine:
    @staticmethod
    def rules(work: Path, baseline: Path) -> dict[str, tuple[bool | None, bool | None]]:
        """Manifest id -> (blocked by content rules, blocked by full rules); None when unknown."""
        rows = [
            json.loads(x)
            for x in (work / "manifest.jsonl").read_text(encoding="utf-8").splitlines()
            if x
        ]
        results = json.loads((baseline / "results.json").read_text(encoding="utf-8"))
        by_sample: dict[str, tuple[bool | None, bool | None]] = {}
        for part in ("malware", "benign"):
            for v in results[part]["verdicts"]:
                if v["tool"] != "cordon":
                    continue
                full = v["blocked"]
                content = (
                    None if full is None else bool(full) and v.get("detail") != "identity-only"
                )
                by_sample[v["sample"]] = (content, full)
        random_path = work / "rules_random.json"
        randoms = (
            json.loads(random_path.read_text(encoding="utf-8")) if random_path.exists() else {}
        )
        out: dict[str, tuple[bool | None, bool | None]] = {}
        for r in rows:
            if r["source"] in ("datadog", "malregistry"):
                found = by_sample.get(r["path"])
            elif r["source"] == "top":
                found = by_sample.get(f"{r['ecosystem']}/{r['name']}")
            else:
                v = randoms.get(r["path"])
                found = None if v is None else (v["blocked"], v["blocked"])
            out[r["id"]] = found if found is not None else (None, None)
        return out

    @staticmethod
    def thresholds(train: list[tuple[int, float, float]], fpr: float) -> tuple[float, float]:
        """(package, file) thresholds: at most `fpr` of training legitimates flagged by either,
        the most training malicious caught."""
        legit = np.array([(p, f) for label, p, f in train if label == 0])
        bad = np.array([(p, f) for label, p, f in train if label == 1])
        budget = int(np.floor(fpr * len(legit)))
        best = (float("inf"), float("inf"))
        best_caught = -1
        for share in np.linspace(0.0, 1.0, 21):
            # Spend `share` of the budget on the package model, the rest on the file model.
            p_cut = (
                np.sort(legit[:, 0])[::-1][min(len(legit) - 1, int(budget * share))]
                if budget
                else legit[:, 0].max()
            )
            remaining = legit[legit[:, 0] <= p_cut]
            left = budget - int((legit[:, 0] > p_cut).sum())
            f_cut = (
                np.sort(remaining[:, 1])[::-1][min(len(remaining) - 1, max(left, 0))]
                if len(remaining)
                else 1.0
            )
            flagged = int(((legit[:, 0] > p_cut) | (legit[:, 1] > f_cut)).sum())
            if flagged > budget:
                continue
            caught = int(((bad[:, 0] > p_cut) | (bad[:, 1] > f_cut)).sum())
            if caught > best_caught:
                best_caught, best = caught, (float(p_cut), float(f_cut))
        return best

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--work", type=Path, default=Path("/work"))
        parser.add_argument(
            "--baseline", type=Path, default=Path("/bench/results/baseline-2026-10-11")
        )
        parser.add_argument("--split", choices=("hash", "time", "campaign"), default="time")
        parser.add_argument("--fpr", type=float, default=0.005)
        args = parser.parse_args()
        rows = {
            json.loads(x)["id"]: json.loads(x)
            for x in (args.work / "manifest.jsonl").read_text(encoding="utf-8").splitlines()
            if x
        }
        package = args.work / f"model-{args.split}"
        files = json.loads(
            (args.work / f"files-{args.split}" / "scores.json").read_text(encoding="utf-8")
        )
        p_train = json.loads((package / "train_oof.json").read_text(encoding="utf-8"))
        p_held = {
            e["id"]: e["score"]
            for e in json.loads((package / "held_scores.json").read_text(encoding="utf-8"))
        }
        train = [
            (int(rows[i]["label"]), s, files["train_oof"].get(i, 0.0)) for i, s in p_train.items()
        ]
        p_cut, f_cut = Combine.thresholds(train, args.fpr)
        rules = Combine.rules(args.work, args.baseline)
        table: dict[str, dict[str, list[bool]]] = defaultdict(lambda: defaultdict(list))
        for i, p in p_held.items():
            r = rows[i]
            group = (
                f"legitimate {r['source']} {r['ecosystem']}"
                if r["label"] == 0
                else f"malicious {r['source']} {r['ecosystem']} {r['kind']}"
            )
            model = p > p_cut or files["held"].get(i, 0.0) > f_cut
            content, full = rules[i]
            columns = {"model": model}
            if content is not None:
                columns["rules content"] = content
                columns["rules content + model"] = content or model
            if full is not None:
                columns["rules full"] = bool(full)
                columns["rules full + model"] = bool(full) or model
            for name, value in columns.items():
                table[group][name].append(value)
                table["ALL " + ("legitimate" if r["label"] == 0 else "malicious")][name].append(
                    value
                )
        print(
            f"split={args.split} thresholds package>{p_cut:.4f} file>{f_cut:.4f} (training FPR budget {args.fpr:.2%})"
        )
        names = [
            "model",
            "rules content",
            "rules content + model",
            "rules full",
            "rules full + model",
        ]
        print(f"  {'group':48s} {'n':>6s} " + " ".join(f"{n:>22s}" for n in names))
        for group in sorted(table):
            cells = []
            for n in names:
                hits = table[group].get(n, [])
                cells.append(
                    f"{100 * sum(hits) / len(hits):6.2f}% of {len(hits):6d}"
                    if hits
                    else f"{'-':>22s}"
                )
            print(
                f"  {group:48s} {len(table[group]['model']):6d} "
                + " ".join(f"{c:>22s}" for c in cells)
            )
        return 0


if __name__ == "__main__":
    sys.exit(Combine.main())
