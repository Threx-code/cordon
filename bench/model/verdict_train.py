#!/usr/bin/env python3
"""Train the package verdict (`core/verdict.py`) from what scans reported, and measure it held out.

```
  benign rows (long-tail rescan)  ┐                       work half ──► monotone trees
  malware rows (as published)     ├─► result.verdict ───►            ──► block / warn thresholds
  adjudication (not malicious,    ┘   features              holdout ──► the figures this prints
  no payload: excluded)
```

Every row's features are the ones the scanner itself reported (`result.verdict`), so what is
trained is what is scored. Halves are fixed by a hash: a benign unit by its name, a malware sample
by its package (every version of one package on one side). Thresholds are chosen on the work half
only -- `block` the lowest score at which no ecosystem blocks more than `--block-share` of its units,
`warn` the lowest at which every ecosystem stays at or above `--quiet` with no warning -- and the
holdout half is scored once with them.

    docker run --rm --network none -v OUT:/o -v DATA:/r:ro -v "$PWD:/s:ro" -e PYTHONPATH=/s/src \\
      cordon-model:next python /s/bench/model/verdict_train.py --benign /o/benign.jsonl \\
      --malware /o/malware-scans.jsonl --corpus /r/d0d8ea9/scans.jsonl --noisy /o/noisy.txt \\
      --adjudication /r/adjudication-malware.jsonl /r/adjudication-malware-supplement.jsonl \\
      --out /o/verdict.json.gz
"""

from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
import math
from pathlib import Path

from cordon_scanner.core.models import Severity
from cordon_scanner.core.verdict import VerdictFeatures, VerdictModel


class VerdictTrain:
    @staticmethod
    def half(key: str) -> str:
        return "holdout" if hashlib.sha256(key.encode()).digest()[0] % 2 else "work"

    @staticmethod
    def group(name: str) -> str:
        parts = name.split("/")
        return "/".join(parts[:4]) if parts[0] == "datadog" else "/".join(parts[:2])

    @staticmethod
    def rows(path: Path):
        seen: set[str] = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            # Two scanners over one sample from either end may both reach a unit.
            if row.get("file") in seen:
                continue
            seen.add(row.get("file"))
            yield row
        return
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                yield json.loads(line)
            except ValueError:
                continue

    @staticmethod
    def export(clf, vocab: list[str], block: float, warn: float, trained_on: dict) -> dict:
        """sklearn's HistGradientBoosting trees as `VerdictModel.score` walks them."""
        trees = []
        for predictors in clf._predictors:
            nodes = predictors[0].nodes
            tree = []
            for n in nodes:
                tree.append(
                    {"leaf": True, "value": float(n["value"])}
                    if n["is_leaf"]
                    else {
                        "leaf": False,
                        "feature": int(n["feature_idx"]),
                        "threshold": float(n["num_threshold"]),
                        "left": int(n["left"]),
                        "right": int(n["right"]),
                        "missing_left": bool(n["missing_go_to_left"]),
                    }
                )
            trees.append(tree)
        return {
            "version": trained_on.get("version", ""),
            "vocab": vocab,
            "package": list(VerdictFeatures.PACKAGE),
            "baseline": float(clf._baseline_prediction.ravel()[0]),
            "trees": trees,
            "thresholds": {"block": block, "warn": warn},
            "trained_on": trained_on,
        }

    @staticmethod
    def recall_by_area(rows, labels, blocked) -> dict[str, str]:
        """Malicious blocked per area: each labelled set by its name, the malware set by source."""
        caught: collections.Counter = collections.Counter()
        seen: collections.Counter = collections.Counter()
        for r, y, b in zip(rows, labels, blocked, strict=True):
            if not y:
                continue
            parts = r["file"].split("/")
            area = (
                parts[0]
                if parts[0] in ("msb", "asb", "mcpv")
                else ("/".join(parts[:3]) if parts[0] == "datadog" else parts[0])
            )
            seen[area] += 1
            caught[area] += bool(b)
        return {
            k: f"{caught[k]}/{seen[k]} = {100 * caught[k] / seen[k]:.1f}%" for k in sorted(seen)
        }

    @classmethod
    def main(cls) -> None:
        import numpy as np
        from sklearn.ensemble import HistGradientBoostingClassifier

        p = argparse.ArgumentParser()
        p.add_argument("--benign", type=Path, required=True)
        p.add_argument("--malware", type=Path, required=True)
        p.add_argument(
            "--corpus", type=Path, required=True, help="full-corpus scans: ecosystem sizes"
        )
        p.add_argument("--noisy", type=Path, required=True)
        p.add_argument("--adjudication", type=Path, nargs="*", default=[])
        p.add_argument(
            "--labelled",
            nargs="*",
            default=[],
            help="NAME=PATH rescans of labelled sets (skills, MCP servers): a row is malicious when "
            "its path starts with malware/ or malicious-mcp-variants/; NAME is its ecosystem",
        )
        p.add_argument(
            "--sample",
            type=Path,
            help="the benign sample list; when the rescan is partial, each ecosystem's benign "
            "blocks and warnings are scaled by sampled / scanned",
        )
        p.add_argument("--out", type=Path)
        p.add_argument(
            "--per-ecosystem", action="store_true", help="a threshold per package ecosystem"
        )
        p.add_argument(
            "--dump", type=Path, help="per-row half, label, area and score as JSON lines"
        )
        p.add_argument("--block-share", type=float, default=0.4)
        p.add_argument("--quiet", type=float, default=98.3)
        a = p.parse_args()

        excluded = set()
        for path in a.adjudication:
            for r in cls.rows(path):
                if r.get("verdict") in (
                    "not-malicious",
                    "no-payload",
                    "vulnerable-fixture",
                    "empty-template",
                ):
                    excluded.add(r["file"])
        noisy = set(a.noisy.read_text(encoding="utf-8").split())
        total = {"work": collections.Counter(), "holdout": collections.Counter()}
        for r in cls.rows(a.corpus):
            total[cls.half(r["file"])][r["file"].split("/")[0]] += 1

        if a.sample is not None:
            # Every sampled unit is benign data: the noisy units, and those added because a newer
            # rule might fire on them. Units outside the sample were quiet and stay counted so.
            noisy |= set(a.sample.read_text(encoding="utf-8").split())
        data = []
        scanned: collections.Counter = collections.Counter()
        for r in cls.rows(a.benign):
            if r["file"] in noisy and r.get("verdict"):
                data.append((r, 0, cls.half(r["file"])))
                scanned[r["file"].split("/")[0]] += 1
        scale: dict[str, float] = {}
        if a.sample is not None:
            sampled = collections.Counter(
                line.split("/")[0]
                for line in a.sample.read_text(encoding="utf-8").split()
                if line in noisy
            )
            scale = {e: sampled[e] / scanned[e] for e in scanned if scanned[e]}
        for r in cls.rows(a.malware):
            if r["file"] not in excluded and r.get("verdict"):
                data.append((r, 1, cls.half(cls.group(r["file"]))))
        for spec in a.labelled:
            name, _, path = spec.partition("=")
            for r in cls.rows(Path(path)):
                if not r.get("verdict"):
                    continue
                unit = r["file"]
                malicious = unit.startswith(("malware/", "malicious-mcp-variants/"))
                # The design split for mcp-variants (`mcpv:` + server), by name elsewhere.
                key = (
                    "mcpv:" + unit.rstrip("/").rsplit("/", 1)[-1]
                    if name == "mcpv"
                    else name + ":" + unit
                )
                h = "holdout" if hashlib.sha256(key.encode()).digest()[0] % 2 else "work"
                r = {**r, "file": f"{name}/{unit}"}
                data.append((r, int(malicious), h))
                if not malicious:
                    total[h][name] += 1
        vocab = sorted({k for r, _, _ in data for k in r["verdict"]["rules"]})
        model_stub = {"vocab": vocab}

        def vec(r):
            v = r["verdict"]
            return VerdictModel.vector(model_stub, v["rules"], v["package"])

        X = {h: [] for h in ("work", "holdout")}
        Y = {h: [] for h in X}
        M = {h: [] for h in X}
        for r, y, h in data:
            X[h].append(vec(r))
            Y[h].append(y)
            M[h].append(r)
        mono = [1] * len(vocab) + [0] * len(VerdictFeatures.PACKAGE) + [1, 1, 0]
        clf = HistGradientBoostingClassifier(
            max_iter=300, learning_rate=0.08, max_leaf_nodes=31, monotonic_cst=mono, random_state=7
        )
        clf.fit(np.array(X["work"]), np.array(Y["work"]))
        prob = {h: clf.predict_proba(np.array(X[h]))[:, 1] for h in X}

        def strong(f) -> bool:
            return (
                f[0].startswith("MALWARE.")
                and ".KNOWN" not in f[0]
                and f[2] in ("high", "confirmed")
                and Severity[f[1].upper()] >= Severity.HIGH
            )

        # The floor: MALWARE.* rules that never fired on a benign unit of the WORK half and caught
        # malware there. A rule that misfired is weighed by the model until its precision is fixed.
        benign_hits = collections.Counter()
        malware_hits = collections.Counter()
        for r, y, h in data:
            if h != "work":
                continue
            for rule in {f[0] for f in r.get("findings", []) if strong(f)}:
                (malware_hits if y else benign_hits)[rule] += 1
        floor = sorted(r for r in malware_hits if malware_hits[r] >= 3 and not benign_hits[r])

        def floored(r) -> bool:
            return any(strong(f) and f[0] in floor for f in r.get("findings", []))

        malware_ecosystem = {
            "datadog/npm": "npm",
            "datadog/pypi": "pypi",
            "datadog/ide_extensions": "openvsx",
            "malregistry": "pypi",
        }

        def area(r) -> str:
            """Which threshold a row answers to: skills, MCP servers, or a package ecosystem.

            Each ecosystem's line is set on its own benign units: editor extensions' telemetry
            must not decide where npm's malware stops being blocked."""
            first = r["file"].split("/")[0]
            if first in ("msb", "asb", "pub") or r["file"].startswith("datadog/ai-skills"):
                return "skill"
            if first in ("mcpv", "mcpc", "mcp"):
                return "mcp"
            for prefix, eco in malware_ecosystem.items():
                if r["file"].startswith(prefix):
                    return eco
            # Only an ecosystem with malware to measure gets its own line; the rest share one,
            # set on all of them together -- a line fitted to a few hundred benign units of one
            # ecosystem moves on the other half (review 98: terraform, nix, actions).
            own = set(malware_ecosystem.values())
            return first if a.per_ecosystem and first in own else "package"

        def code(f) -> bool:
            return VerdictFeatures.is_code(f[0]) and ".KNOWN" not in f[0]

        def outcome(r, s, block, warn) -> tuple[bool, bool]:
            """(blocked, warned) as `Verdict.decide` and the engine grade the row."""
            findings = [f for f in r.get("findings", []) if code(f)]
            if not r["verdict"]["rules"]:
                return False, False
            if floored(r) or s >= block:
                return True, True
            if s >= warn:
                blocked = any(
                    len(f) > 3 and f[3] == "malicious" and Severity[f[1].upper()] >= Severity.HIGH
                    for f in findings
                )
                warned = blocked or any(Severity[f[1].upper()] >= Severity.MEDIUM for f in findings)
                return blocked, warned
            return False, False

        def score(h, thresholds):
            blocked_b = collections.Counter()
            warned_b = collections.Counter()
            caught = n = 0
            for r, y, s in zip(M[h], Y[h], prob[h], strict=True):
                block, warn = thresholds[area(r)]
                blocked, warned = outcome(r, s, block, warn)
                if y:
                    n += 1
                    caught += blocked
                    continue
                eco = r["file"].split("/")[0]
                blocked_b[eco] += blocked
                warned_b[eco] += warned
            ecos = total[h]
            block_rate = {e: 100 * blocked_b[e] * scale.get(e, 1.0) / max(ecos[e], 1) for e in ecos}
            quiet = {e: 100 - 100 * warned_b[e] * scale.get(e, 1.0) / max(ecos[e], 1) for e in ecos}
            return caught, max(n, 1), block_rate, quiet

        eco_area = {}
        for r, _, _ in data:
            eco_area.setdefault(r["file"].split("/")[0], area(r))
        areas = tuple(sorted({area(r) for r, _, _ in data}))
        thresholds = dict.fromkeys(areas, (0.99, 0.99))
        for x in areas:
            mine = {e for e, ar in eco_area.items() if ar == x}

            def worst_block(t, x=x, mine=mine):
                trial = {**thresholds, x: (t, t)}
                rates = score("work", trial)[2]
                return max((rates.get(e, 0.0) for e in mine), default=0.0)

            block = next(
                (t for t in np.linspace(0.02, 0.99, 98) if worst_block(t) <= a.block_share), 0.99
            )

            def worst_quiet(w, x=x, mine=mine, block=block):
                trial = {**thresholds, x: (block, w)}
                rates = score("work", trial)[3]
                return min((rates.get(e, 100.0) for e in mine), default=100.0)

            warn = next(
                (w for w in np.linspace(0.001, block, 200) if worst_quiet(w) >= a.quiet), block
            )
            thresholds[x] = (float(block), float(warn))
        block, warn = thresholds.get("package", thresholds.get("npm", (0.99, 0.99)))
        if a.dump is not None:
            with a.dump.open("w", encoding="utf-8") as handle:
                for h in ("work", "holdout"):
                    for r, y, p_ in zip(M[h], Y[h], prob[h], strict=True):
                        b, w = thresholds[area(r)]
                        handle.write(
                            json.dumps(
                                {
                                    "file": r["file"],
                                    "half": h,
                                    "y": int(y),
                                    "area": area(r),
                                    "score": round(float(p_), 4),
                                    "blocked": outcome(r, p_, b, w)[0],
                                    "rules": r["verdict"]["rules"],
                                }
                            )
                            + "\n"
                        )
        report = {}
        for h in ("work", "holdout"):
            caught, n, block_rate, quiet = score(h, thresholds)
            z = 1.96
            p_hat = caught / n
            centre = p_hat + z * z / (2 * n)
            margin = z * math.sqrt(p_hat * (1 - p_hat) / n + z * z / (4 * n * n))
            report[h] = {
                "malware": f"{caught}/{n}",
                "recall": round(100 * p_hat, 2),
                "recall_ci95_low": round(100 * (centre - margin) / (1 + z * z / n), 2),
                "ecosystems_block_ok": sum(v <= 0.5 for v in block_rate.values()),
                "ecosystems_quiet_ok": sum(v >= 98 for v in quiet.values()),
                "ecosystems": len(block_rate),
                "worst_block": sorted(block_rate.items(), key=lambda x: -x[1])[:5],
                "worst_quiet": sorted(quiet.items(), key=lambda x: x[1])[:5],
                "recall_by_area": cls.recall_by_area(
                    M[h],
                    Y[h],
                    [
                        outcome(r, p_, *thresholds[area(r)])[0]
                        for r, p_ in zip(M[h], prob[h], strict=True)
                    ],
                ),
            }
        print(
            json.dumps(
                {"thresholds": thresholds, "floor": floor, **report}, indent=1, default=float
            )
        )
        if a.out:
            model = cls.export(
                clf,
                vocab,
                float(block),
                float(warn),
                {
                    "benign": len(Y["work"]) - sum(Y["work"]),
                    "malware": sum(Y["work"]),
                    "half": "work",
                },
            )
            model["floor"] = floor
            model["thresholds"]["areas"] = {
                x: {"block": b, "warn": w} for x, (b, w) in thresholds.items()
            }
            with gzip.open(a.out, "wt", encoding="utf-8") as handle:
                json.dump(model, handle, separators=(",", ":"))


if __name__ == "__main__":
    VerdictTrain.main()
