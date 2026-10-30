#!/usr/bin/env python3
"""Per-area verdict trees, fitted on folded features and added to the shipped model as format 3.

```
  rows (jsonl, raw) ── FeatureRecord.read(row, producer) ──► (schema, folded features)
        │                         │ schema neither current nor accepted ──► refused, nothing written
        v                         v
  per area: only what a user's scan computes (FeatureScope), support floor ── 5 family folds (out-of-fold) ──► line at the benign bar
        │
        └─ fit on every row ──► export ──► self-check: VerdictModel.score on every row
                                             == the fit's own probability, or nothing is written
        v
  base model (format 2; no hashed feature, so folding leaves its scores alone)
        + by_area[area] trees + areas[area] line + FeatureFold.stamp() ──► format 3 model
```

The base model's own trees and its policy (keep, lift areas, floor, add-only) are carried as they
are. That is sound only because none of its features is a hashed code feature, which `carry`
checks: folding changes no input those trees read.

Rows: `--rows NAME=LABEL[:PREFIX]` for each `<NAME>-<producer>.jsonl` under `--dir` (LABEL 0 benign,
1 malware; PREFIX keeps only units under it), `--held` lists of units never read, `--producer` the
rows' writer's version (`FeatureSchema.version` of that checkout), `--accept` a version proven to
compute the same features as this tree (by a paired scan, recorded in the manifest).

The fit's settings are the shipped fit's (HistGradientBoosting: 300 iterations, learning rate 0.08,
31 leaves, L2 1.0); its line is the score the out-of-fold benign rows exceed at `--bar`.
"""

from __future__ import annotations

import argparse
import gzip
import json
import math
import re
import sys
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from cordon_scanner.decide.feature_schema import (
    FeatureFold,
    FeatureRecord,
    FeatureSchema,
    FeatureScope,
)
from cordon_scanner.decide.verdict import VerdictModel


class AreaFit:
    """Fit, export and check one area's trees; add them to a base model. Stateless."""

    SETTINGS: dict[str, Any] = {  # noqa: RUF012 -- read-only, the shipped fit's settings
        "max_iter": 300,
        "learning_rate": 0.08,
        "max_leaf_nodes": 31,
        "l2_regularization": 1.0,
        "random_state": 20261030,
    }
    #: The largest difference between a score the scanner computes from the exported trees and the
    #: fit's own probability: both walk the same splits, in single precision.
    TOLERANCE: float = 1e-6

    @staticmethod
    def family(unit: str) -> str:
        """The publisher family a unit is grouped by, so no family is on both sides of a fold."""
        parts = unit.split("/")
        name = parts[3] if unit.startswith("datadog/") and len(parts) > 3 else parts[-1]
        return "fam:" + re.split(r"[@/_\-.]", name.lstrip("@"))[0].lower()

    @staticmethod
    def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
        if n == 0:
            return (0.0, 1.0)
        p = k / n
        d = 1 + z * z / n
        c = p + z * z / (2 * n)
        s = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
        return ((c - s) / d, (c + s) / d)

    @staticmethod
    def rows(
        where: Path,
        sets: list[tuple[str, int, str | None]],
        producer: str,
        commit: str,
        held: set[str],
        area: str | None,
        accepted: set[str],
    ) -> Iterator[tuple[int, str, dict[str, float]]]:
        """(label, unit, folded features) of every row of `area` (every area when None), refusing a
        row whose version is neither this tree's nor accepted."""
        allowed = {FeatureSchema.current(), *accepted}
        for name, label, prefix in sets:
            with (where / f"{name}-{commit}.jsonl").open(encoding="utf-8") as handle:
                for line in handle:
                    row = json.loads(line)
                    unit = row["file"]
                    if unit in held or (prefix and not unit.startswith(prefix)):
                        continue
                    if area is not None and (row.get("verdict") or {}).get("area") != area:
                        continue
                    schema, features = FeatureRecord.read(row, producer)
                    if schema not in allowed:
                        raise ValueError(
                            f"{name}: {unit} has features of version {schema}, not this tree's"
                            f" ({FeatureSchema.current()}) or an accepted one: refused"
                        )
                    yield label, unit, features

    @staticmethod
    def export(clf: Any, names: list[str]) -> dict[str, Any]:
        """HistGradientBoosting trees as `VerdictModel.score` walks them."""
        trees = []
        for predictors in clf._predictors:
            trees.append(
                [
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
                    for n in predictors[0].nodes
                ]
            )
        return {
            "features": names,
            "baseline": float(clf._baseline_prediction.ravel()[0]),
            "trees": trees,
        }

    @staticmethod
    def check(
        section: dict[str, Any], rows: list[dict[str, float]], expected: list[float]
    ) -> float:
        """The largest difference between the scanner's score of each row (already folded) under
        `section` and the fit's own probability; raises when any exceeds TOLERANCE."""
        worst = 0.0
        for features, want in zip(rows, expected, strict=True):
            worst = max(worst, abs(VerdictModel.score(section, features) - want))
        if worst > AreaFit.TOLERANCE:
            raise ValueError(f"the exported trees score {worst:.3g} away from the fit: not written")
        return worst

    @staticmethod
    def carry(base: dict[str, Any]) -> dict[str, Any]:
        """The base model as a format-3 model, its trees and policy as they are. Refused unless it is
        format 2 and reads no hashed code feature anywhere, so folding changes nothing it reads."""
        if base.get("format") != VerdictModel.UNFOLDED:
            raise ValueError(
                f"the base model is format {base.get('format')}, not the unfolded format"
            )
        sections = [base, *(base.get("by_area") or {}).values()]
        if base.get("registry"):
            sections.append(base["registry"])
        unread = sorted(
            {n for s in sections for n in s["features"] if not FeatureScope.computed(n)}
        )
        if unread:
            raise ValueError(
                f"the base model reads features a user's scan never computes ({unread[:3]})"
            )
        hashed = sorted({n for s in sections for n in s["features"] if FeatureFold.HASHED.match(n)})
        if hashed:
            raise ValueError(
                f"the base model reads hashed features ({hashed[:3]}...): refit it folded"
            )
        return {
            **base,
            "format": VerdictModel.FORMAT,
            **FeatureFold.stamp(),
            "by_area": dict(base.get("by_area") or {}),
        }

    @staticmethod
    def fit(
        rows: list[tuple[int, str, dict[str, float]]], bar: float, min_support: int
    ) -> tuple[dict[str, Any], float, dict[str, Any]]:
        """(exported trees, line, measurement) for one area's rows."""
        import numpy as np
        from sklearn.ensemble import HistGradientBoostingClassifier
        from sklearn.model_selection import GroupKFold

        support = Counter(name for _, _, f in rows for name in f)
        # Only what a user's scan computes (FeatureScope): a feature the scan never computes would
        # read zero on every scan the model judges.
        measure_only = sorted(n for n in support if not FeatureScope.computed(n))
        names = sorted(
            n for n, c in support.items() if c >= min_support and FeatureScope.computed(n)
        )
        col = {n: i for i, n in enumerate(names)}
        matrix = np.zeros((len(rows), len(names)), dtype=np.float32)
        for i, (_, _, f) in enumerate(rows):
            for name, value in f.items():
                j = col.get(name)
                if j is not None:
                    matrix[i, j] = value
        y = np.array([label for label, _, _ in rows], dtype=np.int8)
        groups = [AreaFit.family(unit) for _, unit, _ in rows]
        nb, nm = int((y == 0).sum()), int((y == 1).sum())
        oof = np.zeros(len(rows))
        for tr, te in GroupKFold(n_splits=5).split(matrix, y, groups):
            clf = HistGradientBoostingClassifier(**AreaFit.SETTINGS).fit(matrix[tr], y[tr])
            oof[te] = clf.predict_proba(matrix[te])[:, 1]
        benign = np.sort(oof[y == 0])[::-1]
        allowed = math.floor(bar * nb)
        line = float(benign[allowed]) + 1e-9 if allowed < nb else 0.0
        fp = int((oof[y == 0] >= line).sum())
        tp = int((oof[y == 1] >= line).sum())
        final = HistGradientBoostingClassifier(**AreaFit.SETTINGS).fit(matrix, y)
        section = AreaFit.export(final, names)
        if not all(FeatureScope.computed(n) for n in section["features"]):
            raise ValueError(
                "a feature a user's scan never computes reached the export: not written"
            )
        kept = [{n: f[n] for n in f if n in col} for _, _, f in rows]
        worst = AreaFit.check(section, kept, [float(p) for p in final.predict_proba(matrix)[:, 1]])
        measured = {
            "benign": nb,
            "malware": nm,
            "features": len(names),
            "measure_only_left_out": len(measure_only),
            "min_support": min_support,
            "bar": bar,
            "line": line,
            "benign_blocked": fp,
            "fp_wilson": AreaFit.wilson(fp, nb),
            "recall": tp / nm if nm else 0.0,
            "recall_wilson": AreaFit.wilson(tp, nm),
            "folds": 5,
            "export_worst_difference": worst,
        }
        return section, line, measured

    @staticmethod
    def fixture(out: Path) -> None:
        """The gate's record of an export (`tests/unit/data/area_fit/export.json`): trees fitted on
        seeded random counts under folded feature names, the rows and the fit's own probabilities,
        so a test without scikit-learn can hold the scanner's score of an export to the fit."""
        import random

        import numpy as np
        from sklearn.ensemble import HistGradientBoostingClassifier

        rng = random.Random("area-fit-fixture|2026-10-30")  # noqa: S311 -- a fixture, not key material
        names = [f"pkg:code_install_tok_f{i}" for i in range(12)] + [
            "r:SUSPECT.X.001#n",
            "pkg:files",
        ]
        rows = [
            {n: float(rng.randint(0, 6)) for n in names if rng.random() < 0.6} for _ in range(400)
        ]
        y = [
            int(r.get("pkg:code_install_tok_f3", 0) + r.get("r:SUSPECT.X.001#n", 0) > 6)
            for r in rows
        ]
        matrix = np.array([[r.get(n, 0.0) for n in names] for r in rows], dtype=np.float32)
        clf = HistGradientBoostingClassifier(**{**AreaFit.SETTINGS, "max_iter": 40}).fit(matrix, y)
        section = AreaFit.export(clf, names)
        expected = [float(p) for p in clf.predict_proba(matrix)[:, 1]]
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps({"section": section, "rows": rows, "expected": expected}), encoding="utf-8"
        )

    @classmethod
    def main(cls) -> None:
        if sys.argv[1:2] == ["--fixture"]:
            cls.fixture(Path(sys.argv[2]))
            return
        p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        p.add_argument("--dir", type=Path, required=True, help="where the row files are")
        p.add_argument(
            "--commit", required=True, help="the row files' producer commit (file suffix)"
        )
        p.add_argument("--producer", required=True, help="that commit's FeatureSchema version")
        p.add_argument(
            "--accept", nargs="*", default=[], help="versions proven equal to this tree's"
        )
        p.add_argument("--rows", nargs="+", required=True, help="NAME=LABEL[:PREFIX]")
        p.add_argument("--held", nargs="*", default=[], type=Path, help="unit lists never read")
        p.add_argument("--areas", nargs="+", required=True)
        p.add_argument("--base", type=Path, required=True, help="the shipped model (format 2)")
        p.add_argument("--bar", type=float, default=0.02, help="benign rate the line allows")
        p.add_argument("--min-support", type=int, default=100)
        p.add_argument("--out", type=Path, required=True)
        a = p.parse_args()
        # One file may hold both labels under different prefixes (`asb=0:benign/ asb=1:malware/`).
        sets: list[tuple[str, int, str | None]] = []
        for spec in a.rows:
            name, rest = spec.split("=", 1)
            label, _, prefix = rest.partition(":")
            sets.append((name, int(label), prefix or None))
        held = {
            u.strip()
            for h in a.held
            for u in h.read_text(encoding="utf-8").splitlines()
            if u.strip()
        }
        with gzip.open(a.base, "rt", encoding="utf-8") as handle:
            model = cls.carry(json.load(handle))
        fits: dict[str, Any] = {}
        for area in a.areas:
            rows = list(cls.rows(a.dir, sets, a.producer, a.commit, held, area, set(a.accept)))
            section, line, measured = cls.fit(rows, a.bar, a.min_support)
            model["by_area"][area] = section
            model["areas"][area] = (
                line  # unrounded: rounding down would let one more benign row past
            )
            fits[area] = measured
            print(area, json.dumps(measured), flush=True)
        model["manifest"] = {
            **(model.get("manifest") or {}),
            "area_fits": fits,
            "rows": {"commit": a.commit, "producer": a.producer, "accepted": a.accept},
        }
        with gzip.open(a.out, "wt", encoding="utf-8") as handle:
            json.dump(model, handle)
        print(f"written {a.out}", file=sys.stderr)


if __name__ == "__main__":
    AreaFit.main()
