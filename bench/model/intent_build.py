#!/usr/bin/env python3
"""Build the intent layer's weights (`core/intent.py`) from what scans reported, on study data only.

```
  benign npm scans ─┐   verdict.intent.facts      K folds within half A (malware by family,
  half-A malware ───┼─► (the scanner's own facts,  benign by package name)
  families (S5) ────┤    same version: S3)           │ train: purpose envelopes, rows (M1, E2, E3)
  adjudication ─────┘    candidates excluded (E7)    │ held out: each row's ratio (M8), then scores
                                                     ▼
                         rows kept in >= K-1 folds and still above 1 held out (M8)
                         threshold: lowest line with held-out benign 95% upper bound <= 0.5% (T5),
                                    then popular npm the same (S2); the stricter wins
                                                     │
                         final rows and envelopes on all of half A ──► intent.json.gz
                         aggregate report: rates, intervals, family counts -- nothing per sample
```

Every fact is read from the scan record (`verdict.intent.facts`), and every score is computed by
the scanner's own `IntentFacts.mismatched` and `IntentScore`, so what is measured here is what a
scan scores. A record from another facts version is refused (S3), not mixed in.

Half B is never read here (M2/T1). The report is study data: the held-out numbers come from
cross-validation inside half A and are not a result; half B, scored once with the committed code,
is. Nothing is written per sample -- no list of which malware passed or why: that would be an
evasion oracle, and it is not needed to build or audit the weights (19, step 8).

    docker run --rm --network none -v DATA:/d:ro -v OUT:/o -v "$PWD:/s:ro" -e PYTHONPATH=/s/src \\
      cordon-prepush:70b92cac7b3c python /s/bench/model/intent_build.py \\
      --benign /d/npm-benign/scans.jsonl --malware /d/halfA/scans.jsonl \\
      --families /d/halfA/families.json --exclude /s/reviews/review-98/data/adjudication-*.jsonl \\
      --popular /d/popular/scans.jsonl --scanner-commit <sha> --dataset "<what and where>" \\
      --out /o/intent.json.gz --report /o/intent-report.json
"""

from __future__ import annotations

import argparse
import collections
import datetime
import gzip
import hashlib
import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cordon_scanner.core.intent import IntentFacts, IntentScore, IntentWeights


@dataclass(frozen=True)
class Unit:
    """One scanned package, as the builder reads it: its facts and the key its fold is drawn from."""

    facts: frozenset[str]
    key: str
    family: str = ""


class IntentBuild:
    @staticmethod
    def wilson(k: float, n: int, z: float = 1.96) -> tuple[float, float, float]:
        """Rate and 95% Wilson interval; `k` may be fractional (family-weighted counts)."""
        if n <= 0:
            return 0.0, 0.0, 1.0
        p = k / n
        centre = (p + z * z / (2 * n)) / (1 + z * z / n)
        half = z * math.sqrt(max(p * (1 - p), 0.0) / n + z * z / (4 * n * n)) / (1 + z * z / n)
        return p, max(0.0, centre - half), min(1.0, centre + half)

    @staticmethod
    def package_key(path: str) -> str:
        """Every version of one package on one side of a split: the name without its version."""
        base = path.rsplit("/", 1)[-1]
        return re.sub(r"-\d[\w.+-]*\.tgz$|\.tgz$", "", base)

    @staticmethod
    def fold(key: str, folds: int) -> int:
        return hashlib.sha256(key.encode()).digest()[0] % folds

    # -- reading --------------------------------------------------------------------------------

    @staticmethod
    def read(
        paths: list[Path],
        families: dict[str, str] | None,
        excluded: set[str],
        skipped: collections.Counter[str],
    ) -> list[Unit]:
        """The npm packages of scan files whose facts this scanner version computes."""
        out: list[Unit] = []
        for path in paths:
            with path.open(encoding="utf-8") as handle:
                for line in handle:
                    record = json.loads(line)
                    name = str(record.get("file", ""))
                    verdict = record.get("verdict") or {}
                    intent = verdict.get("intent")
                    if name in excluded:
                        skipped["adjudication candidate (E7)"] += 1
                    elif verdict.get("area") != "npm":
                        skipped["not npm (M3)"] += 1
                    elif not intent:
                        skipped["no intent facts: scanned by older code (S3)"] += 1
                    elif intent.get("facts_version") != IntentFacts.VERSION:
                        skipped["other facts version (S3)"] += 1
                    else:
                        key = IntentBuild.package_key(name)
                        family = (families or {}).get(name, key) if families is not None else ""
                        out.append(
                            Unit(frozenset(IntentFacts.admitted(intent["facts"])), key, family)
                        )
        return out

    @staticmethod
    def excluded(paths: list[Path]) -> set[str]:
        """Units an adjudication file names, whatever its verdict: label noise stays out (E7)."""
        out: set[str] = set()
        for path in paths:
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    row = json.loads(line)
                    out.update(str(row[k]) for k in ("file", "unit") if row.get(k))
        return out

    # -- envelopes and rows ---------------------------------------------------------------------

    @staticmethod
    def envelopes(benign: list[Unit]) -> dict[str, Any]:
        """Per claimed purpose (and `all`), each trigger fact's benign 95% upper bound."""
        by: dict[str, list[frozenset[str]]] = collections.defaultdict(list)
        for unit in benign:
            by["all"].append(unit.facts)
            for purpose in IntentFacts.claimed(unit.facts):
                by[purpose].append(unit.facts)
        out: dict[str, Any] = {}
        for purpose, members in sorted(by.items()):
            n = len(members)
            counts = collections.Counter(
                f for facts in members for f in facts if f.startswith("t:")
            )
            out[purpose] = {
                "n": n,
                "zero": round(IntentBuild.wilson(0, n)[2], 6),
                "upper": {
                    f: round(IntentBuild.wilson(k, n)[2], 6) for f, k in sorted(counts.items())
                },
            }
        return out

    @staticmethod
    def derived(units: list[Unit], envelopes: dict[str, Any], a: argparse.Namespace) -> list[Unit]:
        return [
            Unit(
                u.facts
                | frozenset(
                    IntentFacts.mismatched(u.facts, envelopes, a.mismatch_limit, a.envelope_min_n)
                ),
                u.key,
                u.family,
            )
            for u in units
        ]

    @staticmethod
    def rates(
        benign: list[Unit], malware: list[Unit]
    ) -> dict[str, tuple[int, float, int, int, int]]:
        """Per fact: (benign count, family-weighted malware count, families, benign n, family n).
        Each family weighs 1, its packages sharing it (E3)."""
        size = collections.Counter(u.family for u in malware)
        kb: collections.Counter[str] = collections.Counter(f for u in benign for f in u.facts)
        km: dict[str, float] = collections.defaultdict(float)
        fams: dict[str, set[str]] = collections.defaultdict(set)
        for u in malware:
            for f in u.facts:
                km[f] += 1 / size[u.family]
                fams[f].add(u.family)
        names = set(kb) | set(km)
        return {f: (kb[f], km[f], len(fams[f]), len(benign), len(size)) for f in sorted(names)}

    @staticmethod
    def rows(benign: list[Unit], malware: list[Unit], a: argparse.Namespace) -> dict[str, dict]:
        """Every fact's row, eligible or not: rates, both Wilson intervals, the conservative
        ratio (malware lower bound / benign upper bound, capped: M1, E2), cost class and group."""
        out: dict[str, dict] = {}
        for fact, (kb, km, families, nb, nf) in IntentBuild.rates(benign, malware).items():
            known = IntentFacts.classify(fact)
            if known is None:
                continue
            pb, lb, hb = IntentBuild.wilson(kb, nb)
            pm, lm, hm = IntentBuild.wilson(km, nf)
            ratio = min(a.cap, lm / hb) if hb > 0 else a.cap
            out[fact] = {
                "cost": known[0],
                "group": known[1],
                "benign": kb,
                "benign_n": nb,
                "benign_rate": round(pb, 6),
                "benign_interval": [round(lb, 6), round(hb, 6)],
                "malware": round(km, 3),
                "families": families,
                "family_n": nf,
                "malware_rate": round(pm, 6),
                "malware_interval": [round(lm, 6), round(hm, 6)],
                "ratio": round(ratio, 6),
                "eligible": families >= a.min_families and ratio > 1,
            }
        return out

    @staticmethod
    def weighted(rows: dict[str, dict], keep: set[str] | None, cheap_cap: float) -> dict[str, Any]:
        """A model `IntentScore` reads, from the eligible rows (and only `keep`, when given)."""
        return {
            "cheap_cap": cheap_cap,
            "rows": {
                f: {**r, "weight": math.log(r["ratio"])}
                for f, r in rows.items()
                if r["eligible"] and (keep is None or f in keep)
            },
        }

    @staticmethod
    def scores(units: list[Unit], model: dict[str, Any]) -> list[float]:
        return [IntentScore.score(IntentScore.contributions(u.facts, model), model) for u in units]

    # -- cross-validation -----------------------------------------------------------------------

    @staticmethod
    def split(units: list[Unit], k: int, folds: int, by_family: bool) -> tuple[list, list]:
        train, test = [], []
        for u in units:
            (
                test if IntentBuild.fold(u.family if by_family else u.key, folds) == k else train
            ).append(u)
        return train, test

    @staticmethod
    def crossval(
        benign: list[Unit], malware: list[Unit], a: argparse.Namespace, keep: set[str] | None
    ) -> tuple[collections.Counter[str], list[Unit], list[Unit], list, list]:
        """Each fold: envelopes and rows on its training part, then its held-out part scored.
        Returns how many folds selected each fact, the held-out units (with their fold's derived
        facts), and their scores."""
        selected: collections.Counter[str] = collections.Counter()
        held_b: list[Unit] = []
        held_m: list[Unit] = []
        scores_b: list[float] = []
        scores_m: list[float] = []
        for k in range(a.folds):
            train_b, test_b = IntentBuild.split(benign, k, a.folds, by_family=False)
            train_m, test_m = IntentBuild.split(malware, k, a.folds, by_family=True)
            envelopes = IntentBuild.envelopes(train_b)
            rows = IntentBuild.rows(
                IntentBuild.derived(train_b, envelopes, a),
                IntentBuild.derived(train_m, envelopes, a),
                a,
            )
            selected.update(f for f, r in rows.items() if r["eligible"])
            model = IntentBuild.weighted(rows, keep, a.cheap_cap)
            test_b = IntentBuild.derived(test_b, envelopes, a)
            test_m = IntentBuild.derived(test_m, envelopes, a)
            held_b += test_b
            held_m += test_m
            scores_b += IntentBuild.scores(test_b, model)
            scores_m += IntentBuild.scores(test_m, model)
        return selected, held_b, held_m, scores_b, scores_m

    @staticmethod
    def kept(
        selected: collections.Counter[str],
        held_b: list[Unit],
        held_m: list[Unit],
        a: argparse.Namespace,
    ) -> set[str]:
        """M8: a row carries weight only if most folds select it and, held out, malware still
        shows its fact more often than benign packages do."""
        held = IntentBuild.rates(held_b, held_m)
        out: set[str] = set()
        for fact, count in selected.items():
            if count < a.folds - 1 or fact not in held:
                continue
            kb, km, _, nb, nf = held[fact]
            if nf and km / nf > (kb / nb if nb else 1.0):
                out.add(fact)
        return out

    @staticmethod
    def blocked(scores: list[float], threshold: float, cheap_cap: float) -> list[bool]:
        model = {"threshold": threshold, "cheap_cap": cheap_cap}
        return [IntentScore.crosses(s, model) for s in scores]

    @staticmethod
    def threshold(scores: list[float], cheap_cap: float, bar: float, floor: float) -> float | None:
        """The lowest line at which the benign packages scored block at most `bar` on the 95%
        upper bound (T5), never under `floor`. None when no line does (too few benign units)."""
        candidates = sorted({floor, *(s + 1e-9 for s in scores if s + 1e-9 > floor)})
        n = len(scores)
        for line in candidates:
            k = sum(IntentBuild.blocked(scores, line, cheap_cap))
            if IntentBuild.wilson(k, n)[2] <= bar:
                return line
        return None

    @staticmethod
    def malware_rate(
        units: list[Unit], scores: list[float], line: float, cheap_cap: float
    ) -> dict[str, Any]:
        size = collections.Counter(u.family for u in units)
        hit = IntentBuild.blocked(scores, line, cheap_cap)
        k = sum(1 / size[u.family] for u, h in zip(units, hit, strict=True) if h)
        rate, lo, hi = IntentBuild.wilson(k, len(size))
        return {
            "packages": len(units),
            "families": len(size),
            "families_blocked": round(k, 2),
            "rate": round(rate, 6),
            "interval": [round(lo, 6), round(hi, 6)],
        }

    @staticmethod
    def benign_rate(scores: list[float], line: float, cheap_cap: float) -> dict:
        k = sum(IntentBuild.blocked(scores, line, cheap_cap))
        rate, lo, hi = IntentBuild.wilson(k, len(scores))
        return {
            "k": k,
            "n": len(scores),
            "rate": round(rate, 6),
            "lower": round(lo, 6),
            "upper": round(hi, 6),
        }

    # -- the build ------------------------------------------------------------------------------

    @staticmethod
    def build(
        benign: list[Unit],
        malware: list[Unit],
        popular: list[Unit],
        a: argparse.Namespace,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """`(weights, report)`; raises ValueError when no line meets the benign bar."""
        selected, held_b, held_m, _, _ = IntentBuild.crossval(benign, malware, a, None)
        keep = IntentBuild.kept(selected, held_b, held_m, a)
        # Second pass with only the kept rows: the held-out scores the line is chosen on.
        _, _, held_m, scores_b, scores_m = IntentBuild.crossval(benign, malware, a, keep)
        floor = a.cheap_cap + 1e-6  # cosmetic facts at their cap stay under the line (M6)
        line = IntentBuild.threshold(scores_b, a.cheap_cap, IntentWeights.BENIGN_BAR, floor)
        if line is None:
            raise ValueError("no line keeps held-out benign npm within 0.5% (95% upper bound)")
        envelopes = IntentBuild.envelopes(benign)
        rows = IntentBuild.rows(
            IntentBuild.derived(benign, envelopes, a),
            IntentBuild.derived(malware, envelopes, a),
            a,
        )
        final = IntentBuild.weighted(rows, keep, a.cheap_cap)
        popular_rate = None
        if popular:
            scored = IntentBuild.scores(IntentBuild.derived(popular, envelopes, a), final)
            strict = IntentBuild.threshold(scored, a.cheap_cap, IntentWeights.BENIGN_BAR, line)
            if strict is None:
                raise ValueError("no line keeps popular npm within 0.5% (95% upper bound, S2)")
            line = strict
            popular_rate = IntentBuild.benign_rate(scored, line, a.cheap_cap)
        benign_at = IntentBuild.benign_rate(scores_b, line, a.cheap_cap)
        weights = {
            "format": IntentWeights.FORMAT,
            "facts_version": IntentFacts.VERSION,
            "version": a.version or f"{a.date}-{a.scanner_commit[:8]}",
            "scanner_commit": a.scanner_commit,
            "dataset": a.dataset,
            "date": a.date,
            "scope": ["npm"],
            "threshold": round(line, 6),
            "cheap_cap": a.cheap_cap,
            "mismatch_limit": a.mismatch_limit,
            "envelope_min_n": a.envelope_min_n,
            "threshold_benign": {
                **benign_at,
                "measured": "held out within half A (cross-validated)",
            },
            "threshold_popular": popular_rate,
            "envelopes": envelopes,
            "rows": {
                f: {
                    **{k: v for k, v in r.items() if k != "eligible"},
                    "weight": round(math.log(r["ratio"]), 9),
                    "provenance": IntentFacts.provenance(f),
                    "kept": True,
                }
                for f, r in final["rows"].items()
            },
        }
        # The stored weight is the log of the stored (rounded) ratio, exactly.
        for row in weights["rows"].values():
            row["weight"] = math.log(min(IntentWeights.CAP, row["ratio"]))
        report = {
            "label": "STUDY DATA: half A, cross-validated within it; not a result (T1). Half B is "
            "the test, scored once with committed code.",
            "benign_npm": benign_at,
            "popular_npm": popular_rate,
            "malware_half_a_held_out": IntentBuild.malware_rate(
                held_m, scores_m, line, a.cheap_cap
            ),
            "threshold": weights["threshold"],
            "rows_kept": len(weights["rows"]),
            "rows_selected_in_some_fold": len(selected),
            "rows": {
                f: {
                    k: r[k]
                    for k in ("cost", "group", "benign_rate", "malware_rate", "families", "ratio")
                }
                for f, r in sorted(weights["rows"].items(), key=lambda kv: -kv[1]["ratio"])
            },
        }
        problems = IntentWeights.problems(weights)
        if problems:
            raise ValueError("the built file breaks the design's rules: " + "; ".join(problems))
        return weights, report

    @staticmethod
    def main(argv: list[str] | None = None) -> int:
        p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        p.add_argument("--benign", type=Path, nargs="+", required=True, help="benign npm scans")
        p.add_argument(
            "--malware", type=Path, nargs="+", required=True, help="half-A malware scans"
        )
        p.add_argument("--families", type=Path, required=True, help="{file: family}, S5-fixed")
        p.add_argument("--exclude", type=Path, nargs="*", default=[], help="adjudication files")
        p.add_argument("--popular", type=Path, nargs="*", default=[], help="popular npm scans")
        p.add_argument("--scanner-commit", required=True)
        p.add_argument("--dataset", required=True)
        p.add_argument("--date", default=datetime.date.today().isoformat())
        p.add_argument("--version", default="")
        p.add_argument("--folds", type=int, default=5)
        p.add_argument("--min-families", type=int, default=IntentWeights.MIN_FAMILIES)
        p.add_argument("--cap", type=float, default=IntentWeights.CAP)
        p.add_argument("--cheap-cap", type=float, default=round(math.log(2), 6))
        p.add_argument("--mismatch-limit", type=float, default=0.01)
        p.add_argument("--envelope-min-n", type=int, default=50)
        p.add_argument("--out", type=Path, required=True)
        p.add_argument("--report", type=Path, required=True)
        a = p.parse_args(argv)
        if a.min_families < IntentWeights.MIN_FAMILIES or a.cap > IntentWeights.CAP:
            p.error("the loader refuses rows under its family minimum or over its cap (E2)")
        skipped: collections.Counter[str] = collections.Counter()
        excluded = IntentBuild.excluded(a.exclude)
        families = json.loads(a.families.read_text(encoding="utf-8"))
        benign = IntentBuild.read(a.benign, None, excluded, skipped)
        malware = IntentBuild.read(a.malware, families, excluded, skipped)
        popular = IntentBuild.read(a.popular, None, excluded, skipped) if a.popular else []
        try:
            weights, report = IntentBuild.build(benign, malware, popular, a)
        except ValueError as error:
            print(f"intent build failed: {error}", file=sys.stderr)
            return 1
        report["skipped"] = dict(skipped)
        report["inputs"] = {"benign": len(benign), "malware": len(malware), "popular": len(popular)}
        with gzip.open(a.out, "wt", encoding="utf-8") as handle:
            json.dump(weights, handle, sort_keys=True, separators=(",", ":"))
        a.report.write_text(json.dumps(report, indent=1, sort_keys=True), encoding="utf-8")
        print(
            json.dumps(
                {k: report[k] for k in ("benign_npm", "popular_npm", "threshold", "rows_kept")}
            )
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(IntentBuild.main())
