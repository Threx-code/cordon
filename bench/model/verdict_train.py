#!/usr/bin/env python3
"""Train the package verdict (`core/verdict.py`) from what scans reported, and measure it held out.

```
  benign corpus rescan ─┐                                   work half ──► monotone trees
  malware (as published)├─► findings + verdict.package ──►      │  5-fold out-of-fold scores
  skills, MCP sets      ┘   = VerdictFeatures.evidence          ▼
  adjudication (not malicious, no payload: excluded)        a line per area: the lowest score at
                                                            which no ecosystem in it blocks more
                                                            than --budget of ITS corpus units
                                                                │
  holdout half ── scored once ──► per ecosystem, per malware source, content-only and with intel
                                  + every miss and every benign block (attribution)
```

Every row's features are computed by the scanner's own `VerdictFeatures.evidence` from what the
scan recorded, so what is trained is what is scored, and an outcome here is the outcome a user
gets: a unit is blocked when its score reaches its area's line, or when a finding the verdict never
re-grades (`Verdict.floored`) trips the default gate.

Benign rates are counted against every unit of the ecosystem in the corpus half, not against the
rescanned sample: the sample is the units any earlier scan flagged plus a coverage extra, and the
units outside it were quiet (review 98, 08-PROGRESS). Halves are fixed by a hash of the package
name, so every version of one package is on one side.

    docker run --rm --network none -v W:/w:ro -v OUT:/o -v "$PWD:/s:ro" -e PYTHONPATH=/s/src \\
      cordon-model:next python /s/bench/model/verdict_train.py --corpus /w/corpus.txt \\
      --benign /w/f3/benign/scans.jsonl --malware /w/f3/mal/malware-scans.jsonl \\
      --labelled msb=/w/f3/msb/scans.jsonl asb=/w/f3/asb/scans.jsonl skills=/w/f3/pub/scans.jsonl \\
                 mcpv=/w/f3/mcpv/scans.jsonl mcpc=/w/f3/mcpc/scans.jsonl \\
      --adjudication /s/reviews/review-98/data/adjudication-malware.jsonl \\
                     /s/reviews/review-98/data/adjudication-malware-supplement.jsonl \\
                     /s/reviews/review-98/data/adjudication-mcp-variants.jsonl \\
      --out /o/verdict.json.gz --report /o/verdict-report.json --attribution /o/attribution.jsonl
"""

from __future__ import annotations

import argparse
import collections
import datetime
import gzip
import hashlib
import itertools
import json
import re
from pathlib import Path
from typing import Any

from cordon_scanner.decide.verdict import Verdict, VerdictFeatures, VerdictModel
from cordon_scanner.foundation.config import Config
from cordon_scanner.foundation.models import Category, Confidence, Severity
from cordon_scanner.foundation.taxonomy import Taxonomy

try:  # the scanner's own content-gate definition, for the add-only OR (one definition of "blocked")
    from bench.tools.content import Content
except ImportError:  # pragma: no cover - script invocation puts bench/model on the path, not repo
    import pathlib as _pl
    import sys as _sys

    _sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[2]))
    from bench.tools.content import Content

#: Findings the benign measure does not count: a secret, a policy choice, a known vulnerability or
#: the scan's own notes are not a malware verdict (review 98).
NOT_MALWARE = ("SECRET.", "POLICY.", "VULNERABLE.", "OPERATIONAL.")
#: Adjudicated not to be the malware the label says.
EXCLUDED = {
    "not-malicious",
    "no-payload",
    "vulnerable-fixture",
    "empty-template",
    "identical-to-benign-reference",
}
#: Rules the verdict never re-grades, whatever its code score: a name, a provenance or a
#: dependency-source flag is orthogonal to what a package's own code does (a clean-looking package
#: can carry a typosquat name or a 999.x dependency-confusion release). Shipped in `keep` and
#: honoured by `Verdict._lowers`, so the code-content model can lift only code-evidence findings.
NAME_PROVENANCE_RULES = frozenset(
    {
        "SUSPECT.PACKAGE.NAME_RISK.001",
        "SUSPECT.TYPOSQUAT.PACKAGE_NAME.001",
        "SUSPECT.DEPENDENCY.TYPOSQUAT.001",
        "SUSPECT.MCP.TOOL_SQUATTING.001",
        "SUSPECT.PACKAGE.STARJACKING.001",
        "SUSPECT.DEPENDENCY.CONFUSION.001",
        "SUSPECT.INSTALL.DEPENDENCY_CONFUSION.001",
        "SUSPECT.DEPENDENCY.REMOTE_TARBALL.001",
        "MALWARE.DEPENDENCY.REMOTE_TARBALL.001",
        "MALWARE.DEPENDENCY.PAYLOAD.001",
        "SUSPECT.PACKAGE.MANIFEST_CONFUSION.001",
        "SUSPECT.PACKAGE.PROVENANCE.001",
        "SUSPECT.PROVENANCE.MISMATCH.001",
        "SUSPECT.PACKAGE.PLACEHOLDER_RELEASE.001",
    }
)
GENERATED = re.compile(r"__(CI|PI|MIXED)_(B\d+)$")
#: A corpus directory and the ecosystem it is part of.
ECOSYSTEM = {"popular-npm": "npm", "popular-pypi": "pypi"}
#: The real-malware benchmark's ecosystem names, as the corpus names the same ecosystem.
BENCHMARK_ECOSYSTEM = {
    "gomod": "go",
    "cargo": "crates",
    "composer": "packagist",
    "vscode": "openvsx",
}
#: Benchmark sources that are also `--labelled` sets (scanned with their benign side there), and
#: description rows that are not package scans.
AREAS = {"npm", "pypi", "openvsx", "actions", *(name for name, _ in Verdict._ECOSYSTEMS)}
BENCHMARK_ELSEWHERE = {
    "maliciousskillbench",
    "malskillbench",
    "mcp-variants",
    "mcptox",
    "mcpsafetybench",
}
#: The labelled sets: how a unit is labelled, and the key its half is drawn from.
LABELLED = {
    "msb": ("malware/", lambda u: "malskillbench:" + VerdictTrain.base(u.split("/", 1)[1])),
    "asb": ("malware/", lambda u: "asb:" + u),
    "skills": (None, lambda u: "corpus:" + "__".join(u.split("__")[:2])),
    "mcpv": ("malicious", lambda u: "mcpv:" + u.split("/")[-1].split("_")[0]),
    "mcpc": (None, lambda u: "pkg:" + VerdictTrain.package_name(u)),
}


class VerdictTrain:
    POLICY = Config.default().policy

    @staticmethod
    def half(key: str) -> str:
        return "holdout" if hashlib.sha256(key.encode()).digest()[0] % 2 else "work"

    @staticmethod
    def base(name: str) -> str:
        m = GENERATED.search(name)
        return name[: m.start()] if m else name

    @staticmethod
    def package_name(path: str) -> str:
        """A package's name without its version: every release on one side of the split."""
        name = path.split("/")[-1]
        name = re.sub(
            r"(\.tgz|\.tar\.gz|\.zip|\.whl|\.gem|\.crate|\.vsix|\.nupkg|\.jar)$", "", name
        )
        return re.sub(r"[-_.@]?v?\d[\w.+-]*$", "", name) or name

    @staticmethod
    def malware_key(unit: str) -> str:
        return "pkg:" + VerdictTrain.package_name("/".join(unit.split("/")[:4]))

    @staticmethod
    def family_key(unit: str) -> str:
        """A publisher family: the scope or first name token, so `@42ailab/*` and its platform
        builds stay on one side (review 98, 15-ADVERSARIAL-REVIEW A1a)."""
        parts = unit.split("/")
        name = parts[3] if unit.startswith("datadog/") and len(parts) > 3 else parts[-1]
        return "fam:" + re.split(r"[@/_\-.]", name.lstrip("@"))[0].lower()

    @staticmethod
    def rows(path: Path):
        seen: set[str] = set()
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                # A unit scanned twice (a restarted run) counts once; a crash or timeout is not
                # a scan result and is reported, not scored.
                if row.get("file") in seen or "findings" not in row:
                    continue
                if row.get("exit", 0) not in (0, 1):
                    continue
                seen.add(row["file"])
                yield row

    @classmethod
    def trips(cls, finding: list) -> bool:
        """`PolicyGate` on a recorded finding, as the default policy grades it."""
        rule, severity, confidence, category = finding[:4]
        if Category(category) in cls.POLICY.fail_on_categories:
            return True
        if Taxonomy.domain_of(rule) in cls.POLICY.advisory_domains:
            return False
        if Confidence[confidence.upper()] < cls.POLICY.min_confidence_to_fail:
            return False
        return (
            cls.POLICY.fail_on_severity is not None
            and Severity[severity.upper()] >= cls.POLICY.fail_on_severity
        )

    @staticmethod
    def evidence(row: dict) -> dict[str, float]:
        package = (row.get("verdict") or {}).get("package") or {}
        return VerdictFeatures.evidence(
            (
                (
                    f[0],
                    int(Severity[f[1].upper()]),
                    int(Confidence[f[2].upper()]),
                    f[3],
                    f[4] or "",
                )
                for f in row["findings"]
            ),
            package,
        )

    @classmethod
    def load(cls, a: argparse.Namespace) -> tuple[list[dict], dict[str, collections.Counter]]:
        """Every row with its label, ecosystem, area, halves and features; and the denominators."""
        family_map: dict[str, str] = (
            json.loads(a.family_map.read_text(encoding="utf-8"))
            if getattr(a, "family_map", None)
            else {}
        )
        excluded: set[str] = set()
        for path in a.adjudication:
            for r in cls.rows_any(path):
                if r.get("verdict") in EXCLUDED and r.get("file"):
                    excluded.add(r["file"])
        size: dict[str, collections.Counter] = {
            "work": collections.Counter(),
            "holdout": collections.Counter(),
        }
        for unit in a.corpus.read_text(encoding="utf-8").split():
            eco = unit.split("/")[0]
            size[cls.half("pkg:" + cls.package_name(unit))][ECOSYSTEM.get(eco, eco)] += 1
        data: list[dict] = []
        fresh: dict[str, dict] = {}
        for spec in a.features:
            name, _, path = spec.partition("=")
            prefix = "" if name in ("benign", "malware") else f"{name}/"
            for row in cls.rows(Path(path)):
                if row.get("verdict"):
                    fresh[prefix + row["file"]] = row["verdict"]

        newer_scan: dict[str, dict] = {}
        for path in a.override:
            for row in cls.rows(path):
                newer_scan[row["file"]] = row

        registry: dict[str, dict] = {}
        for path in a.registry:
            for row in cls.rows_any(path):
                if isinstance(row.get("facts"), dict):
                    registry[row["file"]] = row["facts"]
        sampled: set[str] = set()
        if a.registry:
            # The second review's run: npm and PyPI only, every row with a registry record, the
            # benign denominator the sample whose records were acquired. A unit without a record
            # would teach the model that having one is the signal.
            units = a.registry_units.read_text(encoding="utf-8").split()
            sampled = {u for u in units if u in registry}
            # Counted as rows are added: a sampled unit not yet scanned is not "quiet", it is
            # unmeasured, and stays out of the denominator.
            size = {"work": collections.Counter(), "holdout": collections.Counter()}

        def add(
            row: dict,
            label: int,
            eco: str,
            key: str,
            source: str,
            family: str,
            half: str | None = None,
        ) -> None:
            row = newer_scan.get(row["file"], row)
            if a.registry:
                facts = registry.get(row["file"])
                if facts is None or eco not in ("npm", "pypi"):
                    return
                if not label and row["file"] not in sampled:
                    return
                if not label:
                    size[cls.half(key)][eco] += 1
                verdict = row.get("verdict") or {}
                row = {
                    **row,
                    "verdict": {**verdict, "package": {**(verdict.get("package") or {}), **facts}},
                }
            if row["file"] in fresh:
                newer = fresh[row["file"]]
                row = {
                    **row,
                    "verdict": {
                        **(row.get("verdict") or {}),
                        "package": newer.get("package") or {},
                        "area": newer.get("area"),
                    },
                }
            features = cls.evidence(row)
            rules = {k[2:]: v for k, v in features.items() if k.startswith("r:") and "#" not in k}
            data.append(
                {
                    "file": row["file"],
                    "label": label,
                    "eco": eco,
                    "source": source,
                    "half": half or cls.half(key),
                    "family_half": half or cls.half(family),
                    "family": family,
                    "area": cls.area(row, eco, rules),
                    "f": features,
                    "findings": row["findings"],
                    "date": (re.search(r"/(20\d\d-\d\d-\d\d)-", row["file"]) or [None, ""])[1],
                }
            )

        # A labelled set scanned in full replaces the corpus directory it was drawn from: the MCP
        # servers (`mcpc`) are the corpus's `mcp` directory, every unit scanned.
        replaced = {"mcp"} if any(spec.startswith("mcpc=") for spec in a.labelled) else set()
        for half in size.values():
            for eco in replaced:
                half.pop(eco, None)
        seen: set[str] = set()
        for row in itertools.chain(cls.rows(a.benign), *(cls.rows(p) for p in a.registry_scans)):
            if row["file"] in seen:
                continue
            seen.add(row["file"])
            raw_eco = row["file"].split("/")[0]
            if raw_eco in replaced:
                continue
            eco = a.eco or ECOSYSTEM.get(raw_eco, raw_eco)
            key = "pkg:" + cls.package_name(row["file"])
            add(row, 0, eco, key, "corpus", key)
        if a.benchmark:
            # Every ecosystem's real malware, on the benchmark's own split: its holdout is never
            # trained on, whatever this trainer's hash would have said.
            manifest_path, scans_path = a.benchmark
            manifest = {
                r["path"]: r
                for r in cls.rows_any(manifest_path)
                if r.get("status") == "confirmed" and r.get("source") not in BENCHMARK_ELSEWHERE
            }
            for row in cls.rows(scans_path):
                m = manifest.get(row["file"])
                # The name the adjudications and earlier scans give the same sample.
                alias = row["file"].replace("data/datadog/samples/", "datadog/", 1)
                alias = alias.replace("data/malregistry/", "malregistry/", 1)
                if m is None or alias in excluded:
                    continue
                row = {**row, "file": alias}
                eco = BENCHMARK_ECOSYSTEM.get(m["ecosystem"], m["ecosystem"])
                verdict = row.get("verdict") or {}
                if verdict.get("area") in (None, Verdict.FALLBACK) and eco in AREAS:
                    # A scan from before every ecosystem had its own area: the manifest knows the
                    # ecosystem exactly, so the row answers to that ecosystem's line.
                    row = {**row, "verdict": {**verdict, "area": eco}}
                add(row, 1, eco, "bench:" + m["family"], m["source"], m["family"], m["split"])
        for row in cls.rows(a.malware) if a.malware else ():
            if row["file"] in excluded:
                continue
            u = row["file"]
            eco = (
                "npm"
                if u.startswith("datadog/npm")
                else "pypi"
                if u.startswith(("datadog/pypi", "malregistry"))
                else "openvsx"
                if u.startswith("datadog/ide")
                else "skill"
            )
            eco = a.eco or eco
            source = "malregistry" if u.startswith("malregistry") else "/".join(u.split("/")[:2])
            family = family_map.get(row["file"], cls.family_key(u))
            add(row, 1, eco, cls.malware_key(u), source, family)
        for spec in a.labelled:
            name, _, path = spec.partition("=")
            prefix, keyer = LABELLED[name]
            for row in cls.rows(Path(path)):
                unit = row["file"]
                if unit in excluded:
                    continue
                label = int(bool(prefix) and unit.startswith(prefix))
                key = keyer(unit)
                row = {**row, "file": f"{name}/{unit}"}
                add(row, label, name, key, name, key)
                if not label:
                    size[cls.half(key)][name] += 1
        return data, size

    @staticmethod
    def rows_any(path: Path):
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                yield json.loads(line)
            except ValueError:
                continue

    @staticmethod
    def area(row: dict, eco: str, rules: dict[str, int]) -> str:
        """The line a row answers to, as `Verdict.area` decides it at scan time.

        A scan that recorded its area is read as recorded. Older scans did not; the archive layout
        is then known from the ecosystem the unit came from, and the rest from what was recorded.
        """
        recorded = (row.get("verdict") or {}).get("area")
        if recorded == Verdict.FALLBACK and eco in AREAS:
            # Scanned before every ecosystem had an area of its own: the corpus folder names the
            # ecosystem. (A layout the scan still cannot place, Bazel's upstream source archives,
            # answers to the fallback line at scan time; round 2 trains on scans that record it.)
            return eco
        if recorded:
            return recorded
        package = (row.get("verdict") or {}).get("package") or {}
        if eco in ("mcp", "mcpv", "mcpc") or any(r.startswith("SUSPECT.MCP.") for r in rules):
            return "mcp"
        if (
            eco in ("npm", "pypi", "openvsx")
            or eco in {r for r, _ in Verdict._ECOSYSTEMS}
            or eco == "actions"
        ):
            return eco
        if package.get("skill") or eco in ("msb", "asb", "skills", "skill"):
            return "skill"
        return Verdict.FALLBACK

    @classmethod
    def unstable(cls, pair: list[Path], threshold: float = 0.01) -> set[str]:
        """Features whose value differs between two scans of the same units by two scanner
        versions on more than `threshold` of the units both scanned."""
        old = {r["file"]: cls.evidence(r) for r in cls.rows(pair[0]) if "findings" in r}
        differs: collections.Counter = collections.Counter()
        shared = 0
        for r in cls.rows(pair[1]):
            if "findings" not in r or r["file"] not in old:
                continue
            shared += 1
            before, after = old[r["file"]], cls.evidence(r)
            for k in before.keys() | after.keys():
                if abs(before.get(k, 0.0) - after.get(k, 0.0)) > 1e-6:
                    differs[k] += 1
        if shared < 500:
            raise SystemExit(f"--version-check: only {shared} units scanned by both versions")
        print(f"version check: {shared} units scanned by both")
        return {k for k, n in differs.items() if n / shared > threshold}

    @staticmethod
    def export(clf, names: list[str]) -> dict[str, Any]:
        """sklearn's HistGradientBoosting trees as `VerdictModel.score` walks them."""
        trees = []
        for predictors in clf._predictors:
            tree = []
            for n in predictors[0].nodes:
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
            "format": VerdictModel.FORMAT,
            "features": names,
            "baseline": float(clf._baseline_prediction.ravel()[0]),
            "trees": trees,
        }

    @classmethod
    def main(cls) -> None:
        import numpy as np
        from sklearn.ensemble import HistGradientBoostingClassifier

        p = argparse.ArgumentParser()
        p.add_argument("--corpus", type=Path, required=True, help="every benign corpus unit")
        p.add_argument("--benign", type=Path, required=True)
        p.add_argument(
            "--malware", type=Path, help="npm/PyPI malware scans (superseded by --benchmark)"
        )
        p.add_argument(
            "--eco",
            help="force this ecosystem for --benign/--malware rows when the path does not name one "
            "(a single-ecosystem corpus such as the PyPI baseline)",
        )
        p.add_argument(
            "--family-map",
            type=Path,
            help="json {scan file -> family} overriding the path-derived malware family "
            "(e.g. the S5 families of the PyPI half-A); benign keeps its PEP 503 normalised key",
        )
        p.add_argument(
            "--benchmark",
            type=Path,
            nargs=2,
            metavar=("MANIFEST", "SCANS"),
            help="the real-malware benchmark: every ecosystem, its own work/holdout split",
        )
        p.add_argument(
            "--labelled", nargs="*", default=[], help="NAME=PATH, NAME in " + ",".join(LABELLED)
        )
        p.add_argument("--adjudication", type=Path, nargs="*", default=[])
        p.add_argument(
            "--pending",
            type=Path,
            nargs="*",
            default=[],
            help="proposed adjudications still awaiting a second review: never applied, reported "
            "as the second denominator",
        )
        p.add_argument(
            "--features",
            nargs="*",
            default=[],
            help="NAME=PATH features-only passes (reviews/review-98/tools/features_only.py), NAME "
            "benign, malware or a --labelled name: their package features and area replace the "
            "scan's, unit by unit",
        )
        p.add_argument(
            "--override",
            type=Path,
            nargs="*",
            default=[],
            help="targeted rescans with a newer scanner: each record replaces the full scan's "
            "record of the same unit (the units a detector change can affect)",
        )
        p.add_argument(
            "--version-check",
            type=Path,
            nargs=2,
            metavar=("OLD", "FRESH"),
            help="benign scans of the same units by the training scans' scanner and the current "
            "one: features that differ between them are dropped",
        )
        p.add_argument(
            "--scope",
            nargs="*",
            default=[],
            help="the only areas the model judges (the scanner leaves every other area alone)",
        )
        p.add_argument("--budget", type=float, default=0.3, help="percent of an ecosystem's units")
        p.add_argument(
            "--keep-rule-min",
            type=int,
            default=10,
            help="untrained means untouched: a code rule seen on fewer than this many work-half "
            "malware units is kept (never re-graded or lifted), and an area with fewer than this "
            "many work-half malware units is add-only. The model lowers a block only where it has "
            "training support (review 98: the G7 fresh/actions regression came from lifting rules "
            "and areas the npm-only split never trained on -- REMOTE_TARBALL, EXFIL.DNS, DESTROY).",
        )
        p.add_argument(
            "--split",
            choices=("package", "family", "time", "p8"),
            default="package",
            help="package: halves by package name; family: malware by publisher family; time: "
            "malware published before --cutoff trains, after tests; p8: the halves in --p8-split",
        )
        p.add_argument("--cutoff", default="2026-05-01")
        p.add_argument(
            "--seed",
            type=int,
            default=0,
            help="RNG seed threaded through the CV family-fold shuffle and the trees",
        )
        p.add_argument(
            "--p8-split",
            type=Path,
            help="review-98 P8 split (data/p8-split.jsonl): per unit, train->work, later->holdout, "
            "campaign-aware so no family straddles. Used with --split p8 for malware AND benign.",
        )
        p.add_argument(
            "--leave-out", default="", help="a labelled set kept out of training entirely"
        )
        p.add_argument("--no-monotone", action="store_true")
        p.add_argument(
            "--add-only",
            nargs="*",
            default=[],
            help="areas where the verdict may add a block but never lift one",
        )
        p.add_argument(
            "--separate",
            nargs="*",
            default=[],
            help="areas given trees of their own, fitted on that area's rows only",
        )
        p.add_argument(
            "--registry",
            type=Path,
            nargs="*",
            default=[],
            help="registry facts (reviews/review-98/tools/registry_facts.py): the second review's "
            "publisher facts. With them the run is npm and PyPI only, on the units that have a "
            "record on both sides -- never content-only",
        )
        p.add_argument(
            "--registry-units",
            type=Path,
            help="the random benign units whose records were acquired: the benign denominator",
        )
        p.add_argument(
            "--registry-scans",
            type=Path,
            nargs="*",
            default=[],
            help="scans of sampled benign units the --benign file does not hold (quiet units)",
        )
        p.add_argument("--out", type=Path)
        p.add_argument("--report", type=Path)
        p.add_argument("--attribution", type=Path)
        p.add_argument("--dump", type=Path, help="every row: half, eco, area, label, score, kept")
        a = p.parse_args()

        if not (a.malware or a.benchmark):
            raise SystemExit("--malware or --benchmark is required")
        data, size = cls.load(a)
        p8_halves: dict[str, str] = {}
        if a.p8_split:
            for row in cls.rows_any(a.p8_split):
                p8_halves[row["unit"]] = "work" if row["split"] == "train" else "holdout"
        for r in data:
            if a.split == "p8":
                # The review-98 campaign-aware split: a unit not in it is unmeasured, not quiet.
                r["half"] = p8_halves.get(r["file"], "none")
            if a.split == "family" and r["label"] and r["source"].startswith("datadog"):
                r["half"] = r["family_half"]
            if a.split == "time" and r["label"] and r["date"]:
                r["half"] = "work" if r["date"] < a.cutoff else "holdout"
            if (
                a.split == "time"
                and r["label"]
                and not r["date"]
                and r["source"].startswith("datadog")
            ):
                r["half"] = "none"
            if a.leave_out and r["eco"] == a.leave_out:
                r["half"] = "holdout"
        if a.scope:
            # One ecosystem at a time: train, set lines and report only where the model will judge.
            data = [r for r in data if r["area"] in a.scope]
        unstable = cls.unstable(a.version_check) if a.version_check else set()
        if unstable:
            # A feature the scanner computes differently now than when these scans were made
            # teaches the model the scanner's version, not malware (round 1, 2026-10-19: benign
            # scans without `import_files`, malware scans with it -> 64% of benign npm blocked).
            print(f"dropped {len(unstable)} version-unstable features: {sorted(unstable)[:40]}")
            for r in data:
                r["f"] = {k: v for k, v in r["f"].items() if k not in unstable}
        work = [r for r in data if r["half"] == "work" and r["eco"] != a.leave_out]
        test = [r for r in data if r["half"] == "holdout"]
        if a.split == "p8":
            # The ship bar: the >=2-distinct-domain-at->=MEDIUM baseline on the holdout. The trained
            # model must beat it -- more malware blocked at no more benign blocked.
            def two_domain(findings: list) -> bool:
                domains = set()
                for f in findings or []:
                    try:
                        sev = Severity[f[1].upper()]
                    except (KeyError, IndexError, AttributeError):
                        continue
                    if sev >= Severity.MEDIUM:
                        domains.add(Taxonomy.domain_of(f[0]))
                return len(domains) >= 2

            mal = [r for r in test if r["label"]]
            ben = [r for r in test if not r["label"]]
            bm = sum(two_domain(r["findings"]) for r in mal)
            bb = sum(two_domain(r["findings"]) for r in ben)
            print(
                f"P8 >=2-domain baseline (holdout): malware {bm}/{len(mal)} = "
                f"{100 * bm / max(1, len(mal)):.1f}%, benign {bb}/{len(ben)} = "
                f"{100 * bb / max(1, len(ben)):.2f}% -- the model must beat this"
            )
        names = sorted({k for r in work for k in r["f"]})
        index = {k: i for i, k in enumerate(names)}

        def matrix(rows):
            x = np.zeros((len(rows), len(names)), dtype=np.float32)
            for i, r in enumerate(rows):
                for k, v in r["f"].items():
                    if k in index:
                        x[i, index[k]] = v
            return x

        monotone = [0 if (a.no_monotone or k.startswith("pkg:")) else 1 for k in names]

        def model():
            return HistGradientBoostingClassifier(
                max_iter=300,
                learning_rate=0.08,
                max_leaf_nodes=31,
                l2_regularization=1.0,
                monotonic_cst=monotone,
                random_state=a.seed,
            )

        xw, yw = matrix(work), np.array([r["label"] for r in work])
        # The floor: code rules that, at high confidence and high severity, fired on no benign unit
        # of the work half and on at least three malware samples there. Chosen by that evidence,
        # not by the rule's prefix: `SUSPECT.EXFIL.WALLET_SECRET.001` blocked every hijacked `xrpl`
        # release at high confidence and the model held it as a warning (review 98).
        strong = collections.Counter()
        misfired = collections.Counter()
        for r in work:
            for f in r["findings"]:
                if (
                    VerdictFeatures.is_code(f[0])
                    and f[2] in ("high", "confirmed")
                    and Severity[f[1].upper()] >= Severity.HIGH
                ):
                    (strong if r["label"] else misfired)[f[0]] += 1
        floor = sorted(rule for rule, n in strong.items() if n >= 3 and not misfired[rule])
        floor_set = frozenset(floor)
        # Untrained means untouched (review 98, the G7 fresh/actions regression): the model may
        # lower a block only for a rule it actually learned. A code rule seen on fewer than
        # --keep-rule-min work-half malware units is kept, not re-graded -- the A/B showed the
        # model lifting rare-rule blocks it never trained on (SUSPECT.DEPENDENCY.REMOTE_TARBALL,
        # EXFIL.DNS, DESTROY.HOME_OR_ROOT, DECODE_EXEC.INVISIBLE), a fresh-set net loss.
        rule_support = collections.Counter()
        for r in work:
            if not r["label"]:
                continue
            for rule in {
                f[0] for f in r["findings"] if VerdictFeatures.is_code(f[0]) and cls.trips(f)
            }:
                rule_support[rule] += 1

        def trained(rule: str) -> bool:
            return rule_support[rule] >= a.keep_rule_min

        rare_rules = {
            f[0]
            for r in data
            for f in r["findings"]
            if VerdictFeatures.is_code(f[0]) and not trained(f[0])
        }
        # An area with fewer than --keep-rule-min work-half malware units is add-only: the model
        # has no basis to lift a block there. Under the npm-only P8 split that is actions and every
        # non-npm area; npm (and skill/mcp if above the floor) keep full re-grading.
        area_malware = collections.Counter(r["area"] for r in work if r["label"])
        add_only_areas = set(a.add_only) | {
            area for area in {r["area"] for r in data} if area_malware[area] < a.keep_rule_min
        }
        # The allowlist the model SHIPS (`lift_areas`): the areas it may lower a block in -- those
        # with enough work-half malware to have trained on. The scanner default-denies every other
        # area, `package` and the fallback included, so an area the scan computes but the split
        # never trained (actions as `package`) is add-only, not lifted (review 98 G7).
        lift_areas = {r["area"] for r in data} - add_only_areas
        print(
            f"keep-rule-min={a.keep_rule_min}: {len(rare_rules)} thin-support rules + "
            f"{len(NAME_PROVENANCE_RULES)} name/provenance rules in `keep`; "
            f"lift_areas (>={a.keep_rule_min} work malware): {sorted(lift_areas)}"
        )

        def untouched_trip(r, content_only: bool) -> bool:
            """A finding the verdict never re-grades trips the gate."""
            for f in r["findings"]:
                if f[0].startswith(NOT_MALWARE) or (
                    content_only and VerdictFeatures.is_intel(f[0])
                ):
                    continue
                code = VerdictFeatures.is_code(f[0])
                kept = (
                    not code
                    or (f[0] in floor_set and f[2] in ("high", "confirmed"))
                    or not trained(f[0])
                    or f[0] in NAME_PROVENANCE_RULES
                )
                if kept and cls.trips(f):
                    return True
            return False

        def gate_trip(r, content_only: bool) -> bool:
            """Any finding trips the gate, as it does without the verdict."""
            return any(
                cls.trips(f)
                for f in r["findings"]
                if not f[0].startswith(NOT_MALWARE)
                and not (content_only and VerdictFeatures.is_intel(f[0]))
            )

        def content_block(r) -> bool:
            # The shipped scanner's content gate (bench/tools/content.py): one definition of
            # "blocked", so an add-only area's model can never remove a block the content rules make.
            return any(
                len(f) >= 7
                and Content.fails(f[0], f[1], f[2], f[3])
                and Content.is_content(f[0], f[6])
                for f in r["findings"]
            )

        for r in data:
            add_only = r["area"] in add_only_areas
            floor = content_block(r) if add_only else False  # add-only ORs with the content gate
            r["kept"] = (gate_trip if add_only else untouched_trip)(r, content_only=True) or floor
            r["kept_intel"] = (
                gate_trip if add_only else untouched_trip
            )(r, content_only=False) or floor
            r["has_code"] = any(k.startswith("r:") for k in r["f"])

        groups = {x: [i for i, r in enumerate(work) if r["area"] == x] for x in a.separate}
        taken = {i for idx in groups.values() for i in idx}
        groups["*"] = [i for i in range(len(work)) if i not in taken]
        for idx in groups.values():
            if not idx:
                continue
            idx_a = np.array(idx, dtype=int)
            # Family-grouped, seeded CV: whole families go to one fold (the work half is already
            # family-whole), so an out-of-fold score is never set with a sibling release on the
            # training side. Families are shuffled by --seed and dealt round-robin into 5 folds,
            # which keeps every fold non-empty when there are at least five families. With fewer
            # (a small area), the original positional split is used so every row is still scored.
            members: dict[str, list[int]] = collections.defaultdict(list)
            for pos, i in enumerate(idx_a):
                members[work[int(i)]["family"]].append(pos)
            g = np.empty(len(idx_a), dtype=int)
            if len(members) >= 5:
                fam_keys = list(members)
                np.random.default_rng(a.seed).shuffle(fam_keys)
                for fold_i, fam in enumerate(fam_keys):
                    for pos in members[fam]:
                        g[pos] = fold_i % 5
            else:
                g = np.arange(len(idx_a)) % 5
            for k in range(5):
                tr, te = idx_a[g != k], idx_a[g == k]
                fold = model().fit(xw[tr], yw[tr]).predict_proba(xw[te])[:, 1]
                for i, s_ in zip(te, fold, strict=True):
                    work[i]["score"] = float(s_)
        oof = np.array([r["score"] for r in work])

        def blocked(r, lines, intel=False) -> bool:
            # The second review scores content-free packages too: that is what it is for.
            over = (r["has_code"] or bool(a.registry)) and r["score"] >= lines.get(
                r["area"], lines[Verdict.FALLBACK]
            )
            return bool(over or (r["kept_intel"] if intel else r["kept"]))

        def benign_rates(rows, lines, half) -> dict[str, tuple[int, int]]:
            hit = collections.Counter(
                r["eco"] for r in rows if not r["label"] and blocked(r, lines)
            )
            return {e: (hit[e], size[half][e]) for e in size[half] if size[half][e]}

        # Lines: start blocking nothing by score, then lower each area's line as far as every
        # ecosystem it touches stays within budget -- counting what the other areas already block.
        areas = sorted({r["area"] for r in work} | {Verdict.FALLBACK})
        lines = dict.fromkeys(areas, 1.01)
        grid = np.unique(np.concatenate([np.round(oof, 4), [1.01]]))
        first = ("skill", "mcp", "npm", "pypi", "openvsx")
        for area in [*first, *sorted(set(lines) - {*first, Verdict.FALLBACK}), Verdict.FALLBACK]:
            if area not in lines:
                continue
            touched = {r["eco"] for r in work if r["area"] == area and not r["label"]}
            # What each ecosystem already blocks without this area's score. One within budget must
            # stay within it; one already over (an add-only area's gate) may take at most a sliver
            # more, so a failing ecosystem neither pins every other line nor gets worse.
            base = benign_rates(work, {**lines, area: 1.01}, "work")
            cap = {
                e: max(a.budget / 100 * n, k + 0.0005 * n)
                for e, (k, n) in base.items()
                if e in touched
            }

            def ok(t, area=area, cap=cap) -> bool:
                rates = benign_rates(work, {**lines, area: t}, "work")
                return all(rates[e][0] <= c for e, c in cap.items())

            lo, hi = 0, len(grid) - 1
            while lo < hi:  # the lowest line within budget; blocking only grows as it falls
                mid = (lo + hi) // 2
                if ok(float(grid[mid])):
                    hi = mid
                else:
                    lo = mid + 1
            lines[area] = float(grid[lo])
        # A package whose kind the scan cannot tell answers to the strictest package line.
        lines[Verdict.FALLBACK] = max(
            lines[x] for x in lines if x not in ("skill", "mcp") and x not in add_only_areas
        )
        # An untrained area is pass-through: the model neither lifts (G7) nor adds a block by its
        # score there, since the score has no training support. Its line blocks nothing, so the
        # outcome equals today's gate (kept = gate_trip). Reducing benign in these areas is the
        # G6 rule work's job, not the model's.
        for area in add_only_areas:
            lines[area] = 1.01

        fitted = {x: model().fit(xw[idx], yw[idx]) for x, idx in groups.items()}
        xt = matrix(test)
        for x, clf in fitted.items():
            idx = [
                i for i, r in enumerate(test) if (r["area"] if r["area"] in fitted else "*") == x
            ]
            if idx:
                for i, s_ in zip(idx, clf.predict_proba(xt[idx])[:, 1], strict=True):
                    test[i]["score"] = float(s_)
        exported = cls.export(fitted["*"], names)
        if a.separate:
            exported["by_area"] = {x: cls.export(fitted[x], names) for x in a.separate}
        # The exported trees must score exactly what was measured.
        drift = max(
            (
                abs(
                    VerdictModel.score(exported.get("by_area", {}).get(r["area"], exported), r["f"])
                    - r["score"]
                )
                for r in test[:500]
            ),
            default=0,
        )
        print(f"exported trees against sklearn, largest difference: {drift:.2e}")
        if drift >= 1e-4:
            raise SystemExit(f"exported trees do not score what was measured: {drift}")

        def ci_low(k: int, n: int) -> float:
            if not n:
                return 0.0
            z, ph = 1.96, k / n
            centre = ph + z * z / (2 * n)
            margin = z * ((ph * (1 - ph) / n + z * z / (4 * n * n)) ** 0.5)
            return round(100 * (centre - margin) / (1 + z * z / n), 2)

        report: dict[str, Any] = {
            "split": a.split,
            "leave_out": a.leave_out,
            "budget_percent": a.budget,
            "lines": lines,
            "floor": floor,
            "add_only": sorted(add_only_areas),
            "lift_areas": sorted(lift_areas),
            "keep": sorted(rare_rules | NAME_PROVENANCE_RULES),
            "benign_blocked": {},
            "malware_caught": {},
        }
        pending: set[str] = set()
        fixtures: set[str] = set()
        for path in a.pending:
            for r in cls.rows_any(path):
                verdict = r.get("proposed") or r.get("verdict")
                if verdict in EXCLUDED and r.get("file"):
                    pending.add(r["file"])
                if verdict == "malicious-fixture" and r.get("file"):
                    fixtures.add(r["file"])
        relabelled = collections.Counter(
            r["eco"]
            for r in test
            if not r["label"] and r["file"].split("/", 1)[-1] in fixtures and blocked(r, lines)
        )
        dropped = collections.Counter(
            r["eco"] for r in test if not r["label"] and r["file"].split("/", 1)[-1] in fixtures
        )
        for eco, (k, n) in sorted(benign_rates(test, lines, "holdout").items()):
            report["benign_blocked"][eco] = {
                "blocked": k,
                "units": n,
                "percent": round(100 * k / n, 3),
                "within_bar": k / n <= 0.005,
            }
            if dropped[eco]:
                k2, n2 = k - relabelled[eco], n - dropped[eco]
                report["benign_blocked"][eco]["percent_if_pending_accepted"] = round(
                    100 * k2 / n2, 3
                )
        by: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0, 0, 0, 0])
        for r in test:
            if r["label"]:
                for key in (r["source"], "ALL"):
                    by[key][0] += 1
                    by[key][1] += blocked(r, lines)
                    by[key][2] += blocked(r, lines, intel=True)
                    if r["file"] not in pending:
                        by[key][3] += 1
                        by[key][4] += blocked(r, lines)
        for key, (n, k, ki, n2, k2) in sorted(by.items()):
            report["malware_caught"][key] = {
                "samples": n,
                "content_only": round(100 * k / n, 2),
                "content_only_ci95_low": ci_low(k, n),
                "with_intel": round(100 * ki / n, 2),
                "content_only_if_pending_accepted": round(100 * k2 / max(n2, 1), 2),
                "samples_if_pending_accepted": n2,
            }
        print(json.dumps(report, indent=1))
        if a.dump:
            with a.dump.open("w", encoding="utf-8") as handle:
                for r in work + test:
                    handle.write(
                        json.dumps(
                            {
                                k: r.get(k)
                                for k in ("file", "half", "eco", "area", "label", "score", "kept")
                            }
                            | {"has_code": r["has_code"]}
                        )
                        + "\n"
                    )
        if a.attribution:
            with a.attribution.open("w", encoding="utf-8") as handle:
                for r in test:
                    b = blocked(r, lines)
                    if bool(r["label"]) == b:
                        continue
                    handle.write(
                        json.dumps(
                            {
                                "file": r["file"],
                                "label": "malware" if r["label"] else "benign",
                                "outcome": "missed" if r["label"] else "blocked",
                                "eco": r["eco"],
                                "area": r["area"],
                                "score": round(r["score"], 4),
                                "line": lines.get(r["area"], lines[Verdict.FALLBACK]),
                                "by_floor": r["kept"],
                                "rules": sorted(
                                    (k[2:] for k in r["f"] if k.startswith("r:") and "#" not in k),
                                    key=lambda k: -r["f"]["r:" + k],
                                )[:8],
                            }
                        )
                        + "\n"
                    )
        if a.out:
            body = {
                **exported,
                "areas": lines,
                "floor": floor,
                "add_only": sorted(add_only_areas),
                "lift_areas": sorted(lift_areas),
                "keep": sorted(rare_rules | NAME_PROVENANCE_RULES),
            }
            if a.scope:
                body["scope"] = sorted(a.scope)
            digest = hashlib.sha256(
                json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            body["version"] = f"{datetime.date.today().isoformat()}-{digest[:12]}"
            body["manifest"] = {
                "digest": digest,
                "trained_on": {
                    "half": "work",
                    "benign": int(len(yw) - yw.sum()),
                    "malware": int(yw.sum()),
                    "inputs": [
                        str(a.benign),
                        str(a.malware),
                        *map(str, a.benchmark or ()),
                        *a.labelled,
                    ],
                },
                "budget_percent": a.budget,
                "measured_holdout": {
                    "benign_blocked": report["benign_blocked"],
                    "malware_caught": report["malware_caught"],
                },
            }
            with gzip.open(a.out, "wt", encoding="utf-8") as handle:
                json.dump(body, handle, separators=(",", ":"))
        if a.report:
            a.report.write_text(json.dumps(report, indent=1), encoding="utf-8")


if __name__ == "__main__":
    VerdictTrain.main()
