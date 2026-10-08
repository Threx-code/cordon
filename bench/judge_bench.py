#!/usr/bin/env python3
"""The agent judge, measured: does a model catch new wordings without flagging real projects?

Three measurements, each on text nothing in Cordon was tuned on:

1. The agent matrix's instruction texts -- every distinct attack and benign body, including both
   held-out wording sets (`bench/agent_matrix.py`).
2. ATR's held-out rule families: attacks and benign twins of the rules whose id hashes into the
   held-out 30% (the split `scripts/import_atr.py` documents), sampled with a fixed seed.
3. A fresh real-world corpus (`bench/fetch_agent_configs.py --fresh`): every committed instruction
   file, judged whole -- the false-alarm rate on real projects.

    python bench/judge_bench.py --judge ollama:qwen2.5:7b --atr ATR --corpus FRESH --cache DIR

Verdicts are cached, so a stopped run resumes. A text counts as flagged when the judge calls it
malicious with evidence that is in the text -- what `--judge` reports at MEDIUM.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

import agent_matrix as matrix
from fetch_agent_configs import INSTRUCTION_FILES

from cordon_scanner.judge import (
    BudgetExhausted,
    Chunker,
    Judge,
    JudgeError,
    ProviderFactory,
    VerdictCache,
)

HELD_OUT_SHARE = 30


class JudgeBench:
    """Runs the judge over the three sets and keeps a tally per set."""

    def __init__(self, judge: Judge) -> None:
        self.judge = judge
        self.rows: list[dict[str, Any]] = []

    def flagged(self, kind: str, path: str, text: str, *, suspicious: bool = False) -> bool | None:
        """Whether any piece of `text` is judged malicious with verified evidence; None on failure."""
        for chunk in Chunker.split(text):
            try:
                verdict = self.judge.judge(kind, path, chunk)
            except (BudgetExhausted, JudgeError):
                return None
            if verdict is None:
                continue
            wanted = ("malicious", "suspicious") if suspicious else ("malicious",)
            if verdict.verdict in wanted and verdict.verified:
                return True
        return False

    def record(
        self, group: str, name: str, attack: bool, text: str, path: str = "CLAUDE.md"
    ) -> None:
        result = self.flagged("agent instruction file", path, text)
        self.rows.append({"group": group, "name": name, "attack": attack, "flagged": result})
        print(
            f"  {group:22} {'attack' if attack else 'benign'} {result!s:5} {name[:60]}", flush=True
        )

    def matrix(self) -> None:
        sets = [
            ("matrix/dev", matrix.INSTRUCTION_ATTACKS, True),
            ("matrix/held-out", matrix.INSTRUCTION_HELD_OUT, True),
            ("matrix/held-out-2", matrix.INSTRUCTION_HELD_OUT_2, True),
        ]
        for group, rows, _ in sets:
            for family, variant, body in rows:
                self.record(group, f"{family}/{variant}", True, matrix.Carriers._md(body))
        benign = [
            ("matrix/benign", [(v, b) for v, b in matrix.INSTRUCTION_BENIGN]),
            ("matrix/held-out-benign", list(matrix.INSTRUCTION_HELD_OUT_BENIGN)),
            ("matrix/held-out-2-benign", list(matrix.INSTRUCTION_HELD_OUT_2_BENIGN)),
        ]
        for group, rows in benign:
            for variant, body in rows:
                self.record(group, variant, False, matrix.Carriers._md(body))

    def atr(self, checkout: Path, sample: int) -> None:
        attacks: list[tuple[str, str]] = []
        benign: list[tuple[str, str]] = []
        for path in sorted((checkout / "rules").rglob("*.yaml")):
            try:
                rule = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError:
                continue
            if not isinstance(rule, dict) or "id" not in rule or rule.get("status") == "deprecated":
                continue
            rule_id = str(rule["id"])
            if hashlib.sha256(rule_id.encode()).digest()[0] % 100 >= HELD_OUT_SHARE:
                continue
            tests = rule.get("test_cases") or {}
            for key, bucket in (("true_positives", attacks), ("true_negatives", benign)):
                for case in tests.get(key) or ():
                    text = case.get("input") if isinstance(case, dict) else None
                    if isinstance(text, dict):
                        text = json.dumps(text)
                    for field in ("tool_response", "content", "user_input", "tool_description"):
                        if (
                            text is None
                            and isinstance(case, dict)
                            and isinstance(case.get(field), str)
                        ):
                            text = case[field]
                    if isinstance(text, str) and text.strip():
                        bucket.append((rule_id, text))
        rng = random.Random(5)  # noqa: S311  (a reproducible sample, not a secret)
        for group, bucket, attack in (
            ("atr/held-out-attack", attacks, True),
            ("atr/held-out-benign", benign, False),
        ):
            for rule_id, text in rng.sample(bucket, min(sample, len(bucket))):
                self.record(group, rule_id, attack, text)

    def corpus(self, directory: Path, sample: int | None) -> None:
        files = [
            (repo, path)
            for repo in sorted((directory / "files").iterdir())
            if repo.is_dir()
            for path in sorted(repo.rglob("*"))
            if path.is_file() and path.name in INSTRUCTION_FILES
        ]
        if sample is not None and sample < len(files):
            files = random.Random(9).sample(files, sample)  # noqa: S311  (reproducible, not secret)
        for repo, path in files:
            text = path.read_text(encoding="utf-8", errors="replace")
            self.record("fresh-corpus", f"{repo.name}/{path.name}", False, text, path.name)

    def summary(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for group in dict.fromkeys(r["group"] for r in self.rows):
            rows = [r for r in self.rows if r["group"] == group and r["flagged"] is not None]
            if not rows:
                continue
            attack = rows[0]["attack"]
            good = sum(1 for r in rows if r["flagged"] == attack)
            label = "caught" if attack else "left clean"
            out[group] = f"{label} {good}/{len(rows)} ({good / len(rows):.1%})"
        return out

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--judge", required=True)
        parser.add_argument("--atr", type=Path)
        parser.add_argument("--atr-sample", type=int, default=150)
        parser.add_argument("--corpus", type=Path)
        parser.add_argument(
            "--corpus-sample",
            type=int,
            help="judge this many corpus files, drawn with a fixed seed",
        )
        parser.add_argument("--cache", type=Path, required=True)
        parser.add_argument("--json", type=Path)
        args = parser.parse_args()
        judge = Judge(
            ProviderFactory.from_spec(args.judge), cache=VerdictCache(args.cache), max_calls=10**9
        )
        bench = JudgeBench(judge)
        bench.matrix()
        if args.atr:
            bench.atr(args.atr, args.atr_sample)
        if args.corpus:
            bench.corpus(args.corpus, args.corpus_sample)
        summary = bench.summary()
        print(json.dumps(summary, indent=1))
        if args.json:
            args.json.write_text(
                json.dumps({"summary": summary, "rows": bench.rows}, indent=1), encoding="utf-8"
            )
        return 0


if __name__ == "__main__":
    sys.exit(JudgeBench.main())
