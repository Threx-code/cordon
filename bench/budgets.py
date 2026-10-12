#!/usr/bin/env python3
"""Per-rule noise budgets on the benign long tail, and the check that holds them (MEAS-6).

```
  longtail_levels.py summary (packages a rule BLOCKED / WARNED on, out of N scanned)
        │
        ├── derive ──► bench/budgets.json   per rule: packages per 10,000, at each level
        │                                   (a new derive can only lower a budget, never raise it)
        │
        └── check  ──► exit 1 when any rule fires above its budget, a rule with no budget blocks
                       at all, or the overall no-warning rate falls below the recorded one
```

    python3 bench/budgets.py derive bench/longtail/summary.json
    python3 bench/budgets.py check  bench/longtail/subset-summary.json

A budget is a ceiling measured on real packages, not a target: a rule that needs more room is a
rule that got noisier, and that is the regression this exists to stop.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BUDGETS = Path(__file__).resolve().parent / "budgets.json"
PER = 10_000
SLACK = 1.25
"""Room for sampling noise when a subset is checked against budgets set on the full corpus: a
rule may fire up to 25% above its measured rate, plus one package, before the check fails."""


class Budgets:
    @staticmethod
    def rates(summary: dict[str, object]) -> tuple[int, dict[str, dict[str, float]]]:
        scanned = (
            int(summary["all"]["scanned"])
            - int(summary["all"]["errors"])
            - int(  # type: ignore[index]
                summary["all"]["known_malicious"]  # type: ignore[index]
            )
        )
        out: dict[str, dict[str, float]] = {}
        for level, key in (("block", "block_rules"), ("warn", "warn_rules")):
            for rule, packages in summary.get(key, []):  # type: ignore[union-attr]
                out.setdefault(rule, {})[level] = round(packages * PER / max(scanned, 1), 2)
        return scanned, out

    @classmethod
    def derive(
        cls, summary: dict[str, object], previous: dict[str, object] | None
    ) -> dict[str, object]:
        scanned, rates = cls.rates(summary)
        old = (previous or {}).get("rules", {})
        rules: dict[str, dict[str, float]] = {}
        for rule, levels in rates.items():
            for level, rate in levels.items():
                prior = old.get(rule, {}).get(level) if isinstance(old, dict) else None
                rules.setdefault(rule, {})[level] = rate if prior is None else min(rate, prior)
        no_warning = summary["all"]["no_warning_rate"]  # type: ignore[index]
        prior_rate = (previous or {}).get("no_warning_rate")
        return {
            "per": PER,
            "scanned": scanned,
            "no_warning_rate": no_warning if prior_rate is None else max(no_warning, prior_rate),
            "rules": dict(sorted(rules.items())),
        }

    @classmethod
    def check(cls, summary: dict[str, object], budgets: dict[str, object]) -> list[str]:
        scanned, rates = cls.rates(summary)
        limits = budgets["rules"]
        failures: list[str] = []
        for rule, levels in sorted(rates.items()):
            for level, rate in levels.items():
                limit = limits.get(rule, {}).get(level)  # type: ignore[union-attr]
                if limit is None:
                    if level == "block":
                        failures.append(f"{rule} blocks {rate}/10k packages and has no budget")
                    continue
                allowed = limit * SLACK + PER / max(scanned, 1)
                if rate > allowed:
                    failures.append(f"{rule} {level}s {rate}/10k packages; budget {limit}/10k")
        floor = float(budgets["no_warning_rate"]) - 0.01  # type: ignore[arg-type]
        measured = float(summary["all"]["no_warning_rate"])  # type: ignore[index]
        if measured < floor:
            failures.append(
                f"no-warning rate {measured:.2%} is below the recorded {floor + 0.01:.2%}"
            )
        return failures

    @classmethod
    def main(cls) -> int:
        parser = argparse.ArgumentParser(
            description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
        )
        parser.add_argument("action", choices=("derive", "check"))
        parser.add_argument("summary", type=Path)
        args = parser.parse_args()
        summary = json.loads(args.summary.read_text(encoding="utf-8"))
        previous = json.loads(BUDGETS.read_text(encoding="utf-8")) if BUDGETS.exists() else None
        if args.action == "derive":
            BUDGETS.write_text(
                json.dumps(cls.derive(summary, previous), indent=1) + "\n", encoding="utf-8"
            )
            return 0
        if previous is None:
            print("no budgets yet: run derive on the full long-tail summary first", file=sys.stderr)
            return 2
        failures = cls.check(summary, previous)
        for failure in failures:
            print(failure)
        return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(Budgets.main())
