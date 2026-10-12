"""Noise budgets only tighten, and the check fails a rule that got noisier.

```
  summary ── derive ──► budgets (per 10,000 packages)  ── check(new summary) ──► failures
```
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "bench"))

from budgets import Budgets


class Summaries:
    @staticmethod
    def of(
        blocks: list[tuple[str, int]], warns: list[tuple[str, int]], no_warning: float
    ) -> dict[str, object]:
        return {
            "all": {
                "scanned": 10_000,
                "errors": 0,
                "known_malicious": 0,
                "no_warning_rate": no_warning,
            },
            "block_rules": [list(b) for b in blocks],
            "warn_rules": [list(w) for w in warns],
        }


class TestBudgets:
    def test_a_rule_within_its_budget_passes(self) -> None:
        budgets = Budgets.derive(Summaries.of([("R.BLOCK", 10)], [("R.WARN", 200)], 0.9), None)
        assert Budgets.check(Summaries.of([("R.BLOCK", 11)], [("R.WARN", 210)], 0.9), budgets) == []

    def test_a_noisier_rule_fails(self) -> None:
        budgets = Budgets.derive(Summaries.of([("R.BLOCK", 10)], [], 0.9), None)
        assert Budgets.check(Summaries.of([("R.BLOCK", 30)], [], 0.9), budgets)

    def test_a_new_blocking_rule_needs_a_budget(self) -> None:
        budgets = Budgets.derive(Summaries.of([], [], 0.9), None)
        assert Budgets.check(Summaries.of([("R.NEW", 1)], [], 0.9), budgets)

    def test_a_lower_no_warning_rate_fails(self) -> None:
        budgets = Budgets.derive(Summaries.of([], [], 0.95), None)
        assert Budgets.check(Summaries.of([], [], 0.90), budgets)

    def test_budgets_only_tighten(self) -> None:
        first = Budgets.derive(Summaries.of([("R", 10)], [], 0.9), None)
        second = Budgets.derive(Summaries.of([("R", 50)], [], 0.8), first)
        assert second["rules"]["R"]["block"] == 10.0
        assert second["no_warning_rate"] == 0.9
