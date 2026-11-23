"""The stages a candidate rule passes in order, and the first one it cannot.

A candidate that would block legitimate packages is stopped by the earliest stage that can see it: the pre-test (the Wilson upper bound
of its legitimate fire rate, `PreTest`), the gate (the rate on the benign sets within the ecosystem budget), the shadow run (the
rate seen on live scans while it only warns) and the device's rollback (`RuleBreaker.THRESHOLD`, the share of local scans it may
block in a day). `Stages.run` takes the rate each stage would see and returns the stage that stopped the candidate, or none.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

from bench.cdi.pretest import PreTest

from cordon_scanner.cloud.agent.rule_breaker import RuleBreaker


class Stages:
    ORDER: ClassVar[tuple[str, ...]] = ("pretest", "gate", "shadow", "rollback")
    GATE_BUDGET: ClassVar[float] = 0.003
    """The share of an ecosystem's benign units a block may add at the gate (the loop's `--budget` of 0.3%)."""
    SHADOW_BUDGET: ClassVar[float] = 0.01

    @classmethod
    def run(cls, rates: Mapping[str, tuple[int, int]]) -> dict[str, Any]:
        """`rates` gives `(blocked, units)` for each stage that has a measurement; a stage with none is passed over. The record
        names the stage that stopped the candidate (`stopped_at`), the stages it passed, and why."""
        passed: list[str] = []
        for stage in cls.ORDER:
            if stage not in rates:
                continue
            blocked, units = rates[stage]
            reason = cls.refusal(stage, blocked, units)
            if reason is not None:
                return {"stopped_at": stage, "passed": passed, "reason": reason}
            passed.append(stage)
        return {"stopped_at": None, "passed": passed, "reason": ""}

    @classmethod
    def refusal(cls, stage: str, blocked: int, units: int) -> str | None:
        rate = blocked / units if units else 1.0
        if stage == "pretest":
            upper = PreTest.legit_bound(blocked, units)
            return None if upper <= PreTest.LEGIT_UPPER else f"legitimate upper bound {upper:.4f}"
        limit = {
            "gate": cls.GATE_BUDGET,
            "shadow": cls.SHADOW_BUDGET,
            "rollback": RuleBreaker.THRESHOLD,
        }[stage]
        return None if rate <= limit else f"{blocked} of {units} ({rate:.1%}) is over {limit:.1%}"


__all__ = ["Stages"]
