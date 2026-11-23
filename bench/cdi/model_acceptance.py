"""The acceptance of a model candidate: seven checks, run as one report.

A candidate model is accepted only when every one of these holds, and the report says which did not and why:

    lose_zero         no malware unit the base build blocks is lost, on the work half
    legit_ceiling     the upper 95% bound of the legitimate units blocked is at most 0.5%, on all of each area's data
    levers_alone      each lever (the model, the rules, a combination ...) was measured on its own, not only together
    ablation          for each input family, the model without it was measured; a family that adds false blocks and catches no
                      malware is named to be removed, and the candidate is not accepted while it is in
    detector_only     the blocks only the model makes (no rule blocks the unit) are reported on their own, with their legit count
    same_features     what was trained is what is scored: the feature schema digest of the training rows equals that of the records
                      the shipped scanner writes
    scored_once       each held-out set was scored once: the seal log shows one use of it, not two

Inputs are counts and digests, never a unit name. Nothing here trains or scans."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from bench.cdi.gate import Gate

CEILING: Final = 0.005
CHECKS: Final = (
    "lose_zero",
    "legit_ceiling",
    "levers_alone",
    "ablation",
    "detector_only",
    "same_features",
    "scored_once",
)


class ModelAcceptance:
    @staticmethod
    def _result(name: str, passed: bool, reason: str = "") -> dict[str, Any]:
        return {"check": name, "passed": passed, "reason": "" if passed else reason}

    @classmethod
    def lose_zero(cls, work: Mapping[str, Any]) -> dict[str, Any]:
        lost = work.get("malware_lost")
        if not isinstance(lost, int):
            return cls._result("lose_zero", False, "the work half's lost malware count is not stated")
        return cls._result("lose_zero", lost == 0, f"{lost} malware units the base blocks are lost on the work half")

    @classmethod
    def legit_ceiling(cls, areas: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
        if not areas:
            return cls._result("legit_ceiling", False, "no area's legitimate count is stated")
        for area in sorted(areas):
            blocked, total = areas[area].get("legit_blocked"), areas[area].get("legit_n")
            if not isinstance(blocked, int) or not isinstance(total, int) or total <= 0 or blocked > total:
                return cls._result("legit_ceiling", False, f"area {area}: the legitimate counts are missing or inconsistent")
            upper = Gate.wilson(blocked, total)[1]
            if upper > CEILING:
                return cls._result("legit_ceiling", False, f"area {area}: the upper bound {upper:.2%} is over {CEILING:.1%}")
        return cls._result("legit_ceiling", True)

    @classmethod
    def levers_alone(cls, levers: Mapping[str, Any], required: tuple[str, ...]) -> dict[str, Any]:
        missing = [name for name in required if not isinstance(levers.get(name), Mapping) or "malware_blocked" not in levers[name]]
        return cls._result("levers_alone", not missing, f"lever {missing[0]} was not measured alone" if missing else "")

    @classmethod
    def ablation(cls, families: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
        if not families:
            return cls._result("ablation", False, "no input family was ablated")
        for name in sorted(families):
            row = families[name]
            if not isinstance(row.get("extra_legit_blocks"), int) or not isinstance(row.get("extra_malware_caught"), int):
                return cls._result("ablation", False, f"input family {name}: the ablation counts are missing")
            if row["extra_legit_blocks"] > 0 and row["extra_malware_caught"] == 0:
                return cls._result(
                    "ablation", False, f"input family {name} adds {row['extra_legit_blocks']} false blocks and catches no malware: remove it"
                )
        return cls._result("ablation", True)

    @classmethod
    def detector_only(cls, only: Mapping[str, Any]) -> dict[str, Any]:
        if not all(isinstance(only.get(k), int) for k in ("malware_blocked", "legit_blocked")):
            return cls._result("detector_only", False, "the blocks only the model makes are not reported on their own")
        return cls._result("detector_only", True)

    @classmethod
    def same_features(cls, trained: str, scored: str) -> dict[str, Any]:
        same = bool(trained) and trained == scored
        return cls._result("same_features", same, "the features trained on are not the features the shipped scanner writes")

    @classmethod
    def scored_once(cls, uses: Mapping[str, int]) -> dict[str, Any]:
        if not uses:
            return cls._result("scored_once", False, "no held-out set use is recorded")
        twice = sorted(name for name, n in uses.items() if n != 1)
        return cls._result("scored_once", not twice, f"held-out set {twice[0]} was scored {uses[twice[0]]} times, not once" if twice else "")

    @classmethod
    def report(cls, evidence: Mapping[str, Any], required_levers: tuple[str, ...] = ("model", "rules")) -> dict[str, Any]:
        """The seven checks over one candidate's evidence, in order, and whether it is accepted (all seven pass)."""
        checks = [
            cls.lose_zero(evidence.get("work") or {}),
            cls.legit_ceiling(evidence.get("areas") or {}),
            cls.levers_alone(evidence.get("levers") or {}, required_levers),
            cls.ablation(evidence.get("ablation") or {}),
            cls.detector_only(evidence.get("detector_only") or {}),
            cls.same_features(str(evidence.get("trained_features", "")), str(evidence.get("scored_features", ""))),
            cls.scored_once(evidence.get("heldout_uses") or {}),
        ]
        return {
            "accepted": all(c["passed"] for c in checks),
            "failed": [c["check"] for c in checks if not c["passed"]],
            "checks": checks,
        }
