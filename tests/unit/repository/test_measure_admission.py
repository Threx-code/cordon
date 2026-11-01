"""The admission table of release item 45 (scripts/measure/measure_admission.py), on rows built for
the test: solo is one evidence family, the model's own blocks are not removable, the floor holds."""

from __future__ import annotations

import importlib.util
from typing import Any

from support import ROOT


class AdmissionKit:
    @staticmethod
    def module() -> Any:
        spec = importlib.util.spec_from_file_location(
            "measure_admission", ROOT / "scripts" / "measure" / "measure_admission.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.Admission

    @staticmethod
    def row(kind: str, rules: list[str], *, score: float = 0.1, n: int = 0) -> dict[str, Any]:
        return {
            "path": f"/x/{kind}-{n}.tgz",
            "set": "benign-npm" if kind == "benign" else "malware-ddnpm",
            "tags": [],
            "exit": 1 if rules else 0,
            "findings": [
                [r, "high", "high", "suspicious", f"{kind}-{n}.tgz!package/a.js"] for r in rules
            ],
            "verdict": {"area": "npm", "score": score, "block": 0.5},
        }


class TestTheTable:
    def test_one_observation_twice_is_still_alone(self) -> None:
        table = AdmissionKit.module().table(
            [AdmissionKit.row("benign", ["SUSPECT.DROPPER.001", "SUSPECT.DROPPER.REMOTE_CODE.001"])]
        )["table"]
        assert {e["rule"] for e in table if e["benign_solo"] == 1} == {
            "SUSPECT.DROPPER.001",
            "SUSPECT.DROPPER.REMOTE_CODE.001",
        }

    def test_two_families_are_not_solo(self) -> None:
        table = AdmissionKit.module().table(
            [AdmissionKit.row("benign", ["SUSPECT.DROPPER.001", "SUSPECT.OBFUSCATION.PACKED.001"])]
        )["table"]
        assert table == []

    def test_a_benign_block_the_model_also_makes_is_not_removable(self) -> None:
        rows = [AdmissionKit.row("benign", ["SUSPECT.X.001"], score=0.9, n=i) for i in range(6)]
        (entry,) = AdmissionKit.module().table(rows)["table"]
        assert entry["benign_solo"] == 6 and entry["benign_removed"] == 0

    def test_a_rule_qualifies_only_past_the_floor_and_the_budgets(self) -> None:
        admission = AdmissionKit.module()
        clean = [AdmissionKit.row("benign", [], n=i) for i in range(200)]
        noisy = [AdmissionKit.row("benign", ["SUSPECT.X.001"], n=1000 + i) for i in range(40)]
        malware = [AdmissionKit.row("malware", [], n=i) for i in range(4000)]
        (entry,) = admission.table(clean + noisy + malware)["table"]
        assert entry["floor_met"] and entry["spends_more_fa_than_miss"] and entry["qualifies"]
        (few,) = admission.table(clean + noisy[:4] + malware)["table"]
        assert not few["floor_met"] and not few["qualifies"]

    def test_malware_the_model_does_not_recover_is_named_and_bounds_it(self) -> None:
        admission = AdmissionKit.module()
        clean = [AdmissionKit.row("benign", [], n=i) for i in range(200)]
        noisy = [AdmissionKit.row("benign", ["SUSPECT.X.001"], n=1000 + i) for i in range(40)]
        malware = [AdmissionKit.row("malware", [], n=i) for i in range(4000)]
        alone = [
            AdmissionKit.row("malware", ["SUSPECT.X.001"], score=0.1, n=9000 + i) for i in range(3)
        ]
        (entry,) = admission.table(clean + noisy + malware + alone)["table"]
        assert entry["lost"] == ["malware-9000.tgz", "malware-9001.tgz", "malware-9002.tgz"]
        assert entry["k"] == 1 and not entry["qualifies"]


class TestTheModelIsNotItsOwnCorroboration:
    """Item 46's finding (120 of 131 benign solo blocks over the line fall under it without their own
    rule): the model corroborates a rule only on the rest of the evidence."""

    @staticmethod
    def scorer(values: dict[str, float], area: str | None) -> float:
        # A model that rides on the gate count, as the shipped one did on these units.
        return 0.4 + 0.2 * values.get("gate", 0.0) + 0.3 * values.get("pkg:other_evidence", 0.0)

    @staticmethod
    def row(extra: dict[str, float]) -> dict[str, Any]:
        row = AdmissionKit.row("benign", ["SUSPECT.DROPPER.001"], score=0.6)
        row["verdict"]["features"] = {
            "values": {"r:SUSPECT.DROPPER.001": 3.0, "gate": 1.0, "max": 3.0, **extra}
        }
        return row

    def test_a_score_that_rides_on_the_rule_is_no_corroboration(self) -> None:
        (entry,) = AdmissionKit.module().table([self.row({})], self.scorer)["table"]
        assert entry["benign_removed"] == 1

    def test_a_score_on_other_evidence_still_is(self) -> None:
        rows = [self.row({"pkg:other_evidence": 1.0})]
        (entry,) = AdmissionKit.module().table(rows, self.scorer)["table"]
        assert entry["benign_removed"] == 0
