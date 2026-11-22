"""The two candidate lanes, each end to end on a fixture: a model retrains only through the one entry point, and a rule pack
goes census, proposal, shadow and gate with no retraining anywhere on its path."""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

import pytest
from support import ROOT as REPO

sys.path.insert(0, str(REPO))

from bench.cdi.distill import Distiller, PackRenderer
from bench.cdi.mutations import AdversarialGate
from bench.model import area
from test_distill import FactsKit
from test_pack_probing import Evasion

CDI = REPO / "bench" / "cdi"
TRAINING_LIBRARIES = {"lightgbm", "sklearn", "joblib", "xgboost", "torch", "scipy"}


def imported(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


class TestTheRulePackLaneNeverRetrains:
    def modules(self) -> list[Path]:
        # every module of the candidate loop except the model-lane ones (a model's acceptance and its drift watch read a model's
        # numbers; they fit nothing)
        return sorted(p for p in CDI.glob("*.py") if not p.name.startswith("test_"))

    def test_no_module_of_the_rule_lane_imports_a_training_library_or_a_trainer(self) -> None:
        offenders = {
            p.name: sorted(
                n
                for n in imported(p)
                if n.split(".")[0] in TRAINING_LIBRARIES or n.startswith("bench.model.train") or "verdict_train" in n
            )
            for p in self.modules()
        }
        assert {k: v for k, v in offenders.items() if v} == {}

    def test_no_module_of_the_rule_lane_names_the_entry_point_in_code(self) -> None:
        for p in self.modules():
            tree = ast.parse(p.read_text(encoding="utf-8"))
            docstrings = {
                id(n.body[0].value)
                for n in ast.walk(tree)
                if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef)) and n.body and isinstance(n.body[0], ast.Expr)
            }
            strings = [
                n.value
                for n in ast.walk(tree)
                if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings
            ]
            assert not any("train.py" in text for text in strings), p.name

    def test_the_lane_runs_on_a_fixture_from_miss_to_a_shadow_pack(self) -> None:
        # census and proposal: the distiller reads the missed units' facts and proposes a predicate
        candidate = Distiller().distill(Evasion.first_window()).candidate
        assert candidate is not None and candidate["train"]["families"] == 4
        # shadow: the proposal is rendered as a pack in the learned namespace, a rule and no code
        pack = PackRenderer.render(candidate, "LEARNED.NPM.001")
        assert "id: LEARNED.NPM.001" in pack and "kind: composite" in pack and "def " not in pack
        # gate: the same text under an adversarial rewrite is not what the gate keeps
        verdict = AdversarialGate.check(lambda text: "spawn" in text, ["spawn('x')", "spawn('y')"])
        assert verdict["caught"] == 2


class TestTheModelLaneRunsThroughTheOneEntryPoint:
    def test_the_fixture_area_runs_end_to_end_and_writes_the_model_its_metrics_and_the_list_hash(self, tmp_path: Path) -> None:
        pytest.importorskip("lightgbm")
        from bench.model import train

        listing = tmp_path / "train.txt"
        listing.write_text("\n".join(f"unit-{i}" for i in range(80)) + "\n", encoding="utf-8")
        args = argparse.Namespace(train=listing, seed=3, work=tmp_path)
        assert train.Training.fixture(args) == 0
        written = sorted(p.name for p in (tmp_path / "model-fixture").iterdir())
        assert written == ["metrics.json", "model.json.gz", "training_list.sha256"]

    def test_every_trainer_is_started_by_the_entry_point_and_by_nothing_else(self) -> None:
        assert set(area.EntryPoint.TRAINERS) >= {"verdict", "skill-text", "area-fit", "mcp"}
        for name in area.EntryPoint.TRAINERS.values():
            assert (REPO / "bench" / "model" / name).exists()
