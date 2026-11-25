"""Each security control of the learning system, and each hardening item of its third stage, names the test that records it.

`learning_controls.json` lists, for rows SI-J1 and SI-M3, a test file and a test name per control, or says why the control has
no test yet. This checks that every listed test exists, that every control of both lists is present, and that an open control
gives its reason, so a control cannot lose its test or be dropped without a trace."""

from __future__ import annotations

import json
from typing import Any, ClassVar

from support import ROOT

REGISTRY = ROOT / "tests" / "unit" / "repository" / "release" / "learning_controls.json"


class Registry:
    CONTROLS: ClassVar[dict[str, tuple[str, ...]]] = {
        "SI-J1": (
            "poisoned samples and labels",
            "compromised sources",
            "archive and parser exploits",
            "prompt injection",
            "unsafe-rule steering",
            "drift",
            "training dependency compromise",
            "stage privilege separation",
            "signing-key compromise",
            "resource exhaustion",
        ),
        "SI-M3": (
            "poisoning",
            "parser failure",
            "signature",
            "permission",
            "compatibility",
            "rollback",
            "reproducibility",
            "performance",
            "recovery",
        ),
    }

    @staticmethod
    def load() -> dict[str, dict[str, Any]]:
        loaded: dict[str, dict[str, Any]] = json.loads(REGISTRY.read_text(encoding="utf-8"))
        return loaded


class TestEveryControlNamesItsTest:
    def test_every_control_of_both_rows_is_listed(self) -> None:
        registry = Registry.load()
        for row, controls in Registry.CONTROLS.items():
            assert set(registry[row]) == set(controls), row

    def test_every_listed_test_exists(self) -> None:
        missing = []
        for row, controls in Registry.load().items():
            for control, entry in controls.items():
                if isinstance(entry, dict):
                    continue
                path, name = entry
                source = ROOT / path
                if not source.is_file() or f"def {name}(" not in source.read_text(encoding="utf-8"):
                    missing.append(f"{row}: {control}: {path}::{name}")
        assert not missing, missing

    def test_a_control_without_a_test_says_why(self) -> None:
        for row, controls in Registry.load().items():
            for control, entry in controls.items():
                if isinstance(entry, dict):
                    assert len(str(entry.get("open", ""))) > 20, f"{row}: {control}"
