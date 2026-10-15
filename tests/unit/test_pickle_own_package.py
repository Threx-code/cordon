"""A pickle naming the package's own classes, or the ordinary data stack, is not unrecognised
code (review 98)."""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config

RULE = "SUSPECT.MODEL.PICKLE_IMPORT.001"


class PickleHelpers:
    @staticmethod
    def rules(tmp_path, module: str, name: str, *, ship: str | None = None) -> set[str]:
        if ship:
            (tmp_path / ship).mkdir()
            (tmp_path / ship / "__init__.py").write_text("", encoding="utf-8")
        payload = f"c{module}\n{name}\n(tR.".encode()
        (tmp_path / "cache.pkl").write_bytes(payload)
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {f.rule_id for f in result.findings}


class TestPickleImports:
    def test_the_packages_own_class_is_recognised(self, tmp_path) -> None:
        assert RULE not in PickleHelpers.rules(tmp_path, "mypkg.models", "Thing", ship="mypkg")

    def test_a_class_from_nowhere_in_the_tree_is_not(self, tmp_path) -> None:
        assert RULE in PickleHelpers.rules(tmp_path, "elsewhere.models", "Thing")

    @pytest.mark.parametrize(
        ("module", "name"),
        [("joblib.numpy_pickle", "NumpyArrayWrapper"), ("catboost.core", "CatBoostClassifier")],
    )
    def test_the_data_stack_is_recognised(self, tmp_path, module: str, name: str) -> None:
        assert RULE not in PickleHelpers.rules(tmp_path, module, name)
