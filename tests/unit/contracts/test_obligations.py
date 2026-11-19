"""`Obligations`: stable, documented, never reused (cordon-a0, 2026-11-17). `obligations.golden.json` records every code ever issued."""

from __future__ import annotations

import json

import pytest

from cordon_scanner.contracts.obligations import Obligations
from support import ROOT

GOLDEN = ROOT / "tests" / "unit" / "contracts" / "obligations.golden.json"


class TestTheRegistry:
    def test_nothing_is_wrong_with_it(self) -> None:
        assert Obligations.problems() == []

    def test_every_code_ever_issued_still_means_what_it_meant(self) -> None:
        issued = json.loads(GOLDEN.read_text(encoding="utf-8"))
        for code, name in issued.items():
            assert Obligations.is_registered(code) or code in Obligations.RETIRED, (
                f"{code} was removed"
            )
            if Obligations.is_registered(code):
                assert Obligations.lookup(code).name == name, f"{code} was renamed"
        assert {entry.code: entry.name for entry in Obligations.ALL}.items() <= issued.items()

    def test_an_unregistered_code_is_refused(self) -> None:
        assert not Obligations.is_registered("O999")
        with pytest.raises(KeyError):
            Obligations.lookup("O999")
