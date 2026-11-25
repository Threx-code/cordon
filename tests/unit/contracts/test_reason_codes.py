"""`ReasonCodes`: stable, documented, never reused (design spec 5.5).

`reason_codes.golden.json` records every code ever issued with its name. A code removed or renamed is
a failing test; a code added is appended to the golden file in the same change.
"""

from __future__ import annotations

import json

from cordon_scanner.contracts.reason_codes import ReasonCodes
from support import ROOT

GOLDEN = ROOT / "tests" / "unit" / "contracts" / "reason_codes.golden.json"


class TestTheRegistryIsSound:
    def test_nothing_is_wrong_with_it(self) -> None:
        assert ReasonCodes.problems() == []

    def test_every_group_of_the_spec_is_there(self) -> None:
        assert {entry.group for entry in ReasonCodes.ALL} == set(ReasonCodes.GROUPS)

    def test_a_hard_stop_cannot_be_lifted(self) -> None:
        assert all(not entry.overridable for entry in ReasonCodes.in_group("R1"))

    def test_an_unregistered_code_is_refused(self) -> None:
        assert not ReasonCodes.is_registered("R999")
        try:
            ReasonCodes.lookup("R999")
        except KeyError:
            return
        raise AssertionError("an unregistered code was found")


class TestNeverReused:
    def test_every_code_ever_issued_still_means_what_it_meant(self) -> None:
        issued = json.loads(GOLDEN.read_text(encoding="utf-8"))
        for code, name in issued.items():
            assert ReasonCodes.is_registered(code) or code in ReasonCodes.RETIRED, (
                f"{code} was removed"
            )
            if ReasonCodes.is_registered(code):
                assert ReasonCodes.lookup(code).name == name, f"{code} was renamed"

    def test_the_golden_file_lists_every_registered_code(self) -> None:
        issued = json.loads(GOLDEN.read_text(encoding="utf-8"))
        assert {entry.code: entry.name for entry in ReasonCodes.ALL}.items() <= issued.items()
