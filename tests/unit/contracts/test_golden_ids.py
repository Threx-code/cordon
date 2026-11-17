"""The golden file of canonical ids (design spec 21.2 M0): the inputs and ids stay what they were.

`golden_ids.json` holds 2,000 benign inputs across every kind (built by `tests/kits/contract_goldens.py`
from the popularity lists in `intel/data` and a fixed list of well-known names; nothing from a corpus) and
the canonical id of each. A change to a canonical form shows as a changed golden file in review.
"""

from __future__ import annotations

import json

from cordon_scanner.contracts.subjects import CanonicalIds, SubjectKind
from support import ROOT

GOLDEN = ROOT / "tests" / "unit" / "contracts" / "golden_ids.json"


class TestTheGoldenIds:
    def test_there_are_two_thousand_inputs_across_every_kind(self) -> None:
        rows = json.loads(GOLDEN.read_text(encoding="utf-8"))
        assert len(rows) == 2000
        assert {row["kind"] for row in rows} == {kind.value for kind in SubjectKind}

    def test_every_id_is_what_canonical_id_returns_now_and_on_a_second_run(self) -> None:
        for row in json.loads(GOLDEN.read_text(encoding="utf-8")):
            first = CanonicalIds.canonical_id(SubjectKind(row["kind"]), row["parts"])
            second = CanonicalIds.canonical_id(
                SubjectKind(row["kind"]), dict(reversed(list(row["parts"].items())))
            )
            assert first == second == row["id"], row

    def test_the_ids_are_distinct_enough_to_tell_the_subjects_apart(self) -> None:
        rows = json.loads(GOLDEN.read_text(encoding="utf-8"))
        assert len({row["id"] for row in rows}) > 1500
