"""The content rule (what "blocked" means) lives in `contracts` and answers as it always did.

`content_rule.golden.json` records the answers of `bench/tools/content.py` as it stood before the move:
`Content.fails` over every rule id of the taxonomy's prefixes (and the intel shapes) with every severity,
confidence and category; `Content.is_content` for every detector against every one of those rule ids;
`Content.gap_blocked` over 150 row shapes; and the sets themselves. A change to the rule shows here, and
in the bench's own tests, as a diff to review.
"""

from __future__ import annotations

import itertools
import json
import sys

from cordon_scanner.contracts import content_rule
from cordon_scanner.contracts.content_rule import Content
from support import ROOT

GOLDEN = json.loads(
    (ROOT / "tests" / "unit" / "contracts" / "content_rule.golden.json").read_text(encoding="utf-8")
)


class TestAnswersAsBefore:
    def test_the_sets_are_the_recorded_ones(self) -> None:
        sets = GOLDEN["sets"]
        assert sorted(content_rule.CONTENT_DETECTORS) == sets["content"]
        assert sorted(content_rule.INTEL_DETECTORS) == sets["intel"]
        assert sorted(content_rule.CONTENT_GAPS) == sets["gaps"]
        assert list(content_rule.INTEL_RULE_PREFIXES) == sets["prefixes"]
        assert list(content_rule.INTEL_MARKERS) == sets["markers"]

    def test_fails_gives_the_recorded_answer_for_every_input(self) -> None:
        combos = list(
            itertools.product(GOLDEN["severities"], GOLDEN["confidences"], GOLDEN["categories"])
        )
        for rule in GOLDEN["rules"]:
            now = "".join("1" if Content.fails(rule, s, c, k) else "0" for s, c, k in combos)
            assert now == GOLDEN["fails"][rule], rule

    def test_is_content_gives_the_recorded_answer_for_every_detector_and_rule(self) -> None:
        for detector, recorded in GOLDEN["is_content"].items():
            now = "".join("1" if Content.is_content(r, detector) else "0" for r in GOLDEN["rules"])
            assert now == recorded, detector

    def test_gap_blocked_gives_the_recorded_answer_for_every_row_shape(self) -> None:
        for row, recorded in GOLDEN["gap_rows"]:
            assert Content.gap_blocked(row) is recorded, row

    def test_the_grid_is_wide_enough_to_mean_something(self) -> None:
        assert len(GOLDEN["rules"]) > 100 and len(GOLDEN["is_content"]) > 40
        assert any("1" in v for v in GOLDEN["fails"].values())
        assert any("0" in v for v in GOLDEN["fails"].values())


class TestTheBenchUsesThisDefinition:
    def test_the_bench_module_is_these_objects(self) -> None:
        sys.path.insert(0, str(ROOT / "bench" / "tools"))
        try:
            import content as bench_content
        finally:
            sys.path.remove(str(ROOT / "bench" / "tools"))
        assert bench_content.Content is Content
        assert bench_content.CONTENT_DETECTORS is content_rule.CONTENT_DETECTORS
        assert bench_content.INTEL_DETECTORS is content_rule.INTEL_DETECTORS
        assert bench_content.CONTENT_GAPS is content_rule.CONTENT_GAPS
