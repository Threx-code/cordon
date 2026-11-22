"""The seven checks for a model candidate, run as one report."""

from __future__ import annotations

import copy

import pytest
from bench.cdi.model_acceptance import CHECKS, ModelAcceptance

DIGEST = "ab" * 32
GOOD = {
    "work": {"malware_lost": 0},
    "areas": {"npm": {"legit_blocked": 2, "legit_n": 9000}, "pypi": {"legit_blocked": 0, "legit_n": 4000}},
    "levers": {"model": {"malware_blocked": 410}, "rules": {"malware_blocked": 380}},
    "ablation": {"imports": {"extra_legit_blocks": 1, "extra_malware_caught": 12}, "names": {"extra_legit_blocks": 0, "extra_malware_caught": 0}},
    "detector_only": {"malware_blocked": 30, "legit_blocked": 1},
    "trained_features": DIGEST,
    "scored_features": DIGEST,
    "heldout_uses": {"npm-held": 1, "pypi-held": 1},
}


def changed(path: list[str], value):
    evidence = copy.deepcopy(GOOD)
    node = evidence
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return evidence


class TestTheReport:
    def test_a_candidate_meeting_every_check_is_accepted(self) -> None:
        report = ModelAcceptance.report(GOOD)
        assert report["accepted"] is True and report["failed"] == []
        assert [c["check"] for c in report["checks"]] == list(CHECKS) and len(CHECKS) == 7

    @pytest.mark.parametrize(
        "path,value,check,reason",
        [
            (["work", "malware_lost"], 1, "lose_zero", "1 malware units"),
            (["areas", "npm", "legit_blocked"], 60, "legit_ceiling", "area npm: the upper bound"),
            (["levers", "model"], {}, "levers_alone", "lever model was not measured alone"),
            (["ablation", "names"], {"extra_legit_blocks": 3, "extra_malware_caught": 0}, "ablation", "input family names"),
            (["detector_only"], {}, "detector_only", "not reported on their own"),
            (["scored_features"], "cd" * 32, "same_features", "not the features the shipped scanner writes"),
            (["heldout_uses", "npm-held"], 2, "scored_once", "npm-held was scored 2 times"),
        ],
    )
    def test_each_check_fails_alone_and_says_why(self, path, value, check, reason) -> None:
        report = ModelAcceptance.report(changed(path, value))
        assert report["accepted"] is False and report["failed"] == [check]
        assert reason in next(c for c in report["checks"] if c["check"] == check)["reason"]

    def test_missing_evidence_is_a_failure_not_a_pass(self) -> None:
        report = ModelAcceptance.report({})
        assert report["accepted"] is False and report["failed"] == list(CHECKS)

    def test_the_ceiling_is_on_the_upper_bound_not_the_rate(self) -> None:
        few = changed(["areas"], {"npm": {"legit_blocked": 0, "legit_n": 300}})
        assert ModelAcceptance.report(few)["failed"] == ["legit_ceiling"]

    def test_a_family_with_false_blocks_that_also_catches_malware_stays(self) -> None:
        assert ModelAcceptance.report(GOOD)["checks"][3]["passed"] is True

    def test_the_report_names_no_unit(self) -> None:
        assert "u1" not in str(ModelAcceptance.report(GOOD))
