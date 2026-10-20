"""The intent layer's weights builder (`bench/model/intent_build.py`) on made-up fact sets: no
package content. The file it writes must satisfy every rule the scanner's loader holds.
"""

from __future__ import annotations

import argparse
import collections
import json
import math
import sys

import pytest

from cordon_scanner.decide.intent import IntentFacts, IntentWeights
from support import ROOT as REPO

sys.path.insert(0, str(REPO / "bench" / "model"))
from intent_build import IntentBuild, Unit


class TestTheBuilder:
    """Steps 3 and 5 on made-up fact sets (no package content)."""

    @staticmethod
    def args(**over) -> argparse.Namespace:
        base = {
            "folds": 5,
            "min_families": 5,
            "cap": 50.0,
            "cheap_cap": round(math.log(2), 6),
            "mismatch_limit": 0.01,
            "envelope_min_n": 50,
            "scanner_commit": "1" * 40,
            "dataset": "made up",
            "date": "2026-10-19",
            "version": "",
        }
        return argparse.Namespace(**{**base, **over})

    @staticmethod
    def corpus(benign_n: int = 3000) -> tuple[list[Unit], list[Unit]]:
        benign = [
            Unit(
                frozenset({"has_readme", "purpose_text"} | ({"hook"} if i % 25 == 0 else set())),
                f"benign-{i}",
            )
            for i in range(benign_n)
        ]
        malware = [
            Unit(
                frozenset({"hook", "t:install:egress"} | ({"conceal:loader"} if i % 2 else set())),
                f"mal-{i}",
                f"family-{i % 60}",
            )
            for i in range(300)
        ]
        return benign, malware

    def test_a_family_of_clones_weighs_one(self) -> None:
        benign = [Unit(frozenset(), f"b{i}") for i in range(100)]
        clones = [Unit(frozenset({"hook"}), f"c{i}", "one") for i in range(50)]
        others = [Unit(frozenset(), f"o{i}", f"f{i}") for i in range(9)]
        _, km, families, _, nf = IntentBuild.rates(benign, clones + others)["hook"]
        assert (km, families, nf) == (pytest.approx(1.0), 1, 10)

    def test_a_fact_seen_in_fewer_than_five_families_carries_no_weight(self) -> None:
        benign = [Unit(frozenset(), f"b{i}") for i in range(1000)]
        malware = [Unit(frozenset({"gate:time"}), f"m{i}", f"f{i % 4}") for i in range(40)]
        rows = IntentBuild.rows(benign, malware, self.args())
        assert not rows["gate:time"]["eligible"]

    def test_the_build_keeps_every_rule_of_the_loader(self) -> None:
        benign, malware = self.corpus()
        weights, report = IntentBuild.build(benign, malware, [], self.args())
        assert IntentWeights.problems(weights) == []
        assert weights["threshold_benign"]["upper"] <= IntentWeights.BENIGN_BAR
        assert "t:install:egress" in weights["rows"]
        assert "has_readme" not in weights["rows"]  # as common in benign: no weight
        assert report["label"].startswith("STUDY DATA")

    def test_the_report_holds_aggregates_only(self) -> None:
        benign, malware = self.corpus()
        _, report = IntentBuild.build(benign, malware, [], self.args())
        text = json.dumps(report)
        assert "mal-" not in text
        assert "benign-" not in text

    def test_too_few_benign_packages_to_meet_the_bar_is_a_failed_build(self) -> None:
        benign, malware = self.corpus(benign_n=300)
        with pytest.raises(ValueError, match=r"0\.5%"):
            IntentBuild.build(benign, malware, [], self.args())

    def test_popular_packages_make_the_line_stricter_never_looser(self) -> None:
        benign, malware = self.corpus()
        plain, _ = IntentBuild.build(benign, malware, [], self.args())
        popular = [
            Unit(frozenset({"hook", "t:install:egress"} if i < 4 else set()), f"p{i}")
            for i in range(2000)
        ]
        strict, _ = IntentBuild.build(benign, malware, popular, self.args())
        assert strict["threshold"] >= plain["threshold"]
        assert strict["threshold_popular"]["upper"] <= IntentWeights.BENIGN_BAR

    def test_records_from_older_code_are_refused(self, tmp_path) -> None:
        path = tmp_path / "scans.jsonl"
        records = [
            {"file": "a.tgz", "verdict": {"area": "npm"}},
            {
                "file": "b.tgz",
                "verdict": {"area": "npm", "intent": {"facts_version": 0, "facts": []}},
            },
            {"file": "c.tgz", "verdict": {"area": "pypi", "intent": {"facts_version": 1}}},
            {
                "file": "d.tgz",
                "verdict": {
                    "area": "npm",
                    "intent": {"facts_version": IntentFacts.VERSION, "facts": ["hook", "reg_x"]},
                },
            },
        ]
        path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
        skipped: collections.Counter[str] = collections.Counter()
        units = IntentBuild.read([path], None, set(), skipped)
        assert [u.facts for u in units] == [frozenset({"hook"})]
        assert sum(skipped.values()) == 3

    def test_adjudication_candidates_stay_out(self, tmp_path) -> None:
        scans, adjudication = tmp_path / "scans.jsonl", tmp_path / "adj.jsonl"
        facts = {"facts_version": IntentFacts.VERSION, "facts": ["hook"]}
        scans.write_text(
            json.dumps({"file": "x.tgz", "verdict": {"area": "npm", "intent": facts}}),
            encoding="utf-8",
        )
        adjudication.write_text(
            json.dumps({"file": "x.tgz", "verdict": "not-malicious"}) + "\n", encoding="utf-8"
        )
        skipped: collections.Counter[str] = collections.Counter()
        assert IntentBuild.read([scans], {}, IntentBuild.excluded([adjudication]), skipped) == []
