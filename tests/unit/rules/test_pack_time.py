"""A delivered rule pack is timed on a fixed corpus of invented text, and one over its budget is not run.

The corpus is the same bytes on every machine. The budget is CPU time: 200 ms for one pack and 500 ms for all delivered packs of a scan, the larger of those and ten times a calibration the
scanner takes once per process on the same corpus. A pack over budget is refused with the reason, which the scan's result carries like any other rule it did not run. The backend gate calls the
same function (`PackTime.problem`).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.intel.malware.feed_rules import FeedRules
from cordon_scanner.rules.calibration import CalibrationCorpus
from cordon_scanner.rules.feed_packs import FeedPacks
from cordon_scanner.rules.loader import RuleLoader
from cordon_scanner.rules.pack_time import PackTime
from kits.delivered_sets import GOOD, Isolated, Sets

CORPUS_DIGEST = "2c0d9d6e5a0bc49649a164d75923c5b36808e86959d7572468b8a665aa85757d"


class Timed(Isolated):
    @staticmethod
    def install(*packs: tuple[str, str, str]) -> None:
        """Packs as (file stem, rule id, call word): one regex rule each."""
        files, entries = {}, []
        for stem, rule_id, word in packs:
            name = f"rulepack-{stem}.yaml"
            files[name] = Sets.pack(stem, rule_id, f"{word}_call", f"{word}_call(x)")
            entries.append(Sets.entry(name))
        FeedRules.install(Sets.rules(entries, files))

    @staticmethod
    def fixed_cost(
        monkeypatch: pytest.MonkeyPatch, seconds: float, *, calibration: float = 0.001
    ) -> None:
        monkeypatch.setattr(
            PackTime, "measure", classmethod(lambda cls, pack: seconds if pack.rules else 0.0)
        )
        monkeypatch.setattr(PackTime, "calibration", staticmethod(lambda: calibration))

    @staticmethod
    def loaded() -> list[str]:
        return Sets.ids(FeedPacks.packs(RuleLoader(), set(), shadow=False))


class TestTheCorpusIsInventedAndTheSameEverywhere(Isolated):
    def test_it_is_forty_files_of_plain_ascii_of_a_fixed_size(self) -> None:
        files = CalibrationCorpus.files()
        assert len(files) == CalibrationCorpus.FILES == 40
        assert all(len(data) >= CalibrationCorpus.BYTES_PER_FILE for data in files)
        assert sum(len(data) for data in files) > 900_000
        assert all(data.isascii() for data in files)

    def test_every_call_makes_the_same_bytes_and_the_digest_is_pinned(self) -> None:
        assert CalibrationCorpus.files() == CalibrationCorpus.files()
        assert CalibrationCorpus.digest() == CORPUS_DIGEST

    def test_every_word_is_made_of_the_invented_syllables_only(self) -> None:
        import re

        letters = "".join(sorted(set("".join(CalibrationCorpus.SYLLABLES))))
        words = set(re.findall(rb"[A-Za-z]+", b" ".join(CalibrationCorpus.files()[:3])))
        assert words and all(re.fullmatch(f"[{letters}]+", word.decode()) for word in words)


class TestTheBudgetIsRelativeToTheMachine(Isolated):
    def test_a_fast_machine_has_the_fixed_figures(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(PackTime, "calibration", staticmethod(lambda: 0.001))
        assert PackTime.budgets() == (0.2, 0.5)

    def test_a_slow_machine_has_ten_times_its_calibration(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(PackTime, "calibration", staticmethod(lambda: 1.0))
        assert PackTime.budgets() == (10.0, 10.0)

    def test_the_calibration_is_a_real_positive_time(self) -> None:
        assert 0 < PackTime.calibration() < 30


class TestAPackOverItsBudget(Timed):
    def test_one_under_budget_loads_and_reports_no_gap(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.fixed_cost(monkeypatch, 0.05)
        self.install(("good", GOOD, "good"))
        assert self.loaded() == [GOOD]
        assert FeedPacks.skipped(RuleLoader(), set(), shadow=False) == ()

    def test_one_over_budget_is_not_run_and_its_reason_is_reported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.fixed_cost(monkeypatch, 0.25)
        self.install(("good", GOOD, "good"))
        assert self.loaded() == []
        ((rule_id, why),) = FeedPacks.skipped(RuleLoader(), set(), shadow=False)
        assert rule_id == GOOD and "250 ms" in why and "budget of 200 ms" in why

    def test_the_same_pack_is_run_on_a_machine_slow_enough_to_allow_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.fixed_cost(monkeypatch, 0.25, calibration=0.05)
        self.install(("good", GOOD, "good"))
        assert self.loaded() == [GOOD]

    def test_the_gate_function_gives_the_same_answer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.fixed_cost(monkeypatch, 0.25)
        self.install(("good", GOOD, "good"))
        assert [pack.rules for pack in FeedPacks.packs(RuleLoader(), set(), shadow=False)] == [()]
        monkeypatch.undo()
        real = RuleLoader().load_text(Sets.pack("good", GOOD, "good_call", "good_call(x)"))
        assert PackTime.problem(real) is None and 0 <= PackTime.measure(real) < 0.2


class TestAllPacksTogether(Timed):
    def test_packs_each_under_budget_but_over_it_together_are_cut_off_in_order(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.fixed_cost(monkeypatch, 0.18)
        self.install(
            ("a", "LEARNED.EDGE.1", "a"), ("b", "LEARNED.EDGE.2", "b"), ("c", "LEARNED.EDGE.3", "c")
        )
        assert self.loaded() == ["LEARNED.EDGE.1", "LEARNED.EDGE.2"]
        skipped = FeedPacks.skipped(RuleLoader(), set(), shadow=False)
        assert [rule_id for rule_id, _ in skipped] == ["LEARNED.EDGE.3"]
        assert "all packs may take" in skipped[0][1]


class TestTheScanResultSaysSo(Timed):
    def test_a_pack_not_run_for_time_is_in_the_stats_and_the_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.engine.registry import Registry
        from cordon_scanner.report.base import ReportOptions

        self.fixed_cost(monkeypatch, 0.25)
        self.install(("good", GOOD, "good"))
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "p", "version": "1.0.0"}), encoding="utf-8"
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        assert list(result.stats.rule_gaps) == [GOOD]
        body: Any = json.loads(
            b"".join(Registry().reporter("json").render(result, ReportOptions(color=False)))
        )
        assert "budget of 200 ms" in body["stats"]["rule_gaps"][GOOD]
