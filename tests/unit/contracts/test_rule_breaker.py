"""The device's circuit breaker: a delivered rule that blocks over 1% of the local scans of 24 hours is run as a warning.

The record is 24 hourly buckets in the device runtime's own local store, and nowhere else. A rate is read only over at least a hundred scans, a rule at or under 1% is left alone, a bucket older
than 24 hours no longer counts, and the reason a rule was demoted is kept in the store.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from cordon_scanner.cloud.agent.rule_breaker import KIND, REASONS, RuleBreaker
from cordon_scanner.cloud.local_store import LocalStore
from cordon_scanner.foundation.models import Severity
from cordon_scanner.intel.malware.feed_rules import FeedRules
from cordon_scanner.rules.feed_packs import FeedPacks
from cordon_scanner.rules.loader import RuleLoader
from kits.bundle_kit import T0
from kits.delivered_sets import GOOD, Isolated, Sets


class Scans:
    @staticmethod
    def run(breaker: RuleBreaker, count: int, blocked: dict[str, int], *, start: int = 0) -> None:
        """`count` scans, one a minute from `start`, the first `blocked[rule]` of them blocked by that rule."""
        for n in range(count):
            rules = [rule for rule, times in blocked.items() if n < times]
            breaker.record(T0 + timedelta(minutes=start + n), rules)


class TestTheRate(Isolated):
    def test_a_rule_over_one_percent_of_enough_scans_is_demoted_with_its_reason(
        self, tmp_path: Path
    ) -> None:
        breaker = RuleBreaker(LocalStore(tmp_path))
        Scans.run(breaker, 150, {GOOD: 3})
        reasons = breaker.demotions(T0 + timedelta(minutes=151))
        assert list(reasons) == [GOOD]
        assert "blocked 3 of 150 local scans in 24 hours (2.0%)" in reasons[GOOD]

    def test_a_rule_at_one_percent_or_under_is_left_alone(self, tmp_path: Path) -> None:
        breaker = RuleBreaker(LocalStore(tmp_path))
        Scans.run(breaker, 200, {GOOD: 2})
        assert breaker.demotions(T0 + timedelta(minutes=201)) == {}

    def test_too_few_scans_is_not_a_rate(self, tmp_path: Path) -> None:
        breaker = RuleBreaker(LocalStore(tmp_path))
        Scans.run(breaker, 50, {GOOD: 50})
        assert breaker.demotions(T0 + timedelta(minutes=51)) == {}

    def test_a_block_older_than_24_hours_no_longer_counts(self, tmp_path: Path) -> None:
        breaker = RuleBreaker(LocalStore(tmp_path))
        Scans.run(breaker, 150, {GOOD: 10})
        assert breaker.demotions(T0 + timedelta(hours=23)) != {}
        assert breaker.demotions(T0 + timedelta(hours=30)) == {}

    def test_the_reason_is_kept_in_the_store_and_so_are_the_buckets_and_nothing_else(
        self, tmp_path: Path
    ) -> None:
        store = LocalStore(tmp_path)
        breaker = RuleBreaker(store)
        Scans.run(breaker, 150, {GOOD: 5})
        breaker.demotions(T0 + timedelta(minutes=151))
        blob = store.blob(KIND, REASONS)
        assert blob is not None and GOOD in json.loads(blob.data)
        assert store.blob(KIND, "buckets") is not None

    def test_a_second_runtime_on_the_same_store_reads_the_same_record(self, tmp_path: Path) -> None:
        Scans.run(RuleBreaker(LocalStore(tmp_path)), 150, {GOOD: 4})
        assert list(RuleBreaker(LocalStore(tmp_path)).demotions(T0 + timedelta(minutes=151))) == [
            GOOD
        ]


class TestTheRuleRunsAsAWarning(Isolated):
    def test_the_demotion_reaches_the_loaded_rule(self, tmp_path: Path) -> None:
        name = "rulepack-zgood.yaml"
        FeedRules.install(
            Sets.rules(
                [Sets.entry(name)], {name: Sets.pack("good", GOOD, "zzgood_call", "zzgood_call(x)")}
            )
        )
        breaker = RuleBreaker(LocalStore(tmp_path))
        Scans.run(breaker, 150, {GOOD: 6})
        reasons = breaker.demotions(T0 + timedelta(minutes=151))
        (pack,) = FeedPacks.packs(RuleLoader(), set(), shadow=False, demote=reasons)
        (compiled,) = pack.rules
        assert (
            compiled.rule.severity is Severity.LOW and "blocked 6 of 150" in compiled.rule.message
        )
