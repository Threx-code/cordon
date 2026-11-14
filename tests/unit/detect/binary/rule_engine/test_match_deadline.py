"""The time one match may take is the matching thread's CPU time, with a wall backstop
(`rule_engine/deadline.py`): a loaded machine, a sleep or being starved does not use the budget up, so
the same file gets the same answer busy or idle (reviews/release-080/LOAD-INDEPENDENT-BUDGETS.md)."""

from __future__ import annotations

import time
from typing import Any

import pytest

from cordon_scanner.detect.binary.rule_engine.deadline import MatchDeadline, MatchStalled
from cordon_scanner.detect.binary.rule_engine.lang import Rules
from cordon_scanner.detect.binary.rule_engine.tokens import RuleError
from cordon_scanner.detect.binary.rule_files import RuleFileEngine

RULE = "rule ab { strings: $s = { 61 62 } condition: #s > 5 }"
DATA = b"ab" * 40_000  # well past the 4,096 events between two readings of the deadline


class Clock:
    """`time.monotonic` that jumps `by` seconds after its first reading: a machine that stalled."""

    def __init__(self, by: float) -> None:
        self.by, self.real, self.reads = by, time.monotonic, 0

    def __call__(self) -> float:
        self.reads += 1
        return self.real() + (self.by if self.reads > 1 else 0.0)


class TestTheBudgetIsCpuTime:
    def test_sleeping_does_not_use_it_up(self) -> None:
        deadline = MatchDeadline(0.05)
        time.sleep(0.2)  # four budgets of wall time, no CPU, inside the 0.5 s backstop
        assert not MatchDeadline.passed(deadline)

    def test_cpu_spent_does_use_it_up_and_is_final(self) -> None:
        deadline = MatchDeadline(0.05)
        began = time.thread_time()
        while time.thread_time() - began < 0.2:
            pass
        assert MatchDeadline.passed(deadline)
        assert not isinstance(MatchDeadline.timeout(deadline), MatchStalled)

    def test_the_wall_backstop_ends_a_match_that_uses_no_cpu(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        deadline = MatchDeadline(1.0)
        monkeypatch.setattr(time, "monotonic", lambda: deadline.wall_end + 1)
        assert MatchDeadline.passed(deadline)
        assert isinstance(MatchDeadline.timeout(deadline), MatchStalled)

    def test_a_plain_float_is_still_a_monotonic_deadline(self) -> None:
        assert MatchDeadline.passed(time.monotonic() - 1)
        assert not MatchDeadline.passed(time.monotonic() + 60)
        assert not MatchDeadline.passed(None)
        assert MatchDeadline.left(None) == -1.0

    def test_a_native_call_is_given_the_cpu_budget_and_the_wall_backstop(self) -> None:
        deadline = MatchDeadline(1.0)
        assert 0.9 < MatchDeadline.left(deadline) <= 1.0
        assert 9.0 < MatchDeadline.wall_left(deadline) <= 10.0
        assert MatchDeadline.wall_left(time.monotonic() + 5) == -1.0


class TestAMatchUnderLoad:
    def test_a_match_stalled_for_five_times_its_budget_still_matches(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The wall jumps 5 s mid-match against a 1 s budget: wall-clock ended it, CPU time does not."""
        rules = Rules.compile(RULE)
        monkeypatch.setattr(time, "monotonic", Clock(5.0))
        assert [m.rule for m in rules.match(DATA, timeout=1.0)] == ["ab"]

    def test_a_match_stalled_past_the_backstop_is_ended_as_stalled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rules = Rules.compile(RULE)
        monkeypatch.setattr(time, "monotonic", Clock(50.0))
        with pytest.raises(RuleError) as caught:
            rules.match(DATA, timeout=1.0)
        assert isinstance(caught.value.__cause__, MatchStalled)


class Fake:
    """A rule set whose match is stalled `stalls` times, then answers."""

    def __init__(self, stalls: int, error: type[TimeoutError] = MatchStalled) -> None:
        self.stalls, self.error, self.calls = stalls, error, 0

    def match(self, data: bytes, timeout: float | None = None, given: Any = None) -> list[Any]:
        self.calls += 1
        if self.calls <= self.stalls:
            raise RuleError("matching took longer than the time allowed") from self.error("stalled")
        return ["matched"]


class TestOneRerunOfAStalledMatch:
    @staticmethod
    def engine(rules: Fake) -> RuleFileEngine:
        engine = object.__new__(RuleFileEngine)
        engine.identity, engine.pool, engine.given, engine.rules = None, None, {}, rules  # type: ignore[assignment]
        return engine

    def test_a_match_stalled_once_is_run_again_and_answers(self) -> None:
        rules = Fake(stalls=1)
        assert self.engine(rules).match(b"x") == ["matched"]
        assert rules.calls == 2

    def test_a_match_stalled_twice_is_still_the_gap(self) -> None:
        rules = Fake(stalls=2)
        with pytest.raises(RuleError) as caught:
            self.engine(rules).match(b"x")
        assert isinstance(caught.value.__cause__, MatchStalled)
        assert rules.calls == 2  # one rerun, never a third

    def test_a_match_that_spent_its_cpu_is_not_run_again(self) -> None:
        rules = Fake(stalls=1, error=TimeoutError)
        with pytest.raises(RuleError):
            self.engine(rules).match(b"x")
        assert rules.calls == 1
