"""engine.isolation.supervisor: a unit that exhausts memory or CPU, or hangs, costs that unit and
nothing else; one that died only beside others keeps its result; the rest come back by index. The
workloads are planted here: a worker resolves them by name, as it resolves the engine's own."""

from __future__ import annotations

import multiprocessing
import os
import sys
import time
from pathlib import Path

import pytest

from cordon_scanner.engine.isolation.supervisor import (
    Bounds,
    IsolationUnavailable,
    Reason,
    Supervisor,
    Unit,
)


class Workloads:
    """What a planted unit does in its worker; `item` says how."""

    @staticmethod
    def setup() -> None:
        return None

    @staticmethod
    def setup_that_raises() -> None:
        raise RuntimeError("planted: a setup that cannot finish")

    @staticmethod
    def run(item: tuple[str, object]) -> object:
        kind, arg = item
        if kind == "echo":
            return arg
        if kind == "hog":  # past the address-space limit
            return len(bytearray(int(arg)))  # type: ignore[call-overload]
        if kind == "spin":  # CPU, forever
            while True:
                pass
        if kind == "burn":  # CPU for `arg` seconds, then done
            until = time.process_time() + float(arg)  # type: ignore[arg-type]
            while time.process_time() < until:
                pass
            return "burnt"
        if kind == "sleep":  # no CPU: only the wall backstop sees it
            time.sleep(float(arg))  # type: ignore[arg-type]
            return "woke"
        if kind == "busy":  # in flight a while, so others overlap it
            folder = Path(str(arg))
            mark = folder / f"{os.getpid()}.running"
            mark.touch()
            time.sleep(1.0)
            mark.unlink()
            return "busy"
        if kind == "company":  # dies when another unit is in flight beside it, lives alone
            time.sleep(0.4)
            others = [p for p in Path(str(arg)).glob("*.running") if p.stem != str(os.getpid())]
            if others:
                os._exit(9)
            return "alone"
        if kind == "die":
            os._exit(9)
        if kind == "raise":
            raise UnicodeEncodeError("utf-8", "\udcff", 0, 1, "planted: surrogates not allowed")
        raise AssertionError(kind)


class Harness:
    @staticmethod
    def supervisor(bounds: Bounds, workers: int = 2, setup: str = "setup") -> Supervisor:
        module = Workloads.__module__
        return Supervisor(
            multiprocessing.get_context("spawn"),
            (f"{module}:Workloads.{setup}", ()),
            f"{module}:Workloads.run",
            bounds,
            workers,
        )


class TestTheSupervisor:
    def test_every_result_comes_back_by_its_index(self) -> None:
        units = [Unit(i, ("echo", i * i), 1) for i in range(12)]
        outcome = Harness.supervisor(Bounds(), workers=3).run(units)
        assert outcome.results == {i: i * i for i in range(12)}
        assert not outcome.failed

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="RLIMIT_AS is Linux's")
    def test_a_unit_past_the_memory_limit_costs_only_itself(self) -> None:
        units = [Unit(0, ("echo", "a"), 1), Unit(1, ("hog", 2 << 30), 1), Unit(2, ("echo", "b"), 1)]
        outcome = Harness.supervisor(Bounds(memory_bytes=1 << 30)).run(units)
        assert outcome.results == {0: "a", 2: "b"}
        assert outcome.failed == {1: Reason.MEMORY}
        assert outcome.isolation["memory_limit"] == "enforced"

    @pytest.mark.skipif(sys.platform == "win32", reason="no RLIMIT_CPU on Windows")
    def test_a_unit_past_its_cpu_budget_is_ended_by_the_kernel(self) -> None:
        units = [Unit(0, ("spin", None), 1), Unit(1, ("echo", "after"), 1)]
        outcome = Harness.supervisor(Bounds(cpu_floor=1.0, wall_factor=60.0)).run(units)
        assert outcome.failed == {0: Reason.CPU}
        assert outcome.results == {1: "after"}

    @pytest.mark.skipif(sys.platform == "win32", reason="no RLIMIT_CPU on Windows")
    def test_an_idle_worker_is_not_ended_for_the_cpu_before(self) -> None:
        """Each unit uses most of a 2 s budget; one worker runs them all, so the CPU it has used
        passes any one unit's budget many times over: the limit is per unit, released between."""
        units = [Unit(i, ("burn", 1.2), 1) for i in range(5)]
        outcome = Harness.supervisor(Bounds(cpu_floor=2.0, wall_factor=60.0), workers=1).run(units)
        assert not outcome.failed
        assert outcome.results == dict.fromkeys(range(5), "burnt")

    def test_a_unit_that_hangs_without_cpu_meets_the_wall_backstop(self) -> None:
        units = [Unit(0, ("sleep", 60), 1), Unit(1, ("echo", "after"), 1)]
        outcome = Harness.supervisor(Bounds(cpu_floor=0.5, wall_factor=2.0)).run(units)
        assert outcome.failed == {0: Reason.WALL}
        assert outcome.results == {1: "after"}

    def test_a_unit_that_dies_only_in_company_keeps_its_result(self, tmp_path: Path) -> None:
        units = [Unit(0, ("busy", str(tmp_path)), 1), Unit(1, ("company", str(tmp_path)), 1)]
        supervisor = Harness.supervisor(Bounds(), workers=2)
        outcome = supervisor.run(units)
        assert [u.index for u in supervisor.retry] == [1]  # it did die in company first
        assert outcome.results == {0: "busy", 1: "alone"}  # and its second run was alone
        assert not outcome.failed

    def test_a_unit_that_dies_alone_too_is_reported_and_the_rest_finish(self) -> None:
        units = [Unit(i, ("echo", i), 1) for i in range(4)] + [Unit(4, ("die", None), 1)]
        outcome = Harness.supervisor(Bounds(), workers=2).run(units)
        assert outcome.failed == {4: Reason.DIED}
        assert outcome.results == {i: i for i in range(4)}

    def test_a_unit_that_raises_is_named_and_its_worker_goes_on(self) -> None:
        units = [Unit(0, ("raise", None), 1)] + [Unit(i, ("echo", i), 1) for i in range(1, 5)]
        supervisor = Harness.supervisor(Bounds(), workers=1)
        outcome = supervisor.run(units)
        assert outcome.failed[0].startswith(f"{Reason.FAILED}: UnicodeEncodeError: ")
        assert outcome.results == {i: i for i in range(1, 5)}
        assert not supervisor.retry  # raised, not died: named at once, not run again

    def test_no_unit_is_started_past_the_deadline(self) -> None:
        seen: list[int] = []
        units = [Unit(0, ("sleep", 1.5), 1)] + [Unit(i, ("echo", i), 1) for i in range(1, 4)]
        supervisor = Harness.supervisor(Bounds(), workers=1)
        supervisor.deadline = time.monotonic() + 0.5
        supervisor.on_result = lambda index, result: seen.append(index)
        outcome = supervisor.run(units)
        assert outcome.results == {0: "woke"}  # the one running finished
        assert sorted(outcome.unstarted) == [1, 2, 3]
        assert seen == [0]

    def test_no_worker_that_can_start_is_said_not_run_here(self) -> None:
        with pytest.raises(IsolationUnavailable):
            Harness.supervisor(Bounds(), setup="setup_that_raises").run([Unit(0, ("echo", 1), 1)])
