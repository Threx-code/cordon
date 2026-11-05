"""engine.isolation.supervisor: a unit that exhausts memory or CPU, or hangs, costs that unit and
nothing else; one that died only beside others keeps its result; the rest come back by index. The
workloads are planted here: a worker resolves them by name, as it resolves the engine's own."""

from __future__ import annotations

import multiprocessing
import os
import subprocess
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
    Worker,
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
    def setup_that_hangs() -> None:
        time.sleep(600)

    @staticmethod
    def wait_for(path: Path, pattern: str | None = None) -> None:
        """Until `path` exists (or holds a file matching `pattern`), bounded: a broken handshake
        ends in the assertion that follows, never in a hang."""
        for _ in range(3000):
            if any(path.glob(pattern)) if pattern else path.exists():
                return
            time.sleep(0.01)

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
        if kind == "busy":  # in flight until `company`'s first run has seen it, so they overlap
            folder = Path(str(arg))
            mark = folder / f"{os.getpid()}.running"
            mark.touch()
            # A handshake, not a sleep: the two workers may become ready seconds apart, and a fixed
            # sleep let `busy` finish before `company` started (item 63: 5 of 30 runs on 144c6bf9).
            Workloads.wait_for(folder / "company.died")
            mark.unlink()
            return "busy"
        if kind == "company":  # dies when another unit is in flight beside it, lives alone
            folder = Path(str(arg))
            if not (folder / "company.died").exists():
                Workloads.wait_for(folder, "*.running")  # its first run: until `busy` is in flight
            others = [p for p in folder.glob("*.running") if p.stem != str(os.getpid())]
            if others:
                (folder / "company.died").touch()
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
    def test_a_unit_the_size_of_a_whole_scan_is_waited_for(self) -> None:
        """The context worker and the expander run one unit sized as the whole scan: its wall
        backstop (10 times a per-byte CPU budget) passed the selector's 2**31 ms and the scan ended
        "timeout is too large", exit 2, on a 300 MB archive (the merge gate's cdktn unit)."""
        units = [Unit(0, ("echo", "whole"), 400 << 20)]
        outcome = Harness.supervisor(Bounds(cpu_per_byte=1.1e-3), workers=1).run(units)
        assert outcome.results == {0: "whole"}

    def test_no_unit_waits_past_the_wall_ceiling(self) -> None:
        """However large the unit, a hang is a gap within `wall_ceiling` (outer-layer review)."""
        bounds = Bounds(cpu_per_byte=1.0)
        assert bounds.wall_budget(10**9) == bounds.wall_ceiling == 4 * 3600.0
        assert Bounds().wall_budget(1) == 300.0  # an ordinary unit's backstop is unchanged

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

    def test_no_unit_is_started_past_the_deadline(self, monkeypatch) -> None:
        """Driven by the supervisor's clock, never the host's speed: the deadline passes the moment
        the first unit is given, so with one worker the other three are queued when it is checked
        (a wall-clock deadline here failed whenever a spawned worker took longer to start)."""
        seen: list[int] = []
        units = [Unit(i, ("echo", i), 1) for i in range(4)]
        supervisor = Harness.supervisor(Bounds(), workers=1)
        now = [0.0]
        supervisor.clock = lambda: now[0]
        supervisor.deadline = 10.0
        give = Worker.give

        def given_then_past(worker: Worker, unit: Unit, bounds: Bounds) -> None:
            give(worker, unit, bounds)
            now[0] = 20.0

        monkeypatch.setattr(Worker, "give", given_then_past)
        supervisor.on_result = lambda index, result: seen.append(index)
        outcome = supervisor.run(units)
        # The one running either finished before the deadline was seen, or was ended at it (item 64):
        # never failed, never run again.
        assert outcome.results in ({0: 0}, {})
        assert sorted(outcome.unstarted) == ([1, 2, 3] if outcome.results else [0, 1, 2, 3])
        assert seen == sorted(outcome.results)
        assert not outcome.failed

    def test_a_unit_running_at_the_deadline_is_ended_at_it(self) -> None:
        """Item 64: under load a unit in flight ran on to its own wall backstop, ten times its CPU
        budget, long past the scan's deadline (the long-line probe: a 60 s budget, 343 s). The
        deadline holds for it too: it is ended, and its file is reported unexamined."""
        supervisor = Harness.supervisor(Bounds(), workers=1)
        supervisor.deadline = time.monotonic() + 3.0
        outcome = supervisor.run([Unit(0, ("sleep", 60), 1)])
        assert outcome.results == {}
        assert outcome.unstarted == [0]
        assert not outcome.failed
        assert not supervisor.retry

    def test_a_worker_that_never_starts_holds_no_scan_past_its_deadline(self) -> None:
        """A worker hung before it said ready held no unit, so the wait had no timeout at all: the
        deadline was read only once something answered (macOS CI: a one-file case spent the whole
        900 s budget, "the scan's budget was spent before it finished", 5 Nov)."""
        supervisor = Harness.supervisor(Bounds(), workers=1, setup="setup_that_hangs")
        supervisor.deadline = time.monotonic() + 2.0
        began = time.monotonic()
        outcome = supervisor.run([Unit(0, ("echo", 1), 1)])
        assert time.monotonic() - began < 2.0 + Supervisor.STOP_GRACE + 10
        assert outcome.unstarted == [0] and outcome.results == {}

    def test_a_worker_that_never_starts_is_a_failed_start_after_its_backstop(
        self, monkeypatch
    ) -> None:
        """No deadline: a worker not ready within `START_BACKSTOP` ends as one that ended before it
        was ready, so a scan whose workers cannot start is a scanner error, never a hang."""
        monkeypatch.setattr(Worker, "START_BACKSTOP", 2.0)
        began = time.monotonic()
        with pytest.raises(IsolationUnavailable):
            Harness.supervisor(Bounds(), workers=1, setup="setup_that_hangs").run(
                [Unit(0, ("echo", 1), 1)]
            )
        assert time.monotonic() - began < 2 * 2.0 + 20

    def test_no_worker_that_can_start_is_said_not_run_here(self) -> None:
        with pytest.raises(IsolationUnavailable):
            Harness.supervisor(Bounds(), setup="setup_that_raises").run([Unit(0, ("echo", 1), 1)])


class TestTheBudgetIsOnTopOfWhatTheWorkerInherits:
    """RLIMIT_AS counts every mapping, the parent's included: a host whose address space was past the
    budget (a 4 GB reservation, never touched) had every worker fail and every scan end incomplete,
    on 3.12 as on 3.14. The budget is now what a worker may add to what it was forked with."""

    SCRIPT = (
        "import mmap, sys\n"
        "from pathlib import Path\n"
        "held = mmap.mmap(-1, 4 << 30)\n"
        "from cordon_scanner import Scanner\n"
        "from cordon_scanner.foundation.config.settings import Config\n"
        "root = Path(sys.argv[1])\n"
        "(root / 'index.js').write_text('module.exports = 1;\\n')\n"
        "result = Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(root)\n"
        "print('complete' if result.content_complete else 'incomplete')\n"
    )

    @pytest.mark.skipif(
        not sys.platform.startswith("linux"), reason="RLIMIT_AS is enforced on Linux"
    )
    def test_a_large_host_still_scans_complete(self, tmp_path) -> None:
        done = subprocess.run(
            [sys.executable, "-c", self.SCRIPT, str(tmp_path)],
            capture_output=True,
            text=True,
            timeout=600,
            env={**os.environ, "HOME": str(tmp_path)},
        )
        assert done.stdout.strip().endswith("complete") and "incomplete" not in done.stdout, (
            done.stdout[-500:],
            done.stderr[-1500:],
        )

    def test_the_address_space_is_read(self) -> None:
        from cordon_scanner.engine.isolation.supervisor import Limits

        if sys.platform.startswith("linux"):
            assert Limits.address_space() > 0
        else:
            assert Limits.address_space() == 0
