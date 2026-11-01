"""Units of work run in supervised worker processes, one at a time each, so a unit that exhausts
memory or CPU costs that unit and nothing else (item 28, detector isolation).

A worker is started with spawn or forkserver (`ParallelScanner.start_context`), never forked from
this process, runs a setup function once, then takes one unit at a time down its pipe and answers
with its result. What it may use is bounded where the platform enforces it: address space by
RLIMIT_AS, and each unit's CPU by RLIMIT_CPU (its soft limit raised to the CPU used so far plus the
unit's budget before each unit, so a runaway unit is ended by the kernel with SIGXCPU, inside C code
too). A wall clock far above the CPU budget is the backstop for a unit that hangs without burning
CPU, and on a platform with no CPU limit.

A worker that dies, or is ended, takes only the unit in hand. That unit is run again once, alone:
dispatch is paused until nothing else is in flight, and it gets a fresh worker under the same bounds.
Which process the kernel's out-of-memory killer picks depends on what else runs beside it, so a unit
that died only in company keeps its result; one that dies alone is reported, with why, and never
passes. Results are keyed by the unit's index, so the caller restores input order.
"""

from __future__ import annotations

import contextlib
import importlib
import math
import multiprocessing.connection
import os
import signal
import time
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from multiprocessing.connection import Connection
    from multiprocessing.context import BaseContext

#: A worker's exit status when an allocation past its memory limit raised MemoryError in a unit.
MEMORY_EXIT = 86


class Reason:
    """Why a unit has no result: the words a report names it by."""

    MEMORY = "memory"  # MemoryError past the worker's address-space limit
    CPU = "cpu"  # SIGXCPU: the unit's CPU budget
    WALL = "wall"  # the wall-clock backstop: a unit that hangs without burning CPU
    DIED = "died"  # any other end: killed (the out-of-memory killer's SIGKILL), crashed
    FAILED = "failed"  # the unit raised: its exception's type and message follow, after ": "


@dataclass(frozen=True, slots=True)
class Bounds:
    """What one worker may use. `memory_bytes` 0 sets no address-space limit; a unit's CPU budget is
    `max(cpu_floor, cpu_per_byte * size)` seconds, and its wall backstop `wall_factor` times that."""

    memory_bytes: int = 0
    cpu_floor: float = 30.0
    cpu_per_byte: float = 0.0
    wall_factor: float = 10.0

    def cpu_budget(self, size: int) -> float:
        return max(self.cpu_floor, self.cpu_per_byte * size)

    def wall_budget(self, size: int) -> float:
        return self.wall_factor * self.cpu_budget(size)


@dataclass(frozen=True, slots=True)
class Unit:
    """One unit of work: its index (input order), what the work function receives, its size."""

    index: int
    item: Any
    size: int


@dataclass(slots=True)
class Outcome:
    """What a supervised run produced: each unit's result by index, each unit with none and why,
    and what the workers recorded of the isolation they ran under."""

    results: dict[int, Any] = field(default_factory=dict)
    failed: dict[int, str] = field(default_factory=dict)
    isolation: dict[str, str] = field(default_factory=dict)
    #: Units never given to a worker because the deadline had passed first.
    unstarted: list[int] = field(default_factory=list)


class IsolationUnavailable(RuntimeError):
    """No worker could be started: the work was not run anywhere."""


class Worker:
    """One supervised process and the unit it holds."""

    def __init__(self, context: BaseContext, setup: tuple[str, tuple[Any, ...]], work: str,
                 bounds: Bounds) -> None:  # fmt: skip
        ours, theirs = context.Pipe()
        self.conn: Connection = ours
        self.process = context.Process(  # type: ignore[attr-defined]  # spawn and forkserver have it
            target=WorkerMain.run, args=(theirs, setup, work, bounds), daemon=True
        )
        self.process.start()
        theirs.close()
        self.ready = False
        self.unit: Unit | None = None
        self.given_at = 0.0

    def give(self, unit: Unit, bounds: Bounds) -> None:
        self.unit, self.given_at = unit, time.monotonic()
        self.conn.send((unit.index, unit.item, bounds.cpu_budget(unit.size)))

    def overdue(self, bounds: Bounds, now: float) -> bool:
        return self.unit is not None and now - self.given_at > bounds.wall_budget(self.unit.size)

    def end(self) -> None:
        if self.process.is_alive():
            self.process.kill()
        self.process.join(5)
        self.conn.close()

    def reason(self) -> str:
        code = self.process.exitcode
        if code == MEMORY_EXIT:
            return Reason.MEMORY
        if code == -getattr(signal, "SIGXCPU", -1):
            return Reason.CPU
        return Reason.DIED


class WorkerMain:
    """What runs inside a worker process."""

    @staticmethod
    def resolve(name: str) -> Callable[..., Any]:
        module, _, attribute = name.partition(":")
        target: Any = importlib.import_module(module)
        for part in attribute.split("."):
            target = getattr(target, part)
        return target  # type: ignore[no-any-return]

    @staticmethod
    def run(
        conn: Connection, setup: tuple[str, tuple[Any, ...]], work: str, bounds: Bounds
    ) -> None:
        isolation = Limits.apply(bounds)
        WorkerMain.resolve(setup[0])(*setup[1])
        run = WorkerMain.resolve(work)
        conn.send(("ready", isolation))
        while True:
            message = conn.recv()
            if message is None:
                return
            index, item, cpu_budget = message
            Limits.cpu_for_next(cpu_budget)
            try:
                result = run(item)
            except MemoryError:
                # Past the address-space limit: the unit is reported, and this process, whose
                # state a failed allocation may have left anywhere, is not used again.
                os._exit(MEMORY_EXIT)
            except Exception as exc:  # noqa: BLE001 - any exception costs the unit, named, not the scan
                # An ordinary exception leaves the process sound: the unit is reported with what
                # raised, and the worker takes the next one.
                Limits.cpu_release()
                conn.send(("failed", index, f"{Reason.FAILED}: {type(exc).__name__}: {exc}"[:500]))
                continue
            # Released before the worker waits for its next unit: an idle worker is never ended for
            # the CPU the unit before used.
            Limits.cpu_release()
            conn.send(("done", index, result))


class Limits:
    """The bounds a worker applies to itself, and what it recorded of them."""

    @staticmethod
    def apply(bounds: Bounds) -> dict[str, str]:
        recorded = {"memory_limit": "not_enforced", "cpu_limit": "not_enforced"}
        try:
            import resource
        except ImportError:  # Windows: no rlimits; death and the wall backstop still hold
            return recorded
        if bounds.memory_bytes > 0:
            try:
                _, hard = resource.getrlimit(resource.RLIMIT_AS)
                limit = (
                    bounds.memory_bytes
                    if hard == resource.RLIM_INFINITY
                    else min(bounds.memory_bytes, hard)
                )
                resource.setrlimit(resource.RLIMIT_AS, (limit, hard))
                if resource.getrlimit(resource.RLIMIT_AS)[0] == limit:
                    recorded["memory_limit"] = "enforced"
            except (ValueError, OSError):
                pass  # macOS accepts no lower RLIMIT_AS than it has: recorded as not enforced
        if hasattr(resource, "RLIMIT_CPU") and hasattr(signal, "SIGXCPU"):
            recorded["cpu_limit"] = "enforced"
        # SIGXCPU's default action dumps core: a unit ended on its CPU budget must leave no core
        # file (the size of the worker's memory) behind in the directory it ran in.
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(
                resource.RLIMIT_CORE, (0, resource.getrlimit(resource.RLIMIT_CORE)[1])
            )
        return recorded

    @staticmethod
    def cpu_for_next(budget: float) -> None:
        """RLIMIT_CPU's soft limit set to the CPU this process has used plus `budget`, rounded up:
        past it, the kernel ends the unit with SIGXCPU, whose default action (end the process) no
        code here replaces. Only the soft limit is set: an unprivileged process cannot raise a hard
        limit it lowered, so lowering it once would cap every later unit. A budget past the hard
        limit is not set at all; the wall backstop still bounds that unit.

        CPU time is the same for a unit from run to run on one machine whatever else runs, which is
        what makes it the budget; it differs between machines, and the budget's headroom (10 times
        a measured rate) keeps a two to three times slower runner from reaching it on a benign unit.
        """
        try:
            import resource
        except ImportError:
            return
        if not hasattr(resource, "RLIMIT_CPU"):
            return
        usage = resource.getrusage(resource.RUSAGE_SELF)
        soft = math.ceil(usage.ru_utime + usage.ru_stime + budget) + 1
        _, hard = resource.getrlimit(resource.RLIMIT_CPU)
        if hard != resource.RLIM_INFINITY and soft > hard:
            return
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(resource.RLIMIT_CPU, (soft, hard))

    @staticmethod
    def cpu_release() -> None:
        """RLIMIT_CPU's soft limit back to its hard limit, between units."""
        try:
            import resource
        except ImportError:
            return
        if not hasattr(resource, "RLIMIT_CPU"):
            return
        _, hard = resource.getrlimit(resource.RLIMIT_CPU)
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(resource.RLIMIT_CPU, (hard, hard))


class Supervisor:
    """Runs units across up to `workers` supervised processes: each unit's result, or why it has
    none, by its index."""

    def __init__(self, context: BaseContext, setup: tuple[str, tuple[Any, ...]], work: str,
                 bounds: Bounds, workers: int, *, deadline: float | None = None,
                 on_result: Callable[[int, Any], None] | None = None) -> None:  # fmt: skip
        """`deadline`, a `time.monotonic()` reading: no unit is given to a worker after it (those
        go to `Outcome.unstarted`); one already running finishes. `on_result` is called in this
        process with each unit's index and result as it arrives."""
        self.context, self.setup, self.work, self.bounds = context, setup, work, bounds
        self.workers = max(1, workers)
        self.deadline, self.on_result = deadline, on_result
        self.outcome = Outcome()
        self.retry: list[Unit] = []

    def run(self, units: Iterable[Unit]) -> Outcome:
        queue = deque(units)
        if not queue:
            return self.outcome
        pool = [self._start() for _ in range(min(self.workers, len(queue)))]
        self._drain(pool, queue, retried=False)
        # Each unit that died in company, once more, alone: nothing else in flight beside it.
        for unit in self.retry:
            self._drain([self._start()], deque([unit]), retried=True)
        return self.outcome

    def _start(self) -> Worker:
        return Worker(self.context, self.setup, self.work, self.bounds)

    def _drain(self, pool: list[Worker], queue: deque[Unit], *, retried: bool) -> None:
        """Every unit of `queue` run on `pool`, a dead worker replaced while units remain."""
        started_any = False
        unready_ends = 0
        try:
            while pool and (queue or any(w.unit is not None for w in pool)):
                if self.deadline is not None and queue and time.monotonic() >= self.deadline:
                    self.outcome.unstarted.extend(unit.index for unit in queue)
                    queue.clear()
                for worker in pool:
                    if worker.ready and worker.unit is None and queue:
                        worker.give(queue.popleft(), self.bounds)
                if not queue and all(w.unit is None for w in pool):
                    # Nothing to give and nothing in flight (the deadline may have just emptied the
                    # queue): waiting now, with no unit's backstop to bound it, would never end.
                    break
                self._wait(pool)
                started_any = started_any or any(w.ready for w in pool)
                for worker in list(pool):
                    if worker.process.is_alive() and not worker.overdue(
                        self.bounds, time.monotonic()
                    ):
                        continue
                    pool.remove(worker)
                    self._lost(worker, Reason.WALL if worker.process.is_alive() else None, retried)
                    worker.end()
                    if not worker.ready:
                        # It ended before it was ready: tried once more in a fresh worker; when no
                        # worker has started at all and that one ends too, nothing can run here.
                        unready_ends += 1
                        if not started_any and unready_ends >= 2:
                            raise IsolationUnavailable(
                                f"no worker could start: it ended before it was ready "
                                f"({worker.reason()}, exit {worker.process.exitcode})"
                            )
                        pool.append(self._start())
                    elif queue:
                        pool.append(self._start())
        finally:
            for worker in pool:
                if worker.process.is_alive():
                    worker.conn.send(None)
                worker.end()

    def _wait(self, pool: list[Worker]) -> None:
        """Until a worker answers or ends, or the nearest wall backstop falls due."""
        now = time.monotonic()
        due = [w.given_at + self.bounds.wall_budget(w.unit.size) - now for w in pool if w.unit]
        timeout = max(0.0, min(due)) if due else None
        waitable: list[Any] = [w.conn for w in pool] + [w.process.sentinel for w in pool]
        for ready in multiprocessing.connection.wait(waitable, timeout):
            worker = next((w for w in pool if ready is w.conn or ready == w.process.sentinel), None)
            if worker is None or ready is not worker.conn:
                continue
            try:
                message = worker.conn.recv()
            except (EOFError, OSError):
                continue  # it ended: its sentinel says how
            self._answer(worker, message)

    def _answer(self, worker: Worker, message: tuple[Any, ...]) -> None:
        if message[0] == "ready":
            worker.ready = True
            self.outcome.isolation = dict(message[1])
        elif message[0] == "done" and worker.unit is not None and message[1] == worker.unit.index:
            self.outcome.results[message[1]] = message[2]
            worker.unit = None
            if self.on_result is not None:
                self.on_result(message[1], message[2])
        elif message[0] == "failed" and worker.unit is not None and message[1] == worker.unit.index:
            # The same exception from the same input: not run again, which would only repeat it.
            self.outcome.failed[message[1]] = message[2]
            worker.unit = None

    def _lost(self, worker: Worker, reason: str | None, retried: bool) -> None:
        """The unit a worker held when it ended: once more alone, or reported."""
        unit = worker.unit
        if unit is None:
            return
        if retried:
            self.outcome.failed[unit.index] = reason or worker.reason()
        else:
            self.retry.append(unit)


__all__ = [
    "MEMORY_EXIT",
    "Bounds",
    "IsolationUnavailable",
    "Outcome",
    "Reason",
    "Supervisor",
    "Unit",
]
