"""Parallel file inspection.

Detectors were written as pure functions over immutable units precisely so that
this module could exist without changing any of them. Nothing here reaches into
a detector; it moves the same calls onto other processes.

Three design points are worth stating, because each is a decision rather than a
default.

**Processes, not threads.** Matching is CPU-bound and runs in Python bytecode
around the regex engine, so threads would contend on the interpreter lock and
deliver nothing. Processes also give each worker its own memory, which bounds
the damage a pathological input can do to one worker rather than the whole scan.

**Workers are initialised once, not per task.** Compiling the rule set is the
expensive part of starting up, so it happens once per worker at pool creation.
Sending compiled rules with every task would cost more than the parallelism
saves.

**Results are reordered before they are returned.** Completion order depends on
scheduling, and constraint C5 requires that two runs of the same scan produce
identical output. Workers therefore return their input index alongside their
findings, and the caller restores the original order.

Parallelism is off for small scans. Starting a pool costs tens of milliseconds
per worker, which is more than a few hundred files take to scan outright, and a
pre-commit hook is exactly the case that must not pay it.
"""

from __future__ import annotations

import math
import multiprocessing
import multiprocessing.context
import os
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, as_completed, wait
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from concurrent.futures._base import Future

    from cordon_scanner.detect.base import ScanContext
    from cordon_scanner.foundation.config.settings import Config
    from cordon_scanner.foundation.content import FileContent
    from cordon_scanner.foundation.models import Finding

MIN_FILES_FOR_PARALLEL = 400
"""Below this, a scan runs in the calling process.

Pool startup is tens of milliseconds per worker plus interpreter initialisation.
On a few hundred files that is most of the runtime, so parallelism would make
the common case slower while helping only the rare one.
"""

WorkItem = tuple[int, str, int, str, "bytes | str | None"]
"""One file handed to a worker: its index, path, size, the parent's content
hash, and -- for a source whose bytes are not on disk -- the bytes themselves,
or for an archive member kept on disk past `max_file_bytes` the path it was kept
at (`FileContent.carried`). The hash travels so the worker can tell whether it
read what the parent read; see `_inspect_batch`."""

MAX_CARRIED_BYTES = 64 * 1024 * 1024
"""How much content a non-re-readable source may send to the pool.

A source whose bytes are not on disk -- the git index, an archive -- cannot let
a worker re-read by path, so its content travels in the work item instead. That
is bounded: a commit is small, and this is the cap past which a scan stays
serial rather than pickling an unbounded amount of a repository into a pool.
Sixty-four megabytes is far above any commit and far below a memory problem.
"""

MAX_WORKERS = 16

#: Settings a worker needs that `Config.to_dict()` does not carry, because `to_dict()` is the
#: repository schema and these come only from the operator or the organisation policy: where a
#: scan may send bytes (`clamav`, `rule_file`, `judge`), how the judge reports and its budget, and the
#: policy lists per-file rules read. Each one missing here made a parallel scan disagree with a
#: serial one; `tests/unit/engine/test_parallel.py` fails when a new field is in neither this nor
#: `PARENT_ONLY_SETTINGS`.
CARRIED_SETTINGS: tuple[str, ...] = (
    "clamav",
    "rule_file",
    "rule_module_data",
    "judge",
    "judge_blocks",
    "judge_max_calls",
    "allowed_action_owners",
    "internal_namespaces",
)

#: Settings a worker does not need, with the reason. A worker inspects files and returns
#: findings; everything else -- the cache, how the configuration was assembled, the policy
#: ceiling already applied to the values it receives -- stays with the parent.
PARENT_ONLY_SETTINGS: dict[str, str] = {
    "explicit_limits": "which limits the operator set by hand; the values themselves are carried",
    "notify_channels": "the parent posts the gate's outcome after the scan; a worker never notifies",
    "notify_on": "the parent decides whether to post, after the scan; a worker never notifies",
    "private_registries": "registries are asked by the parent, about the graph; a worker never reaches one",
    "keyrings": "provenance is verified by the parent, about the graph; a worker never reads a keyring",
    "provenance": "where each setting came from, for `config show`",
    "cache_dir": "the parent reads and writes the cache",
    "use_cache": "the parent reads and writes the cache",
    "constraints": "the organisation ceiling, already applied to the carried values",
    "org_limits": "the organisation ceiling, already applied to the carried limits",
    "untrusted_exclusions": "exclusions are applied by the parent's walk",
    "reduced_limits": "reported by the parent",
    "from_untrusted_source": "reported by the parent",
    "clamped_settings": "reported by the parent",
    "_rechecking": "the parent's own re-entry guard",
}
"""Ceiling on worker count.

A high-core CI runner spawning one worker per core over a medium repository
spends more time starting processes than matching bytes. The ceiling costs
nothing on the sizes where more workers would actually help.
"""

AVERAGE_FILE_BYTES = 8 * 1024
"""Assumed mean source-file size, used only to estimate a batch count.

An estimate rather than a measurement because the batch count is needed to size
the pool, and sizing happens before the files have been read. Being wrong costs
at most a few idle or overloaded workers, never a difference in findings."""

BATCH_TARGET_BYTES = 4 * 1024 * 1024
"""The largest batch: batches are sized by cumulative bytes rather than by file count.

One very large file and a thousand small ones are not the same work. Sizing by
count leaves a worker holding the large file while the others idle, which is the
usual reason a parallel scan is barely faster than a serial one.
"""

WORK_PER_WORKER = 1024 * 1024
"""The estimated work, in bytes, that pays for one more worker.

A worker costs about 1.7 s of CPU to start (0.7 s of imports, 1 s to build its engine; 0.04 s
for the second engine in one process), and matching costs about 2 s of CPU per megabyte of
source. Sized by batches of `BATCH_TARGET_BYTES` instead, a 9 MB archive (armadaproject/armada,
1,346 members) got three workers and three batches, one holding 899 of the files, and took as
long at `--jobs 4` as at `--jobs 1` (17.5 s against 18.0 s of member scanning)."""

BATCHES_PER_WORKER = 8
"""How many batches each worker's share of the work is cut into.

A worker that finishes takes the next batch, so the scan ends when the work does rather than
when the batch that happened to hold the expensive files does. Bytes are a poor estimate of
a file's cost -- a minified bundle and a data file of the same size are not the same work --
and only small batches make that error stop mattering. A batch costs one task submission and
one pickled result, which is nothing beside matching it."""

MIN_BATCH_BYTES = 256 * 1024
"""The smallest batch, so a scan of many tiny files is not cut into thousands of tasks."""


class ParallelScanner:
    """Runs file inspection across a process pool.

    Processes rather than threads: the work is CPU-bound regex matching, and
    Python's global interpreter lock makes threads useless for it.

    Two properties are load-bearing and both are about not lying:

    Results are restored to input order before returning. Completion order
    depends on scheduling, and identical inputs must produce identical output.

    Pool failure returns empty rather than raising, and the caller then runs
    serially. A platform where processes cannot be spawned degrades to a slower
    scan instead of a failed one. This is also where a silent failure once hid:
    a config that could not round-trip through `to_dict` killed every worker in
    its initialiser, the pool returned nothing, and the engine fell back to
    serial without a word. The fallback is correct; being quiet about it was
    not.
    """

    #: Per-process state, built once in the pool initialiser. A class attribute
    #: rather than a module global because a worker process holds exactly one,
    #: and it belongs to the class that puts it there.
    _worker: ClassVar[_WorkerState | None] = None

    @staticmethod
    def worker_count(requested: int, file_count: int, total_bytes: int = 0) -> int:
        """Decide how many workers to use.

        Returns 1 when parallelism would not pay, so the caller has a single
        condition to check rather than a special case.

        The work is estimated from the larger of the bytes the walk actually found and the
        file count at an average size. From the count alone, 450 files of a few hundred
        kilobytes each estimated as 3.6 MB -- one batch, one worker -- while the bytes said
        over a hundred; and a tree of many tiny files still has per-file cost the bytes
        under-state.
        """
        if requested == 1:
            return 1
        estimate = max(total_bytes, file_count * AVERAGE_FILE_BYTES)
        if file_count < 2 or estimate < MIN_FILES_FOR_PARALLEL * AVERAGE_FILE_BYTES:
            return 1

        available = requested if requested > 0 else ParallelScanner.available_cpus()
        # Never more workers than the work pays for, and never more than files. The comment
        # claimed this and the code did not do it, so a repository just over the threshold
        # started a process per core to share one batch.
        affordable = max(1, math.ceil(estimate / WORK_PER_WORKER))
        return max(1, min(available, MAX_WORKERS, affordable, file_count))

    @staticmethod
    def batch_target(total_bytes: int, workers: int) -> int:
        """The batch size for `workers` sharing `total_bytes`: `BATCHES_PER_WORKER` batches each,
        between `MIN_BATCH_BYTES` and `BATCH_TARGET_BYTES`."""
        share = math.ceil(total_bytes / max(1, workers * BATCHES_PER_WORKER))
        return max(MIN_BATCH_BYTES, min(BATCH_TARGET_BYTES, share))

    @staticmethod
    def available_cpus(cgroup: str = "/sys/fs/cgroup") -> int:
        """The cores this process may actually use, not the cores the host has.

        `os.cpu_count()` counts the host: inside a container given two CPUs on a
        twelve-core host it says twelve, so an automatic pool started twelve workers
        that shared two cores, each holding its own engine and slice of the input.
        The CPU affinity mask and the cgroup quota (v2 `cpu.max`, v1 `cfs_quota_us`)
        are what the scheduler enforces, so the smallest of the three is the answer.
        """
        try:
            count = len(os.sched_getaffinity(0))
        except (AttributeError, OSError):
            count = os.cpu_count() or 1
        quota = ParallelScanner._cgroup_quota(cgroup)
        if quota is not None:
            count = min(count, max(1, math.ceil(quota)))
        return max(1, count)

    @staticmethod
    def _cgroup_quota(cgroup: str) -> float | None:
        """CPUs the cgroup quota allows, or None when there is no quota to read."""
        root = Path(cgroup)
        try:
            limit, _, period = (root / "cpu.max").read_text(encoding="ascii").strip().partition(" ")
            if limit == "max":
                return None
            return int(limit) / int(period or "100000")
        except (OSError, ValueError, ZeroDivisionError):
            pass
        try:
            quota = int((root / "cpu" / "cpu.cfs_quota_us").read_text(encoding="ascii"))
            interval = int((root / "cpu" / "cpu.cfs_period_us").read_text(encoding="ascii"))
        except (OSError, ValueError):
            return None
        return quota / interval if quota > 0 and interval > 0 else None

    @staticmethod
    def start_context() -> multiprocessing.context.BaseContext:
        """How workers are started: never by forking this process.

        The scanner is multi-threaded by the time it scans (the progress reporter, the git batch
        reader, the cache writer), and `fork()` copies only the calling thread. A lock another
        thread held at that instant is held forever in the child, which is a deadlock that shows up
        once in a few thousand scans and never under a debugger. Python deprecates exactly this and
        3.14 stops doing it by default on Linux. A fork server is forked once, before any of that,
        and is the cheap safe choice where it exists; elsewhere a fresh interpreter is started.
        """
        methods = multiprocessing.get_all_start_methods()
        if "forkserver" not in methods:
            return multiprocessing.get_context("spawn")
        context = multiprocessing.get_context("forkserver")
        # The engine's modules imported once, in the fork server, rather than again by every worker
        # it forks: 0.7 s of CPU per worker otherwise. A module import is all it does here -- no
        # thread is started and nothing is read -- so the fork stays as safe as it was.
        context.set_forkserver_preload(["cordon_scanner.engine.engine"])
        return context

    @staticmethod
    def batch_by_bytes(
        items: Sequence[WorkItem], target: int = BATCH_TARGET_BYTES
    ) -> list[list[WorkItem]]:
        """Group (index, path, size) triples into byte-balanced batches.

        A file larger than the target gets a batch of its own rather than being
        split, since a file is the smallest unit a detector can reason about.
        """
        batches: list[list[WorkItem]] = []
        current: list[WorkItem] = []
        accumulated = 0

        for item in items:
            size = item[2]
            if current and accumulated + size > target:
                batches.append(current)
                current, accumulated = [], 0
            current.append(item)
            accumulated += size

        if current:
            batches.append(current)
        return batches

    @staticmethod
    def _initialise(
        engine_type: Callable[[Config], Any],
        config_payload: dict[str, Any],
        root: str,
        detector_ids: tuple[str, ...],
        inventory: Any = None,
        operator: dict[str, Any] | None = None,
        facts: dict[str, Any] | None = None,
    ) -> None:
        """Build one worker's engine.

        `engine_type` is the parent's engine class, handed over rather than imported: the engine
        runs the pipeline that runs this pool, so naming it here closed an import cycle. A class
        crosses to the worker by its qualified name.

        Runs once per process. Everything expensive -- loading rule packs,
        compiling patterns, discovering detectors -- happens here rather than per
        task, which is the difference between parallelism helping and hurting.

        `detector_ids` is the set the parent already decided should run, after
        applying detector configuration, the offline flag and each detector's
        own applicability check. The worker used to ignore all three and run
        every detector it could find, so a repository that disabled `capability`
        got findings from it at `-j 8` and not at `-j 1`. Since the worker count
        defaults to the machine's core count, the same scan produced different
        results on different machines -- and determinism is what baselines,
        caches and reproducible gates rest on.

        `install_hook_paths` and `ci_hook_paths` are here for exactly the same
        reason, and they were missing. `engine._context(inventory)` builds them
        from the inventory alone, which knows a manifest DECLARES a hook but not
        which file the hook runs: `inventory.hooks` records `package.json`, not
        `scripts/setup.js`. The parent fills that in afterwards, resolving each
        command to the file it reaches and then following its imports -- and none
        of it reached the workers.

        What that cost was not a lower score. `ctx.in_install_hook` is a
        precondition on the composites, so a script that posts the environment
        out during `postinstall` produced MALWARE.EXFIL.001 at critical with one
        worker and NOTHING with eight. Same files, same count, same rules; the
        finding simply was not there. Parallelism engages above four hundred
        files and the worker count defaults to the core count, so the default
        configuration on any real repository was the one missing it.

        The hook paths were fixed, then the unreached bodies, the image, the entry files and the
        package facts, each when its absence was found -- and the five set after them
        (`agent_run_paths`, `shipped_native_paths`, `library_entry_paths`,
        `library_closure_paths`, `declared_dependencies`) never reached a worker, so above the
        parallel threshold a skill's script, a library's entry closure and a shipped binary were
        judged as ordinary files. `facts` is now every field of the parent's context but the
        process-local ones (`ScanContext.LOCAL`), so a field added later reaches the workers
        without anyone remembering to send it.
        """
        from cordon_scanner.foundation.collector import Collector

        Collector.relax()  # a worker only scans: its collector stays relaxed

        from cordon_scanner.foundation.config.settings import Config as _Config

        config = _Config.from_dict(config_payload, source="<worker>")
        if operator:
            # The operator-only settings (`--clamav`, `--rule-file`) are not in `to_dict()` on
            # purpose: it is the repository schema, and a scan target must never choose where its
            # own bytes are sent. So they cross to the workers separately. Without this every
            # worker ran the ClamAV detector with no daemon address: above the parallel threshold
            # a `--clamav` scan reported "clamd at  could not be reached" and came back
            # incomplete, and `--rule-file` matched nothing.
            from dataclasses import replace as _replace_operator

            config = _replace_operator(config, **operator)
        engine = engine_type(config)
        if inventory is None:
            # Only when the parent could not supply one. Each worker used to run
            # a complete inventory walk of the repository, so a 200,000-file
            # monorepo with sixteen workers paid for seventeen full traversals
            # of a tree the parent had already walked. The inventory is a frozen
            # dataclass, so it crosses the process boundary as data.
            inventory = engine.inventory(ParallelScanner._to_path(root))
        wanted = set(detector_ids)
        detectors = tuple(d for d in engine.detectors if getattr(d, "id", "") in wanted)

        context = engine._context(inventory)
        context = ParallelScanner.worker_context(context, facts)
        ParallelScanner._worker = _WorkerState(
            engine=engine,
            context=context,
            detectors=detectors,
        )

    @staticmethod
    def worker_context(context: ScanContext, facts: dict[str, Any] | None) -> ScanContext:
        """The worker's scan context: its own process-local fields, and the parent's facts.

        Assignment over the context the worker derived from the inventory, not a union: the
        parent derived its own context from the same inventory first and then added to it, so its
        facts are what the worker would compute and more, and a worker that held anything the
        parent does not would judge a file differently from a serial scan."""
        from dataclasses import replace as _replace

        return _replace(context, **(facts or {}))

    @staticmethod
    def _to_path(root: str) -> Path:
        from pathlib import Path

        return Path(root)

    @staticmethod
    def _inspect_batch(
        batch: list[WorkItem], root: str, deadline: float | None = None
    ) -> list[tuple[int, list[dict[str, Any]], bool | None, bool]]:
        """Scan one batch inside a worker.

        Findings cross the process boundary as dictionaries rather than as domain
        objects. That keeps the boundary explicit and depends only on the
        serialisation the JSON reporter already relies on, rather than on every
        domain type remaining picklable forever.

        A work item may carry the file's bytes. That is how a source whose
        content is not on disk -- `--staged`, which reads the git index -- is
        scanned in parallel at all: re-reading by path would scan the working
        tree while the caller believes it is scanning the index. The bytes the
        parent already read travel with the item, and the worker reads nothing.

        `deadline` is the scan's budget as a `time.monotonic()` reading, which is the same clock
        in every process on the machine. A file reached after it is not read: it comes back
        marked `None`, not examined, for the parent to report.
        """
        if ParallelScanner._worker is None:  # pragma: no cover - only reachable on a broken pool
            return []

        from pathlib import Path

        from cordon_scanner.foundation.content import FileContent, Skipped

        engine = ParallelScanner._worker.engine
        ctx = ParallelScanner._worker.context
        detectors = ParallelScanner._worker.detectors
        out: list[tuple[int, list[dict[str, Any]], bool | None, bool]] = []

        for index, relative, _size, expected, carried in batch:
            if deadline is not None and time.monotonic() >= deadline:
                out.append((index, [], None, False))  # not examined: the budget ran out first
                continue
            if isinstance(carried, str):
                loaded = FileContent.load(Path(carried), relative, engine.config.limits)
            elif carried is not None:
                loaded = FileContent.from_bytes(relative, carried, limits=engine.config.limits)
            else:
                loaded = FileContent.load(Path(root) / relative, relative, engine.config.limits)
            if isinstance(loaded, Skipped):
                # An empty list used to be returned here with nothing said. The
                # serial path turns a `Skipped` into OPERATIONAL.FILE.UNREADABLE
                # and marks the scan incomplete, so coverage shrank silently and
                # whether it did depended on the machine's core count. The
                # `False` says the result is not trustworthy; the parent reports
                # it exactly as the serial path would.
                out.append((index, [], False, False))
                continue

            if loaded.sha256 != expected:
                # The parent read this file and computed its hash; the worker
                # read it again and got something else. That happens when
                # anything mutates the tree between the two reads -- a
                # postinstall that has already run, a dev server, a concurrent
                # job on a shared workspace, or a racer committed as part of the
                # payload.
                #
                # Returning the findings anyway would have them cached under the
                # parent's key, so `{}` becomes the permanent cached result for
                # the malicious content's own hash and every later scan of that
                # exact content on that machine is a silent hit. The engine's
                # docstring claims a cache hit is provably identical to a cold
                # run; this is where that stopped being true.
                out.append((index, [], False, False))
                continue

            findings, intact, cacheable = ParallelScanner._inspected(
                loaded, relative, root, ctx, detectors
            )
            out.append((index, findings, True, cacheable) if intact else (index, [], False, False))

        return out

    @staticmethod
    def _batch_results(
        future: Any,
    ) -> list[tuple[int, list[dict[str, Any]], bool | None, bool]]:
        """A batch's per-file results; a timed batch's detector times added to this process's."""
        from cordon_scanner.engine.detector_clock import DetectorClock

        result = future.result()
        if isinstance(result, tuple):
            out, taken = result
            DetectorClock.add(taken)
            return out  # type: ignore[no-any-return]
        return result  # type: ignore[no-any-return]

    @staticmethod
    def _inspect_batch_timed(
        batch: list[WorkItem], root: str, deadline: float | None = None
    ) -> tuple[list[tuple[int, list[dict[str, Any]], bool | None, bool]], dict[str, float]]:
        """`_inspect_batch`, with the CPU time each detector spent on it (`DetectorClock`)."""
        from cordon_scanner.engine.detector_clock import DetectorClock

        # The clock follows the scan that asked for it, not this worker's environment: a warm pool's
        # workers may have started before the scan turned the clock on.
        with DetectorClock.on():
            out = ParallelScanner._inspect_batch(batch, root, deadline)
        return out, DetectorClock.taken()

    @staticmethod
    def _inspected(
        loaded: FileContent, relative: str, root: str, ctx: Any, detectors: tuple[Any, ...]
    ) -> tuple[list[dict[str, Any]], bool, bool]:
        """One file's findings as they cross back to the parent, whether the file stayed the same
        while it was read, and whether its inspection stayed within it (`ScanCache.watch`)."""
        from cordon_scanner.engine.cache import ScanCache

        with ScanCache.watch(root, relative) as watch:
            produced, failures, windowed, intact = ParallelScanner._inspect_unit(
                loaded, relative, ctx, detectors
            )
        if not intact:
            return [], False, False
        produced.extend(windowed)
        findings: list[dict[str, Any]] = [
            # The same per-file hash the serial path records, and recorded
            # here too because `test_parallel_matches_serial_exactly` is
            # what this codebase has instead of hoping the two agree.
            f.with_file_hash(loaded.sha256).to_dict()
            if f.location.path == relative
            else f.to_dict()
            for f in produced
        ]
        findings.extend(failures)
        return findings, True, not watch.reached

    @staticmethod
    def _inspect_unit(
        loaded: FileContent, relative: str, ctx: Any, detectors: tuple[Any, ...]
    ) -> tuple[list[Any], list[dict[str, Any]], list[Finding], bool]:
        """One unit inspected inside the worker: every detector, the judge last, then the windows past its prefix."""
        from cordon_scanner.detect.base import FileUnit
        from cordon_scanner.engine.detector_clock import DetectorClock
        from cordon_scanner.engine.window_pass import WindowPass

        unit = FileUnit(content=loaded, language=ParallelScanner._language(relative, loaded))
        produced: list[Any] = []
        failures: list[dict[str, Any]] = []

        def inspect(
            detector: Any,
            part: Any,
            failures: list[dict[str, Any]] = failures,
            relative: str = relative,
        ) -> list[Any]:
            try:
                return DetectorClock.timed(
                    getattr(detector, "id", "unknown"), lambda: list(detector.inspect(part, ctx))
                )
            except Exception as exc:  # noqa: BLE001
                # A detector that fails in a worker must not silently reduce
                # coverage. It is reported the same way the serial path reports
                # it, so a broken detector looks identical either way.
                failures.append(
                    ParallelScanner._operational_dict(
                        path=relative,
                        detector=getattr(detector, "id", "unknown"),
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
                return []

        from cordon_scanner.detect.registry import JudgeGate

        active = []
        for detector in JudgeGate.last(list(detectors)):
            # The judge on the grey band only, after the rest: as the serial path.
            if getattr(detector, "id", "") == JudgeGate.ID and not JudgeGate.wants(produced):
                continue
            active.append(detector)
            produced.extend(inspect(detector, unit))
        # The rest of an oversized file, a window at a time: the call the serial path makes.
        windowed, intact = WindowPass.run(unit, active, inspect, produced)
        return produced, failures, windowed, intact

    @staticmethod
    def _language(relative: str, content: FileContent) -> str | None:
        """Path first, then the shebang.

        Kept identical to the engine's own choice: a worker that identified
        languages differently from the parent would select different rules, and
        the same scan would produce different findings depending on how many
        files it happened to contain.
        """
        from cordon_scanner.analysis.shared.languages import LanguageRegistry

        return LanguageRegistry.of_file(relative, content)

    @staticmethod
    def _operational_dict(*, path: str, detector: str, error: str) -> dict[str, Any]:
        """A serialised OPERATIONAL finding for a worker-side detector failure."""
        import hashlib

        digest = hashlib.sha256(f"{detector}:{path}".encode()).hexdigest()
        return {
            "rule_id": "OPERATIONAL.DETECTOR.FAILED",
            "category": "operational",
            "severity": "info",
            "confidence": "confirmed",
            "message": (
                f"Detector {detector!r} failed on this file, so its checks did not run: {error}"
            ),
            "location": {"path": path},
            "evidence": {
                "kind": "metadata",
                "match_hash": f"sha256:{digest}",
                "redaction": "none",
            },
            "remediation": "Report this with the file that triggered it.",
            "explanation": {
                "summary": "Reported so that reduced coverage is never silent.",
                "matched_rule": "OPERATIONAL.DETECTOR.FAILED",
            },
            "risk": {"value": 0, "base": 0, "confidence_multiplier": 1.0, "factors": []},
            "detector": detector,
        }

    @staticmethod
    def run(
        *,
        config: Config,
        root: str,
        files: Sequence[WorkItem],
        workers: int,
        detector_ids: Sequence[str],
        engine_type: Callable[[Config], Any],
        inventory: Any = None,
        facts: dict[str, Any] | None = None,
        on_batch: Callable[[Sequence[int]], None] | None = None,
        deadline: float | None = None,
        unstarted: list[int] | None = None,
    ) -> list[tuple[int, list[Finding], bool, bool]] | None:
        """Inspect files across a pool, returning results in input order.

        Returns None when the pool could not run, and a list otherwise -- an
        empty list included. The caller re-scans serially on None, so a platform
        where processes cannot be spawned degrades to a slower scan rather than
        a failed one. Returning `[]` for both meant a pool that ran correctly
        and legitimately found nothing was indistinguishable from one that never
        started, and the whole batch was scanned a second time.

        `on_batch` is called with the indices of each batch as its results
        arrive, so a caller can report progress while the pool is still running.
        It is called from this process, never from a worker -- a worker has no
        terminal, and several writing to one would interleave. It receives
        indices only, so nothing about how a caller displays them can reach a
        finding.

        `detector_ids` has no default on purpose. Defaulting it to "all" would
        reintroduce the divergence this parameter exists to fix, and defaulting
        it to "none" would silently scan nothing -- so a caller has to say.

        `facts` is the parent's context (`ScanContext.facts`); see `_initialise`. Each result is
        `(index, findings, trusted, cacheable)`: `cacheable` is False when inspecting the file
        reached past its own bytes (`ScanCache.watch`).

        `deadline` (a `time.monotonic()` reading) is the scan's budget. Once it passes, no batch
        that has not started is started: those are cancelled and their files' indices go into
        `unstarted`, for the caller to report unexamined. Batches already running finish, and
        their results are kept. With no deadline the pool runs every batch, as it always did.
        """

        batches = ParallelScanner.batch_by_bytes(
            files, ParallelScanner.batch_target(sum(item[2] for item in files), workers)
        )
        if not batches:
            return []

        payload = config.to_dict()
        collected: list[tuple[int, list[Finding], bool, bool]] = []

        try:
            with ProcessPoolExecutor(
                max_workers=workers,
                mp_context=ParallelScanner.start_context(),
                initializer=ParallelScanner._initialise,
                initargs=(
                    engine_type,
                    payload,
                    root,
                    tuple(detector_ids),
                    inventory,
                    {key: getattr(config, key) for key in CARRIED_SETTINGS},
                    dict(facts or {}),
                ),
            ) as pool:
                ParallelScanner._dispatch(
                    pool, batches, root, collected, on_batch, deadline, unstarted
                )
        except Exception:  # noqa: BLE001
            return None

        # Restored to input order. Completion order depends on scheduling, and
        # identical inputs must produce identical output.
        collected.sort(key=lambda pair: pair[0])
        return collected

    @staticmethod
    def _collect(
        futures: list[Future[list[tuple[int, list[dict[str, Any]], bool | None, bool]]]],
        collected: list[tuple[int, list[Finding], bool, bool]],
        on_batch: Callable[[Sequence[int]], None] | None,
        unstarted: list[int] | None = None,
    ) -> None:
        """Each batch's results as it finishes, reported to the caller as they arrive."""
        from cordon_scanner.engine.cache import ScanCache

        # As each finishes, not in submission order. Waiting on futures
        # in order means one slow batch holds back the reporting of
        # every batch behind it that has already finished, so the count
        # stalls and then leaps -- which is the appearance of a hang
        # that reporting progress exists to remove.
        #
        # Safe because nothing downstream depends on this order: every
        # result carries its own index, and `ScanResult.sorted` orders
        # findings by severity, risk, path, line, rule and fingerprint,
        # never by completion. A test asserts a parallel scan and a
        # serial one produce identical output.
        for future in as_completed(futures):
            completed: list[int] = []
            for index, findings, trusted, cacheable in ParallelScanner._batch_results(future):
                if trusted is None:  # the worker reached it after the deadline
                    if unstarted is not None:
                        unstarted.append(index)
                    continue
                collected.append(
                    (index, [ScanCache.finding_from_dict(f) for f in findings], trusted, cacheable)
                )
                completed.append(index)
            if on_batch is not None:
                on_batch(completed)

    @staticmethod
    def _dispatch(
        pool: ProcessPoolExecutor,
        batches: list[list[WorkItem]],
        root: str,
        collected: list[tuple[int, list[Finding], bool, bool]],
        on_batch: Callable[[Sequence[int]], None] | None,
        deadline: float | None,
        unstarted: list[int] | None,
    ) -> None:
        """Every batch submitted to the pool and its results collected; with a deadline, what the
        pool has not reached by then is left unexamined (`_collect_until`).

        The deadline is a `time.monotonic()` reading taken in this process and compared in the
        workers. That is sound because the monotonic clock is one system-wide clock on Linux and
        macOS (CLOCK_MONOTONIC) and on Windows, not a per-process counter."""
        from cordon_scanner.engine.detector_clock import DetectorClock

        # With the detector clock on, each batch also hands back its workers' detector times.
        inspect: Callable[..., Any] = (
            ParallelScanner._inspect_batch_timed
            if DetectorClock.enabled()
            else ParallelScanner._inspect_batch
        )
        futures = [pool.submit(inspect, batch, root, deadline) for batch in batches]
        if deadline is None:
            ParallelScanner._collect(futures, collected, on_batch)
        else:
            ParallelScanner._collect_until(
                dict(zip(futures, batches, strict=True)),
                collected,
                on_batch,
                deadline,
                unstarted if unstarted is not None else [],
            )

    @staticmethod
    def _collect_until(
        batches: dict[
            Future[list[tuple[int, list[dict[str, Any]], bool | None, bool]]], list[WorkItem]
        ],
        collected: list[tuple[int, list[Finding], bool, bool]],
        on_batch: Callable[[Sequence[int]], None] | None,
        deadline: float,
        unstarted: list[int],
    ) -> None:
        """`_collect`, stopping at the deadline: a batch not started by then is cancelled and its
        files go into `unstarted`. A running batch stops at its next file (`_inspect_batch` checks
        the same deadline), and what it examined before that is kept."""
        pending = set(batches)
        cutoff: float | None = deadline
        while pending:
            timeout = None if cutoff is None else max(0.0, cutoff - time.monotonic())
            done, pending = wait(pending, timeout=timeout, return_when=FIRST_COMPLETED)
            ParallelScanner._collect(list(done), collected, on_batch, unstarted)
            if cutoff is not None and time.monotonic() >= cutoff:
                for future in pending:
                    if future.cancel():
                        unstarted.extend(item[0] for item in batches[future])
                pending = {future for future in pending if not future.cancelled()}
                cutoff = None


# ---------------------------------------------------------------------------
# Worker state
# ---------------------------------------------------------------------------


@dataclass
class _WorkerState:
    """Per-process scanning state, built once at pool start."""

    engine: Any
    context: Any
    detectors: tuple[Any, ...] = ()


__all__ = [
    "BATCH_TARGET_BYTES",
    "MAX_WORKERS",
    "MIN_FILES_FOR_PARALLEL",
    "ParallelScanner",
]
