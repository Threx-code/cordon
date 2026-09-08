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
import os
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon.core.config import Config
    from cordon.core.models import Finding

MIN_FILES_FOR_PARALLEL = 400
"""Below this, a scan runs in the calling process.

Pool startup is tens of milliseconds per worker plus interpreter initialisation.
On a few hundred files that is most of the runtime, so parallelism would make
the common case slower while helping only the rare one.
"""

MAX_WORKERS = 16
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
"""Batches are sized by cumulative bytes rather than by file count.

One very large file and a thousand small ones are not the same work. Sizing by
count leaves a worker holding the large file while the others idle, which is the
usual reason a parallel scan is barely faster than a serial one.
"""


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
    def worker_count(requested: int, file_count: int) -> int:
        """Decide how many workers to use.

        Returns 1 when parallelism would not pay, so the caller has a single
        condition to check rather than a special case.
        """
        if requested == 1:
            return 1
        if file_count < MIN_FILES_FOR_PARALLEL:
            return 1

        available = requested if requested > 0 else (os.cpu_count() or 1)
        # Never more workers than batches. The comment claimed this and the code
        # did not do it, so a repository just over the threshold started a
        # process per core to share one batch.
        batches = max(1, math.ceil(file_count * AVERAGE_FILE_BYTES / BATCH_TARGET_BYTES))
        return max(1, min(available, MAX_WORKERS, batches))

    @staticmethod
    def batch_by_bytes(
        items: Sequence[tuple[int, str, int]], target: int = BATCH_TARGET_BYTES
    ) -> list[list[tuple[int, str, int]]]:
        """Group (index, path, size) triples into byte-balanced batches.

        A file larger than the target gets a batch of its own rather than being
        split, since a file is the smallest unit a detector can reason about.
        """
        batches: list[list[tuple[int, str, int]]] = []
        current: list[tuple[int, str, int]] = []
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
        config_payload: dict[str, Any], root: str, detector_ids: tuple[str, ...]
    ) -> None:
        """Build one worker's engine.

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
        """

        from cordon.core.config import Config as _Config
        from cordon.core.engine import Engine

        config = _Config.from_dict(config_payload, source="<worker>")
        engine = Engine(config)
        inventory = engine.inventory(ParallelScanner._to_path(root))
        wanted = set(detector_ids)
        detectors = tuple(d for d in engine.detectors if getattr(d, "id", "") in wanted)
        ParallelScanner._worker = _WorkerState(
            engine=engine,
            context=engine._context(inventory),
            detectors=detectors,
        )

    @staticmethod
    def _to_path(root: str):
        from pathlib import Path

        return Path(root)

    @staticmethod
    def _inspect_batch(
        batch: list[tuple[int, str, int]], root: str
    ) -> list[tuple[int, list[dict[str, Any]]]]:
        """Scan one batch inside a worker.

        Findings cross the process boundary as dictionaries rather than as domain
        objects. That keeps the boundary explicit and depends only on the
        serialisation the JSON reporter already relies on, rather than on every
        domain type remaining picklable forever.
        """
        if ParallelScanner._worker is None:  # pragma: no cover - only reachable on a broken pool
            return []

        from pathlib import Path

        from cordon.core.content import FileContent, Skipped
        from cordon.detect.base import FileUnit

        engine = ParallelScanner._worker.engine
        ctx = ParallelScanner._worker.context
        detectors = ParallelScanner._worker.detectors
        out: list[tuple[int, list[dict[str, Any]]]] = []

        for index, relative, _size in batch:
            loaded = FileContent.load(Path(root) / relative, relative, engine.config.limits)
            if isinstance(loaded, Skipped):
                out.append((index, []))
                continue

            unit = FileUnit(content=loaded, language=ParallelScanner._language(relative, loaded))
            findings: list[dict[str, Any]] = []
            for detector in detectors:
                try:
                    findings.extend(f.to_dict() for f in detector.inspect(unit, ctx))
                except Exception as exc:
                    # A detector that fails in a worker must not silently reduce
                    # coverage. It is reported the same way the serial path reports
                    # it, so a broken detector looks identical either way.
                    findings.append(
                        ParallelScanner._operational_dict(
                            path=relative,
                            detector=getattr(detector, "id", "unknown"),
                            error=f"{type(exc).__name__}: {exc}",
                        )
                    )
            out.append((index, findings))

        return out

    @staticmethod
    def _language(relative: str, content) -> str | None:
        """Path first, then the shebang.

        Kept identical to the engine's own choice: a worker that identified
        languages differently from the parent would select different rules, and
        the same scan would produce different findings depending on how many
        files it happened to contain.
        """
        from cordon.langs.registry import LanguageRegistry

        by_path = LanguageRegistry.identify_language(relative)
        if by_path is not None:
            return by_path
        return LanguageRegistry.language_from_interpreter(content.shebang or "")

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
        files: Sequence[tuple[int, str, int]],
        workers: int,
        detector_ids: Sequence[str],
    ) -> list[tuple[int, list[Finding]]] | None:
        """Inspect files across a pool, returning results in input order.

        Returns None when the pool could not run, and a list otherwise -- an
        empty list included. The caller re-scans serially on None, so a platform
        where processes cannot be spawned degrades to a slower scan rather than
        a failed one. Returning `[]` for both meant a pool that ran correctly
        and legitimately found nothing was indistinguishable from one that never
        started, and the whole batch was scanned a second time.

        `detector_ids` has no default on purpose. Defaulting it to "all" would
        reintroduce the divergence this parameter exists to fix, and defaulting
        it to "none" would silently scan nothing -- so a caller has to say.
        """
        from cordon.core.cache import ScanCache

        batches = ParallelScanner.batch_by_bytes(list(files))
        if not batches:
            return []

        payload = config.to_dict()
        collected: list[tuple[int, list[Finding]]] = []

        try:
            with ProcessPoolExecutor(
                max_workers=workers,
                initializer=ParallelScanner._initialise,
                initargs=(payload, root, tuple(detector_ids)),
            ) as pool:
                futures = [
                    pool.submit(ParallelScanner._inspect_batch, batch, root) for batch in batches
                ]
                for future in futures:
                    for index, findings in future.result():
                        collected.append(
                            (index, [ScanCache.finding_from_dict(f) for f in findings])
                        )
        except Exception:
            return None

        # Restored to input order. Completion order depends on scheduling, and
        # identical inputs must produce identical output.
        collected.sort(key=lambda pair: pair[0])
        return collected


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
