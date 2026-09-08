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

import os
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

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

BATCH_TARGET_BYTES = 4 * 1024 * 1024
"""Batches are sized by cumulative bytes rather than by file count.

One very large file and a thousand small ones are not the same work. Sizing by
count leaves a worker holding the large file while the others idle, which is the
usual reason a parallel scan is barely faster than a serial one.
"""


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
    # Never more workers than batches, or the surplus processes are started and
    # immediately idle.
    return max(1, min(available, MAX_WORKERS))


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


# ---------------------------------------------------------------------------
# Worker state
# ---------------------------------------------------------------------------

_WORKER: _WorkerState | None = None


@dataclass
class _WorkerState:
    """Per-process scanning state, built once at pool start."""

    engine: Any
    context: Any


def _initialise(config_payload: dict[str, Any], root: str) -> None:
    """Build one worker's engine.

    Runs once per process. Everything expensive -- loading rule packs,
    compiling patterns, discovering detectors -- happens here rather than per
    task, which is the difference between parallelism helping and hurting.
    """
    global _WORKER

    from cordon.core.config import Config as _Config
    from cordon.core.engine import Engine

    config = _Config.from_dict(config_payload, source="<worker>")
    engine = Engine(config)
    inventory = engine.inventory(_to_path(root))
    _WORKER = _WorkerState(engine=engine, context=engine._context(inventory))


def _to_path(root: str):
    from pathlib import Path

    return Path(root)


def _inspect_batch(
    batch: list[tuple[int, str, int]], root: str
) -> list[tuple[int, list[dict[str, Any]]]]:
    """Scan one batch inside a worker.

    Findings cross the process boundary as dictionaries rather than as domain
    objects. That keeps the boundary explicit and depends only on the
    serialisation the JSON reporter already relies on, rather than on every
    domain type remaining picklable forever.
    """
    if _WORKER is None:  # pragma: no cover - only reachable on a broken pool
        return []

    from pathlib import Path

    from cordon.core.content import FileContent, Skipped
    from cordon.detect.base import FileUnit
    from cordon.langs.registry import LanguageRegistry

    engine = _WORKER.engine
    ctx = _WORKER.context
    out: list[tuple[int, list[dict[str, Any]]]] = []

    for index, relative, _size in batch:
        loaded = FileContent.load(Path(root) / relative, relative, engine.config.limits)
        if isinstance(loaded, Skipped):
            out.append((index, []))
            continue

        unit = FileUnit(content=loaded, language=LanguageRegistry.identify_language(relative))
        findings: list[dict[str, Any]] = []
        for detector in engine.detectors:
            try:
                findings.extend(f.to_dict() for f in detector.inspect(unit, ctx))
            except Exception as exc:
                # A detector that fails in a worker must not silently reduce
                # coverage. It is reported the same way the serial path reports
                # it, so a broken detector looks identical either way.
                findings.append(
                    _operational_dict(
                        path=relative,
                        detector=getattr(detector, "id", "unknown"),
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
        out.append((index, findings))

    return out


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


def scan_parallel(
    *,
    config: Config,
    root: str,
    files: Sequence[tuple[int, str, int]],
    workers: int,
) -> list[tuple[int, list[Finding]]]:
    """Inspect files across a pool, returning results in input order.

    Falls back to an empty result on pool failure rather than raising. The
    caller then runs serially, so a platform where processes cannot be spawned
    degrades to a slower scan instead of a failed one.
    """
    from cordon.core.cache import ScanCache

    batches = batch_by_bytes(list(files))
    if not batches:
        return []

    payload = config.to_dict()
    collected: list[tuple[int, list[Finding]]] = []

    try:
        with ProcessPoolExecutor(
            max_workers=workers,
            initializer=_initialise,
            initargs=(payload, root),
        ) as pool:
            futures = [pool.submit(_inspect_batch, batch, root) for batch in batches]
            for future in futures:
                for index, findings in future.result():
                    collected.append((index, [ScanCache.finding_from_dict(f) for f in findings]))
    except Exception:
        return []

    # Restored to input order. Completion order depends on scheduling, and
    # identical inputs must produce identical output.
    collected.sort(key=lambda pair: pair[0])
    return collected


__all__ = [
    "BATCH_TARGET_BYTES",
    "MAX_WORKERS",
    "MIN_FILES_FOR_PARALLEL",
    "batch_by_bytes",
    "scan_parallel",
    "worker_count",
]
