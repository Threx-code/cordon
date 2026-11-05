"""What a worker found that left a file unread reaches the parent's gate (item 27). Under --jobs a
detector's crash came back as a finding the merge added and never counted: the scan said
complete. And a finding's `degrades_coverage` was lost crossing back, so the parent could not tell
a detector that answered fewer questions than it was asked from one that answered them all."""

from __future__ import annotations

import dataclasses
from types import SimpleNamespace

import pytest

from cordon_scanner import Scanner
from cordon_scanner.decide.policy import PolicyGate
from cordon_scanner.detect.base import DetectorRequirements, FileUnit
from cordon_scanner.engine.cache import ScanCache
from cordon_scanner.engine.parallel import ParallelScanner
from cordon_scanner.engine.pipeline.accumulator import Accumulator
from cordon_scanner.engine.pipeline.detection import Detection
from cordon_scanner.foundation.config.policy import Policy
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.models import Category
from cordon_scanner.foundation.results import OperationalFinding
from support import requires_forked_workers

#: Files in the tree: the smallest that crosses into two batches, so --jobs 2 runs two workers
#: (as tests/unit/engine/test_parallel.py's FIXTURE_FILES, asserted below).
FILES = 1_100


class RaisesOnOneFile:
    """A detector that raises on one file: at module level, so a worker can import it."""

    id = "raises-on-one"
    version = "1.0.0"
    categories = frozenset({Category.SUSPICIOUS})
    requires = DetectorRequirements(content=True)

    def applicable(self, ctx) -> bool:
        return True

    def inspect(self, unit, ctx):
        if unit.path.endswith("mod0007.js"):
            raise RuntimeError("raised on one file")
        return ()


class ParallelGapsKit:
    @staticmethod
    def merged(findings: list) -> Accumulator:
        acc = Accumulator()
        unit = FileUnit(content=FileContent.from_bytes("pkg/a.py", b"x = 1\n"))
        # the merge reads `self` only to cache a result, which `cacheable=False` skips
        Detection.merge_worker_results(
            SimpleNamespace(), [(0, findings, True, False, (True, ()))], [unit], [], acc, None, ""
        )
        return acc

    @staticmethod
    def note(rule: str, *, degrades: bool = False, detector: str = "capability"):
        finding = OperationalFinding.build(
            path="pkg/a.py", rule_id=rule, message="m", remediation="r"
        )
        return dataclasses.replace(finding, detector=detector, degrades_coverage=degrades)

    @staticmethod
    def cached(findings: list) -> list:
        """The keys the merge stored, for one trusted, cacheable worker result."""
        puts: list = []
        engine = SimpleNamespace(
            cache=SimpleNamespace(put=lambda key, value, facts="": puts.append(key)),
            cache_key=lambda unit, ctx, signature: unit.path,
        )
        unit = FileUnit(content=FileContent.from_bytes("pkg/a.py", b"x = 1\n"))
        Detection.merge_worker_results(
            engine, [(0, findings, True, True, (True, ()))], [unit], [], Accumulator(), None, ""
        )
        return puts


class TestAWorkersGap:
    def test_a_detector_that_failed_in_a_worker_is_a_gap(self) -> None:
        acc = ParallelGapsKit.merged([ParallelGapsKit.note("OPERATIONAL.DETECTOR.FAILED")])
        assert not acc.complete
        assert ("OPERATIONAL.DETECTOR.FAILED", "pkg/a.py") in acc.content_gaps

    def test_a_finding_that_degrades_coverage_leaves_the_scan_incomplete(self) -> None:
        acc = ParallelGapsKit.merged([ParallelGapsKit.note("OPERATIONAL.X.Y", degrades=True)])
        assert not acc.complete

    def test_a_finding_that_does_not_changes_nothing(self) -> None:
        acc = ParallelGapsKit.merged([ParallelGapsKit.note("OPERATIONAL.X.Y")])
        assert acc.complete and not acc.content_gaps

    def test_an_advisory_source_s_leaves_the_advisory_side_incomplete(self) -> None:
        """The serial path's `Detection.degraded` sets it; the merge recorded only the content
        side's, so under --jobs an advisory source that answered fewer questions said complete."""
        acc = ParallelGapsKit.merged(
            [
                ParallelGapsKit.note(
                    "OPERATIONAL.REGISTRY.UNANSWERED", degrades=True, detector="registry"
                )
            ]
        )
        assert acc.advisory_complete is False and acc.content_gaps == []

    def test_a_result_holding_a_degrading_finding_is_not_cached(self) -> None:
        """An advisory source's degrading finding leaves `acc.complete` alone, so its file was
        cached, and a warm hit returned it without setting `advisory_complete` again: the cold
        and warm scans disagreed (outer-layer review of C5)."""
        degrading = ParallelGapsKit.note(
            "OPERATIONAL.REGISTRY.UNANSWERED", degrades=True, detector="registry"
        )
        assert ParallelGapsKit.cached([degrading]) == []
        assert ParallelGapsKit.cached([ParallelGapsKit.note("OPERATIONAL.FILE.SYMLINK")]) == [
            "pkg/a.py"
        ]

    def test_degrades_coverage_crosses_back_from_a_worker(self) -> None:
        note = ParallelGapsKit.note("OPERATIONAL.X.Y", degrades=True)
        assert ScanCache.finding_from_dict(note.to_dict()).degrades_coverage


@pytest.mark.slow
class TestTheTwoPathsAgree:
    @requires_forked_workers
    def test_a_detector_that_raises_on_one_file_blocks_at_one_worker_and_at_two(
        self, tmp_path
    ) -> None:
        root = tmp_path / "repo"
        root.mkdir()
        for i in range(FILES):
            (root / f"mod{i:04d}.js").write_text(f"export const v{i} = {i};\n", encoding="utf-8")
        assert ParallelScanner.worker_count(2, file_count=FILES) > 1  # two really run
        outcomes = []
        for workers in (1, 2):
            config = Config.default().with_overrides(
                use_cache=False, limits=Config.default().limits.merged(max_workers=workers)
            )
            result = Scanner(config, detectors=[RaisesOnOneFile()]).scan(root)
            verdict = PolicyGate.evaluate(result, Policy.default())
            outcomes.append((result.content_complete, result.content_gaps, verdict.exit_code))
        assert outcomes[0] == outcomes[1]
        complete, gaps, exit_code = outcomes[0]
        assert not complete
        assert ("OPERATIONAL.DETECTOR.FAILED", "mod0007.js") in gaps
        assert exit_code.name == "INCOMPLETE"

    @pytest.mark.parametrize(
        ("manifest", "payload_name", "payload"),
        [
            # Only a hook's interpreter decides it: `node ./payload.png` makes payload.png
            # JavaScript, and its content has too few markers for the content sniff. A worker
            # named the language from the file alone (LanguageRegistry.of_file), so under --jobs
            # this was no language and no language rule read it. Fails on the old pool.
            (
                '{"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node ./payload.png"}}',
                "payload.png",
                "const p = atob(BLOB);\neval(p);\n",
            ),
            # The content sniff decides it, which of_file already did in a worker: a guard.
            (
                '{"name": "x", "version": "1.0.0"}',
                "loader",
                "const p = atob(BLOB);\neval(p);\nmodule.exports = function run(a) { return a; };\n",
            ),
        ],
    )
    def test_the_parent_s_language_reaches_the_worker(
        self, tmp_path, manifest: str, payload_name: str, payload: str
    ) -> None:
        """The parent's language for a unit is the worker's (outer-layer review, item 28). Built-in
        detectors only, so the workers run."""
        root = tmp_path / "repo"
        root.mkdir()
        for i in range(FILES):
            (root / f"mod{i:04d}.js").write_text(f"export const v{i} = {i};\n", encoding="utf-8")
        (root / "package.json").write_text(manifest, encoding="utf-8")
        (root / payload_name).write_text(payload, encoding="utf-8")
        found = []
        for workers in (1, 2):
            config = Config.default().with_overrides(
                use_cache=False, limits=Config.default().limits.merged(max_workers=workers)
            )
            result = Scanner(config).scan(root)
            found.append(
                sorted(
                    (f.rule_id, f.location.line)
                    for f in result.findings
                    if f.location.path == payload_name
                )
            )
        assert found[0] == found[1]
        assert any(rule == "SUSPECT.DECODE_EXEC.001" for rule, _ in found[0])
