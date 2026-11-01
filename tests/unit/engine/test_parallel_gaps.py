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
            SimpleNamespace(), [(0, findings, True, False)], [unit], [], acc, None, ""
        )
        return acc

    @staticmethod
    def note(rule: str, *, degrades: bool = False):
        finding = OperationalFinding.build(
            path="pkg/a.py", rule_id=rule, message="m", remediation="r"
        )
        return dataclasses.replace(finding, detector="capability", degrades_coverage=degrades)


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

    def test_degrades_coverage_crosses_back_from_a_worker(self) -> None:
        note = ParallelGapsKit.note("OPERATIONAL.X.Y", degrades=True)
        assert ScanCache.finding_from_dict(note.to_dict()).degrades_coverage


@pytest.mark.slow
class TestTheTwoPathsAgree:
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
