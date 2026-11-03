"""Every file a scan was given is accounted for (release item 38, notes/38-per-file-coverage-ledger.md):
read, named by a step's own coverage finding, or OPERATIONAL.COVERAGE.UNACCOUNTED at its path. The
ledger reads nothing; it joins what the steps already record."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.engine.parallel import ParallelScanner
from cordon_scanner.engine.pipeline import archive_stages
from cordon_scanner.engine.pipeline.accumulator import Accumulator
from cordon_scanner.engine.pipeline.coverage import CoverageLedger
from cordon_scanner.engine.pipeline.stages import ScanStages
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Severity
from cordon_scanner.foundation.results import OperationalFinding

RULE = CoverageLedger.RULE


class LedgerKit:
    @staticmethod
    def tree(root: Path, count: int = 3) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        for n in range(count):
            (root / f"m{n}.py").write_text(f"x = {n}\n", encoding="utf-8")
        return root

    @staticmethod
    def config(**overrides) -> Config:
        overrides.setdefault("use_cache", False)
        return Config.default().with_overrides(**overrides)

    @staticmethod
    def unaccounted(result) -> list[str]:
        return sorted(f.location.path for f in result.findings if f.rule_id == RULE)

    @staticmethod
    def package(path: Path, members: dict[str, bytes]) -> Path:
        with tarfile.open(path, "w:gz") as tar:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return path

    @staticmethod
    def timing_out_pool(monkeypatch: pytest.MonkeyPatch, *, keep: int) -> None:
        """A pool that inspects the first `keep` files it is given and leaves the rest unstarted, as a
        budget running out does."""

        def run(**kwargs):
            files = kwargs["files"]
            kwargs["unstarted"].extend(item[0] for item in files[keep:])
            return [(item[0], [], True, False, (True, ())) for item in files[:keep]]

        monkeypatch.setattr(ParallelScanner, "run", staticmethod(run))


class TestAFileNoStepAccountsFor:
    def test_a_unit_dropped_without_a_gap_is_unaccounted_at_its_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        original = ScanStages.read_units

        def drops_one(self, *args, **kwargs):
            return [u for u in original(self, *args, **kwargs) if u.path != "m1.py"]

        monkeypatch.setattr(ScanStages, "read_units", drops_one)
        result = Scanner(LedgerKit.config()).scan(LedgerKit.tree(tmp_path / "t"))
        assert LedgerKit.unaccounted(result) == ["m1.py"]

    def test_an_unrelated_operational_note_at_its_path_does_not_account_for_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Outer-layer review: a note that says nothing about reading the file is no state.
        original = ScanStages.read_units

        def drops_one_with_a_note(self, root, inventory, acc, *rest):
            acc.append(
                OperationalFinding.build(
                    path="m1.py",
                    rule_id="OPERATIONAL.REFERENCE.NOT_FOUND",
                    message="m",
                    remediation="r",
                    severity=Severity.INFO,
                )
            )
            units = original(self, root, inventory, acc, *rest)
            return [u for u in units if u.path != "m1.py"]

        monkeypatch.setattr(ScanStages, "read_units", drops_one_with_a_note)
        result = Scanner(LedgerKit.config()).scan(LedgerKit.tree(tmp_path / "t"))
        assert LedgerKit.unaccounted(result) == ["m1.py"]

    def test_report_only_it_is_info_and_leaves_the_scan_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        original = ScanStages.read_units
        monkeypatch.setattr(
            ScanStages,
            "read_units",
            lambda self, *a, **k: [u for u in original(self, *a, **k) if u.path != "m1.py"],
        )
        result = Scanner(LedgerKit.config()).scan(LedgerKit.tree(tmp_path / "t"))
        [finding] = [f for f in result.findings if f.rule_id == RULE]
        assert finding.severity is Severity.INFO
        assert result.complete

    def test_blocking_it_is_a_content_gap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        original = ScanStages.read_units
        monkeypatch.setattr(
            ScanStages,
            "read_units",
            lambda self, *a, **k: [u for u in original(self, *a, **k) if u.path != "m1.py"],
        )
        monkeypatch.setattr(CoverageLedger, "BLOCKING", True)
        result = Scanner(LedgerKit.config()).scan(LedgerKit.tree(tmp_path / "t"))
        assert LedgerKit.unaccounted(result) == ["m1.py"]
        assert not result.complete


class TestEveryExistingStateIsAccountedForOnce:
    def test_a_clean_tree_has_nothing_unaccounted(self, tmp_path: Path) -> None:
        result = Scanner(LedgerKit.config()).scan(LedgerKit.tree(tmp_path / "t"))
        assert LedgerKit.unaccounted(result) == []

    def test_a_truncated_file_is_named_by_its_truncation_only(self, tmp_path: Path) -> None:
        root = LedgerKit.tree(tmp_path / "t")
        (root / "big.py").write_text("x = 1\n" * 4000, encoding="utf-8")
        config = LedgerKit.config()
        config = config.with_overrides(limits=config.limits.merged(max_file_bytes=1000))
        result = Scanner(config).scan(root)
        assert LedgerKit.unaccounted(result) == []

    def test_a_symbolic_link_is_named_by_its_own_note(self, tmp_path: Path) -> None:
        root = LedgerKit.tree(tmp_path / "t")
        (root / "link.py").symlink_to(root / "m0.py")
        result = Scanner(LedgerKit.config()).scan(root)
        assert LedgerKit.unaccounted(result) == []

    def test_a_pruned_directory_is_the_operators_scope_not_unaccounted(
        self, tmp_path: Path
    ) -> None:
        root = LedgerKit.tree(tmp_path / "t")
        LedgerKit.tree(root / "node_modules" / "dep")
        result = Scanner(LedgerKit.config()).scan(root)
        assert LedgerKit.unaccounted(result) == []

    def test_an_archive_in_a_directory_accounts_for_each_member(self, tmp_path: Path) -> None:
        root = LedgerKit.tree(tmp_path / "t")
        LedgerKit.package(root / "vendor.tgz", {"package/a.js": b"module.exports = 1;\n"})
        result = Scanner(LedgerKit.config()).scan(root)
        assert LedgerKit.unaccounted(result) == []

    def test_a_package_scan_accounts_for_each_member(self, tmp_path: Path) -> None:
        archive = LedgerKit.package(
            tmp_path / "p.tgz",
            {
                "package/package.json": b'{"name": "p", "version": "1.0.0"}',
                "package/index.js": b"module.exports = 1;\n",
            },
        )
        result = Scanner(LedgerKit.config()).scan(archive)
        assert LedgerKit.unaccounted(result) == []

    def test_derived_units_are_never_ledger_entries(self, tmp_path: Path) -> None:
        root = LedgerKit.tree(tmp_path / "t")
        packed = "eval(function(p,a,c,k,e,d){return p}('0 1',2,2,'var|x'.split('|'),0,{}))\n"
        (root / "packed.js").write_text(packed, encoding="utf-8")
        result = Scanner(LedgerKit.config()).scan(root)
        assert not [p for p in LedgerKit.unaccounted(result) if "#" in p]


class TestTheReviewChanges:
    def test_files_the_pool_never_started_are_gapped_by_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Change 1: the budget stops after the first of three files; the other two are named.
        LedgerKit.timing_out_pool(monkeypatch, keep=1)
        result = Scanner(LedgerKit.config()).scan(LedgerKit.tree(tmp_path / "t"))
        assert any(f.rule_id == "OPERATIONAL.SCAN.TIMEOUT" for f in result.findings)
        assert LedgerKit.unaccounted(result) == []

    def test_members_of_an_archive_slice_cut_by_the_timeout_are_gapped_by_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Change 2: one member per slice; the first slice's pool stops at the budget, so every
        # slice after it is never started.
        monkeypatch.setattr(archive_stages, "ARCHIVE_SLICE", 1)
        LedgerKit.timing_out_pool(monkeypatch, keep=0)
        archive = LedgerKit.package(
            tmp_path / "p.tgz", {f"package/m{n}.js": b"module.exports = 1;\n" for n in range(3)}
        )
        result = Scanner(LedgerKit.config()).scan(archive)
        assert LedgerKit.unaccounted(result) == []

    def test_members_of_slices_past_the_deadline_are_gapped_by_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Change 2, the other cut: the deadline has passed before a slice starts.
        original = archive_stages.ArchiveStages.parallel
        monkeypatch.setattr(
            archive_stages.ArchiveStages,
            "parallel",
            lambda self, units, deadline, *rest: original(self, units, 0.0, *rest),
        )
        archive = LedgerKit.package(
            tmp_path / "p.tgz", {f"package/m{n}.js": b"module.exports = 1;\n" for n in range(3)}
        )
        config = LedgerKit.config()
        config = config.with_overrides(limits=config.limits.merged(total_timeout=900.0))
        result = Scanner(config).scan(archive)
        assert any(f.rule_id == "OPERATIONAL.SCAN.TIMEOUT" for f in result.findings)
        assert LedgerKit.unaccounted(result) == []

    def test_a_warm_scan_accounts_exactly_as_a_cold_one(self, tmp_path: Path) -> None:
        # Change 3: a cache hit is READ by its path.
        root = LedgerKit.tree(tmp_path / "t")
        config = LedgerKit.config(use_cache=True, cache_dir=str(tmp_path / "cache"))
        cold = Scanner(config).scan(root)
        warm = Scanner(config).scan(root)
        assert warm.stats.cache_hits > 0
        assert LedgerKit.unaccounted(cold) == LedgerKit.unaccounted(warm) == []

    def test_a_file_read_in_windows_is_one_entry(self, tmp_path: Path) -> None:
        # Change 4: a file read in windows is one READ entry.
        root = LedgerKit.tree(tmp_path / "t", count=1)
        (root / "big.js").write_text("var a = 1;\n" * 2000, encoding="utf-8")
        config = LedgerKit.config()
        config = config.with_overrides(limits=config.limits.merged(max_file_bytes=4096))
        result = Scanner(config).scan(root)
        assert LedgerKit.unaccounted(result) == []


class TestTheLedgersWork:
    class CountingSet(set):
        lookups = 0

        def __contains__(self, item) -> bool:
            type(self).lookups += 1
            return super().__contains__(item)

    @pytest.mark.parametrize("files", [1_000, 10_000])
    def test_is_one_lookup_per_file(self, files: int) -> None:
        # Linear in files, by step count: one membership test of the read set per tree file.
        TestTheLedgersWork.CountingSet.lookups = 0
        acc = Accumulator()
        acc.ledger_tree = [f"f{n}.py" for n in range(files)]
        acc.ledger_read = TestTheLedgersWork.CountingSet(acc.ledger_tree)
        assert CoverageLedger.unaccounted(acc) == []
        assert TestTheLedgersWork.CountingSet.lookups == files

    def test_past_the_named_cap_one_finding_gives_the_rest(self) -> None:
        acc = Accumulator()
        acc.ledger_tree = [f"f{n}.py" for n in range(CoverageLedger.NAMED + 5)]
        found = CoverageLedger.findings(acc)
        assert len(found) == CoverageLedger.NAMED + 1
        assert "5 more" in found[-1].message
