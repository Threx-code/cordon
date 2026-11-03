"""The binary readers read the whole file, not its first max_file_bytes (notes/74-binary-readers-read-the-
whole-file.md). A binary padded past 10 MiB, its import table after the padding, passed every binary
rule. Inert inputs only: `kits.paddedkit` builds headers, padding and an import table naming calls, with
no code; nothing here runs.
"""

from __future__ import annotations

import gc
import tracemalloc
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.detect.base import FileUnit
from cordon_scanner.detect.binary import whole_bytes
from cordon_scanner.detect.binary.imports import ImportReader
from cordon_scanner.detect.binary.whole_bytes import WholeBytes
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits
from kits.paddedkit import PAD, PaddedKit

INJECTION = "SUSPECT.BINARY.PROCESS_INJECTION.001"


class WholeKit:
    @staticmethod
    def unit(path: Path, limits: Limits | None = None) -> FileUnit:
        content = FileContent.load(path, path.name, limits or Limits())
        assert isinstance(content, FileContent)
        return FileUnit(content=content, language=None, opens=str(path))

    @staticmethod
    def rules(path: Path) -> set[tuple[str, str]]:
        report = Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(path)
        return {(f.rule_id, f.severity.name) for f in report.findings}


class TestTheWholeCopy:
    def test_a_file_under_the_limit_is_its_content(self, tmp_path) -> None:
        path = tmp_path / "small.exe"
        path.write_bytes(PaddedKit.pe(pad=0))
        unit = WholeKit.unit(path)
        whole = WholeBytes.of(unit)
        assert whole.data is unit.content.raw and whole.gap == ""

    def test_a_padded_binary_is_read_to_its_end(self, tmp_path) -> None:
        path = tmp_path / "padded.exe"
        path.write_bytes(PaddedKit.pe())
        unit = WholeKit.unit(path)
        assert unit.content.truncated and ImportReader.read(unit.content.raw) is None
        whole = WholeBytes.of(unit)
        assert whole.gap == "" and len(whole.data) == unit.content.size
        table = ImportReader.read(whole.data)
        assert table is not None and "WriteProcessMemory" in table.symbols

    def test_an_elf_padded_the_same_way_is_read_too(self, tmp_path) -> None:
        path = tmp_path / "padded.elf"
        path.write_bytes(PaddedKit.elf(["ptrace"], ["libc.so.6"]))
        unit = WholeKit.unit(path)
        table = ImportReader.read(WholeBytes.of(unit).data)
        assert table is not None and "ptrace" in table.symbols

    def test_past_the_stream_limit_the_prefix_is_read_and_the_gap_said(self, tmp_path) -> None:
        path = tmp_path / "padded.exe"
        path.write_bytes(PaddedKit.pe())
        limits = Limits(max_file_bytes=1 << 20, max_stream_bytes=2 << 20)
        whole = WholeBytes.of(WholeKit.unit(path, limits))
        assert len(whole.data) == 2 << 20 and "past limits.max_stream_bytes" in whole.gap

    def test_a_file_that_shrinks_after_it_was_opened_is_a_gap_not_a_crash(self, tmp_path) -> None:
        path = tmp_path / "padded.exe"
        path.write_bytes(PaddedKit.pe())
        unit = WholeKit.unit(path)
        with path.open("r+b") as handle:
            handle.truncate(PAD // 2)
        whole = WholeBytes.of(unit)
        assert whole.data is unit.content.raw and "changed while it was read" in whole.gap

    def test_without_the_headroom_for_the_copy_it_is_not_taken(self, tmp_path, monkeypatch) -> None:
        path = tmp_path / "padded.exe"
        path.write_bytes(PaddedKit.pe())
        unit = WholeKit.unit(path)
        monkeypatch.setattr(WholeBytes, "headroom", staticmethod(lambda: 1 << 20))
        whole = WholeBytes.of(unit)
        assert whole.data is unit.content.raw and "memory headroom" in whole.gap


class TestInAScan:
    def test_the_padded_injector_is_found(self, tmp_path) -> None:
        (tmp_path / "tool.exe").write_bytes(PaddedKit.pe())
        rules = {rule for rule, _ in WholeKit.rules(tmp_path)}
        assert INJECTION in rules

    def test_the_same_binary_unpadded_is_found_as_before(self, tmp_path) -> None:
        (tmp_path / "tool.exe").write_bytes(PaddedKit.pe(pad=0))
        assert INJECTION in {rule for rule, _ in WholeKit.rules(tmp_path)}

    def test_a_reader_failing_on_the_whole_copy_reads_the_prefix_and_says_so(
        self, tmp_path, monkeypatch
    ) -> None:
        (tmp_path / "tool.exe").write_bytes(PaddedKit.pe())
        real = ImportReader.read

        def fails_when_long(data):
            if len(data) > 10 << 20:
                raise ValueError("a reader that cannot take the long buffer")
            return real(data)

        monkeypatch.setattr(ImportReader, "read", staticmethod(fails_when_long))
        rules = WholeKit.rules(tmp_path)
        assert ("OPERATIONAL.FILE.TRUNCATED", "INFO") in rules
        assert INJECTION not in {rule for rule, _ in rules}  # the prefix holds no import table

    def test_the_copy_is_not_kept_once_the_scan_returns(self, tmp_path) -> None:
        (tmp_path / "tool.exe").write_bytes(PaddedKit.pe())
        scanner = Scanner(Config.default().with_overrides(use_cache=False, offline=True))
        scanner.scan(tmp_path)  # warm imports and tables, so they are not counted below
        gc.collect()
        tracemalloc.start()
        try:
            before = tracemalloc.get_traced_memory()[0]
            report = scanner.scan(tmp_path)
            del report
            gc.collect()
            after, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert peak - before > PAD, "the readers were given the whole file"
        assert after - before < PAD // 4, "and nothing held the copy once the scan returned"


class TestTheGapFinding:
    def test_it_names_the_reader_and_why(self, tmp_path) -> None:
        path = tmp_path / "padded.exe"
        path.write_bytes(PaddedKit.pe())
        finding = WholeBytes.gap_finding(
            WholeKit.unit(path), "rule engine", "it could not be matched whole"
        )
        assert finding.rule_id == "OPERATIONAL.FILE.TRUNCATED"
        assert "rule engine" in finding.message and "could not be matched whole" in finding.message

    @pytest.mark.parametrize("attr", ["MARGIN", "GAP_RULE"])
    def test_its_constants_are_declared(self, attr) -> None:
        assert hasattr(whole_bytes.WholeBytes, attr)
