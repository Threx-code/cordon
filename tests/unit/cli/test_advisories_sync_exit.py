"""`advisories sync --only` ends with the clean exit code once the sync has written its output."""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner.cli.main import CommandLine
from cordon_scanner.intel.advisories import osv_import
from cordon_scanner.intel.advisories.advisories import DatabaseMeta


class TestSyncExit:
    def test_a_finished_osv_sync_exits_clean(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        names = sorted(osv_import.ECOSYSTEM_OSV_NAMES)
        meta = DatabaseMeta(built_at="2026-11-24T00:00:00Z", sources=(), record_count=0)
        result = osv_import.SyncResult(per_ecosystem={}, meta=meta)
        monkeypatch.setattr(osv_import.OsvImport, "sync_all", staticmethod(lambda *a, **k: result))
        monkeypatch.setattr(
            osv_import.OsvImport, "write_output", staticmethod(lambda *a, **k: None)
        )
        monkeypatch.setenv("CORDON_CONFIG_DIR", str(tmp_path))
        code = CommandLine.main(["advisories", "sync", "--only", *names])
        assert code == 0 and "synced 0 advisories" in capsys.readouterr().out
