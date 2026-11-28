"""`advisories sync`: the bundle, the OSV ecosystems, the distribution families and NVD, what each prints,
and which failure is a configuration error (`cli/commands/advisories.py`)."""

from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from cordon_scanner.cli.commands.advisories import AdvisoriesCommand
from cordon_scanner.foundation.errors import ConfigError, ExitCode
from cordon_scanner.images.distrodb import DistroDatabase
from cordon_scanner.intel.advisories import nvd_import, osv_import
from cordon_scanner.intel.advisories.advisories import AdvisoryFiles
from cordon_scanner.intel.advisories.nvd import NvdData
from cordon_scanner.intel.store import dbsync


class _Base:
    @staticmethod
    def run(action: str | None = "sync", **over: Any) -> int:
        base: dict[str, Any] = {
            "advisories_command": action,
            "only": None,
            "os": None,
            "bundle": None,
        }
        return AdvisoriesCommand.run(argparse.Namespace(**{**base, **over}))

    @pytest.fixture(autouse=True)
    def _sync_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(AdvisoryFiles, "user_sync_dir", staticmethod(lambda: tmp_path / "sync"))


run = _Base.run


class TestArguments(_Base):
    def test_without_an_action_it_asks_for_sync_and_an_unknown_one_is_refused(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert run(None) == int(ExitCode.CONFIG_ERROR)
        assert "advisories needs sync" in capsys.readouterr().err
        with pytest.raises(ConfigError, match="unknown advisories action: purge"):
            run("purge")

    def test_an_unknown_ecosystem_is_named_with_the_ones_to_choose_from(self) -> None:
        with pytest.raises(ConfigError, match="unknown ecosystem") as raised:
            run(only=["pypi", "cobol"])
        assert "cobol" in str(raised.value)
        assert "npm" in str(raised.value.hint) and "pypi" in str(raised.value.hint)  # type: ignore[attr-defined]


class TestBundle(_Base):
    def test_a_verified_bundle_is_installed_where_scans_look_for_advisories(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        seen: list[Any] = []
        monkeypatch.setattr(
            dbsync.AdvisoryBundle,
            "sync_from",
            staticmethod(lambda source, destination: seen.append((source, destination))),
        )
        assert run(bundle="https://example.invalid/bundle") == int(ExitCode.CLEAN)
        assert seen == [("https://example.invalid/bundle", tmp_path / "sync")]
        assert (
            f"installed a verified advisory bundle into {tmp_path / 'sync'}"
            in capsys.readouterr().out
        )

    def test_a_bundle_that_does_not_verify_is_a_config_error_and_installs_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def refuse(source: str, destination: Path) -> None:
            raise dbsync.BundleError("signature does not verify")

        monkeypatch.setattr(dbsync.AdvisoryBundle, "sync_from", staticmethod(refuse))
        with pytest.raises(ConfigError, match="advisories sync: signature does not verify"):
            run(bundle="dir")


class TestOsv(_Base):
    @staticmethod
    def _osv(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
        written: list[Any] = []
        result = SimpleNamespace(
            per_ecosystem={"pypi": [1, 2, 3]}, meta=SimpleNamespace(record_count=3)
        )
        monkeypatch.setattr(
            osv_import.OsvImport,
            "sync_all",
            staticmethod(
                lambda ecosystems, tmp_dir: written.append(("sync", ecosystems)) or result
            ),
        )
        monkeypatch.setattr(
            osv_import.OsvImport,
            "write_output",
            staticmethod(lambda res, destination: written.append(("write", destination))),
        )
        return written

    def test_the_named_ecosystems_are_synced_sorted_and_counted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        written = self._osv(monkeypatch)
        assert run(only=["pypi", "npm"]) == int(ExitCode.CLEAN)
        assert written == [("sync", ("npm", "pypi")), ("write", tmp_path / "sync")]
        out = capsys.readouterr().out
        assert "syncing 2 ecosystem(s) from OSV..." in out
        assert "  pypi: 3 advisor(y/ies)" in out and "  npm: 0 advisor(y/ies)" in out
        assert f"synced 3 advisories to {tmp_path / 'sync'}" in out

    def test_an_osv_failure_is_a_config_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fail(ecosystems: Any, tmp_dir: Path) -> Any:
            raise osv_import.OsvImportError("export unavailable")

        monkeypatch.setattr(osv_import.OsvImport, "sync_all", staticmethod(fail))
        with pytest.raises(ConfigError, match="advisories sync: export unavailable"):
            run(only=["pypi"])

    def test_everything_syncs_osv_then_nvd_unless_nvd_is_left_out(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        written = self._osv(monkeypatch)
        monkeypatch.setattr(AdvisoriesCommand, "_sync_nvd", classmethod(lambda cls, d: 55))
        assert run() == 55
        assert [step for step, _ in written] == ["sync", "write"]
        assert written[0][1] == tuple(sorted(osv_import.ECOSYSTEM_OSV_NAMES))
        assert run(only=["pypi"]) == int(ExitCode.CLEAN)
        capsys.readouterr()


class TestNvd(_Base):
    @staticmethod
    def _nvd(monkeypatch: pytest.MonkeyPatch, written: list[Any]) -> None:
        built = SimpleNamespace(text={"CVE-1": "x", "CVE-2": "y"}, products={"p": 1})
        monkeypatch.setattr(nvd_import.NvdImport, "years", staticmethod(lambda: (2024, 2025)))
        monkeypatch.setattr(nvd_import.NvdImport, "cve_list_records", staticmethod(dict))
        monkeypatch.setattr(
            nvd_import.NvdImport,
            "build",
            staticmethod(lambda years, keep, cve_list: written.append(("build", years)) or built),
        )
        monkeypatch.setattr(
            nvd_import.NvdImport,
            "write",
            staticmethod(lambda destination, b, filtered: written.append(("write", filtered))),
        )
        monkeypatch.setattr(NvdData, "reset", staticmethod(lambda: written.append(("reset",))))

    def test_only_nvd_builds_every_record_writes_them_and_resets_the_reader(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        written: list[Any] = []
        self._nvd(monkeypatch, written)
        assert run(only=["nvd"]) == int(ExitCode.CLEAN)
        assert written == [("build", (2024, 2025)), ("write", False), ("reset",)]
        out = capsys.readouterr().out
        assert "syncing NVD's feeds..." in out
        assert f"synced 2 NVD records across 1 products to {tmp_path / 'sync'}" in out

    def test_an_nvd_failure_is_a_config_error_naming_nvd(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(nvd_import.NvdImport, "years", staticmethod(lambda: (2025,)))
        monkeypatch.setattr(nvd_import.NvdImport, "cve_list_records", staticmethod(dict))

        def fail(*a: Any, **k: Any) -> Any:
            raise nvd_import.NvdImportError("checksum mismatch")

        monkeypatch.setattr(nvd_import.NvdImport, "build", staticmethod(fail))
        with pytest.raises(ConfigError, match="advisories sync: NVD: checksum mismatch"):
            run(only=["nvd"])


class TestDistributions(_Base):
    def test_each_family_is_synced_and_the_directory_named(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(
            DistroDatabase,
            "sync",
            staticmethod(lambda family, tmp_dir: {"debian": 1200, "alpine": 3}[family]),
        )
        monkeypatch.setattr(DistroDatabase, "directory", staticmethod(lambda: tmp_path / "os"))
        assert run(os=["debian", "alpine"]) == int(ExitCode.CLEAN)
        out = capsys.readouterr().out
        assert "  debian: 1,200 package advisor(y/ies)" in out
        assert "  alpine: 3 package advisor(y/ies)" in out
        assert f"distribution advisories are in {tmp_path / 'os'}" in out

    def test_an_unknown_family_is_refused_with_the_choices(self) -> None:
        with pytest.raises(
            ConfigError, match=r"unknown distribution\(s\) for --os: plan9"
        ) as raised:
            run(os=["plan9"])
        assert "debian" in str(raised.value.hint)  # type: ignore[attr-defined]

    def test_a_family_that_fails_to_sync_is_a_config_error_naming_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fail(family: str, tmp_dir: Path) -> int:
            raise osv_import.OsvImportError("no export")

        monkeypatch.setattr(DistroDatabase, "sync", staticmethod(fail))
        with pytest.raises(ConfigError, match="advisories sync --os debian: no export"):
            run(os=["debian"])

    def test_families_alone_do_not_start_the_osv_sync_but_families_with_only_do(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(DistroDatabase, "sync", staticmethod(lambda family, tmp_dir: 1))
        monkeypatch.setattr(DistroDatabase, "directory", staticmethod(lambda: tmp_path))
        called: list[Any] = []
        monkeypatch.setattr(
            osv_import.OsvImport,
            "sync_all",
            staticmethod(
                lambda *a, **k: (
                    called.append(a)
                    or SimpleNamespace(per_ecosystem={}, meta=SimpleNamespace(record_count=0))
                )
            ),
        )
        monkeypatch.setattr(
            osv_import.OsvImport, "write_output", staticmethod(lambda *a, **k: None)
        )
        assert run(os=["debian"]) == int(ExitCode.CLEAN) and called == []
        assert run(os=["debian"], only=["pypi"]) == int(ExitCode.CLEAN) and len(called) == 1
