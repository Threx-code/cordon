"""`verify`: exit code and output for each installation state (`cli/commands/verify_install.py`)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.cli.commands.verify_install import LIMIT, VerifyInstallCommand
from cordon_scanner.foundation.errors import ConfigError, ExitCode
from cordon_scanner.intel.provenance.install_verify import (
    InstallRecord,
    InstallReport,
    InstallState,
    ReleaseCheck,
    VerifiedRecord,
)


class _Base:
    @staticmethod
    def run(**over: Any) -> int:
        base: dict[str, Any] = {
            "target": None,
            "online": False,
            "attestation": None,
            "wheel": None,
            "format": "text",
        }
        return VerifyInstallCommand.run(argparse.Namespace(**{**base, **over}))

    @pytest.fixture
    def written(self, monkeypatch: pytest.MonkeyPatch) -> list[InstallReport]:
        """The reports the running-installation check records for later scans; none touches disk."""
        seen: list[InstallReport] = []
        monkeypatch.setattr(
            VerifiedRecord, "write", classmethod(lambda cls, report, at: seen.append(report))
        )
        return seen

    @staticmethod
    def offline(monkeypatch: pytest.MonkeyPatch, report: InstallReport) -> None:
        monkeypatch.setattr(InstallRecord, "check", classmethod(lambda cls, target=None: report))


class TestStates(_Base):
    def test_a_modified_installation_exits_1_and_names_each_file_on_stderr(
        self,
        monkeypatch: pytest.MonkeyPatch,
        written: list[InstallReport],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        self.offline(
            monkeypatch,
            InstallReport(InstallState.MODIFIED, version="1.2.3", problems=("a.py: hash differs",)),
        )
        assert self.run() == int(ExitCode.FINDINGS)
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "installation modified" in captured.err
        assert "1.2.3" in captured.err
        assert "a.py: hash differs" in captured.err
        assert LIMIT in captured.err

    def test_a_record_consistent_installation_is_incomplete_not_verified(
        self,
        monkeypatch: pytest.MonkeyPatch,
        written: list[InstallReport],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        self.offline(monkeypatch, InstallReport(InstallState.CONSISTENT, reason="offline"))
        assert self.run() == int(ExitCode.INCOMPLETE)
        out = capsys.readouterr().out
        assert "  offline" in out
        assert LIMIT in out

    def test_the_check_of_the_running_installation_is_recorded_for_later_scans(
        self, monkeypatch: pytest.MonkeyPatch, written: list[InstallReport]
    ) -> None:
        report = InstallReport(InstallState.UNVERIFIED)
        self.offline(monkeypatch, report)
        self.run()
        assert written == [report]

    def test_a_verified_installation_exits_0_with_no_limit_line(
        self,
        monkeypatch: pytest.MonkeyPatch,
        written: list[InstallReport],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        self.offline(monkeypatch, InstallReport(InstallState.VERIFIED))
        assert self.run() == int(ExitCode.CLEAN)
        assert LIMIT not in capsys.readouterr().out

    def test_json_carries_the_state_the_exit_code_and_the_limit(
        self,
        monkeypatch: pytest.MonkeyPatch,
        written: list[InstallReport],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        self.offline(monkeypatch, InstallReport(InstallState.CONSISTENT))
        assert self.run(format="json") == int(ExitCode.INCOMPLETE)
        data = json.loads(capsys.readouterr().out)
        assert data["state"] == InstallState.CONSISTENT.value
        assert data["exit"] == int(ExitCode.INCOMPLETE)
        assert data["limit"] == LIMIT


class TestTarget(_Base):
    def test_a_target_that_is_not_a_directory_is_a_config_error(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="is not a directory"):
            self.run(target=str(tmp_path / "missing"))

    def test_a_check_of_another_target_is_not_recorded_for_the_running_installation(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        written: list[InstallReport],
    ) -> None:
        self.offline(monkeypatch, InstallReport(InstallState.CONSISTENT))
        assert self.run(target=str(tmp_path)) == int(ExitCode.INCOMPLETE)
        assert written == []


class TestReleaseFiles(_Base):
    def test_an_attestation_without_its_wheel_is_refused(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self.offline(monkeypatch, InstallReport(InstallState.CONSISTENT))
        with pytest.raises(ConfigError, match="together, or --online"):
            self.run(target=str(tmp_path), attestation=str(tmp_path / "p.json"))

    def test_unreadable_release_files_are_a_config_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self.offline(monkeypatch, InstallReport(InstallState.CONSISTENT))
        with pytest.raises(ConfigError, match="cannot read the release files"):
            self.run(
                target=str(tmp_path),
                attestation=str(tmp_path / "missing.json"),
                wheel=str(tmp_path / "missing.whl"),
            )

    def test_a_provenance_that_is_not_json_is_a_config_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self.offline(monkeypatch, InstallReport(InstallState.CONSISTENT))
        (tmp_path / "p.json").write_text("not json", encoding="utf-8")
        (tmp_path / "w.whl").write_bytes(b"wheel")
        with pytest.raises(ConfigError, match="cannot read the release files"):
            self.run(
                target=str(tmp_path),
                attestation=str(tmp_path / "p.json"),
                wheel=str(tmp_path / "w.whl"),
            )

    def test_both_files_are_handed_to_the_release_check_and_its_verdict_decides_the_exit(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self.offline(monkeypatch, InstallReport(InstallState.CONSISTENT))
        (tmp_path / "p.json").write_text('{"attestations": []}', encoding="utf-8")
        (tmp_path / "w.whl").write_bytes(b"wheel")
        seen: dict[str, Any] = {}

        def release(cls: Any, offline: Any, target: Any, *, provenance: Any, wheel: Any) -> Any:
            seen.update(provenance=provenance, wheel=wheel)
            return InstallReport(InstallState.VERIFIED)

        monkeypatch.setattr(ReleaseCheck, "check", classmethod(release))
        code = self.run(
            target=str(tmp_path),
            attestation=str(tmp_path / "p.json"),
            wheel=str(tmp_path / "w.whl"),
        )
        assert code == int(ExitCode.CLEAN)
        assert seen == {"provenance": {"attestations": []}, "wheel": b"wheel"}

    def test_online_with_no_files_still_runs_the_release_check(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self.offline(monkeypatch, InstallReport(InstallState.CONSISTENT))
        seen: dict[str, Any] = {}

        def release(cls: Any, offline: Any, target: Any, *, provenance: Any, wheel: Any) -> Any:
            seen.update(provenance=provenance, wheel=wheel)
            return InstallReport(InstallState.MODIFIED)

        monkeypatch.setattr(ReleaseCheck, "check", classmethod(release))
        assert self.run(target=str(tmp_path), online=True) == int(ExitCode.FINDINGS)
        assert seen == {"provenance": None, "wheel": None}
