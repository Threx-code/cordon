"""`bundle create | verify | install`: what is printed and the exit code of each (`cli/commands/bundle.py`)."""

from __future__ import annotations

import argparse
import io
import tarfile
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.cli.commands.bundle import BundleCommand
from cordon_scanner.engine.bundle import Bundle, BundleReport
from cordon_scanner.foundation.errors import ConfigError, ExitCode


class _Base:
    @staticmethod
    def run(action: str | None, **over: Any) -> int:
        return BundleCommand.run(argparse.Namespace(bundle_command=action, **over))

    @pytest.fixture
    def source(self, tmp_path: Path) -> Path:
        folder = tmp_path / "src"
        (folder / "sub").mkdir(parents=True)
        (folder / "a.txt").write_text("alpha", encoding="utf-8")
        (folder / "sub" / "b.txt").write_text("beta", encoding="utf-8")
        return folder

    @staticmethod
    def _tamper(bundle: Path) -> Path:
        """The same bundle with one member's bytes changed, so its digest no longer matches the manifest."""
        out = bundle.with_name("tampered.tar.gz")
        with tarfile.open(bundle) as src, tarfile.open(out, "w:gz") as dst:
            for member in src:
                handle = src.extractfile(member)
                data = handle.read() if handle else b""
                if member.name == "a.txt":
                    data = b"changed"
                member.size = len(data)
                dst.addfile(member, io.BytesIO(data))
        return out


run = _Base.run
_tamper = _Base._tamper


class TestCreate(_Base):
    def test_no_action_asks_for_one(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert run(None) == int(ExitCode.CONFIG_ERROR)
        assert "bundle needs create, verify or install" in capsys.readouterr().err

    def test_a_source_that_is_not_a_directory_is_a_config_error(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="is not a directory"):
            run("create", source=str(tmp_path / "nope"), output=str(tmp_path / "o.tgz"))

    def test_create_bundles_every_file_and_says_it_is_unsigned(
        self, source: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out = tmp_path / "o.tgz"
        assert run("create", source=str(source), output=str(out)) == int(ExitCode.CLEAN)
        text = capsys.readouterr().out
        assert "(2 file(s))" in text
        assert "Sign it before it crosses the air gap" in text
        with tarfile.open(out) as archive:
            names = set(archive.getnames())
        assert {"a.txt", "sub/b.txt"} <= names


class TestVerify(_Base):
    def test_a_consistent_bundle_verifies_and_says_it_proves_no_author(
        self, source: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out = Bundle.create(
            tmp_path / "o.tgz", files=[("a.txt", source / "a.txt"), ("b.txt", source / "sub/b.txt")]
        )
        assert run("verify", bundle_file=str(out)) == int(ExitCode.CLEAN)
        assert "internally consistent" in capsys.readouterr().out

    def test_a_changed_member_is_refused_with_the_name_of_the_file(
        self, source: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out = Bundle.create(tmp_path / "o.tgz", files=[("a.txt", source / "a.txt")])
        assert run("verify", bundle_file=str(_tamper(out))) == int(ExitCode.CONFIG_ERROR)
        err = capsys.readouterr().err
        assert "bundle REFUSED" in err
        assert "digest mismatch: a.txt" in err

    def test_a_missing_file_is_refused(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert run("verify", bundle_file=str(tmp_path / "gone.tgz")) == int(ExitCode.CONFIG_ERROR)
        assert "is not a file" in capsys.readouterr().err


class TestInstall(_Base):
    def test_a_verified_bundle_is_written_and_unsigned_is_said(
        self, source: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out = Bundle.create(tmp_path / "o.tgz", files=[("a.txt", source / "a.txt")])
        into = tmp_path / "into"
        assert run("install", bundle_file=str(out), into=str(into)) == int(ExitCode.CLEAN)
        captured = capsys.readouterr()
        assert f"installed 1 file(s) into {into}" in captured.out
        assert "Not authenticated" in captured.err
        assert (into / "a.txt").read_text(encoding="utf-8") == "alpha"

    def test_a_tampered_bundle_writes_nothing(
        self, source: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out = Bundle.create(tmp_path / "o.tgz", files=[("a.txt", source / "a.txt")])
        into = tmp_path / "into"
        assert run("install", bundle_file=str(_tamper(out)), into=str(into)) == int(
            ExitCode.CONFIG_ERROR
        )
        assert "nothing was written" in capsys.readouterr().err
        assert not into.exists()

    def test_an_install_that_fails_after_verifying_is_still_refused(
        self,
        source: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        out = Bundle.create(tmp_path / "o.tgz", files=[("a.txt", source / "a.txt")])
        monkeypatch.setattr(
            Bundle,
            "install",
            classmethod(lambda cls, path, into: BundleReport(ok=False, problems=["disk full"])),
        )
        assert run("install", bundle_file=str(out), into=str(tmp_path / "x")) == int(
            ExitCode.CONFIG_ERROR
        )
        err = capsys.readouterr().err
        assert "nothing was written" in err
        assert "disk full" in err
