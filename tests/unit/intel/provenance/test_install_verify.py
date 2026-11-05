"""`verify`, offline (release item 75, note 75): an installation read against its own RECORD.

Every fixture is a small installation written into a temporary site-packages: a package, its
dist-info and a correct RECORD. Nothing is run from it.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import py_compile
from pathlib import Path
from typing import ClassVar

from cordon_scanner.intel.provenance.install_verify import (
    InstallRecord,
    InstallReport,
    InstallState,
    ReleaseCheck,
    VerifiedRecord,
)
from support import ROOT as REPO


class InstallKit:
    FILES: ClassVar[dict[str, str]] = {
        "cordon_scanner/__init__.py": "VERSION = '9.9.9'\n",
        "cordon_scanner/engine/core.py": "def scan():\n    return 0\n",
    }

    @staticmethod
    def row(root: Path, path: str) -> str:
        data = (root / path).read_bytes()
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        return f"{path},sha256={digest},{len(data)}"

    @classmethod
    def install(cls, root: Path) -> Path:
        info = root / "cordon_scanner-9.9.9.dist-info"
        info.mkdir(parents=True)
        for path, text in cls.FILES.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text, encoding="utf-8")
        (info / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: cordon-scanner\nVersion: 9.9.9\n", encoding="utf-8"
        )
        rows = [cls.row(root, p) for p in (*cls.FILES, "cordon_scanner-9.9.9.dist-info/METADATA")]
        rows.append("cordon_scanner-9.9.9.dist-info/RECORD,,")
        (info / "RECORD").write_text("\n".join(rows) + "\n", encoding="utf-8")
        return root


class TestOffline:
    def test_an_untouched_installation_is_consistent_never_verified(self, tmp_path) -> None:
        report = InstallRecord.check(InstallKit.install(tmp_path))
        assert report.state is InstallState.CONSISTENT, report.problems
        assert report.version == "9.9.9" and report.checked == 3

    def test_one_changed_byte_is_modified_by_name(self, tmp_path) -> None:
        root = InstallKit.install(tmp_path)
        (root / "cordon_scanner/engine/core.py").write_text(
            "def scan():\n    return 1\n", encoding="utf-8"
        )
        report = InstallRecord.check(root)
        assert report.state is InstallState.MODIFIED
        assert "cordon_scanner/engine/core.py: changed" in report.problems

    def test_a_deleted_file_is_modified(self, tmp_path) -> None:
        root = InstallKit.install(tmp_path)
        (root / "cordon_scanner/engine/core.py").unlink()
        assert "cordon_scanner/engine/core.py: missing" in InstallRecord.check(root).problems

    def test_an_added_module_is_modified(self, tmp_path) -> None:
        root = InstallKit.install(tmp_path)
        (root / "cordon_scanner/engine/extra.py").write_text("x = 1\n", encoding="utf-8")
        assert "cordon_scanner/engine/extra.py: not in RECORD" in InstallRecord.check(root).problems

    def test_a_pth_no_distribution_lists_is_modified(self, tmp_path) -> None:
        root = InstallKit.install(tmp_path)
        (root / "zz-startup.pth").write_text("import os\n", encoding="utf-8")
        problems = InstallRecord.check(root).problems
        assert any(p.startswith("zz-startup.pth:") for p in problems)

    def test_a_cached_module_whose_code_is_not_its_source_is_modified(self, tmp_path) -> None:
        # The interpreter runs a cached .pyc instead of its source when the header matches: a cache
        # compiled from other code, under the source's name, is the modification.
        root = InstallKit.install(tmp_path)
        source = root / "cordon_scanner/engine/core.py"
        cached = Path(importlib.util.cache_from_source(str(source)))
        other = tmp_path / "other.py"
        other.write_text("def scan():\n    return 99\n", encoding="utf-8")
        py_compile.compile(str(other), cfile=str(cached))
        problems = InstallRecord.check(root).problems
        assert any("compiled cache differs from its source" in p for p in problems), problems

    def test_a_cache_compiled_from_its_own_source_passes(self, tmp_path) -> None:
        root = InstallKit.install(tmp_path)
        py_compile.compile(str(root / "cordon_scanner/engine/core.py"))
        assert InstallRecord.check(root).state is InstallState.CONSISTENT

    def test_a_rewritten_record_matching_tampered_files_is_still_only_consistent(
        self, tmp_path
    ) -> None:
        # The limit, pinned: whoever can edit Cordon can edit its RECORD too, so offline is never
        # "verified", only consistent.
        root = InstallKit.install(tmp_path)
        (root / "cordon_scanner/engine/core.py").write_text(
            "def scan():\n    return 1\n", encoding="utf-8"
        )
        info = root / "cordon_scanner-9.9.9.dist-info"
        rows = [
            InstallKit.row(root, p)
            for p in (*InstallKit.FILES, "cordon_scanner-9.9.9.dist-info/METADATA")
        ]
        (info / "RECORD").write_text(
            "\n".join([*rows, f"{info.name}/RECORD,,"]) + "\n", encoding="utf-8"
        )
        assert InstallRecord.check(root).state is InstallState.CONSISTENT

    def test_no_installation_there_is_unverified(self, tmp_path) -> None:
        assert InstallRecord.check(tmp_path).state is InstallState.UNVERIFIED

    def test_a_malformed_record_is_modified(self, tmp_path) -> None:
        root = InstallKit.install(tmp_path)
        (root / "cordon_scanner-9.9.9.dist-info/RECORD").write_text("a,b\n", encoding="utf-8")
        assert InstallRecord.check(root).state is InstallState.MODIFIED


class ReleaseKit:
    FIXTURE = REPO / "tests" / "unit" / "data" / "sigstore"

    @classmethod
    def real(cls) -> dict[str, object]:
        """Cordon 0.6.0's own wheel's PEP 740 provenance, as PyPI serves it (see the README there)."""
        import json

        return json.loads(
            (cls.FIXTURE / "pypi-cordon-scanner-0.6.0-provenance.json").read_text(encoding="utf-8")
        )

    @staticmethod
    def wheel(root: Path) -> bytes:
        """A wheel built from the fixture installation's own files and RECORD."""
        import io
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for path in (*InstallKit.FILES, "cordon_scanner-9.9.9.dist-info/METADATA"):
                archive.writestr(path, (root / path).read_bytes())
            archive.writestr(
                "cordon_scanner-9.9.9.dist-info/RECORD",
                (root / "cordon_scanner-9.9.9.dist-info/RECORD").read_bytes(),
            )
        return buffer.getvalue()


class TestTheReleaseCheck:
    def test_the_real_release_attestation_verifies_for_its_own_wheel(self) -> None:
        real = ReleaseKit.real()
        refusal = ReleaseCheck.provenance_refusal(real["provenance"], str(real["sha256"]), "0.6.0")
        assert refusal is None, refusal

    def test_another_wheels_digest_is_refused(self) -> None:
        real = ReleaseKit.real()
        assert ReleaseCheck.provenance_refusal(real["provenance"], "0" * 64, "0.6.0") is not None

    def test_the_same_wheel_claimed_for_another_release_is_refused(self) -> None:
        # Signed by release.yml at v0.6.0: an installation claiming 0.5.0 is not that release.
        real = ReleaseKit.real()
        refusal = ReleaseCheck.provenance_refusal(real["provenance"], str(real["sha256"]), "0.5.0")
        assert refusal is not None and "v0.5.0" in refusal

    def test_nothing_readable_is_refused(self) -> None:
        assert ReleaseCheck.provenance_refusal({}, "0" * 64, "0.6.0") is not None

    def test_a_wheel_the_attestation_is_not_for_is_never_verified(self, tmp_path) -> None:
        root = InstallKit.install(tmp_path)
        (root / "cordon_scanner-9.9.9.dist-info" / "WHEEL").write_text(
            "Wheel-Version: 1.0\nTag: py3-none-any\n", encoding="utf-8"
        )
        offline = InstallRecord.check(root)
        report = ReleaseCheck.check(
            offline, root, provenance=ReleaseKit.real()["provenance"], wheel=ReleaseKit.wheel(root)
        )
        assert report.state is InstallState.UNVERIFIED

    def test_the_wheels_record_against_the_installed_one(self, tmp_path) -> None:
        root = InstallKit.install(tmp_path)
        record = (root / "cordon_scanner-9.9.9.dist-info/RECORD").read_text(encoding="utf-8")
        installed = InstallRecord.check(root).record
        assert ReleaseCheck.record_differences(record, installed) == []
        installer = (
            *installed,
            ("cordon_scanner-9.9.9.dist-info/INSTALLER", "a" * 64, 4),
            ("cordon_scanner/__pycache__/core.cpython-312.pyc", "b" * 64, 9),
            ("../../../bin/cordon-scanner", "c" * 64, 9),
        )
        assert ReleaseCheck.record_differences(record, installer) == []
        changed = tuple(
            (p, "d" * 64, s) if p.endswith("core.py") else (p, d, s) for p, d, s in installed
        )
        assert ReleaseCheck.record_differences(record, changed) == [
            "cordon_scanner/engine/core.py: not as the release built it"
        ]
        extra = (*installed, ("cordon_scanner/backdoor.py", "e" * 64, 5))
        assert ReleaseCheck.record_differences(record, extra) == [
            "cordon_scanner/backdoor.py: installed, but not in the release's wheel"
        ]

    def test_fetching_from_anywhere_but_pypi_is_refused(self) -> None:
        import pytest

        with pytest.raises(OSError):
            ReleaseCheck.fetch("https://example.invalid/x.whl")
        with pytest.raises(OSError):
            ReleaseCheck.fetch("http://pypi.org/x")


class TestWhatAScanSays:
    """A scan says 'installation verified' only from a sealed record `verify` wrote for the running
    version and location, never otherwise (item 75)."""

    @staticmethod
    def running(monkeypatch, tmp_path, version: str = "9.9.9"):
        root = InstallKit.install(tmp_path / "sp")
        monkeypatch.setattr(
            InstallRecord, "find", staticmethod(lambda target: _Dist(root, version))
        )
        monkeypatch.setattr(
            VerifiedRecord, "path", classmethod(lambda cls: tmp_path / "key" / cls.NAME)
        )
        return root

    def test_a_verified_check_is_said(self, monkeypatch, tmp_path) -> None:
        root = self.running(monkeypatch, tmp_path)
        report = InstallReport(
            InstallState.VERIFIED, version="9.9.9", root=str(root), reason="signed"
        )
        VerifiedRecord.write(report, "2026-11-03 11:30 UTC")
        assert VerifiedRecord.line() == "installation verified at 2026-11-03 11:30 UTC (signed)"

    def test_nothing_is_said_without_a_check(self, monkeypatch, tmp_path) -> None:
        self.running(monkeypatch, tmp_path)
        assert VerifiedRecord.line() is None

    def test_a_forged_record_is_not_said(self, monkeypatch, tmp_path) -> None:
        import json

        root = self.running(monkeypatch, tmp_path)
        path = VerifiedRecord.path()
        path.parent.mkdir(parents=True)
        forged = {
            "version": "9.9.9",
            "root": str(root),
            "reason": "x",
            "at": "now",
            "_seal": "0" * 64,
        }
        path.write_text(json.dumps(forged), encoding="utf-8")
        assert VerifiedRecord.line() is None

    def test_another_version_is_not_said(self, monkeypatch, tmp_path) -> None:
        root = self.running(monkeypatch, tmp_path)
        report = InstallReport(InstallState.VERIFIED, version="9.9.8", root=str(root), reason="s")
        VerifiedRecord.write(report, "t")
        assert VerifiedRecord.line() is None

    def test_a_later_failed_check_withdraws_the_record(self, monkeypatch, tmp_path) -> None:
        root = self.running(monkeypatch, tmp_path)
        good = InstallReport(InstallState.VERIFIED, version="9.9.9", root=str(root), reason="s")
        VerifiedRecord.write(good, "t")
        VerifiedRecord.write(InstallReport(InstallState.MODIFIED, version="9.9.9"), "t")
        assert VerifiedRecord.line() is None


class _Dist:
    def __init__(self, root: Path, version: str) -> None:
        self.root, self.version = root, version

    def locate_file(self, name: str) -> Path:
        return self.root / name
