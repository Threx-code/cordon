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

from cordon_scanner.intel.provenance.install_verify import InstallRecord, InstallState


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
