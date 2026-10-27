"""Cordon's own build backend (`scripts/backend/cordon_build.py`): what it puts in a wheel, and that it
builds the same bytes twice. Checked against setuptools when it replaced it: identical contents and
metadata, file for file, less the third-party YARA sources setuptools had shipped without their
licence (now sdist only)."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from support import ROOT


class Built:
    @staticmethod
    def backend() -> Any:
        sys.path.insert(0, str(ROOT / "scripts" / "backend"))
        try:
            import cordon_build
        finally:
            sys.path.pop(0)
        return cordon_build

    @staticmethod
    def wheel(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, editable: bool = False
    ) -> zipfile.ZipFile:
        backend = Built.backend()
        monkeypatch.chdir(ROOT)
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
        build = backend.build_editable if editable else backend.build_wheel  # type: ignore[attr-defined]
        return zipfile.ZipFile(tmp_path / build(str(tmp_path)))


class TestWheel:
    def test_every_module_and_data_file_is_in_the_wheel(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        names = set(Built.wheel(tmp_path, monkeypatch).namelist())
        src = ROOT / "src"
        modules = {
            p.relative_to(src).as_posix()
            for top in ("cordon_scanner", "cordon_sandbox")
            for p in (src / top).rglob("*.py")
            if "__pycache__" not in p.parts
        }
        assert modules and modules <= names
        assert "cordon_scanner/rules/yara/cordon-builtin.yar" in names
        assert not any(n.startswith("cordon_scanner/rules/yara/upstream/") for n in names)
        assert not any("__pycache__" in n or n.endswith(".pyc") for n in names)

    def test_the_record_hashes_every_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wheel = Built.wheel(tmp_path, monkeypatch)
        record = next(n for n in wheel.namelist() if n.endswith(".dist-info/RECORD"))
        rows = list(csv.reader(io.StringIO(wheel.read(record).decode())))
        assert {r[0] for r in rows} == set(wheel.namelist())
        for name, digest, size in rows:
            if name == record:
                continue
            data = wheel.read(name)
            want = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            assert digest == f"sha256={want}" and int(size) == len(data), name

    def test_metadata_carries_the_project(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wheel = Built.wheel(tmp_path, monkeypatch)
        meta = wheel.read(next(n for n in wheel.namelist() if n.endswith("/METADATA"))).decode()
        assert "Name: cordon-scanner" in meta and "License-Expression: Apache-2.0" in meta
        assert "Requires-Dist" not in meta
        entry = wheel.read(
            next(n for n in wheel.namelist() if n.endswith("/entry_points.txt"))
        ).decode()
        assert "cordon-scanner = cordon_scanner.cli.main:CommandLine.main" in entry

    def test_the_same_tree_builds_the_same_bytes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first, second = tmp_path / "a", tmp_path / "b"
        first.mkdir()
        second.mkdir()
        a = Built.wheel(first, monkeypatch).filename
        b = Built.wheel(second, monkeypatch).filename
        assert a and b
        assert Path(a).read_bytes() == Path(b).read_bytes()

    def test_an_editable_install_is_one_path_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wheel = Built.wheel(tmp_path, monkeypatch, editable=True)
        pth = [n for n in wheel.namelist() if n.endswith(".pth")]
        assert len(pth) == 1
        assert wheel.read(pth[0]).decode().strip() == str((ROOT / "src").resolve())
