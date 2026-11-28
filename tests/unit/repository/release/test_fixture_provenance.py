"""Real-file fixtures say where they came from, and are what was taken.

Every folder under `tests/` whose name ends in `_captures` holds a `CAPTURES.md` whose table lists each file in the
folder with its source, its licence, how it was taken, and its sha256; the sha256 is that of the file as committed.
A fixture nobody can trace, or one edited after it was captured, fails here: the rule that fixtures are real,
licensed files is held by a test, not by memory.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import ClassVar

import pytest

from support import ROOT


class CaptureRecords:
    RECORD: ClassVar[str] = "CAPTURES.md"
    COLUMNS: ClassVar[tuple[str, ...]] = ("file", "source", "licence", "how it was taken", "sha256")

    @staticmethod
    def folders() -> list[Path]:
        return sorted(p for p in (ROOT / "tests").rglob("*_captures") if p.is_dir())

    @classmethod
    def rows(cls, folder: Path) -> dict[str, dict[str, str]]:
        """The record's table, keyed by file name: every column named in COLUMNS, cell text stripped."""
        lines = [
            line.strip()
            for line in (folder / cls.RECORD).read_text(encoding="utf-8").splitlines()
            if line.strip().startswith("|")
        ]
        header = [c.strip().lower() for c in lines[0].strip("|").split("|")]
        rows = {}
        for line in lines[2:]:
            cells = [c.strip() for c in line.strip("|").split("|")]
            row = dict(zip(header, cells, strict=False))
            rows[row.get("file", "")] = row
        return rows


class TestEveryCaptureIsTraced:
    def test_there_are_captures_to_hold(self) -> None:
        assert CaptureRecords.folders(), "no *_captures folder was found under tests/"

    @pytest.mark.parametrize(
        "folder",
        CaptureRecords.folders(),
        ids=lambda p: p.relative_to(ROOT).as_posix(),
    )
    def test_each_file_is_listed_with_its_source_licence_and_hash(self, folder: Path) -> None:
        record = folder / CaptureRecords.RECORD
        assert record.is_file(), f"{folder.relative_to(ROOT)} has no {CaptureRecords.RECORD}"
        rows = CaptureRecords.rows(folder)
        # Every file below the folder, nested ones too, by its path from the folder.
        files = sorted(
            p.relative_to(folder).as_posix()
            for p in folder.rglob("*")
            if p.is_file() and p.relative_to(folder).as_posix() != CaptureRecords.RECORD
        )
        assert sorted(rows) == files, f"listed {sorted(rows)}, present {files}"
        for name, row in rows.items():
            for column in CaptureRecords.COLUMNS:
                assert row.get(column), f"{name}: no {column}"
            actual = hashlib.sha256((folder / name).read_bytes()).hexdigest()
            assert row["sha256"] == actual, f"{name}: recorded {row['sha256']}, file is {actual}"
