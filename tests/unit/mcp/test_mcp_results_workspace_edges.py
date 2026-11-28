"""The MCP server's workspace and result summary on the inputs that are rarely sent (`mcp/workspace.py`, `mcp/results.py`)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

import pytest

from cordon_scanner.mcp.results import Results
from cordon_scanner.mcp.workspace import OutsideWorkspace, Workspace


class TestWorkspace:
    def test_started_in_the_home_directory_with_no_root_it_reads_no_paths(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.chdir(tmp_path)
        assert Workspace.of(None).roots == ()
        with pytest.raises(OutsideWorkspace, match="started without a project directory"):
            Workspace.of(None).resolve("x")

    def test_a_root_that_is_a_file_is_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "file.txt"
        target.write_text("x", encoding="utf-8")
        with pytest.raises(ValueError, match="not a directory"):
            Workspace.of([str(target)])

    def test_an_empty_path_or_one_with_a_nul_byte_is_refused(self, tmp_path: Path) -> None:
        workspace = Workspace.of([str(tmp_path)])
        with pytest.raises(OutsideWorkspace, match="empty path or one containing a NUL byte"):
            workspace.resolve("a\x00b")
        with pytest.raises(OutsideWorkspace, match="empty path or one containing a NUL byte"):
            workspace.resolve("   ")


class TestSummary:
    FINDING: ClassVar[dict[str, Any]] = {
        "rule_id": "X.001",
        "severity": "high",
        "category": "suspicious",
        "message": "m",
        "location": {"path": "/work/repo/a.py", "line": 1},
    }

    def test_a_root_prefix_is_taken_off_the_paths_it_starts(self) -> None:
        summary = Results.summarise(
            {"findings": [self.FINDING], "complete": True},
            0,
            max_findings=5,
            root_prefix="/work/repo/",
        )
        assert summary.findings[0]["path"] == "a.py"

    def test_an_incomplete_scan_with_nothing_blocking_is_incomplete_not_a_pass(self) -> None:
        summary = Results.summarise({"findings": [], "complete": False}, 0, max_findings=5)
        assert summary.verdict == "incomplete"

    def test_a_package_check_ignores_a_finding_about_its_own_stand_in_lockfile(self) -> None:
        about_the_stand_in = {**self.FINDING, "location": {"path": "lock.json"}}
        summary = Results.summarise(
            {"findings": [about_the_stand_in], "complete": True},
            1,
            max_findings=5,
            package_only=True,
        )
        assert summary.verdict == "pass"
        assert summary.total == 0

    def test_several_scans_of_one_request_are_as_incomplete_as_their_worst_part(self) -> None:
        partial = Results.summarise({"findings": [], "complete": False}, 0, max_findings=5)
        clean = Results.summarise({"findings": [], "complete": True}, 0, max_findings=5)
        merged = Results.merge([partial, clean], max_findings=5, subject={})
        assert merged.verdict == "incomplete"
        assert "part of it could not be checked" in merged.summary
