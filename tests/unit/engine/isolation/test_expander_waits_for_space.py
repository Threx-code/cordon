"""An archive's result does not depend on how busy the machine is: when the temp space runs out because other scans hold it, the scan waits and expands again.

A member kept on disk that cannot be written for want of space used to be refused as unreadable and block the scan, so the same package gave exit 0 alone and exit 4
beside other scans. The expander now lets the others finish and expands the archive again; only when the space never comes back within the waits and the scan's time
is the archive reported, and then as the machine's temp space, never as the package's member.
"""

from __future__ import annotations

import errno
import io
import os
import tarfile
from pathlib import Path
from typing import Any

from cordon_scanner import Scanner
from cordon_scanner.engine.isolation.expander import ArchiveExpander
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.files.spill import Spill
from cordon_scanner.foundation.limits import DEFAULT_LIMITS
from support import requires_forked_workers

MEMBER_REJECTED = "OPERATIONAL.ARCHIVE.MEMBER_REJECTED"


class Scene:
    """A package with one member too big to hold in memory, and a temp area that is full for a number of writes."""

    @staticmethod
    def tarball(tmp_path: Path) -> Path:
        target = tmp_path / "p-1.0.0.tgz"
        with tarfile.open(target, "w:gz") as tar:
            for path, data in (
                ("package/package.json", b'{"name": "p", "version": "1.0.0"}'),
                ("package/data.bin", os.urandom(6000)),
            ):
                info = tarfile.TarInfo(path)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return target

    @staticmethod
    def full_for(tmp_path: Path, monkeypatch: Any, writes: int) -> Path:
        """The first `writes` spill files cannot be made (no space left); the count is kept in a file, because each try is a new process."""
        counter = tmp_path / "full-for"
        counter.write_text(str(writes), encoding="utf-8")
        real = Spill.writer

        def writer() -> Any:
            left = int(counter.read_text(encoding="utf-8"))
            if left > 0:
                counter.write_text(str(left - 1), encoding="utf-8")
                raise OSError(errno.ENOSPC, "No space left on device")
            return real()

        monkeypatch.setattr(Spill, "writer", staticmethod(writer))
        monkeypatch.setattr(ArchiveExpander, "PAUSE_LEAST", 0.0)
        monkeypatch.setattr(ArchiveExpander, "PAUSE_STEP", 0.01)
        return counter

    @staticmethod
    def scan(target: Path) -> Any:
        limits = DEFAULT_LIMITS.merged(max_file_bytes=1024)
        return Scanner(
            Config.default().with_overrides(use_cache=False, offline=True, limits=limits)
        ).scan(target)

    @staticmethod
    def rules(result: Any) -> set[str]:
        return {finding.rule_id for finding in result.findings}


class TestWaitingForSpace:
    @requires_forked_workers
    def test_with_space_the_member_is_read_and_the_scan_is_complete(self, tmp_path: Path) -> None:
        result = Scene.scan(Scene.tarball(tmp_path))
        assert MEMBER_REJECTED not in Scene.rules(result) and result.content_complete

    @requires_forked_workers
    def test_space_that_comes_back_after_a_few_tries_gives_the_same_result_as_never_missing(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        alone = Scene.scan(Scene.tarball(tmp_path))
        Scene.full_for(tmp_path, monkeypatch, 3)
        loaded = Scene.scan(Scene.tarball(tmp_path))
        assert Scene.rules(loaded) == Scene.rules(alone)
        assert loaded.content_complete is alone.content_complete

    @requires_forked_workers
    def test_it_does_try_again_each_time_the_space_is_missing(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        counter = Scene.full_for(tmp_path, monkeypatch, 3)
        Scene.scan(Scene.tarball(tmp_path))
        assert (
            counter.read_text(encoding="utf-8") == "0"
        )  # three refused writes were each followed by another expansion

    @requires_forked_workers
    def test_space_that_never_comes_back_is_reported_not_passed(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        Scene.full_for(tmp_path, monkeypatch, 10_000)
        monkeypatch.setattr(ArchiveExpander, "SPACE_WAITS", 2)
        result = Scene.scan(Scene.tarball(tmp_path))
        assert not result.content_complete
        assert Scene.rules(result) & {MEMBER_REJECTED, "OPERATIONAL.ARCHIVE.TEMP_SPACE"}


class TestThePause:
    def test_no_pause_once_the_waits_are_spent(self) -> None:
        assert ArchiveExpander._pause(ArchiveExpander.SPACE_WAITS, float("inf")) is None

    def test_a_pause_lies_between_the_least_and_what_the_waits_so_far_allow(self) -> None:
        for waited in range(ArchiveExpander.SPACE_WAITS):
            most = ArchiveExpander.PAUSE_LEAST + (1 + min(waited, 6)) * ArchiveExpander.PAUSE_STEP
            pause = ArchiveExpander._pause(waited, float("inf"))
            assert pause is not None and ArchiveExpander.PAUSE_LEAST <= pause <= most

    def test_no_pause_that_would_end_after_the_scan_s_time(self) -> None:
        import time

        assert ArchiveExpander._pause(0, time.monotonic() + 0.01) is None

    def test_only_a_refusal_for_missing_space_counts(self) -> None:
        full = [["a.bin", "unreadable", "[Errno 28] No space left on device"]]
        other = [["a.bin", "unreadable", "a damaged compressed member"]]
        assert ArchiveExpander._ran_out_of_space(full) and not ArchiveExpander._ran_out_of_space(
            other
        )
        assert not ArchiveExpander._ran_out_of_space([]) and not ArchiveExpander._ran_out_of_space(
            None
        )
