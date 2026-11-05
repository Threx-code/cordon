"""Concurrent writers of one cache file (review 98: parallel scans sharing a cache crashed)."""

from __future__ import annotations

import multiprocessing
import re
import stat
from pathlib import Path

import pytest

from cordon_scanner.foundation.files.atomic import AtomicFile
from cordon_scanner.foundation.files.ownership import Ownership


class AtomicFileWorker:
    @staticmethod
    def hammer(path: str, label: int) -> None:
        for round_ in range(200):
            AtomicFile.write(Path(path), f"{label}:{round_}" * 50)


class TestAtomicFile:
    def test_concurrent_writers_never_fail_and_leave_one_whole_file(self, tmp_path) -> None:
        target = tmp_path / "overlay-_status.json"
        context = multiprocessing.get_context("spawn")
        workers = [
            context.Process(target=AtomicFileWorker.hammer, args=(str(target), n)) for n in range(8)
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        assert all(worker.exitcode == 0 for worker in workers)
        # Exactly one writer's whole payload: never a mixture, never a truncated file.
        content = target.read_text(encoding="utf-8")
        piece = content[: len(content) // 50]
        assert re.fullmatch(r"\d:\d{1,3}", piece)
        assert content == piece * 50
        assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]

    def test_a_replace_windows_refuses_for_a_moment_is_retried(self, tmp_path, monkeypatch) -> None:
        """Windows denies a rename onto a file another writer is renaming onto: eight writers on one
        file failed with "Access is denied" (5 Nov). The refusal is retried, briefly, on Windows."""
        refusals = [PermissionError(13, "Access is denied")] * 3
        real = Path.replace

        def busy(self: Path, target: Path) -> Path:
            if refusals:
                raise refusals.pop()
            return real(self, target)

        monkeypatch.setattr(AtomicFile, "WINDOWS", True)
        monkeypatch.setattr(Path, "replace", busy)
        target = tmp_path / "state.json"
        AtomicFile.write(target, "whole")
        assert target.read_text(encoding="utf-8") == "whole" and not refusals

    def test_a_refusal_that_lasts_is_raised(self, tmp_path, monkeypatch) -> None:
        def refused(self: Path, target: Path) -> Path:
            raise PermissionError(13, "Access is denied")

        monkeypatch.setattr(AtomicFile, "WINDOWS", True)
        monkeypatch.setattr(AtomicFile, "WINDOWS_RETRY_SECONDS", 0.05)
        monkeypatch.setattr(Path, "replace", refused)
        with pytest.raises(PermissionError):
            AtomicFile.write(tmp_path / "state.json", "x")
        assert not list(tmp_path.iterdir())  # the staging file is removed

    def test_the_file_is_its_owners_only(self, tmp_path) -> None:
        target = AtomicFile.write(tmp_path / "credentials.json", "{}")
        if Ownership.windows():
            # No POSIX mode on Windows (it reads 0o666): the profile's ACL is what keeps it private.
            assert Ownership.private(target.stat())
        else:
            assert stat.S_IMODE(target.stat().st_mode) == 0o600
