"""Concurrent writers of one cache file (review 98: parallel scans sharing a cache crashed)."""

from __future__ import annotations

import multiprocessing
import re
import stat
from pathlib import Path

from cordon_scanner.core.atomic import AtomicFile


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

    def test_the_file_is_its_owners_only(self, tmp_path) -> None:
        target = AtomicFile.write(tmp_path / "credentials.json", "{}")
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
