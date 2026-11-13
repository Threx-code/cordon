#!/usr/bin/env python3
"""The package-wide code features of each archive in a list, and nothing else (no scan).

`CodeFeatures` reads the files a package runs at install, at import and through its library closure,
and for a PyPI source distribution that is often one file or none. This reads every Python file of an
archive as one place, `package` (`code_package_*` in `CodeFeatures.of`), so a verdict model can be
fitted on the code a package holds. It is the same extractor the scanner runs under
`CORDON_MEASURE_FEATURES=1` (`ReachedFlows.sources`), run over the archive's members directly:

- each archive is read in memory, a member at a time and a window at a time, never extracted to disk
  and never run; a string's value is never a feature (`CodeFeatures` keeps its shape only);
- a member past `MAX_MEMBER` bytes, or bytes past `MAX_TOTAL` for the archive, are left unread and the
  row says so (`truncated`); a name that is not a readable archive is a row with an `error`, not a stop;
- the rows are `{"file", "features", "py_files", "py_bytes", "truncated"}`, one JSON line each, appended
  as they finish, so an interrupted run resumes where it stopped.

    python package_features.py --list units.txt --root /c --out features.jsonl --workers 6

`--list` names one unit per line, relative to `--root` (`q/pypi/x-1.0.tar.gz` is `/c/q/pypi/x-1.0.tar.gz`).
Only counts are printed.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing
import sys
import tarfile
import time
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon_scanner.detect.code.features import CodeFeatures

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

ZIPS = (".zip", ".whl", ".egg", ".vsix")


class PackageFeatures:
    """One archive's `code_package_*` features, from its Python members."""

    #: One member's bytes read, at most; the archive's Python bytes read in all, at most.
    MAX_MEMBER = 1 << 30
    MAX_TOTAL = 4 << 30

    @staticmethod
    def row(root: Path, name: str) -> dict[str, Any]:
        """The row of the unit `name` under `root`."""
        stats: dict[str, Any] = {"py_files": 0, "py_bytes": 0, "truncated": False}
        try:
            files = PackageFeatures.python_members(root / name, stats)
            features = CodeFeatures.of({"package": files})
        except (OSError, tarfile.TarError, zipfile.BadZipFile, EOFError, ValueError) as error:
            return {"file": name, "error": type(error).__name__, **stats}
        return {"file": name, "features": features, **stats}

    @staticmethod
    def python_members(archive: Path, stats: dict[str, Any]) -> Iterator[tuple[str, Any]]:
        """Each `.py` member as (name, a reader of its windows), in the archive's order. A reader is
        used before the next member is asked for, which a tar stream needs."""
        if archive.name.lower().endswith(ZIPS):
            yield from PackageFeatures._zip(archive, stats)
        else:
            yield from PackageFeatures._tar(archive, stats)

    @staticmethod
    def _window_reader(
        opener: Callable[[], Any], size: int, stats: dict[str, Any]
    ) -> Callable[[], Iterator[bytes]]:
        def windows() -> Iterator[bytes]:
            left = min(size, PackageFeatures.MAX_MEMBER)
            handle = opener()
            try:
                while left > 0:
                    chunk = handle.read(min(CodeFeatures.WINDOW, left))
                    if not chunk:
                        break
                    left -= len(chunk)
                    stats["py_bytes"] += len(chunk)
                    yield chunk
            finally:
                handle.close()

        return windows

    @staticmethod
    def _admit(name: str, size: int, stats: dict[str, Any]) -> bool:
        """Whether this member is read: a Python file within the member and archive budgets."""
        if not name.lower().endswith(".py"):
            return False
        if (
            size > PackageFeatures.MAX_MEMBER
            or stats["py_bytes"] + size > PackageFeatures.MAX_TOTAL
        ):
            stats["truncated"] = True
            return False
        stats["py_files"] += 1
        return True

    @staticmethod
    def _tar(archive: Path, stats: dict[str, Any]) -> Iterator[tuple[str, Any]]:
        with tarfile.open(archive, "r:*") as tar:
            for member in tar:
                if not member.isfile() or not PackageFeatures._admit(
                    member.name, member.size, stats
                ):
                    continue
                yield (
                    member.name,
                    PackageFeatures._window_reader(
                        lambda m=member: tar.extractfile(m), member.size, stats
                    ),
                )

    @staticmethod
    def _zip(archive: Path, stats: dict[str, Any]) -> Iterator[tuple[str, Any]]:
        with zipfile.ZipFile(archive) as bundle:
            for info in bundle.infolist():
                if info.is_dir() or not PackageFeatures._admit(
                    info.filename, info.file_size, stats
                ):
                    continue
                yield (
                    info.filename,
                    PackageFeatures._window_reader(
                        lambda i=info: bundle.open(i), info.file_size, stats
                    ),
                )

    @staticmethod
    def done(out: Path) -> set[str]:
        """The units already in `out`, so a run resumes."""
        if not out.exists():
            return set()
        names: set[str] = set()
        for line in out.read_text(encoding="utf-8").splitlines():
            try:
                names.add(json.loads(line)["file"])
            except (ValueError, KeyError):
                continue
        return names

    @staticmethod
    def run(listing: Path, root: Path, out: Path, workers: int) -> dict[str, int]:
        """Every unit of `listing` not in `out`, `workers` at a time. Counts only."""
        wanted = [u.strip() for u in listing.read_text(encoding="utf-8").splitlines() if u.strip()]
        seen = PackageFeatures.done(out)
        pending = [u for u in wanted if u not in seen]
        counts = {
            "listed": len(wanted),
            "resumed": len(wanted) - len(pending),
            "read": 0,
            "errors": 0,
        }
        started = time.monotonic()
        with (
            out.open("a", encoding="utf-8") as sink,
            multiprocessing.get_context("spawn").Pool(workers) as pool,
        ):
            for row in pool.imap_unordered(
                PackageFeatures.work, [(root, u) for u in pending], chunksize=1
            ):
                sink.write(json.dumps(row, sort_keys=True) + "\n")
                sink.flush()
                counts["errors" if "error" in row else "read"] += 1
        counts["seconds"] = round(time.monotonic() - started)
        return counts

    @staticmethod
    def work(job: tuple[Path, str]) -> dict[str, Any]:
        """One job of the pool: `(root, unit)` to its row (a name a worker process can import)."""
        return PackageFeatures.row(*job)

    @staticmethod
    def main(argv: list[str] | None = None) -> int:
        parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
        parser.add_argument("--list", type=Path, required=True)
        parser.add_argument("--root", type=Path, required=True)
        parser.add_argument("--out", type=Path, required=True)
        parser.add_argument("--workers", type=int, default=6)
        args = parser.parse_args(argv)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        counts = PackageFeatures.run(args.list, args.root, args.out, args.workers)
        print(json.dumps(counts))
        return 0


if __name__ == "__main__":
    sys.exit(PackageFeatures.main())
