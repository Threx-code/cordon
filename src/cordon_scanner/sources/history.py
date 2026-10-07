"""The blobs git history still holds after the working tree stopped holding them.

A credential committed and deleted in the next commit is gone from the tree and present in every
clone, every fork and every CI cache, for as long as the history exists. Scanning the tree finds
none of them, and that is the gap this closes: every blob reachable from any ref whose content is
not in the current tree is read once, by object id, and handed to the same secret detector the
tree scan uses -- with the same hash-only evidence, so the history pass discloses nothing a tree
pass would not.

Read-only, and through the hardened invocation every other git read uses: the repository being
scanned is untrusted, and its configuration cannot redirect what these commands run. Bounded in
blobs, bytes per blob and wall-clock time, and each bound that is hit is reported, because a
history pass that stopped early and said nothing would read as a clean history.
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from cordon_scanner.core.errors import SourceError
from cordon_scanner.sources.git import HARDENING, GitRepository

MAX_BLOBS = 50_000
MAX_BLOB_BYTES = 1 << 20
#: Past `MAX_BLOB_BYTES` a blob is read in chunks of this size, each overlapping the last by
#: `CHUNK_OVERLAP` so that a credential straddling a boundary is whole in one of them; the
#: secret rules are line-oriented, and no credential is near this long.
CHUNK_BYTES = 1 << 20
CHUNK_OVERLAP = 16 << 10
#: The largest blob read at all: a data dump or a lockfile committed once is where a secret
#: hides, and is rarely past this.
MAX_STREAMED_BYTES = 256 << 20
#: An archive is read whole (to be opened) up to this size.
MAX_ARCHIVE_BYTES = 64 << 20
TIME_BUDGET_SECONDS = 300.0
BATCH_TIMEOUT_SECONDS = 30.0


@dataclass(frozen=True, slots=True)
class HistoricalBlob:
    """A blob no longer in the tree, with one path it was committed under."""

    object_id: str
    path: str
    data: bytes


@dataclass
class HistoryCoverage:
    """What the pass read, and what it had to leave unread, so the gap is reportable."""

    considered: int = 0
    read: int = 0
    skipped_large: int = 0
    skipped_over_ceiling: int = 0
    stopped_for_time: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not (self.skipped_large or self.skipped_over_ceiling or self.stopped_for_time)


class GitHistory:
    """The removed-from-tree blobs of one repository, and the commit that introduced each."""

    def __init__(
        self,
        repository: GitRepository,
        *,
        max_blobs: int | None = None,
        max_blob_bytes: int | None = None,
        time_budget: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.repository = repository
        # Read at construction, not bound as defaults, so the module bounds stay configurable.
        self.max_blobs = MAX_BLOBS if max_blobs is None else max_blobs
        self.max_blob_bytes = MAX_BLOB_BYTES if max_blob_bytes is None else max_blob_bytes
        self.time_budget = TIME_BUDGET_SECONDS if time_budget is None else time_budget
        self.clock = clock
        self.coverage = HistoryCoverage()

    def current_blobs(self) -> set[str]:
        """Object ids of every blob in HEAD's tree, which the tree scan already reads."""
        listing = self.repository.run(["ls-tree", "-r", "-z", "--full-tree", "HEAD"], check=False)
        blobs = set()
        for entry in listing.split("\0"):
            meta, _, _path = entry.partition("\t")
            parts = meta.split()
            if len(parts) == 3 and parts[1] == "blob":
                blobs.add(parts[2])
        return blobs

    def removed_blobs(self) -> list[tuple[str, str]]:
        """`(object id, path)` for every historical blob not in HEAD, first path seen per blob."""
        listing = self.repository.run(["rev-list", "--objects", "--all"], check=False)
        current = self.current_blobs()
        candidates: dict[str, str] = {}
        for line in listing.splitlines():
            object_id, _, path = line.partition(" ")
            if path and object_id not in current and object_id not in candidates:
                candidates[object_id] = path
        if not candidates:
            return []
        # rev-list names trees too; keep blobs, with their sizes, in one batch-check.
        checked = self._batch_check(list(candidates))
        return [(oid, candidates[oid]) for oid, kind, _size in checked if kind == "blob"]

    def _batch_check(self, object_ids: list[str]) -> list[tuple[str, str, int]]:
        try:
            completed = subprocess.run(  # noqa: S603 - absolute path, fixed argv, no shell
                [self.repository.binary(), *HARDENING, "cat-file", "--batch-check"],
                cwd=self.repository.root,
                input=("\n".join(object_ids) + "\n").encode(),
                capture_output=True,
                timeout=BATCH_TIMEOUT_SECONDS,
                check=False,
                env=GitRepository._environment(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SourceError(f"git cat-file --batch-check failed: {type(exc).__name__}") from exc
        out = []
        for line in completed.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[2].isdigit():
                out.append((parts[0], parts[1], int(parts[2])))
        self._sizes = {oid: size for oid, _kind, size in out}
        return out

    def blobs(self) -> Iterator[HistoricalBlob]:
        """Each removed blob's content, within the bounds; what was left unread is counted."""
        removed = self.removed_blobs()
        self.coverage.considered = len(removed)
        if len(removed) > self.max_blobs:
            self.coverage.skipped_over_ceiling = len(removed) - self.max_blobs
            removed = removed[: self.max_blobs]
        from cordon_scanner.archive.safe import ArchiveReader

        sizes = getattr(self, "_sizes", {})
        wanted = []
        for object_id, path in removed:
            size = sizes.get(object_id, 0)
            ceiling = MAX_ARCHIVE_BYTES if ArchiveReader.is_archive(path) else MAX_STREAMED_BYTES
            if size > max(self.max_blob_bytes, ceiling):
                self.coverage.skipped_large += 1
                continue
            wanted.append((object_id, path))
        if not wanted:
            return
        started = self.clock()
        try:
            process = subprocess.Popen(  # noqa: S603 - absolute path, fixed argv, no shell
                [self.repository.binary(), *HARDENING, "cat-file", "--batch"],
                cwd=self.repository.root,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=GitRepository._environment(),
            )
        except OSError as exc:
            raise SourceError("git cat-file --batch could not start") from exc
        assert process.stdin is not None and process.stdout is not None  # noqa: S101 - PIPE above
        try:
            for object_id, path in wanted:
                if self.clock() - started > self.time_budget:
                    self.coverage.stopped_for_time = True
                    break
                process.stdin.write(f"{object_id}\n".encode())
                process.stdin.flush()
                header = process.stdout.readline().split()
                if len(header) != 3 or header[1] != b"blob" or not header[2].isdigit():
                    continue
                size = int(header[2])
                if size <= self.max_blob_bytes or ArchiveReader.is_archive(path):
                    data = process.stdout.read(size)
                    process.stdout.read(1)
                    self.coverage.read += 1
                    yield HistoricalBlob(object_id, path, data)
                    continue
                # Streamed, so a large blob never sits in memory whole.
                remaining, tail = size, b""
                while remaining > 0:
                    piece = process.stdout.read(min(CHUNK_BYTES, remaining))
                    if not piece:
                        break
                    remaining -= len(piece)
                    yield HistoricalBlob(object_id, path, tail + piece)
                    tail = piece[-CHUNK_OVERLAP:]
                process.stdout.read(1)
                self.coverage.read += 1
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()

    def introduced_by(self, object_id: str) -> tuple[str, str] | None:
        """`(commit, ISO date)` of the oldest commit that added this blob, or None."""
        log = self.repository.run(
            ["log", "--all", "--format=%H %cI", f"--find-object={object_id}"], check=False
        )
        lines = [line for line in log.splitlines() if line.strip()]
        if not lines:
            return None
        commit, _, when = lines[-1].partition(" ")
        return commit, when
