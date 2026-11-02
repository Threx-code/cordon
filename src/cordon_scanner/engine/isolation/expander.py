"""An archive target expanded in a supervised worker (item 56, phase (c)): the parent opens no tar, zip or
compressed stream, and reads no image's layers.

```
  parent                                             expander (template fork, or spawned)
  ──────                                             ────────────────────────────────────
  the archive's path, its name, the deadline,       `ArchiveStages.source` unchanged: the image's
  the scan's spill directory ──────────────────────► inventory, then its layers or the archive's
                                                     members; each member's bytes to a spill file
       ◄── one JSON document: members [name, spill, size, sha256, refusals so far], the refusals,
           the reader's error, the image inventory (declared records), what the reader reported
  `ArchiveExpander.source`: the same stream `read_members` reads today, each member's bytes read from
  its spill file (random name, O_NOFOLLOW, inside the directory, size and sha256 checked)
```

The parent replays the stream in the worker's order: each refusal is added where the reader added it,
and the reader's error is raised where it stopped, so a deadline or memory budget that ends the read at
a member ends it at the same member as before, with the same refusals said.

The expander dying, hanging, overrunning or answering a refused document leaves no members, and
OPERATIONAL.ARCHIVE.REJECTED at the archive's path, as a refused archive is today. Never a read here.

The spill directory (`SpillDirectory`) is per scan, mode 0700 under a random name, and gone when the scan
ends. It holds a lock file the scan keeps locked while it lives, so one left by a scan that was killed
is swept at the next scan's start, at once, whatever its age (outer-layer review: a loop of killed scans
must not fill the disk).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.foundation.errors import ArchiveError
from cordon_scanner.foundation.limits import DEFAULT_LIMITS

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.engine.engine import Engine
    from cordon_scanner.engine.pipeline.accumulator import Accumulator

SPILL_NAME = re.compile(r"[0-9a-f]{32}")
"""A spill file's name: generated, never a member's (which is the archive's own text)."""
PREFIX = "cordon-expand-"
"""Distinct from the per-process spill (`foundation/files/spill.Spill`), whose sweep is by its own name."""


class SpillDirectory:
    """One scan's directory for expanded members' bytes, held by a lock for the scan's life."""

    LOCK: ClassVar[str] = ".scan.lock"
    #: A directory without a lock to test (a platform with no `flock`, or one caught between its
    #: creation and its lock) is swept once it is older than this: no scan runs longer than a day.
    STALE_SECONDS: ClassVar[float] = 24 * 3600.0

    def __init__(self) -> None:
        SpillDirectory.sweep()
        self.path = Path(tempfile.mkdtemp(prefix=PREFIX))
        self.path.chmod(0o700)
        self._lock = SpillDirectory._hold(self.path / SpillDirectory.LOCK)

    @staticmethod
    def _hold(lock: Path) -> int | None:
        """The lock file, opened and locked for as long as this process (or a worker it forks)
        lives: a killed scan's lock is free the moment it dies, whatever the directory's age."""
        try:
            import fcntl
        except ImportError:
            return None
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(lock, flags, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd

    @staticmethod
    def _abandoned(entry: Path, age: float) -> bool:
        """Whether no scan holds `entry`: its lock is free (by liveness, at once), or it has no lock
        and is past `STALE_SECONDS` (by age, the fallback)."""
        try:
            import fcntl
        except ImportError:
            return age > SpillDirectory.STALE_SECONDS
        try:
            fd = os.open(entry / SpillDirectory.LOCK, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            return age > SpillDirectory.STALE_SECONDS
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False  # a live scan holds it
        finally:
            os.close(fd)
        return True

    @staticmethod
    def sweep(now: float | None = None) -> int:
        """Remove the spill directories this user owns that no scan holds; the count removed."""
        now = time.time() if now is None else now
        removed = 0
        root = Path(tempfile.gettempdir())
        for entry in root.glob(f"{PREFIX}*"):
            try:
                st = entry.lstat()
            except OSError:
                continue
            if (
                entry.is_dir()
                and not entry.is_symlink()
                and st.st_uid == os.getuid()
                and SpillDirectory._abandoned(entry, now - st.st_mtime)
            ):
                shutil.rmtree(entry, ignore_errors=True)
                removed += 1
        return removed

    def remove(self) -> None:
        if self._lock is not None:
            os.close(self._lock)
            self._lock = None
        shutil.rmtree(self.path, ignore_errors=True)


class ExpandWork:
    """The expander's side."""

    @staticmethod
    def spill(data: bytes, directory: Path) -> list[Any]:
        """[spill name, size, sha256 of all of it, prefix length or -1] for one member's bytes."""
        from cordon_scanner.foundation.files.spill import SpilledBytes

        name = secrets.token_hex(16)
        target = directory / name
        if isinstance(data, SpilledBytes):
            shutil.move(data.path, target)
            return [name, data.size, SpilledMember.digest(target), len(data)]
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(target, flags, 0o600), "wb") as fh:
            fh.write(data)
        return [name, len(data), hashlib.sha256(data).hexdigest(), -1]

    @staticmethod
    def run(item: tuple[str, str, float | None, str]) -> str:
        from cordon_scanner.engine.isolation.records import Codec
        from cordon_scanner.engine.parallel import ParallelScanner
        from cordon_scanner.engine.pipeline.accumulator import Accumulator
        from cordon_scanner.engine.progress import NullProgress

        archive, name, deadline, spill = item
        state = ParallelScanner._worker
        if state is None:
            raise RuntimeError("the expander has no scan state")
        engine = state.engine
        for holder in (engine, engine.stages, engine.archive_stages):
            holder.progress = NullProgress()
        data = Path(archive).read_bytes()
        acc = Accumulator(finding_cap=engine.config.limits.max_findings)
        rejected: list[tuple[str, str, str]] = []
        image, members = engine.archive_stages.source(
            data, acc, Path(name), rejected, deadline if deadline is not None else float("inf")
        )
        out: list[list[Any]] = []
        error: str | None = None
        try:
            for member_path, member_data in members:
                out.append(
                    [member_path, *ExpandWork.spill(member_data, Path(spill)), len(rejected)]
                )
        except ArchiveError as exc:
            error = exc.message
        document = {
            "members": out,
            "rejected": [list(r) for r in rejected],
            "error": error,
            "image": None if image is None else Codec.encode(image),
            "findings": [f.to_dict() for f in acc.findings],
            "complete": acc.complete,
            "gaps": [list(gap) for gap in acc.content_gaps],
        }
        return json.dumps(document, separators=(",", ":"), allow_nan=False)


class SpilledMember:
    """How one member's bytes cross: written to a spill file under a generated name, or, for a member
    the reader already kept on disk past `max_file_bytes` (`SpilledBytes`: its prefix in memory,
    all of it on disk), that whole file moved in and its prefix length recorded, so the parent
    rebuilds the same `SpilledBytes` and its windows still read past the prefix."""

    @staticmethod
    def digest(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                h.update(block)
        return h.hexdigest()


class ArchiveExpander:
    """The parent's side: the expander run, its answer checked, the members replayed."""

    RULE = "OPERATIONAL.ARCHIVE.REJECTED"

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.spill: SpillDirectory | None = None

    def end(self) -> None:
        """The scan's spill files removed, whatever the scan's outcome."""
        if self.spill is not None:
            self.spill.remove()
            self.spill = None

    def source(
        self,
        path: Path,
        acc: Accumulator,
        rejected: list[tuple[str, str, str]],
        deadline: float,
    ) -> tuple[Any, Iterator[tuple[str, bytes]]]:
        """`ArchiveStages.source` for an archive target, run in the expander: the image inventory
        (None for a plain archive) and the members, as the same stream."""
        from cordon_scanner.engine.isolation.supervisor import Supervisor, Unit
        from cordon_scanner.engine.parallel import CARRIED_SETTINGS, ParallelScanner
        from cordon_scanner.foundation.results import Repository

        if self.spill is None:
            self.spill = SpillDirectory()
        engine, config = self.engine, self.engine.config
        template = getattr(engine, "_template", None)
        module = f"{ParallelScanner.__module__}:ParallelScanner"
        repository = Repository(root=str(path))
        setup: tuple[str, tuple[Any, ...]]
        if template is not None:
            setup = (f"{module}._prepare", ((), repository, {}))
        else:
            operator = {key: getattr(config, key) for key in CARRIED_SETTINGS}
            setup = (
                f"{module}._initialise",
                (type(engine), config.to_dict(), str(path.parent), (), repository, operator, {}),
            )
        scan_deadline = None if deadline == float("inf") else deadline
        supervisor = Supervisor(
            ParallelScanner.start_context(), setup, f"{__name__}:ExpandWork.run",
            ParallelScanner.BOUNDS, 1, deadline=scan_deadline,
        )  # fmt: skip
        supervisor.template = template
        size = path.stat().st_size
        item = (str(path), path.name, scan_deadline, str(self.spill.path))
        outcome = supervisor.run([Unit(0, item, size)])
        why = ""
        accepted = None
        if 0 in outcome.results and isinstance(outcome.results[0], str):
            accepted, why = self.accept(outcome.results[0], path.name)
        elif 0 in outcome.failed:
            why = f"its expander ended: {outcome.failed[0]}"
        elif outcome.unstarted:
            why = "the scan's time budget was spent while it was being expanded"
        else:
            why = "its expander gave no answer"
        if accepted is None:
            from cordon_scanner.foundation.models import Severity
            from cordon_scanner.foundation.results import OperationalFinding

            acc.incomplete(
                OperationalFinding.build(
                    path=path.name,
                    rule_id=self.RULE,
                    message=f"The archive was refused and not scanned: {why}.",
                    remediation=(
                        "Treat a refused archive as unexamined. If it recurs on an archive you "
                        "trust, report it with the archive."
                    ),
                    severity=Severity.MEDIUM,
                )
            )
            return None, iter(())
        image, members, reader_rejected, error, findings, complete, gaps = accepted
        for finding in findings:
            acc.append(finding)
        acc.absorb(complete, tuple(gaps))
        return image, self._replay(members, reader_rejected, error, rejected)

    def accept(self, text: str, name: str) -> tuple[Any, str]:
        from cordon_scanner.engine.cache import ScanCache
        from cordon_scanner.engine.isolation.records import LIST_ENTRIES, Codec
        from cordon_scanner.foundation.formats.served_json import ServedJson
        from cordon_scanner.images.identity import ImageInventory

        limits = self.engine.config.limits
        bound = max(256 << 20, 2 * (limits.max_memory_bytes or 0))
        if len(text) > bound:
            return None, f"an answer of {len(text)} bytes, past {bound}"
        if ServedJson.depth(text) > 12:
            return None, "an answer nested past its declared shape"
        try:
            doc = json.loads(text)
        except (ValueError, RecursionError, MemoryError):
            return None, "an answer that is not JSON within the decoder's limits"
        if not isinstance(doc, dict) or set(doc) != {
            "members", "rejected", "error", "image", "findings", "complete", "gaps",
        }:  # fmt: skip
            return None, "an answer whose sections are not the declared ones"
        members = doc["members"]
        # Independent of the reader's caps and of every optional limit (review, condition 2): never
        # past what the scan reads at all (its file limit; its total-bytes budget below). Not one
        # archive's cap: a walk holds every nested archive's members, each up to that cap.
        entries = min(limits.max_files or DEFAULT_LIMITS.max_files, LIST_ENTRIES)
        if not isinstance(members, list) or len(members) > entries:
            return None, "more members than an archive may hold"
        total = 0
        names: set[str] = set()
        for m in members:
            if not (
                isinstance(m, list)
                and len(m) == 6
                and isinstance(m[0], str)
                and 0 < len(m[0]) <= 8192
                and isinstance(m[1], str)
                and SPILL_NAME.fullmatch(m[1]) is not None
                and m[1] not in names
                and type(m[2]) is int
                and m[2] >= 0
                and isinstance(m[3], str)
                and re.fullmatch(r"[0-9a-f]{64}", m[3]) is not None
                and type(m[4]) is int
                and -1 <= m[4] <= limits.max_file_bytes
                and type(m[5]) is int
                and 0 <= m[5] <= LIST_ENTRIES
            ):
                return None, "a member of the wrong shape"
            names.add(m[1])
            total += m[2]
        if total > (limits.max_total_bytes or DEFAULT_LIMITS.max_total_bytes):
            return None, "members past the scan's byte budget"
        rejected = doc["rejected"]
        if not isinstance(rejected, list) or len(rejected) > LIST_ENTRIES or not all(
            isinstance(r, list) and len(r) == 3 and all(isinstance(x, str) and len(x) <= 8192 for x in r)
            for r in rejected
        ):  # fmt: skip
            return None, "refusals of the wrong shape"
        if any(m[5] > len(rejected) for m in members):
            return None, "a member naming refusals the answer does not hold"
        error = doc["error"]
        if error is not None and not (isinstance(error, str) and len(error) <= 4096):
            return None, "a reader error of the wrong shape"
        image = None
        if doc["image"] is not None:
            image = Codec.decode(ImageInventory, doc["image"])
            if image is None:
                return None, "an image inventory of the wrong shape"
        findings = []
        if not isinstance(doc["findings"], list):
            return None, "findings of the wrong shape"
        for data in doc["findings"]:
            try:
                findings.append(ScanCache.finding_from_dict(data))
            except Exception:  # noqa: BLE001 - any malformed finding refuses the answer
                return None, "a finding of the wrong shape"
        gaps = doc["gaps"]
        if type(doc["complete"]) is not bool or not isinstance(gaps, list) or not all(
            isinstance(g, list) and len(g) == 2 and all(isinstance(x, str) for x in g) for g in gaps
        ):  # fmt: skip
            return None, "coverage of the wrong shape"
        return (
            image,
            members,
            [tuple(r) for r in rejected],
            error,
            findings,
            doc["complete"],
            [(r, p) for r, p in gaps],
        ), ""

    @staticmethod
    def _read_back(path: Path, size: int, digest: str, prefix: int) -> bytes:
        """One member's bytes from its spill file (never through a link), held to the size and digest
        the expander gave: the bytes themselves, or for a member kept on disk the same
        `SpilledBytes` the reader made, whose file this process now owns and removes."""
        from cordon_scanner.foundation.files.spill import SpilledBytes

        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise ArchiveError(f"an expanded member could not be read back ({exc})") from None
        with os.fdopen(fd, "rb") as fh:
            if prefix >= 0:
                head = fh.read(prefix)
                whole = os.fstat(fh.fileno()).st_size
            else:
                head, whole = fh.read(size + 1), -1
        if prefix >= 0:
            if whole != size or len(head) != prefix or SpilledMember.digest(path) != digest:
                raise ArchiveError("an expanded member changed between the expander and this read")
            return SpilledBytes(head, str(path), size)
        path.unlink()
        if len(head) != size or hashlib.sha256(head).hexdigest() != digest:
            raise ArchiveError("an expanded member changed between the expander and this read")
        return head

    def _replay(
        self,
        members: list[list[Any]],
        reader_rejected: list[tuple[str, str, str]],
        error: str | None,
        rejected: list[tuple[str, str, str]],
    ) -> Iterator[tuple[str, bytes]]:
        """The members as the reader yielded them: each refusal added before the member the reader
        yielded after it, its error raised where it stopped, each member's bytes read back from its
        spill file and held to the size and digest the expander gave."""
        assert self.spill is not None  # noqa: S101 - set in `source`
        directory = self.spill.path
        for member_path, spill_name, size, digest, prefix, refused_so_far in members:
            while len(rejected) < refused_so_far:
                rejected.append(reader_rejected[len(rejected)])
            yield (
                member_path,
                ArchiveExpander._read_back(directory / spill_name, size, digest, prefix),
            )
        rejected.extend(reader_rejected[len(rejected) :])
        if error is not None:
            raise ArchiveError(error)


__all__ = ["ArchiveExpander", "ExpandWork", "SpillDirectory"]
