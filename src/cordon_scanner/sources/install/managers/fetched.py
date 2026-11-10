"""Tools whose fetch runs no package code, guarded by scanning what the fetch wrote before anything
runs it: `terraform init` / `tofu init` (providers run at plan and apply, modules' provisioners at
apply), `helm dependency build|update` (a chart's hooks run in the cluster at install), and
`ansible-galaxy install` (a collection's plugins and a role's tasks run when a playbook does).

The tool fetches as it always does, verifying what it verifies (Terraform checks providers against
the registry's signatures and the lock's hashes). Cordon notes every file under the places the tool
writes before and after; the files that are new or changed are scanned. If any blocks, they are
removed and the lock is put back as it was, so nothing fetched is left where the next command would
run it. A file that was replaced is removed, not restored: the next fetch brings it back, scanned.

What a fetch writes is not always a file. A linked directory (Terraform's plugin cache links each
provider in) is followed and its files scanned: they are what the tool runs. Anything that is not
a regular file once its links are followed -- a FIFO, a device, a socket, a dangling link -- is
refused and removed, never read: reading one hangs or reads without end. A link loop ends at the
first directory already seen, and a walk that passes MAX_FILES files or MAX_BYTES bytes is refused,
so a link to `/` cannot make the guard read the whole disk (S3, reviews/release-080).
"""

from __future__ import annotations

import hashlib
import itertools
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.plan import InstallRefused

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence


@dataclass(frozen=True)
class FetchedPlaces:
    """Where one run of a tool writes: directories it fills, and lock files it rewrites."""

    tool: str
    directories: tuple[Path, ...]
    locks: tuple[Path, ...]


class FetchedTree:
    TERRAFORM: ClassVar[frozenset[str]] = frozenset({"terraform", "tofu"})
    HELM_VERBS: ClassVar[frozenset[str]] = frozenset({"dependency", "dependencies", "dep"})
    HELM_FETCHES: ClassVar[frozenset[str]] = frozenset({"build", "update", "up"})
    GALAXY_PATHS: ClassVar[frozenset[str]] = frozenset({"-p", "--collections-path", "--roles-path"})
    MAX_FILES: ClassVar[int] = 200_000
    MAX_BYTES: ClassVar[int] = 8 << 30
    #: The mark of an entry that is not a regular file once links are followed: never read.
    SPECIAL: ClassVar[str] = "special:"
    #: The mark of a linked directory: followed for its files, removed with them on a block.
    LINK: ClassVar[str] = "link:"

    @classmethod
    def installs(cls, tool: str, args: Sequence[str]) -> bool:
        if tool in cls.TERRAFORM:
            return bool(args) and args[0] in ("init", "get")
        if tool == "helm":
            return len(args) >= 2 and args[0] in cls.HELM_VERBS and args[1] in cls.HELM_FETCHES
        if tool == "ansible-galaxy":
            return (bool(args) and args[0] == "install") or (
                len(args) >= 2 and args[0] in ("collection", "role") and args[1] == "install"
            )
        return False

    @classmethod
    def places(cls, tool: str, args: Sequence[str], project: Path) -> FetchedPlaces:
        if tool in cls.TERRAFORM:
            data = Path(os.environ.get("TF_DATA_DIR") or ".terraform")
            return FetchedPlaces(tool, (project / data,), (project / ".terraform.lock.hcl",))
        if tool == "helm":
            positional = [a for a in args[2:] if not a.startswith("-")]
            chart = project / (positional[0] if positional else ".")
            return FetchedPlaces(tool, (chart / "charts",), (chart / "Chart.lock",))
        given = [
            Path(value).expanduser()
            for flag, value in itertools.pairwise(args)
            if flag in cls.GALAXY_PATHS
        ]
        given += [
            Path(a.partition("=")[2]).expanduser()
            for a in args
            if a.partition("=")[0] in cls.GALAXY_PATHS and "=" in a
        ]
        home = Path.home() / ".ansible"
        return FetchedPlaces(tool, tuple(given) or (home / "collections", home / "roles"), ())

    @classmethod
    def snapshot(cls, places: FetchedPlaces) -> dict[Path, str]:
        """Every entry under the places: a regular file by its content's sha256, a linked
        directory by its target, anything else by its kind, unread."""
        seen: dict[Path, str] = {}
        walked: set[str] = set()
        budget = [cls.MAX_FILES, cls.MAX_BYTES]
        for directory in places.directories:
            if directory.is_dir():
                cls._walk(directory, seen, walked, budget)
        return seen

    @classmethod
    def _walk(cls, top: Path, seen: dict[Path, str], walked: set[str], budget: list[int]) -> None:
        for root, dirs, files in os.walk(top, followlinks=True):
            real = os.path.realpath(root)
            if real in walked:
                dirs[:] = []
                continue
            walked.add(real)
            for name in dirs:
                path = Path(root, name)
                if path.is_symlink():
                    seen[path] = cls.LINK + str(path.readlink())
            for name in files:
                path = Path(root, name)
                budget[0] -= 1
                if budget[0] < 0:
                    raise InstallRefused(
                        f"what the fetch left under {top} holds more than {cls.MAX_FILES} files; "
                        "Cordon does not scan part of it"
                    )
                seen[path] = cls._entry(path, budget)

    @classmethod
    def _entry(cls, path: Path, budget: list[int]) -> str:
        try:
            info = path.stat()
        except OSError:
            return cls.SPECIAL + "dangling link"
        if not stat.S_ISREG(info.st_mode):
            return cls.SPECIAL + stat.filemode(info.st_mode)
        budget[1] -= info.st_size
        if budget[1] < 0:
            raise InstallRefused(
                f"what the fetch left holds more than {cls.MAX_BYTES >> 30} GiB; Cordon does not "
                "scan part of it"
            )
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
        return digest.hexdigest()

    @classmethod
    def _entries_only(cls, places: FetchedPlaces) -> dict[Path, str]:
        """Every entry's path, unread and unfollowed: what an over-large fetch wrote, to remove."""
        out: dict[Path, str] = {}
        for directory in places.directories:
            for root, dirs, files in os.walk(directory, followlinks=False):
                for name in (*dirs, *files):
                    path = Path(root, name)
                    if path.is_symlink() or name in files:
                        out[path] = "?"
        return out

    @staticmethod
    def saved_locks(places: FetchedPlaces) -> dict[Path, bytes | None]:
        return {lock: lock.read_bytes() if lock.is_file() else None for lock in places.locks}

    @staticmethod
    def changed(before: dict[Path, str], after: dict[Path, str]) -> list[Path]:
        return sorted(path for path, digest in after.items() if before.get(path) != digest)

    @staticmethod
    def stage(changed: Sequence[Path], places: FetchedPlaces, into: Path) -> Path:
        """The new and changed files, copied under one folder named for the tool, each at its path
        below the place it was written, so a finding names what was fetched."""
        root = into / f"{places.tool}-fetched"
        for path in changed:
            if path.is_symlink() and path.is_dir():
                continue
            base = next((d for d in places.directories if path.is_relative_to(d)), path.parent)
            target = root / base.name / path.relative_to(base)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
        return root

    @staticmethod
    def undo(changed: Sequence[Path], locks: dict[Path, bytes | None]) -> None:
        """What the fetch wrote, removed; the locks as they were."""
        for path in sorted(changed, key=lambda p: len(p.parts), reverse=True):
            path.unlink(missing_ok=True)
        for lock, data in locks.items():
            if data is None:
                lock.unlink(missing_ok=True)
            else:
                lock.write_bytes(data)

    @classmethod
    def run(
        cls,
        tool: str,
        args: Sequence[str],
        project: Path,
        fetch: Callable[[], int],
        scan: Callable[[Path], bool],
        scratch: Path,
    ) -> int:
        """The fetch, then the scan of what it wrote; undone if the scan blocks. `scan` reports
        and returns whether the files passed."""
        places = cls.places(tool, args, project)
        before = cls.snapshot(places)
        locks = cls.saved_locks(places)
        code = fetch()
        try:
            after = cls.snapshot(places)
        except InstallRefused:
            cls.undo(cls.changed(before, cls._entries_only(places)), locks)
            raise
        changed = cls.changed(before, after)
        if not changed:
            return code
        special = [path for path in changed if after[path].startswith(cls.SPECIAL)]
        if special:
            cls.undo(changed, locks)
            first = special[0]
            raise InstallRefused(
                f"{tool} wrote {first}, which is not a regular file "
                f"({after[first].removeprefix(cls.SPECIAL)}); Cordon removed what the fetch wrote"
            )
        try:
            passed = scan(cls.stage(changed, places, scratch))
        except BaseException:
            cls.undo(changed, locks)
            raise
        if not passed:
            cls.undo(changed, locks)
            return 1
        return code


__all__ = ["FetchedPlaces", "FetchedTree"]
