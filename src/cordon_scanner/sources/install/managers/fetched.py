"""Tools whose fetch runs no package code, guarded by scanning what the fetch wrote before anything
runs it: `terraform init` / `tofu init` (providers run at plan and apply, modules' provisioners at
apply), `helm dependency build|update` (a chart's hooks run in the cluster at install), and
`ansible-galaxy install` (a collection's plugins and a role's tasks run when a playbook does).

The tool fetches as it always does, verifying what it verifies (Terraform checks providers against
the registry's signatures and the lock's hashes). Cordon notes every file under the places the tool
writes before and after; the files that are new or changed are scanned. If any blocks, they are
removed and the lock is put back as it was, so nothing fetched is left where the next command would
run it. A file that was replaced is removed, not restored: the next fetch brings it back, scanned.
"""

from __future__ import annotations

import hashlib
import itertools
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

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

    @staticmethod
    def snapshot(places: FetchedPlaces) -> dict[Path, str]:
        """Every file under the places, by its content's sha256 (a link read through)."""
        seen: dict[Path, str] = {}
        for directory in places.directories:
            if not directory.is_dir():
                continue
            for path in directory.rglob("*"):
                if path.is_file():
                    digest = hashlib.sha256()
                    with path.open("rb") as handle:
                        for block in iter(lambda: handle.read(1 << 20), b""):
                            digest.update(block)
                    seen[path] = digest.hexdigest()
        return seen

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
            base = next((d for d in places.directories if path.is_relative_to(d)), path.parent)
            target = root / base.name / path.relative_to(base)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
        return root

    @staticmethod
    def undo(changed: Sequence[Path], locks: dict[Path, bytes | None]) -> None:
        """What the fetch wrote, removed; the locks as they were."""
        for path in changed:
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
        changed = cls.changed(before, cls.snapshot(places))
        if not changed:
            return code
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
