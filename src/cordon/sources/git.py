"""Git-aware scanning.

Two modes matter, and one of them is a security control rather than a
convenience.

``--staged`` reads content from the **git index**, not the working tree. A
scanner that reads from disk in staged mode is defeated by staging a poisoned
file and then restoring the clean version on disk: the poisoned blob is what
gets committed, the clean one is what gets scanned, and the hook reports
success. Reading the index closes that gap, and it is why staged mode is a
source concern rather than a filter applied later.

``--git-diff`` narrows a scan to what changed. Useful on a large repository,
but narrowing is applied only to *file* analysis: dependency and manifest
checks always run against the whole tree, because a malicious transitive
dependency appears in no diff.

This module is the only place in Cordon that invokes a subprocess. Every call
uses a fixed argument list, a ``--`` separator before anything derived from the
target, NUL-delimited output, and a timeout. No shell, ever.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

from cordon.core.content import FileContent, Skipped, SkipReason
from cordon.core.errors import SourceError

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from cordon.core.limits import Limits
    from cordon.core.walker import WalkEntry, Walker

GIT_TIMEOUT = 30.0


@dataclass(frozen=True, slots=True)
class GitInfo:
    root: Path
    revision: str | None = None
    branch: str | None = None
    remote: str | None = None


class GitRepository:
    """One git repository, and every git invocation Cordon makes.

    Bound to a root rather than taking one per call, because every method needs
    it and passing it repeatedly is how a call ends up running against the wrong
    tree. Construction does not verify the path is a repository -- use
    :meth:`discover` for that -- so the class is cheap to make and the failure
    surfaces at the operation that needs it.

    This is the only class in Cordon that invokes a subprocess, which is why the
    invocation is in one method rather than spread over the callers: a fixed
    argument list, no shell, and a timeout are properties of that one method or
    they are not properties at all.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    # -- Invocation ------------------------------------------------------

    @staticmethod
    @lru_cache(maxsize=1)
    def binary() -> str:
        """Resolve git to an absolute path, once.

        Invoking it by bare name would let whatever appears first on PATH
        answer. That is a weaker position than necessary: the lookup is done
        once, at a known moment, rather than implicitly on every call.
        """
        found = shutil.which("git")
        if not found:
            raise SourceError(
                "git is not installed, so repository-aware scanning is unavailable",
                hint="Install git, or scan the directory without --staged or --git-diff.",
            )
        return found

    def run(self, args: list[str], *, check: bool = True) -> str:
        """Run one git command safely.

        Fixed argv, no shell, bounded time. `git` is invoked because there is no
        other way to read the index, and reading the index is what closes the
        staged-content bypass.
        """
        try:
            completed = subprocess.run(  # noqa: S603 - absolute path, fixed argv, no shell
                [self.binary(), *args],
                cwd=self.root,
                capture_output=True,
                timeout=GIT_TIMEOUT,
                check=False,
                text=False,
            )
        except FileNotFoundError as exc:
            raise SourceError("git could not be executed") from exc
        except subprocess.TimeoutExpired as exc:
            raise SourceError(f"git {args[0]} timed out after {GIT_TIMEOUT}s") from exc

        if check and completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            raise SourceError(f"git {args[0]} failed: {detail}")

        return completed.stdout.decode("utf-8", errors="replace")

    # -- Discovery -------------------------------------------------------

    @classmethod
    def discover(cls, path: str | Path) -> GitInfo | None:
        """Locate the repository containing a path, if there is one."""
        target = Path(path).resolve()
        directory = target if target.is_dir() else target.parent
        try:
            root = cls(directory).run(["rev-parse", "--show-toplevel"]).strip()
        except SourceError:
            return None
        if not root:
            return None

        repository = cls(root)
        revision = repository.run(["rev-parse", "HEAD"], check=False).strip() or None
        branch = repository.run(["rev-parse", "--abbrev-ref", "HEAD"], check=False).strip() or None
        remote = repository.run(["config", "--get", "remote.origin.url"], check=False).strip()

        return GitInfo(
            root=Path(root),
            revision=revision,
            branch=branch,
            # A remote URL can embed credentials. It is recorded for provenance
            # and must not carry a token into a report.
            remote=cls.strip_credentials(remote) or None,
        )

    @staticmethod
    def strip_credentials(url: str) -> str:
        """Remove any userinfo from a remote URL.

        A remote configured as `https://user:token@host/repo` would otherwise
        put a live credential into every report that records provenance.
        """
        if "://" not in url:
            return url
        scheme, _, rest = url.partition("://")
        if "@" in rest:
            rest = rest.rpartition("@")[2]
        return f"{scheme}://{rest}"

    # -- File selection --------------------------------------------------

    def tracked_files(self) -> list[str]:
        """Files git is tracking, so build output and ignored paths are skipped."""
        output = self.run(["ls-files", "-z", "--cached", "--exclude-standard"])
        return [name for name in output.split("\0") if name]

    def staged_files(self) -> list[str]:
        """Paths staged for commit, excluding deletions."""
        output = self.run(["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"])
        return [name for name in output.split("\0") if name]

    def changed_files(self, ref: str) -> list[str]:
        """Paths that differ from a reference.

        The `--` goes after the ref, not before it: git reads everything after
        the separator as a path, so `-- HEAD~1` asks for changes to a file
        called `HEAD~1`. The docstring here claimed the opposite ordering and
        credited it with stopping a branch named like an option from becoming
        one -- which the ordering cannot do, and which is now done by checking
        the ref directly.
        """
        if ref.startswith("-"):
            raise SourceError(
                f"ref {ref!r} starts with a dash and would be read as an option",
                hint="Use the full ref name, for example refs/heads/my-branch.",
            )
        output = self.run(["diff", "--name-only", "-z", "--diff-filter=ACMR", ref, "--"])
        return [name for name in output.split("\0") if name]

    # -- Content ---------------------------------------------------------

    def staged_content(self, path: str) -> bytes | None:
        """Read a path's **staged** content from the index.

        This is the whole point of staged mode. `git show :path` reads the blob
        that will be committed, which may differ from what is on disk right now.
        A scanner that reads the working tree in this mode can be defeated by
        staging a poisoned file and restoring the clean one, and it will report
        success while the poisoned blob goes into the commit.

        Returns bytes, not text, and never raises: a path that cannot be read
        from the index is not a scan failure. It falls back to the working tree
        at the caller, which is the correct behaviour for a file that is tracked
        but unmodified.
        """
        try:
            completed = subprocess.run(  # noqa: S603 - absolute path, fixed argv, no shell
                [self.binary(), "show", f":{path}"],
                cwd=self.root,
                capture_output=True,
                timeout=GIT_TIMEOUT,
                check=False,
                text=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, SourceError):
            return None
        if completed.returncode != 0:
            return None
        return completed.stdout


class GitPathSource:
    """A scan narrowed to a set of paths git named.

    Used by ``--tracked`` and ``--git-diff``. Content still comes from disk,
    because these modes are about *which* files to examine and not about which
    bytes they hold.

    The narrowing is intersected with the walker's output rather than replacing
    it, so exclusions, limits and symlink handling still apply. A path git
    reports but the walker would not have yielded -- one excluded by
    configuration, or beyond a size limit -- stays unscanned, and a git mode
    cannot be used to reach past a limit.
    """

    id = "git-paths"

    def __init__(self, paths: Iterable[str], *, mode: str, empty_is_normal: bool = False) -> None:
        self._paths = frozenset(paths)
        self._mode = mode
        self._empty_is_normal = empty_is_normal

    def entries(self, root: Path, walker: Walker) -> Iterator[WalkEntry]:
        for entry in walker.walk(root):
            if entry.rel_path in self._paths:
                yield entry

    def load(self, entry: WalkEntry, limits: Limits) -> FileContent | Skipped:
        return FileContent.load(entry.real_path, entry.rel_path, limits)

    @property
    def parallel_safe(self) -> bool:
        return True

    @property
    def empty_selection_is_normal(self) -> bool:
        """Depends on which narrowing was asked for, and the two differ.

        A diff can legitimately be empty: a scheduled run against a branch that
        has not moved changes nothing, and failing there every night is how a
        check gets disabled.

        A repository where git tracks nothing is not the same situation. It
        means `--tracked` selected every file it could find and that was none,
        so the pipeline scanned nothing and reported success -- which is the
        outcome this tool exists to make impossible.

        Either way it is reported. This only chooses warning or note.
        """
        return self._empty_is_normal

    def describe(self) -> str:
        return f"{self._mode} ({len(self._paths)} paths)"


class GitIndexSource:
    """A scan of the **staged** content, read from the git index.

    This is the security control. `git show :path` reads the blob that will be
    committed, which may differ from what is on disk right now. A pre-commit
    hook that reads the working tree is defeated by staging a poisoned file and
    restoring the clean one: it reports success while the poisoned blob goes
    into the commit.

    Never parallel. Worker processes re-read files by path from disk, which in
    this mode would scan the working tree while the caller believes it is
    scanning the index -- reintroducing the exact bypass this class exists to
    close, and doing it silently. A staged scan covers one commit's worth of
    files, so the lost parallelism costs nothing measurable.
    """

    id = "git-index"

    def __init__(self, repository: GitRepository, paths: Iterable[str]) -> None:
        self._repository = repository
        self._paths = frozenset(paths)

    def entries(self, root: Path, walker: Walker) -> Iterator[WalkEntry]:
        for entry in walker.walk(root):
            if entry.rel_path in self._paths:
                yield entry

    def load(self, entry: WalkEntry, limits: Limits) -> FileContent | Skipped:
        """Read from the index, and refuse to fall back to disk.

        A staged path whose blob cannot be read is reported as unreadable
        rather than served from the working tree. Falling back would reopen the
        bypass for any path an attacker can make unreadable from the index,
        which is a worse failure than an operational finding saying so.
        """
        raw = self._repository.staged_content(entry.rel_path)
        if raw is None:
            return Skipped(entry.rel_path, SkipReason.UNREADABLE)
        return FileContent.from_bytes(entry.rel_path, raw, limits=limits)

    @property
    def parallel_safe(self) -> bool:
        return False

    @property
    def empty_selection_is_normal(self) -> bool:
        """Yes. A pre-commit hook runs on every commit, including ones that
        stage nothing this scanner reads. It is still reported, as a note rather
        than a warning."""
        return True

    def describe(self) -> str:
        return f"git index ({len(self._paths)} staged paths)"


__all__ = ["GitIndexSource", "GitInfo", "GitPathSource", "GitRepository"]
