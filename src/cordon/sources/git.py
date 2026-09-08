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

from cordon.core.errors import SourceError

GIT_TIMEOUT = 30.0


@lru_cache(maxsize=1)
def _git_binary() -> str:
    """Resolve git to an absolute path, once.

    Invoking it by bare name would let whatever appears first on PATH answer.
    That is a weaker position than necessary: the lookup is done once, at a
    known moment, rather than implicitly on every call.
    """
    found = shutil.which("git")
    if not found:
        raise SourceError(
            "git is not installed, so repository-aware scanning is unavailable",
            hint="Install git, or scan the directory without --staged or --git-diff.",
        )
    return found


@dataclass(frozen=True, slots=True)
class GitInfo:
    root: Path
    revision: str | None = None
    branch: str | None = None
    remote: str | None = None


def _git(args: list[str], cwd: Path, *, check: bool = True) -> str:
    """Run one git command safely.

    Fixed argv, no shell, bounded time. `git` is invoked because there is no
    other way to read the index, and reading the index is what closes the
    staged-content bypass.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - absolute path, fixed argv, no shell
            [_git_binary(), *args],
            cwd=cwd,
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


def discover(path: str | Path) -> GitInfo | None:
    """Locate the repository containing a path, if there is one."""
    target = Path(path).resolve()
    directory = target if target.is_dir() else target.parent
    try:
        root = _git(["rev-parse", "--show-toplevel"], directory).strip()
    except SourceError:
        return None
    if not root:
        return None

    root_path = Path(root)
    revision = _git(["rev-parse", "HEAD"], root_path, check=False).strip() or None
    branch = _git(["rev-parse", "--abbrev-ref", "HEAD"], root_path, check=False).strip() or None
    remote = _git(["config", "--get", "remote.origin.url"], root_path, check=False).strip()

    return GitInfo(
        root=root_path,
        revision=revision,
        branch=branch,
        # A remote URL can embed credentials. It is recorded for provenance and
        # must not carry a token into a report.
        remote=_strip_credentials(remote) or None,
    )


def _strip_credentials(url: str) -> str:
    """Remove any userinfo from a remote URL.

    A remote configured as `https://user:token@host/repo` would otherwise put a
    live credential into every report that records provenance.
    """
    if "://" not in url:
        return url
    scheme, _, rest = url.partition("://")
    if "@" in rest:
        rest = rest.rpartition("@")[2]
    return f"{scheme}://{rest}"


def tracked_files(root: Path) -> list[str]:
    """Files git is tracking, so build output and ignored paths are skipped."""
    output = _git(["ls-files", "-z", "--cached", "--exclude-standard"], root)
    return [name for name in output.split("\0") if name]


def staged_files(root: Path) -> list[str]:
    """Paths staged for commit, excluding deletions."""
    output = _git(["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"], root)
    return [name for name in output.split("\0") if name]


def changed_files(root: Path, ref: str) -> list[str]:
    """Paths that differ from a reference.

    The ref is passed after `--` so a branch named like an option cannot become
    one.
    """
    output = _git(["diff", "--name-only", "-z", "--diff-filter=ACMR", ref, "--"], root)
    return [name for name in output.split("\0") if name]


def staged_content(root: Path, path: str) -> bytes | None:
    """Read a path's **staged** content from the index.

    This is the whole point of staged mode. `git show :path` reads the blob that
    will be committed, which may differ from what is on disk right now. A
    scanner that reads the working tree in this mode can be defeated by staging
    a poisoned file and restoring the clean one, and it will report success
    while the poisoned blob goes into the commit.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - absolute path, fixed argv, no shell
            [_git_binary(), "show", f":{path}"],
            cwd=root,
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


__all__ = [
    "GitInfo",
    "changed_files",
    "discover",
    "staged_content",
    "staged_files",
    "tracked_files",
]
