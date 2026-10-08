"""Code arriving from somewhere else, checked before it reaches the working tree.

A repository is most dangerous the moment it lands: an editor opens its tasks, a shell loads its
`.envrc`, a coding agent reads its instruction files and MCP config, and `npm install` runs its
hooks. None of that needs the developer to run the code on purpose. So `clone` and `pull` scan the
incoming commit from git's object store first, and only then check it out or merge it:

    clone   git clone --no-checkout     history only; the working tree stays empty
            scan the commit's tree      read from the objects, never written to disk
            check out, or remove        a blocked clone leaves nothing behind

    pull    git fetch                   the branch's new commits, not merged
            scan the incoming tree      findings already in your checkout are not counted again
            merge, or stop              a blocked pull leaves your checkout as it was

The same check runs as a `post-checkout` and a `post-merge` hook, for a plain `git clone`,
`git checkout` or `git pull` that did not go through these commands. Those hooks run after git
has written the files, though before anything has executed them, so they undo instead of refuse:
a blocked merge is reset to where it started, a blocked branch switch goes back, and a blocked
clone's files are removed from the working tree (they stay in the object store, to be read).

Two properties hold in every path:

* The incoming code cannot configure its own check. No `cordon.yaml`, policy file or baseline
  inside the commit is read: the check runs on Cordon's defaults and on what the person running
  it typed. A repository that could suppress its own finding would make the check worthless
  exactly when it matters.
* Network steps (`clone`, `fetch`) are the developer's own git, with their credentials and
  configuration, because a private repository needs them. Reading the commit is the scanner's
  hardened git, which runs no program the repository's configuration names.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.core.config import Config, Policy
from cordon_scanner.core.errors import ConfigError, SourceError
from cordon_scanner.core.models import Category, Severity

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.core.models import Finding, ScanResult
    from cordon_scanner.sources.git import GitRepository

INCOMING_ENV: Final = "CORDON_INCOMING"
"""Set while `clone` or `pull` checks out or merges code it has already scanned, so the hooks
those git commands fire do not scan the same commit a second time."""

DEFAULT_FAIL_ON: Final = Severity.CRITICAL
"""What blocks incoming code by default: anything malicious, and anything critical.

Lower than a commit or push gate on purpose. Those judge your own change; this judges a whole
repository someone else wrote, and almost every real project carries an old HIGH advisory
somewhere. Refusing to clone it would teach people to bypass the check, so the default asks only
whether the code is compromised. `--fail-on high` raises it."""


@dataclass(frozen=True, slots=True)
class IncomingCheck:
    """What one incoming commit was found to contain."""

    rev: str
    result: ScanResult
    blocking: tuple[Finding, ...]
    """Findings that meet the policy and are new: not already in the code being replaced."""
    inherited: int = 0
    """Findings that meet the policy but were already there before this code arrived."""

    @property
    def ok(self) -> bool:
        return not self.blocking


class Incoming:
    """Scan code from elsewhere before it is checked out or merged."""

    @staticmethod
    def config(base: Config | None = None, fail_on: str | None = None) -> Config:
        """The configuration an incoming check runs on: the operator's, never the repository's.

        `base` is a configuration the person running the command named explicitly (`--config`).
        Nothing is discovered from the repository being checked.
        """
        config = base or Config.default()
        severity = Severity.parse(fail_on) if fail_on else DEFAULT_FAIL_ON
        policy: Policy = replace(
            config.policy,
            fail_on_severity=severity,
            fail_on_categories=config.policy.fail_on_categories | {Category.MALICIOUS},
        )
        return replace(config, policy=policy)

    @classmethod
    def check(
        cls,
        repository: GitRepository,
        rev: str,
        config: Config,
        *,
        base_rev: str | None = None,
    ) -> IncomingCheck:
        """Scan the tree of `rev` from the object store.

        With `base_rev`, a finding the base commit already had is not counted as arriving: a
        pull is judged on what it brings, not on what the checkout already held.
        """
        from cordon_scanner.core.policy import PolicyGate

        result = cls._scan(repository, rev, config)
        tripping = [f for f in result.active if PolicyGate._fails(f, config.policy)]
        if not tripping or not base_rev:
            return IncomingCheck(rev=rev, result=result, blocking=tuple(tripping))
        before = cls._scan(repository, base_rev, config)
        known = {f.fingerprint for f in before.active}
        new = tuple(f for f in tripping if f.fingerprint not in known)
        return IncomingCheck(
            rev=rev, result=result, blocking=new, inherited=len(tripping) - len(new)
        )

    @staticmethod
    def _scan(repository: GitRepository, rev: str, config: Config) -> ScanResult:
        """One commit's tree, scanned against an empty scratch root.

        The root is empty so the scan's inventory walk cannot pick up the working tree, which
        for a pull or a hook is a different commit from the one being judged. Every file comes
        from the object store.
        """
        from cordon_scanner import Scanner
        from cordon_scanner.sources.git import GitTreeSource

        with tempfile.TemporaryDirectory(prefix="cordon-incoming-") as scratch:
            source = GitTreeSource(repository, rev)
            return Scanner(config, source=source).scan(Path(scratch))

    # -- Git -----------------------------------------------------------------

    @staticmethod
    def own_git(
        args: Sequence[str], cwd: str | Path, *, capture: bool = False
    ) -> subprocess.CompletedProcess[str]:
        """The developer's own git, for the steps that need their credentials and config.

        Hooks this command would fire for code it has just scanned are told so through
        `INCOMING_ENV`; `ext::` remote helpers, which run a program named in a URL, are refused.
        """
        from cordon_scanner.sources.git import GitRepository

        env = {**os.environ, INCOMING_ENV: "1"}
        return subprocess.run(  # noqa: S603 - absolute path, fixed argv, no shell
            [GitRepository.binary(), "-c", "protocol.ext.allow=never", *args],
            cwd=cwd,
            env=env,
            text=True,
            capture_output=capture,
            check=False,
        )

    @classmethod
    def _rev(cls, root: Path, name: str) -> str | None:
        done = cls.own_git(
            ["rev-parse", "--verify", "--quiet", f"{name}^{{commit}}"], root, capture=True
        )
        return done.stdout.strip() or None if done.returncode == 0 else None

    # -- Clone ---------------------------------------------------------------

    @staticmethod
    def default_directory(url: str) -> str:
        """The directory `git clone` would choose: the URL's last part, less `.git`."""
        name = url.rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1]
        name = name.removesuffix(".git") or "repository"
        if name in (".", "..") or name.startswith("-"):
            raise ConfigError(f"cannot name a directory after {url!r}; give one explicitly")
        return name

    @classmethod
    def clone(
        cls,
        url: str,
        directory: Path,
        config: Config,
        *,
        branch: str | None = None,
    ) -> IncomingCheck | None:
        """Clone without checking out, scan the commit, then check it out or remove the clone.

        Returns None for a repository with no commits, which has nothing to check.
        """
        from cordon_scanner.sources.git import GitRepository

        for value, what in ((url, "repository URL"), (branch or "", "branch")):
            if value.startswith("-"):
                raise ConfigError(
                    f"the {what} {value!r} starts with a dash and would be read as an option"
                )
        if directory.exists() and (not directory.is_dir() or any(directory.iterdir())):
            raise ConfigError(
                f"{directory} already exists and is not an empty directory",
                hint="Clone into a new directory, so a blocked clone can be removed entirely.",
            )
        existed = directory.exists()
        command = ["clone", "--no-checkout"]
        if branch:
            command += ["--branch", branch]
        done = cls.own_git(
            [*command, "--", url, str(directory)], directory.parent if existed else Path.cwd()
        )
        if done.returncode != 0:
            raise SourceError(f"git clone failed (exit {done.returncode})")
        root = directory.resolve()
        head = cls._rev(root, "HEAD")
        if head is None:
            return None
        try:
            check = cls.check(GitRepository(root), head, config)
        except BaseException:
            cls._remove(root, existed)
            raise
        if not check.ok:
            cls._remove(root, existed)
            return check
        # The index of a --no-checkout clone is empty; a hard reset fills it and the working
        # tree from the commit just scanned.
        done = cls.own_git(["reset", "--quiet", "--hard", head], root)
        if done.returncode != 0:
            raise SourceError(f"checking out {head[:12]} failed (exit {done.returncode})")
        return check

    @staticmethod
    def _remove(root: Path, keep_directory: bool) -> None:
        """Remove a blocked clone: its objects as well, so nothing of it stays on disk."""

        def writable(function: Any, path: str, *_: Any) -> None:
            # Git writes its objects read-only, and Windows refuses to delete a read-only file:
            # without this the blocked clone stayed on disk, objects and all.
            Path(path).chmod(stat.S_IWRITE)
            function(path)

        if sys.version_info >= (3, 12):
            shutil.rmtree(root, onexc=writable)
        else:
            shutil.rmtree(root, onerror=writable)
        if keep_directory:
            root.mkdir(exist_ok=True)

    # -- Pull ----------------------------------------------------------------

    @classmethod
    def pull(
        cls,
        root: Path,
        config: Config,
        *,
        remote: str | None = None,
        branch: str | None = None,
        merge: bool = False,
    ) -> tuple[IncomingCheck | None, str]:
        """Fetch, scan what would be merged, and merge only when it passes.

        Returns the check (None when there was nothing new) and a sentence saying what happened.
        Fast-forward only unless `merge`, so a pull never makes a merge commit the developer did
        not ask for.
        """
        from cordon_scanner.sources.git import GitRepository

        for value, what in ((remote or "", "remote"), (branch or "", "branch")):
            if value.startswith("-"):
                raise ConfigError(
                    f"the {what} {value!r} starts with a dash and would be read as an option"
                )
        head = cls._rev(root, "HEAD")
        if head is None:
            raise ConfigError("this repository has no commits to pull into")
        if remote is None and branch is None:
            upstream = cls.own_git(
                ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"],
                root,
                capture=True,
            )
            if upstream.returncode != 0:
                raise ConfigError(
                    "the current branch has no upstream to pull from",
                    hint="Name one: cordon-scanner pull origin main",
                )
            remote = upstream.stdout.strip().split("/", 1)[0]
            done = cls.own_git(["fetch", "--quiet", remote], root)
            incoming_ref = "@{upstream}"
        else:
            done = cls.own_git(
                ["fetch", "--quiet", remote or "origin", *([branch] if branch else [])], root
            )
            incoming_ref = "FETCH_HEAD"
        if done.returncode != 0:
            raise SourceError(f"git fetch failed (exit {done.returncode})")
        incoming = cls._rev(root, incoming_ref)
        if incoming is None or incoming == head:
            return None, "already up to date"
        behind = cls.own_git(["merge-base", "--is-ancestor", incoming, head], root)
        if behind.returncode == 0:
            return None, "already up to date"
        check = cls.check(GitRepository(root), incoming, config, base_rev=head)
        if not check.ok:
            return check, f"not merged: {incoming[:12]} was blocked; your checkout is unchanged"
        done = cls.own_git(
            ["merge", "--quiet", *(["--no-edit"] if merge else ["--ff-only"]), incoming], root
        )
        if done.returncode != 0:
            return check, (
                "scanned and passed, but git could not merge it"
                + ("" if merge else " as a fast-forward (pass --merge to allow a merge commit)")
            )
        return check, f"merged {incoming[:12]}"

    # -- Hooks ---------------------------------------------------------------

    @staticmethod
    def _is_null(rev: str) -> bool:
        return not rev.strip("0")

    @classmethod
    def after_checkout(
        cls, root: Path, previous: str, current: str, branch_switch: str, config: Config
    ) -> IncomingCheck | None:
        """The `post-checkout` hook: a clone, or a switch to another branch or commit.

        A file checkout (`git checkout -- path`) and a switch that changes no commit are not
        checked. A blocked switch goes back to where it was; a blocked clone has its files
        removed from the working tree.
        """
        from cordon_scanner.sources.git import GitRepository

        if os.environ.get(INCOMING_ENV) or branch_switch != "1" or previous == current:
            return None
        repository = GitRepository(root)
        if cls._is_null(previous):
            check = cls.check(repository, current, config)
            if not check.ok:
                cls._empty_working_tree(root, repository)
            return check
        check = cls.check(repository, current, config, base_rev=previous)
        if not check.ok:
            back = cls.own_git(["checkout", "--quiet", "-"], root)
            if back.returncode != 0:
                cls.own_git(["checkout", "--quiet", previous], root)
        return check

    @classmethod
    def after_merge(cls, root: Path, config: Config) -> IncomingCheck | None:
        """The `post-merge` hook, after `git pull` or `git merge`: a blocked merge is undone with
        `git reset --merge ORIG_HEAD`, which keeps uncommitted work the merge did not touch."""
        from cordon_scanner.sources.git import GitRepository

        if os.environ.get(INCOMING_ENV):
            return None
        before = cls._rev(root, "ORIG_HEAD")
        after = cls._rev(root, "HEAD")
        if before is None or after is None or before == after:
            return None
        check = cls.check(GitRepository(root), after, config, base_rev=before)
        if not check.ok:
            cls.own_git(["reset", "--quiet", "--merge", before], root)
        return check

    @staticmethod
    def _empty_working_tree(root: Path, repository: GitRepository) -> None:
        """Remove a blocked clone's tracked files from disk, never following a link out of it.

        The objects stay, so the code can still be read with `git show`; it is simply no longer
        where an editor or a shell would act on it.
        """
        for name in repository.tracked_files():
            path = root / name
            try:
                if path.is_symlink() or path.is_file():
                    path.unlink()
            except OSError:
                continue
        for directory in sorted(
            (p for p in root.rglob("*") if p.is_dir() and ".git" not in p.relative_to(root).parts),
            reverse=True,
        ):
            try:
                directory.rmdir()
            except OSError:
                continue
        (root / ".git" / "CORDON_BLOCKED").write_text(
            "This clone was blocked by cordon-scanner and its files removed from the working "
            "tree. Read it with `git show HEAD:<path>`; restore it deliberately with "
            "`git checkout -f HEAD`.\n",
            encoding="utf-8",
        )


__all__ = ["DEFAULT_FAIL_ON", "INCOMING_ENV", "Incoming", "IncomingCheck"]
