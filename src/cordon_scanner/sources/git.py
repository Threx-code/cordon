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

import contextlib
import os
import shutil
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

from cordon_scanner.core.content import FileContent, Skipped, SkipReason
from cordon_scanner.core.errors import SourceError

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from cordon_scanner.core.limits import Limits
    from cordon_scanner.core.walker import WalkEntry, Walker

GIT_TIMEOUT = 30.0

HARDENING: tuple[str, ...] = (
    "--no-pager",
    "--no-optional-locks",
    # Every configuration key below names a program that git will execute. All
    # of them are settable from the scanned repository's own `.git/config`, and
    # `git` reads that file on essentially every command.
    #
    # This was a working remote code execution. A repository containing
    #
    #     [core]
    #         fsmonitor = ./p.sh
    #
    # ran `p.sh` as the invoking user during `cordon scan --staged .` -- the
    # exact command the pre-commit shim and `guard install` configure -- because
    # `git diff --cached` and `git ls-files` both refresh the index, and an
    # index refresh runs the fsmonitor hook. On CI that is the runner holding
    # publish tokens; through the hook it is the developer's laptop. It voided
    # this module's own guarantee that nothing here executes code from the
    # target.
    #
    # `-c` is command-line scope, which outranks local, global and system
    # config, so these cannot be overridden by anything the repository writes --
    # including through `include.path`.
    "-c",
    "core.fsmonitor=",
    "-c",
    "core.hooksPath=",
    "-c",
    "core.sshCommand=",
    "-c",
    "core.gitProxy=",
    "-c",
    "core.askPass=",
    "-c",
    "core.editor=",
    "-c",
    "core.pager=cat",
    "-c",
    "credential.helper=",
    "-c",
    "diff.external=",
    "-c",
    "protocol.ext.allow=never",
    "-c",
    "uploadpack.packObjectsHook=",
)
"""Options neutralising every documented way repository config names a program.

Applied to every invocation. The argument discipline elsewhere in this module --
fixed argv, no shell, a `--` separator, a timeout -- was already right and was
beside the point: the injection was not in the arguments, it was in the
configuration git reads before it looks at them.

What is *not* covered, stated rather than implied: `filter.<name>.clean`,
`filter.<name>.smudge` and `diff.<name>.textconv` are per-driver keys that `-c`
cannot enumerate. They fire only for paths a `.gitattributes` file assigns to a
named driver, and only during operations that apply filters or textconv. The
commands here -- `rev-parse`, `ls-files`, `diff --name-only`, `show :path`,
`config` -- apply none of them: they deal in names and raw blobs.
"""

GIT_ENVIRONMENT: dict[str, str] = {
    # Never block waiting for a credential prompt inside a scan.
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "",
    "SSH_ASKPASS": "",
}
"""Environment overrides applied to every invocation.

Deliberately short. An earlier version also set `GIT_CONFIG_SYSTEM`,
`GIT_CONFIG_GLOBAL`, `GIT_CONFIG_NOSYSTEM` and `GIT_ATTR_NOSYSTEM` to suppress
the machine's own git configuration, on the reasoning that a scan should not
depend on the machine it runs on.

Those are removed, for two reasons.

The first is that they defended against nothing. The attacker in this threat
model controls the *scanned repository*, which means `.git/config` and
`.gitattributes` inside the tree. It does not control the user's global config
or the system config -- anyone who can write those already runs code as the
user. Every dangerous key is neutralised by the `-c` arguments in `HARDENING`
instead, which git ranks above every configuration file, repository-local
included. That is the control; this was decoration on top of it.

The second is that the decoration broke something real. Git for Windows sets
`core.autocrlf=true` in its system configuration. Suppress that and git compares
a CRLF working tree against LF blobs and calls every text file modified, so
`--git-diff` and `--tracked` would have reported every text file in the
repository as changed on every Windows machine. A control that provides no
protection and silently corrupts the result on one platform is worse than
nothing, because its name suggests it is earning its place."""


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
        # Started on first staged read and reused for every later one. None
        # until then, so a repository that is only listed never starts it.
        self._batch_process: subprocess.Popen[bytes] | None = None
        self._batch_failed = False

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

    def run(self, args: list[str], *, check: bool = True, harden: bool = True) -> str:
        """Run one git command safely.

        Fixed argv, no shell, bounded time, and repository configuration
        neutralised. `git` is invoked because there is no other way to read the
        index, and reading the index is what closes the staged-content bypass.

        `harden=False` exists for exactly one caller: reading and writing
        configuration itself. The hardening works by passing `-c` overrides,
        which take precedence over every file -- so a hardened
        `git config --get core.hooksPath` returns the override rather than the
        repository's own value, and the guard's check for a redirected hooks
        directory silently stopped seeing one.

        Dropping the overrides for `git config` is safe because that subcommand
        reads and writes an ini file and refreshes no index: none of the keys
        the hardening neutralises is consulted on that path. It is not safe for
        anything else, which is why it is a parameter and not a default.
        """
        try:
            completed = subprocess.run(  # noqa: S603 - absolute path, fixed argv, no shell
                [self.binary(), *(HARDENING if harden else ()), *args],
                cwd=self.root,
                capture_output=True,
                timeout=GIT_TIMEOUT,
                check=False,
                text=False,
                env={**os.environ, **GIT_ENVIRONMENT},
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

    def untracked_files(self) -> list[str]:
        """Files present and not ignored, which git is not yet tracking.

        `--exclude-standard` applies `.gitignore`, so build output, caches and
        virtualenvs stay out. What is left is the set a developer has created
        and not yet committed -- which for a self-scan is precisely the set most
        likely to contain a problem, because it is the code that was just
        written and has been reviewed by nobody.
        """
        output = self.run(["ls-files", "-z", "--others", "--exclude-standard"])
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
        answered, blob = self._batch_read(path)
        if answered:
            return blob

        try:
            completed = subprocess.run(  # noqa: S603 - absolute path, fixed argv, no shell
                [self.binary(), *HARDENING, "show", f":{path}"],
                cwd=self.root,
                capture_output=True,
                timeout=GIT_TIMEOUT,
                check=False,
                text=False,
                env={**os.environ, **GIT_ENVIRONMENT},
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, SourceError):
            return None
        if completed.returncode != 0:
            return None
        return completed.stdout

    # -- Batched blob reads ----------------------------------------------

    def _batch_read(self, path: str) -> tuple[bool, bytes | None]:
        """Read one blob through a shared `git cat-file --batch` process.

        `git show :path` starts a process per file. A pre-commit hook staging
        two thousand files therefore started two thousand processes and took
        eleven seconds, against a budget of three hundred milliseconds -- and
        that budget is not an efficiency target. A commit-time guard slower than
        about a second gets `--no-verify`, and a bypassed guard protects
        nothing, so process startup was the difference between a control that
        runs and one that does not.

        `--batch` answers an unbounded number of requests from one process.
        Returns `(answered, blob)`. `answered` false means the caller should
        fall back to the single-shot path -- batching is not usable here, this
        path cannot be expressed in the protocol, or the protocol
        desynchronised. Two values rather than a sentinel because the two
        outcomes must not be confusable: `(True, None)` is "git has no such
        blob", and collapsing that into "the batch is unusable" would report a
        staged file as absent, which falls back to the working tree -- the
        exact bypass staged mode exists to close.
        """
        # The protocol is line-delimited, so a path containing a newline cannot
        # be expressed in it. Legal on POSIX, and therefore attacker-choosable.
        if "\n" in path or "\r" in path:
            return (False, None)

        process = self._batch()
        if process is None or process.stdin is None or process.stdout is None:
            return (False, None)

        try:
            process.stdin.write(f":{path}\n".encode())
            process.stdin.flush()
            header = process.stdout.readline()
            if not header:
                raise OSError("cat-file closed its output")
            fields = header.split()
            if len(fields) < 3 or fields[1] in {b"missing", b"ambiguous"}:
                return (True, None)
            size = int(fields[2])
            body: bytes = process.stdout.read(size)
            # The trailing newline git writes after every object. Consumed here
            # so the next reply starts where this one left off; leaving it makes
            # every later answer wrong rather than failing outright.
            process.stdout.read(1)
            if len(body) != size:
                raise OSError("short read from cat-file")
        except (OSError, ValueError, BrokenPipeError):
            self._close_batch()
            return (False, None)
        return (True, body)

    def _batch(self) -> subprocess.Popen[bytes] | None:
        if self._batch_process is not None:
            return self._batch_process
        if self._batch_failed:
            return None
        try:
            self._batch_process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                [self.binary(), *HARDENING, "cat-file", "--batch"],
                cwd=self.root,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={**os.environ, **GIT_ENVIRONMENT},
            )
        except (OSError, SourceError):
            self._batch_failed = True
            return None
        return self._batch_process

    def _close_batch(self) -> None:
        process, self._batch_process = self._batch_process, None
        self._batch_failed = True
        if process is None:
            return
        with contextlib.suppress(OSError):
            if process.stdin is not None:
                process.stdin.close()
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            process.terminate()
            process.wait(timeout=5)

    def close(self) -> None:
        """Release the batch process. Safe to call more than once."""
        self._close_batch()
        self._batch_failed = False

    def __del__(self) -> None:  # pragma: no cover - interpreter teardown
        with contextlib.suppress(Exception):
            self._close_batch()


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

    @property
    def yields_the_whole_walk(self) -> bool:
        """No. This source narrows the walker's output to a named set, so the
        inventory traversal and the scan traversal see different things and
        both have to run."""
        return False

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

    @property
    def yields_the_whole_walk(self) -> bool:
        """No. This source narrows the walker's output to a named set, so the
        inventory traversal and the scan traversal see different things and
        both have to run."""
        return False

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
