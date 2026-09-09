"""Scanner self-integrity and git hook installation.

A scanner that only looks for payloads is one `rm` away from looking for
nothing. This module is what makes deleting the guard harder than passing it.

Two mechanisms, and the second exists because the first has a hole.

**Hook shims in .git/hooks.** With ``core.hooksPath`` pointing at a tracked
directory, the active hooks are tracked files, so a single commit that deletes
them disables every commit-time check *for that very commit* -- and so does
checking out a branch where they are already gone, or merging one. The guard is
then exactly as deletable as the code it guards. So the shims are installed into
``.git/hooks``, which git does not track: no commit, branch switch, merge or
``git clean`` removes them. Each shim runs the scanner itself and **fails
closed** if the scanner is not on `PATH`, refusing the operation rather than
allowing it -- a guard that silently does nothing when it cannot run is not a
guard.

This used to say that each shim delegated to a reviewable tracked hook and
failed closed when that hook was missing. It does not: `SHIM_TEMPLATE` execs
the scanner directly, and there is no tracked hook in the design. The sentence
described an earlier shape and outlived it, which is the more dangerous kind of
wrong -- a reader was being told about a control that was not there.

**A hash manifest.** The shims can still be edited by somebody with local
access. The manifest records a hash of each guard file, and verification fails
on a mismatch.

The limit of the manifest must be stated plainly rather than glossed: an
attacker who edits a guard can regenerate the manifest in the same commit, and
no self-hosted check can prevent that. What the manifest guarantees is that such
a change *cannot be silent*. It must appear as a diff in a file whose only
purpose is to be reviewed. Code-owner rules and branch protection are what put a
human on that diff. Cordon ships the manifest and the verification; it cannot
ship the reviewer.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from cordon_scanner.core.errors import SourceError
from cordon_scanner.version import PROGRAM

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

MANIFEST_NAME = ".cordon-guard.sha256"
SHIM_MARKER = "cordon-guard-shim-v1"
HOOKS = ("pre-commit", "commit-msg", "pre-push")

SHIM_TEMPLATE = """\
#!/usr/bin/env sh
# {marker} -- installed by `{program} guard install`. Do not edit.
#
# Lives in .git/hooks, which git does not track, so no commit, branch switch,
# merge or `git clean` can remove it. It FAILS CLOSED: if {program} is not
# available the operation is refused rather than allowed, because a guard that
# silently does nothing when it cannot run is not a guard.
set -eu

if ! command -v {program} >/dev/null 2>&1; then
    echo "" >&2
    echo "{hook} BLOCKED: {program} is not installed, so the security scan could not run." >&2
    echo "Install it (pipx install cordon-scanner) or remove this hook deliberately." >&2
    exit 1
fi

exec {program} {command}
"""
"""The hook body.

`{program}` is substituted from `version.PROGRAM` rather than written in, so a
shim can never invoke a command that was not the one installed. Getting that
wrong does not degrade quietly: the shim fails closed, and every commit in the
repository is refused until somebody works out why."""

HOOK_COMMANDS = {
    # Staged mode reads the git index rather than the working tree. A hook that
    # reads from disk is defeated by staging a poisoned file and restoring the
    # clean one: it reports success while the poisoned blob goes into the commit.
    "pre-commit": "scan --staged --fail-on critical --quiet",
    # Deliberately redundant with pre-commit. Git runs the hooks it finds, so
    # removing one still leaves the other, and the scan treats a missing guard as
    # a finding, so the removal itself cannot be committed. The cost is one extra
    # scan per commit.
    "commit-msg": "scan --staged --fail-on critical --quiet",
    # The last check before code leaves the machine. Full tree, because a commit
    # made with --no-verify skipped everything above.
    "pre-push": "scan --fail-on high --quiet",
}


class GuardStatus:
    OK = "ok"
    MISSING = "missing"
    NOT_A_SHIM = "not_a_shim"
    NOT_EXECUTABLE = "not_executable"
    HOOKS_PATH_OVERRIDE = "hooks_path_override"
    MANIFEST_MISSING = "manifest_missing"
    TAMPERED = "tampered"
    NOT_A_REPOSITORY = "not_a_repository"


@dataclass(frozen=True, slots=True)
class GuardProblem:
    status: str
    detail: str
    remediation: str


@dataclass(frozen=True, slots=True)
class GuardReport:
    problems: tuple[GuardProblem, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.problems


class Guard:
    """Scanner self-integrity and git hook installation.

    A class because the pieces are one control and only work together: the
    shims are what git runs, the manifest is what makes an edit to them
    visible, and verification is what reads both. Any one of them alone is a
    control that looks present and does nothing, which is worse than no control
    at all, because it is believed.

    Every method is stateless and takes the repository root. There is no
    per-repository state worth holding, and a guard that caches what it saw is a
    guard that can be stale about whether it still exists.
    """

    @staticmethod
    def sha256_of(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _git_dir(root: Path) -> Path:
        """Locate the real .git directory, including for worktrees.

        In a linked worktree, `.git` is a file containing a `gitdir:` pointer rather
        than a directory. Ignoring that would install hooks into a path that does not
        exist and report success.
        """
        candidate = root / ".git"
        if candidate.is_dir():
            return candidate
        if candidate.is_file():
            text = candidate.read_text(encoding="utf-8", errors="replace").strip()
            if text.startswith("gitdir:"):
                pointer = Path(text.partition(":")[2].strip())
                resolved = pointer if pointer.is_absolute() else (root / pointer).resolve()
                # The pointer comes from a file inside the scan target, and
                # `install_hooks` writes three executable shims into
                # `<gitdir>/hooks`, creating parents. A `.git` file reading
                #
                #     gitdir: /Users/victim/.config/autostart
                #
                # therefore put attacker-named executables wherever it pointed.
                #
                # Requiring the target to actually be a git directory is what
                # distinguishes the linked worktree this branch exists for --
                # whose gitdir legitimately sits outside the worktree, under the
                # main repository's `.git/worktrees/` -- from an arbitrary path.
                # A directory holding `commondir`, or `HEAD` and `objects`, is
                # one git made.
                if Guard._is_git_directory(resolved):
                    return resolved
                raise SourceError(
                    f"{candidate} points at {resolved}, which is not a git directory",
                    hint=(
                        "A `.git` file must name the real git directory. Refusing it "
                        "here is what stops a `gitdir:` pointer being used to write "
                        "hook scripts outside the repository."
                    ),
                )
        raise SourceError(
            f"{root} is not a git repository",
            hint="Guard installation needs a repository, since it writes into .git/hooks.",
        )

    @classmethod
    def install_hooks(cls, root: str | Path, *, force: bool = False) -> list[str]:
        """Install the fail-closed shims. Safe to run repeatedly.

        Also clears ``core.hooksPath``. That setting points somewhere else and wins
        when set, so leaving it in place would mean the shims are installed and
        silently never run -- the worst of both outcomes, because the guard reads as
        present in review while doing nothing.
        """
        from cordon_scanner.sources.git import GitRepository

        repository = Path(root).resolve()
        git_dir = cls._git_dir(repository)
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)

        git = GitRepository(repository)
        # `harden=False`: see GitRepository.run. A hardened invocation would
        # return this process's own `-c core.hooksPath=` override instead of the
        # repository's value, and the whole point here is to read that value.
        configured = git.run(
            ["config", "--get", "core.hooksPath"], check=False, harden=False
        ).strip()
        if configured:
            git.run(["config", "--unset-all", "core.hooksPath"], check=False, harden=False)

        installed: list[str] = []
        # Hooks left alone because something else already owned them.
        preserved: list[str] = []
        for hook in HOOKS:
            target = hooks_dir / hook
            # A pre-existing hook that is not one of ours is preserved rather
            # than replaced. `install_hooks` used to overwrite whatever was
            # there -- a project's own `pre-commit`, `commit-msg` or `pre-push`
            # -- with no backup and no warning, which is a destructive act
            # performed silently by a tool whose argument is that silent acts
            # are the problem.
            if target.is_file():
                existing = target.read_text(encoding="utf-8", errors="replace")
                if SHIM_MARKER not in existing and not force:
                    backup = target.with_suffix(f"{target.suffix}.cordon-backup")
                    if not backup.exists():
                        backup.write_text(existing, encoding="utf-8")
                    preserved.append(hook)
                    continue
            target.write_text(
                SHIM_TEMPLATE.format(
                    marker=SHIM_MARKER,
                    hook=hook,
                    command=HOOK_COMMANDS[hook],
                    program=PROGRAM,
                ),
                encoding="utf-8",
            )
            target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            installed.append(hook)

        # The manifest is written as part of installation, not left as an
        # optional extra somebody might do later. That is what makes its absence
        # meaningful: previously it was legitimately missing on almost every
        # repository, so `verify` could not treat a deleted one as tampering --
        # and deleting it is the cheapest way to erase the record of an edit to
        # a guard, which is the manifest's whole purpose.
        if installed:
            cls.write_manifest(repository)

        if preserved:
            raise SourceError(
                f"{', '.join(preserved)} already exist and are not cordon shims; "
                f"a copy of each was saved alongside with a .cordon-backup suffix",
                hint=(
                    "Merge the check into your existing hook, or pass --force to "
                    "replace it. Overwriting somebody's hook silently is how a tool "
                    "breaks a workflow nobody can trace back to it."
                ),
            )

        return installed

    @classmethod
    def write_manifest(cls, root: str | Path, files: Sequence[str] | None = None) -> Path:
        """Record hashes of the guard files.

        The manifest is committed. Its only purpose is to be reviewed, which is what
        makes an edit to a guard visible even though it cannot be prevented.
        """
        repository = Path(root).resolve()
        targets = list(files) if files else cls._default_guard_files(repository)

        lines = [
            f"# Cordon guard manifest. Regenerate with: {PROGRAM} guard update",
            "#",
            "# A change here must be reviewed as carefully as a change to the guards",
            "# themselves. An attacker who edits a guard can regenerate this file in the",
            "# same commit, and no self-hosted check can prevent that. What this file",
            "# guarantees is that such a change cannot be silent: it must appear as a",
            "# diff. Code-owner rules on this path are what put a human on that diff.",
        ]
        for relative in sorted(targets):
            path = repository / relative
            if path.is_file():
                lines.append(f"{Guard.sha256_of(path)}  {relative}")

        manifest = repository / MANIFEST_NAME
        manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return manifest

    @staticmethod
    def _default_guard_files(root: Path) -> list[str]:
        """Files whose integrity the guard rests on."""
        # Derived from CONFIG_FILENAMES rather than restated. The list had
        # `cordon.yaml` and `.cordon.yaml` but not `cordon.yml` or
        # `.cordon.yml`, two of the four names config discovery accepts -- so a
        # repository using either got a manifest that did not cover its
        # configuration while `guard verify` reported the guard intact.
        from cordon_scanner.core.config import CONFIG_FILENAMES

        candidates = [
            *CONFIG_FILENAMES,
            ".pre-commit-config.yaml",
            ".github/workflows/security.yml",
            ".github/workflows/cordon.yml",
        ]
        return [name for name in candidates if (root / name).is_file()]

    @classmethod
    def verify(cls, root: str | Path) -> GuardReport:
        """Check that the guard is intact.

        Every failure names what to do about it. A verification that says something
        is wrong without saying what to do gets disabled rather than fixed.
        """
        repository = Path(root).resolve()
        problems: list[GuardProblem] = []

        try:
            git_dir = cls._git_dir(repository)
        except SourceError as exc:
            return GuardReport(
                (
                    GuardProblem(
                        GuardStatus.NOT_A_REPOSITORY,
                        str(exc),
                        "Run this inside a git repository, or skip guard verification.",
                    ),
                )
            )

        problems.extend(cls._check_hooks_path(repository))
        problems.extend(cls._check_shims(git_dir))
        problems.extend(cls._check_manifest(repository))

        return GuardReport(tuple(problems))

    @staticmethod
    def _check_hooks_path(repository: Path) -> Iterable[GuardProblem]:
        """core.hooksPath overrides .git/hooks and wins when set.

        Setting it is the cheapest way to disable every installed shim while leaving
        them on disk, so the guard looks present and does nothing.
        """
        from cordon_scanner.sources.git import GitRepository

        try:
            configured = (
                GitRepository(repository)
                .run(["config", "--get", "core.hooksPath"], check=False, harden=False)
                .strip()
            )
        except SourceError:
            return

        if configured:
            yield GuardProblem(
                GuardStatus.HOOKS_PATH_OVERRIDE,
                f"core.hooksPath is set to {configured!r}, which overrides the installed hooks",
                f"Run `{PROGRAM} guard install`, which clears it.",
            )

    @staticmethod
    def _is_git_directory(path: Path) -> bool:
        """Whether this path is a directory git itself created.

        A linked worktree's gitdir carries `commondir`; a main repository's
        carries `HEAD` and an `objects` directory. Anything else is a path
        somebody wrote into a `.git` file.
        """
        if not path.is_dir():
            return False
        if (path / "commondir").is_file():
            return True
        return (path / "HEAD").is_file() and (path / "objects").is_dir()

    @staticmethod
    def honours_executable_bit() -> bool:
        """Whether this platform has an executable bit worth checking.

        A method rather than an inline `os.name` test so the Windows branch is
        reachable from a test on any machine. A platform-specific branch that
        only executes on that platform's CI is a branch nobody reads until it
        breaks there.
        """
        return os.name != "nt"

    @classmethod
    def _check_shims(cls, git_dir: Path) -> Iterable[GuardProblem]:
        hooks_dir = git_dir / "hooks"
        for hook in HOOKS:
            path = hooks_dir / hook

            if not path.is_file():
                yield GuardProblem(
                    GuardStatus.MISSING,
                    f".git/hooks/{hook} is not installed, so git is not running the guard",
                    f"Run `{PROGRAM} guard install`.",
                )
                continue

            content = path.read_text(encoding="utf-8", errors="replace")
            if SHIM_MARKER not in content:
                yield GuardProblem(
                    GuardStatus.NOT_A_SHIM,
                    f".git/hooks/{hook} exists but is not the cordon shim",
                    f"Merge the check into your existing hook, or run `{PROGRAM} guard install`.",
                )
                continue

            # A hook without the executable bit is a hook git silently never
            # runs -- on platforms that have one. Windows does not: the bit
            # cannot be set, `stat` never reports it, and Git for Windows runs
            # hooks through its bundled shell regardless.
            #
            # Checking it there made `cordon-scanner guard verify` fail on every Windows
            # machine with a correctly installed guard. That is worse than not
            # checking: a verification that always fails is one people learn to
            # ignore, and then it is not a control on any platform.
            if cls.honours_executable_bit() and not path.stat().st_mode & stat.S_IXUSR:
                yield GuardProblem(
                    GuardStatus.NOT_EXECUTABLE,
                    f".git/hooks/{hook} is not executable, so git will not run it",
                    f"chmod +x {path}",
                )

    @staticmethod
    def _check_manifest(repository: Path) -> Iterable[GuardProblem]:
        manifest = repository / MANIFEST_NAME
        if not manifest.is_file():
            # Absence is not a failure *if the guard was never set up*. Most
            # repositories will never create a manifest, and reporting a missing
            # optional control is how a report becomes noise.
            #
            # But if the shims are installed, the manifest is part of the guard,
            # and deleting it is the cheapest way to erase the record of an edit
            # to one. That is worth saying, at LOW: the manifest's whole purpose
            # is to make an edit visible, and it cannot do that from a repository
            # it is no longer in.
            hooks = repository / ".git" / "hooks"
            if any(
                (hooks / hook).is_file()
                and SHIM_MARKER in (hooks / hook).read_text(encoding="utf-8", errors="replace")
                for hook in HOOKS
            ):
                yield GuardProblem(
                    GuardStatus.TAMPERED,
                    f"{MANIFEST_NAME} is absent while the hooks are installed",
                    f"Run `{PROGRAM} guard update` to regenerate it, or remove the "
                    f"hooks if the guard is no longer wanted.",
                )
            return

        for line in manifest.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            expected, _, relative = stripped.partition("  ")
            if not relative:
                continue

            path = repository / relative
            # Contained, and a regular file. The manifest is committed by
            # whoever controls the repository, so an entry of
            # `../../../../etc/shadow` turned `guard verify` into a hash-match
            # oracle over arbitrary files, and a listed FIFO hung it
            # indefinitely.
            try:
                resolved = path.resolve()
            except OSError:
                continue
            if not resolved.is_relative_to(repository):
                yield GuardProblem(
                    GuardStatus.TAMPERED,
                    f"{relative} points outside the repository",
                    "Remove the entry. A manifest describes files in this repository.",
                )
                continue
            if path.is_symlink() or (path.exists() and not path.is_file()):
                yield GuardProblem(
                    GuardStatus.TAMPERED,
                    f"{relative} is not a regular file",
                    "Remove the entry, or replace the path with a regular file.",
                )
                continue
            if not path.is_file():
                yield GuardProblem(
                    GuardStatus.TAMPERED,
                    f"{relative} is listed in the manifest but is absent",
                    f"Restore the file, or run `{PROGRAM} guard update` if the removal was intended.",
                )
                continue

            actual = Guard.sha256_of(path)
            if actual != expected:
                yield GuardProblem(
                    GuardStatus.TAMPERED,
                    f"{relative} does not match the manifest "
                    f"(expected {expected[:16]}..., found {actual[:16]}...)",
                    f"If the change is intentional, run `{PROGRAM} guard update` and have the "
                    "manifest diff reviewed alongside it.",
                )


__all__ = [
    "HOOKS",
    "MANIFEST_NAME",
    "SHIM_MARKER",
    "Guard",
    "GuardProblem",
    "GuardReport",
    "GuardStatus",
]
