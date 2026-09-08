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
``git clean`` removes them. Each shim delegates to the reviewable tracked hook
and **fails closed** if that hook is missing, which turns deleting the tracked
hooks from a bypass into a blocker.

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
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from cordon.core.errors import SourceError

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

MANIFEST_NAME = ".cordon-guard.sha256"
SHIM_MARKER = "cordon-guard-shim-v1"
HOOKS = ("pre-commit", "commit-msg", "pre-push")

SHIM_TEMPLATE = """\
#!/usr/bin/env sh
# {marker} -- installed by `cordon guard install`. Do not edit.
#
# Lives in .git/hooks, which git does not track, so no commit, branch switch,
# merge or `git clean` can remove it. It FAILS CLOSED: if cordon is not
# available the operation is refused rather than allowed, because a guard that
# silently does nothing when it cannot run is not a guard.
set -eu

if ! command -v cordon >/dev/null 2>&1; then
    echo "" >&2
    echo "{hook} BLOCKED: cordon is not installed, so the security scan could not run." >&2
    echo "Install it (pipx install cordon-scanner) or remove this hook deliberately." >&2
    exit 1
fi

exec cordon {command}
"""

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


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
            return pointer if pointer.is_absolute() else (root / pointer).resolve()
    raise SourceError(
        f"{root} is not a git repository",
        hint="Guard installation needs a repository, since it writes into .git/hooks.",
    )


def install_hooks(root: str | Path) -> list[str]:
    """Install the fail-closed shims. Safe to run repeatedly.

    Also clears ``core.hooksPath``. That setting points somewhere else and wins
    when set, so leaving it in place would mean the shims are installed and
    silently never run -- the worst of both outcomes, because the guard reads as
    present in review while doing nothing.
    """
    from cordon.sources import git as git_source

    repository = Path(root).resolve()
    git_dir = _git_dir(repository)
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    configured = git_source._git(
        ["config", "--get", "core.hooksPath"], repository, check=False
    ).strip()
    if configured:
        git_source._git(["config", "--unset-all", "core.hooksPath"], repository, check=False)

    installed: list[str] = []
    for hook in HOOKS:
        target = hooks_dir / hook
        target.write_text(
            SHIM_TEMPLATE.format(
                marker=SHIM_MARKER, hook=hook, command=HOOK_COMMANDS[hook]
            ),
            encoding="utf-8",
        )
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        installed.append(hook)

    return installed


def write_manifest(root: str | Path, files: Sequence[str] | None = None) -> Path:
    """Record hashes of the guard files.

    The manifest is committed. Its only purpose is to be reviewed, which is what
    makes an edit to a guard visible even though it cannot be prevented.
    """
    repository = Path(root).resolve()
    targets = list(files) if files else _default_guard_files(repository)

    lines = [
        "# Cordon guard manifest. Regenerate with: cordon guard update",
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
            lines.append(f"{sha256_of(path)}  {relative}")

    manifest = repository / MANIFEST_NAME
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest


def _default_guard_files(root: Path) -> list[str]:
    """Files whose integrity the guard rests on."""
    candidates = [
        "cordon.yaml",
        ".cordon.yaml",
        ".pre-commit-config.yaml",
        ".github/workflows/security.yml",
        ".github/workflows/cordon.yml",
    ]
    return [name for name in candidates if (root / name).is_file()]


def verify(root: str | Path) -> GuardReport:
    """Check that the guard is intact.

    Every failure names what to do about it. A verification that says something
    is wrong without saying what to do gets disabled rather than fixed.
    """
    repository = Path(root).resolve()
    problems: list[GuardProblem] = []

    try:
        git_dir = _git_dir(repository)
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

    problems.extend(_check_hooks_path(repository))
    problems.extend(_check_shims(git_dir))
    problems.extend(_check_manifest(repository))

    return GuardReport(tuple(problems))


def _check_hooks_path(repository: Path) -> Iterable[GuardProblem]:
    """core.hooksPath overrides .git/hooks and wins when set.

    Setting it is the cheapest way to disable every installed shim while leaving
    them on disk, so the guard looks present and does nothing.
    """
    from cordon.sources import git as git_source

    try:
        configured = git_source._git(
            ["config", "--get", "core.hooksPath"], repository, check=False
        ).strip()
    except SourceError:
        return

    if configured:
        yield GuardProblem(
            GuardStatus.HOOKS_PATH_OVERRIDE,
            f"core.hooksPath is set to {configured!r}, which overrides the installed hooks",
            "Run `cordon guard install`, which clears it.",
        )


def _check_shims(git_dir: Path) -> Iterable[GuardProblem]:
    hooks_dir = git_dir / "hooks"
    for hook in HOOKS:
        path = hooks_dir / hook

        if not path.is_file():
            yield GuardProblem(
                GuardStatus.MISSING,
                f".git/hooks/{hook} is not installed, so git is not running the guard",
                "Run `cordon guard install`.",
            )
            continue

        content = path.read_text(encoding="utf-8", errors="replace")
        if SHIM_MARKER not in content:
            yield GuardProblem(
                GuardStatus.NOT_A_SHIM,
                f".git/hooks/{hook} exists but is not the cordon shim",
                "Merge the check into your existing hook, or run `cordon guard install`.",
            )
            continue

        # A hook without the executable bit is a hook git silently never runs.
        if not path.stat().st_mode & stat.S_IXUSR:
            yield GuardProblem(
                GuardStatus.NOT_EXECUTABLE,
                f".git/hooks/{hook} is not executable, so git will not run it",
                f"chmod +x {path}",
            )


def _check_manifest(repository: Path) -> Iterable[GuardProblem]:
    manifest = repository / MANIFEST_NAME
    if not manifest.is_file():
        # Absence is not a failure. Most repositories will never create one, and
        # reporting a missing optional control as a problem is how a report
        # becomes noise.
        return

    for line in manifest.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        expected, _, relative = stripped.partition("  ")
        if not relative:
            continue

        path = repository / relative
        if not path.is_file():
            yield GuardProblem(
                GuardStatus.TAMPERED,
                f"{relative} is listed in the manifest but is absent",
                "Restore the file, or run `cordon guard update` if the removal was intended.",
            )
            continue

        actual = sha256_of(path)
        if actual != expected:
            yield GuardProblem(
                GuardStatus.TAMPERED,
                f"{relative} does not match the manifest "
                f"(expected {expected[:16]}..., found {actual[:16]}...)",
                "If the change is intentional, run `cordon guard update` and have the "
                "manifest diff reviewed alongside it.",
            )


__all__ = [
    "HOOKS",
    "MANIFEST_NAME",
    "SHIM_MARKER",
    "GuardProblem",
    "GuardReport",
    "GuardStatus",
    "install_hooks",
    "sha256_of",
    "verify",
    "write_manifest",
]
