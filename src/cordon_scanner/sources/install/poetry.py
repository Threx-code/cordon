"""poetry, locked in a private copy of the project, then installed from scanned files pinned by hash.

    poetry add|remove ...     `poetry add|remove --lock` in the copy (the lock changes, nothing installs)
    poetry install|sync       `poetry lock` in the copy unless poetry.lock is already current
    poetry update ...         `poetry update --lock` in the copy

Before poetry locks anything new, what it would add is resolved by pip wheel-only: poetry reads a
package's metadata from the index, and only builds an sdist when the index has none, so a closure with
a wheel for every package is one poetry locks without running any of it. A requirement only an sdist
satisfies is refused with its name. poetry.lock lists every file's sha256; pip, in poetry's own
environment, picks this machine's file among those hashes; Cordon fetches, verifies and scans it, and
installs with that environment's pip (`--no-index --find-links --require-hashes --no-deps`), then
`poetry install --only-root` installs the project itself (the person's own code).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.pip import PipHooks, PipPlanner, PipRequest
from cordon_scanner.sources.install.plan import (
    InstallPlan,
    InstallRefused,
    PrivateDirectory,
    Runner,
)
from cordon_scanner.sources.install.python_env import HashedRequirements, TargetPython

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.sources.install.registries import InstallRegistries


@dataclass
class PoetryPlan:
    plan: InstallPlan
    #: poetry's environment interpreter, whose pip installs the scanned files.
    python: str
    requirements: str


class PoetryPlanner:
    VERBS: ClassVar[frozenset[str]] = frozenset({"add", "remove", "install", "sync", "update"})
    COPIED: ClassVar[tuple[str, ...]] = ("pyproject.toml", "poetry.lock", "poetry.toml")

    @classmethod
    def plan(
        cls,
        verb: str,
        args: Sequence[str],
        runner: Runner,
        poetry: str,
        hooks: PipHooks,
        registries: InstallRegistries,
        project: Path,
    ) -> PoetryPlan:
        python = cls.environment(runner, poetry, project)
        if verb == "add":
            specs = [a for a in args if not a.startswith("-")]
            cls._precheck(specs, runner, hooks, registries, project, python)
        with PrivateDirectory.made("cordon-poetry-") as scratch:
            PrivateDirectory.copy(project, scratch, cls.COPIED)
            if not (scratch / "pyproject.toml").is_file():
                raise InstallRefused("no pyproject.toml here: poetry has no project to install")
            cls._lock(verb, args, runner, poetry, scratch)
            lock = scratch / "poetry.lock"
            if not lock.is_file():
                raise InstallRefused("poetry resolved but wrote no poetry.lock")
            requirements = HashedRequirements.from_poetry(lock.read_text(encoding="utf-8"))
            manifests = {
                name: (scratch / name).read_bytes()
                for name in ("pyproject.toml", "poetry.lock")
                if (scratch / name).is_file()
            }
            pinned = scratch / "pinned.txt"
            request = PipRequest(
                [python, "-m", "pip"], HashedRequirements.write(requirements, pinned)
            )
            plan = PipPlanner.plan(request, runner, hooks, registries)
        plan.manifests = manifests
        return PoetryPlan(plan, python, requirements)

    @staticmethod
    def environment(runner: Runner, poetry: str, project: Path) -> str:
        """poetry's virtual environment for this project (created by poetry if it has none yet:
        an empty environment, no package code)."""
        done = runner([poetry, "env", "info", "--executable"], project, {**os.environ})
        found = (done.stdout or "").strip().splitlines()
        if done.returncode == 0 and found and found[-1].strip() not in {"", "NA"}:
            return found[-1].strip()
        made = runner([poetry, "env", "use", "python3"], project, {**os.environ})
        done = runner([poetry, "env", "info", "--executable"], project, {**os.environ})
        found = (done.stdout or "").strip().splitlines()
        if made.returncode != 0 or done.returncode != 0 or not found:
            raise InstallRefused(
                "poetry has no environment for this project and could not make one"
            )
        return found[-1].strip()

    @classmethod
    def _lock(
        cls, verb: str, args: Sequence[str], runner: Runner, poetry: str, scratch: Path
    ) -> None:
        env = {**os.environ, "POETRY_NO_INTERACTION": "1"}
        if verb in {"add", "remove", "update"}:
            argv = [poetry, verb, *[a for a in args if a != "--lock"], "--lock"]
        else:
            current = runner([poetry, "check", "--lock"], scratch, env)
            if current.returncode == 0 and (scratch / "poetry.lock").is_file():
                return
            argv = [poetry, "lock"]
        done = runner(argv, scratch, env)
        if done.returncode != 0:
            raise InstallRefused(
                f"poetry could not lock the install:\n{(done.stderr or done.stdout).strip()[-2000:]}"
            )

    @staticmethod
    def _precheck(
        specs: list[str],
        runner: Runner,
        hooks: PipHooks,
        registries: InstallRegistries,
        project: Path,
        python: str,
    ) -> None:
        """What `poetry add` would bring in, resolved wheel-only first: refused (with the name) when
        an sdist is the only way to it, before poetry could build it to read its metadata."""
        refuse = PipHooks(PoetryPlanner._no_sdist, hooks.scan_local, hooks.build_tools)
        wanted = [PoetryPlanner.as_pip(s) for s in specs if s]
        if wanted:
            target = TargetPython.of(python, runner, project)
            request = PipRequest(TargetPython.resolver(runner, project), wanted, target.flags())
            PipPlanner.plan(request, runner, refuse, registries)

    @staticmethod
    def _no_sdist(name: str, _version: str) -> tuple[str, tuple[str, ...]]:
        raise InstallRefused(
            f"{name} has no wheel: poetry would build it to read its metadata",
            hint=f"Install {name} through Cordon's pip in poetry's environment first.",
        )

    @staticmethod
    def as_pip(spec: str) -> str:
        """`name@1.2.3` -> `name==1.2.3`; a range (`@^1.2`, `@~1.2`, `@>=1`) -> `name`: the
        check only asks whether the closure has wheels, and the latest is what a range would pick."""
        name, at, version = spec.partition("@")
        if at and version and version[0].isdigit():
            return f"{name}=={version}"
        return name


__all__ = ["PoetryPlan", "PoetryPlanner"]
