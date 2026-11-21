"""uv, resolved by uv with building switched off, then pinned by hash for pip to pick this machine's files.

    uv pip install ...        `uv pip compile --no-build --generate-hashes` of what was asked
    uv add|remove ...         `uv add|remove --no-sync --no-build` in a private copy of the project
    uv sync|lock|run ...      `uv lock --no-build` in a private copy (skipped under --frozen)

`--no-build` keeps uv from running any package's build backend to learn its metadata (wheels and
static `pyproject.toml` metadata only). The pinned, hashed requirements then go to pip's resolver for
this interpreter (`python_env.TargetPython`), whose report names one file per package; Cordon fetches,
verifies and scans those. The install is `uv pip install --no-index --find-links <scanned>
--require-hashes --no-deps`, then, for a project, `uv sync --frozen --offline` for the project itself
(the person's own code), which finds every dependency already installed.

A requirement that only an sdist satisfies is refused with its name (uv has no way to allow one
scanned build and forbid the rest): Cordon's pip, run inside the environment, handles it.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.pip import PipHooks, PipPlanner, PipRequest
from cordon_scanner.sources.install.plan import (
    InstallPlan,
    InstallRefused,
    PrivateDirectory,
    Runner,
)
from cordon_scanner.sources.install.python_env import ProjectFiles, TargetPython
from cordon_scanner.version import PROGRAM

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.sources.install.registries import InstallRegistries


@dataclass
class UvPlan:
    plan: InstallPlan
    target: TargetPython
    #: Pinned, hashed requirements of the registry files (what `--require-hashes` installs).
    requirements: str
    local: list[str] = field(default_factory=list)
    editable: list[str] = field(default_factory=list)


class UvPlanner:
    PROJECT_VERBS: ClassVar[frozenset[str]] = frozenset({"add", "remove", "sync", "lock", "run"})
    #: `uv pip <verb>` that installs.
    PIP_VERBS: ClassVar[frozenset[str]] = frozenset({"install", "sync"})
    COPIED: ClassVar[tuple[str, ...]] = ("pyproject.toml", "uv.lock", ".python-version", "uv.toml")
    #: `uv export` options that choose what is installed, passed through from the person's command.
    EXPORT_FLAGS: ClassVar[frozenset[str]] = frozenset(
        {"--all-extras", "--no-dev", "--only-dev", "--all-groups", "--no-default-groups"}
    )
    EXPORT_VALUED: ClassVar[frozenset[str]] = frozenset(
        {"--extra", "--group", "--only-group", "--no-group", "--package"}
    )

    @classmethod
    def pip_install(
        cls,
        args: Sequence[str],
        runner: Runner,
        uv: str,
        hooks: PipHooks,
        registries: InstallRegistries,
        cwd: Path,
    ) -> UvPlan:
        rest, local, editable = PipPlanner.split_local(args, cwd)
        target = cls.target(runner, uv, cwd, cls._python_flag(rest))
        requires: set[str] = set()
        for path in [*local, *editable]:
            requires.update(hooks.scan_local(Path(path)))
        with PrivateDirectory.made("cordon-uv-") as scratch:
            source = scratch / "requested.in"
            source.write_text(
                "".join(f"{a}\n" for a in cls._specs(rest))
                + "".join(f"{p}\n" for p in local)
                + "".join(f"-e {p}\n" for p in editable),
                encoding="utf-8",
            )
            files = [str(source), *cls._requirement_files(rest, cwd)]
            compiled = cls._run(
                runner,
                [
                    uv,
                    "pip",
                    "compile",
                    "--no-build",
                    "--generate-hashes",
                    "--quiet",
                    "--python",
                    target.executable,
                    *files,
                ],
                scratch,
                "uv could not resolve the install without building",
            )
        uv_plan = cls._pinned(cls._registry_lines(compiled), target, runner, hooks, registries, cwd)
        if requires:
            uv_plan.plan.files += [
                f for f in hooks.build_tools(tuple(sorted(requires))) if f not in uv_plan.plan.files
            ]
        uv_plan.local, uv_plan.editable = local, editable
        uv_plan.plan.local = [Path(p) for p in [*local, *editable]]
        return uv_plan

    @classmethod
    def project(
        cls,
        verb: str,
        args: Sequence[str],
        runner: Runner,
        uv: str,
        hooks: PipHooks,
        registries: InstallRegistries,
        project: Path,
    ) -> UvPlan:
        frozen = "--frozen" in args
        with PrivateDirectory.made("cordon-uv-") as scratch:
            PrivateDirectory.copy(project, scratch, [*cls.COPIED, *cls.members(project)])
            if not (scratch / "pyproject.toml").is_file():
                raise InstallRefused("no pyproject.toml here: `uv` has no project to install")
            if verb in {"add", "remove"}:
                cls._run(
                    runner,
                    [uv, verb, *cls._own(args), "--no-sync", "--no-build"],
                    scratch,
                    f"uv could not {verb} without building",
                )
            elif not frozen:
                lock = [uv, "lock", "--no-build", *(["--locked"] if "--locked" in args else [])]
                cls._run(runner, lock, scratch, "uv could not lock without building")
            exported = cls._run(
                runner,
                [
                    uv,
                    "export",
                    "--frozen",
                    "--format",
                    "requirements.txt",
                    "--quiet",
                    "--no-emit-project",
                    "--no-emit-workspace",
                    "--no-emit-local",
                    *cls._export_flags(args),
                ],
                scratch,
                "uv could not export the lock",
            )
            manifests = {
                name: (scratch / name).read_bytes()
                for name in ("pyproject.toml", "uv.lock")
                if (scratch / name).is_file()
            }
        target = cls.target(runner, uv, project, cls._python_flag(args))
        uv_plan = cls._pinned(exported, target, runner, hooks, registries, project)
        uv_plan.plan.manifests = manifests
        return uv_plan

    @classmethod
    def _pinned(
        cls,
        requirements: str,
        target: TargetPython,
        runner: Runner,
        hooks: PipHooks,
        registries: InstallRegistries,
        cwd: Path,
    ) -> UvPlan:
        with PrivateDirectory.made("cordon-uv-") as scratch:
            pinned = scratch / "pinned.txt"
            pinned.write_text(requirements, encoding="utf-8")
            request = PipRequest(
                TargetPython.resolver(runner, cwd), ["--no-deps", "-r", str(pinned)], target.flags()
            )
            plan = PipPlanner.plan(request, runner, hooks, registries)
        return UvPlan(plan, target, requirements)

    @staticmethod
    def _run(runner: Runner, argv: list[str], cwd: Path, failure: str) -> str:
        done = runner(argv, cwd, {**os.environ, "UV_NO_PROGRESS": "1"})
        if done.returncode != 0:
            detail = (done.stderr or done.stdout or "").strip()[-2000:]
            hint = f" (a package with no wheel needs `{PROGRAM} pip install` in the environment)"
            raise InstallRefused(f"{failure}{hint if 'no-build' in detail else ''}:\n{detail}")
        return done.stdout or ""

    @staticmethod
    def target(runner: Runner, uv: str, cwd: Path, python: str | None) -> TargetPython:
        """The interpreter uv would install into: `--python`, else the active or project venv."""
        argv = [uv, "python", "find", *([python] if python else [])]
        done = runner(argv, cwd, {**os.environ})
        found = (done.stdout or "").strip().splitlines()
        if done.returncode != 0 or not found:
            raise InstallRefused("uv found no Python environment to install into")
        return TargetPython.of(found[-1], runner, cwd)

    @staticmethod
    def _python_flag(args: Sequence[str]) -> str | None:
        for i, arg in enumerate(args):
            if arg.startswith("--python="):
                return arg.split("=", 1)[1]
            if arg in {"--python", "-p"} and i + 1 < len(args):
                return args[i + 1]
        return None

    @staticmethod
    def _specs(args: Sequence[str]) -> list[str]:
        """The requirement specifiers among `uv pip install` arguments (options dropped)."""
        out, skip = [], False
        for arg in args:
            if skip:
                skip = False
            elif arg in {"-r", "--requirement", "-c", "--constraint", "--python", "-p", "--target"}:
                skip = True
            elif not arg.startswith("-"):
                out.append(arg)
        return out

    @staticmethod
    def _requirement_files(args: Sequence[str], cwd: Path) -> list[str]:
        out = []
        for i, arg in enumerate(args):
            if arg in {"-r", "--requirement"} and i + 1 < len(args):
                out.append(str((cwd / args[i + 1]).resolve()))
        return out

    @staticmethod
    def _registry_lines(compiled: str) -> str:
        """`uv pip compile` output without its local entries (`-e`, `file://`), which are built from
        disk after they were scanned."""
        lines, keep = [], True
        for line in compiled.splitlines():
            if not line.startswith((" ", "\t", "#")):
                keep = not (line.startswith(("-e ", "/")) or "file://" in line)
            if keep:
                lines.append(line)
        return "\n".join(lines) + "\n"

    @classmethod
    def _own(cls, args: Sequence[str]) -> list[str]:
        """The person's arguments to `uv add|remove`, without the ones Cordon sets itself."""
        return [a for a in args if a not in {"--no-sync", "--no-build", "--frozen"}]

    @classmethod
    def _export_flags(cls, args: Sequence[str]) -> list[str]:
        out: list[str] = []
        it = iter(args)
        for arg in it:
            name = arg.split("=", 1)[0]
            if arg in cls.EXPORT_FLAGS:
                out.append(arg)
            elif name in cls.EXPORT_VALUED:
                out.append(arg if "=" in arg else f"{arg}={next(it, '')}")
        return out

    @staticmethod
    def members(project: Path) -> list[str]:
        manifest = project / "pyproject.toml"
        if not manifest.is_file():
            return []
        try:
            document = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise InstallRefused("pyproject.toml could not be read") from exc
        workspace = document.get("tool", {}).get("uv", {}).get("workspace", {})
        return ProjectFiles.members(project, workspace.get("members") or [])


__all__ = ["UvPlan", "UvPlanner"]
