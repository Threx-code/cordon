"""pip, uv and poetry through Cordon: resolved without a build, scanned, then installed from the
scanned files alone (`--no-index --find-links <scanned> --require-hashes --no-deps`)."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.version import PROGRAM

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.cli.commands.install.context import InstallContext
    from cordon_scanner.sources.install.pip import PipHooks
    from cordon_scanner.sources.install.plan import InstallPlan, PackageFile


class PythonTools:
    PIP_INSTALLS: ClassVar[frozenset[str]] = frozenset({"install"})
    #: pip options that say where or how to install, kept for the pinned install; everything else
    #: (indexes, requirement files, constraints) only shapes the resolve.
    PIP_KEEP_FLAGS: ClassVar[frozenset[str]] = frozenset(
        {
            "--user",
            "--break-system-packages",
            "-q",
            "--quiet",
            "-v",
            "--verbose",
            "--force-reinstall",
        }
    )
    PIP_KEEP_VALUED: ClassVar[frozenset[str]] = frozenset({"-t", "--target", "--prefix", "--root"})

    @classmethod
    def pip_installs(cls, args: list[str]) -> bool:
        return bool(args) and args[0] in cls.PIP_INSTALLS

    @staticmethod
    def uv_installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.uv import UvPlanner

        if args[:1] == ["pip"]:
            return args[1:2] != [] and args[1] in UvPlanner.PIP_VERBS
        if args[:2] == ["tool", "install"]:
            return True
        return bool(args) and args[0] in UvPlanner.PROJECT_VERBS

    @staticmethod
    def poetry_installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.poetry import PoetryPlanner

        return bool(args) and args[0] in PoetryPlanner.VERBS

    # -- pip -----------------------------------------------------------------------------------

    @classmethod
    def pip(cls, pip: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.pip import PipPlanner, PipRequest
        from cordon_scanner.sources.install.plan import PrivateDirectory, Subprocesses

        cwd = Path.cwd()
        rest, local, editable = PipPlanner.split_local(args[1:], cwd)
        request = PipRequest([pip], rest, local=local, editable=editable)
        plan = PipPlanner.plan(
            request, Subprocesses.run, cls.hooks([pip], context), context.registries
        )
        keep = cls.pip_keep(rest)
        with PrivateDirectory.made("cordon-install-") as scratch:
            verdict = context.check(plan, scratch)
            if not verdict.ok:
                return context.blocked(verdict)
            if not plan.files and not plan.local:
                print(f"{PROGRAM}: nothing to install", file=sys.stderr)
                return 0
            base = [pip, "install", "--no-index", "--find-links", str(scratch)]
            return cls._pinned_then_local(base, keep, plan, scratch, local, editable, context)

    @classmethod
    def _pinned_then_local(
        cls,
        base: list[str],
        keep: list[str],
        plan: InstallPlan,
        scratch: Path,
        local: Sequence[str],
        editable: Sequence[str],
        context: InstallContext,
    ) -> int:
        installed = [f for f in plan.files if not f.build_only]
        if installed:
            requirements = cls.requirements(installed, scratch / "cordon-requirements.txt")
            code = context.run(
                [*base, "--require-hashes", "--no-deps", "-r", str(requirements), *keep]
            )
            if code != 0:
                return code
        from cordon_scanner.cli.commands.install.python_hooks import BuildRetry

        retry = BuildRetry(cls.hooks([base[0]], context), context, scratch)
        for target in [[path] for path in local] + [["-e", path] for path in editable]:
            code = retry.run([*base, "--no-deps", *keep, *target])
            if code != 0:
                return code
        return 0

    @staticmethod
    def requirements(files: Sequence[PackageFile], at: Path) -> Path:
        at.write_text(
            "".join(f"{f.name}=={f.version} --hash=sha256:{f.digest.hex()}\n" for f in files),
            encoding="utf-8",
        )
        return at

    @classmethod
    def pip_keep(cls, args: Sequence[str]) -> list[str]:
        kept: list[str] = []
        it = iter(args)
        for arg in it:
            flag = arg.split("=", 1)[0]
            if arg in cls.PIP_KEEP_FLAGS:
                kept.append(arg)
            elif flag in cls.PIP_KEEP_VALUED:
                kept.append(arg if "=" in arg else f"{arg}={next(it, '')}")
        return kept

    @classmethod
    def hooks(cls, pip: list[str], context: InstallContext) -> PipHooks:
        """The planner's callbacks: each fetches and scans before pip may build or read anything."""
        from cordon_scanner.cli.commands.install.python_hooks import PythonHooks

        return PythonHooks(pip, context).hooks()

    # -- uv ------------------------------------------------------------------------------------

    @classmethod
    def uv(cls, uv: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.cli.commands.install.uv_install import UvInstall
        from cordon_scanner.sources.install.plan import Subprocesses
        from cordon_scanner.sources.install.python_env import TargetPython

        pip = TargetPython.resolver(Subprocesses.run, Path.cwd())
        return UvInstall(uv, context, cls.hooks(pip, context)).run(args)

    # -- poetry --------------------------------------------------------------------------------

    @classmethod
    def poetry(cls, poetry: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.plan import PrivateDirectory, Subprocesses
        from cordon_scanner.sources.install.poetry import PoetryPlanner
        from cordon_scanner.sources.install.python_env import HashedRequirements

        project = Path.cwd()
        python = PoetryPlanner.environment(Subprocesses.run, poetry, project)
        planned = PoetryPlanner.plan(
            args[0],
            args[1:],
            Subprocesses.run,
            poetry,
            cls.hooks([python, "-m", "pip"], context),
            context.registries,
            project,
        )
        with PrivateDirectory.made("cordon-install-") as scratch:
            verdict = context.check(planned.plan, scratch)
            if not verdict.ok:
                return context.blocked(verdict)
            context.write(project, planned.plan)
            pinned = scratch / "cordon-requirements.txt"
            code = context.run(
                [
                    python,
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    "--find-links",
                    str(scratch),
                    "--require-hashes",
                    *HashedRequirements.write(planned.requirements, pinned),
                ],
                project,
            )
        if code != 0 or args[0] not in {"install", "sync", "add", "update"}:
            return code
        # The project itself (the person's own code), its dependencies already in place.
        return context.run([poetry, "install", "--only-root"], project, {**os.environ})


__all__ = ["PythonTools"]
