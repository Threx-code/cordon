"""npm, pnpm and yarn through Cordon: the lockfile is resolved privately, its tarballs scanned, and the
tool then installs that lockfile frozen, checking each tarball's integrity itself."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cordon_scanner.cli.commands.install.context import InstallContext
    from cordon_scanner.sources.install.plan import InstallPlan


class NodeTools:
    @staticmethod
    def npm_installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.npm import NpmPlanner

        return bool(args) and args[0] in NpmPlanner.INSTALLS

    @staticmethod
    def pnpm_installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.pnpm import PnpmPlanner

        return not args or args[0] in PnpmPlanner.INSTALLS

    @staticmethod
    def yarn_installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.yarn import YarnPlanner

        # A bare `yarn` is `yarn install`.
        return not args or args[0] in YarnPlanner.INSTALLS

    @classmethod
    def npm(cls, npm: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.npm import NpmPlanner
        from cordon_scanner.sources.install.plan import Subprocesses

        project = Path.cwd()
        plan = NpmPlanner.plan(project, args, Subprocesses.run, npm, context.registries)
        # `npm ci` installs the lockfile as written and refuses any tarball whose integrity differs.
        return cls._install(project, plan, context, [npm, "ci", "--no-audit", "--no-fund"])

    @classmethod
    def pnpm(cls, pnpm: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.plan import Subprocesses
        from cordon_scanner.sources.install.pnpm import PnpmPlanner

        project = Path.cwd()
        plan = PnpmPlanner.plan(project, args, Subprocesses.run, pnpm, context.registries)
        return cls._install(project, plan, context, [pnpm, "install", "--frozen-lockfile"])

    @classmethod
    def yarn(cls, yarn: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.plan import Subprocesses
        from cordon_scanner.sources.install.yarn import YarnPlanner

        project = Path.cwd()
        modern = YarnPlanner.modern(project, Subprocesses.run, yarn)
        plan = YarnPlanner.plan(project, args, Subprocesses.run, yarn, context.registries)
        frozen = ["install", "--immutable"] if modern else ["install", "--frozen-lockfile"]
        return cls._install(project, plan, context, [yarn, *frozen])

    @staticmethod
    def _install(project: Path, plan: InstallPlan, context: InstallContext, argv: list[str]) -> int:
        from cordon_scanner.sources.install.plan import PrivateDirectory

        with PrivateDirectory.made("cordon-install-") as scratch:
            verdict = context.check(plan, scratch)
        if not verdict.ok:
            return context.blocked(verdict)
        context.write(project, plan)
        return context.run(argv, project)


__all__ = ["NodeTools"]
