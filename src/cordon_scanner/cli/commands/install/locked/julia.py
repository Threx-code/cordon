"""julia through Cordon: every package Manifest.toml pins is held to its git tree hash and scanned before Pkg builds or loads it."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cordon_scanner.cli.commands.install.context import InstallContext


class JuliaTools:
    @staticmethod
    def installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.managers.julia import JuliaPlanner

        return JuliaPlanner.installs(args)

    @staticmethod
    def julia(julia: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.managers.julia import JuliaPlanner
        from cordon_scanner.sources.install.plan import PrivateDirectory

        project = Path.cwd()
        plan = JuliaPlanner.plan(args, project)
        with PrivateDirectory.made("cordon-julia-") as scratch:
            files = scratch / "files"
            files.mkdir(mode=0o700)
            verdict = context.check(plan, files)
            if not verdict.ok:
                return context.blocked(verdict)
        return context.run([julia, *args], project)


__all__ = ["JuliaTools"]
