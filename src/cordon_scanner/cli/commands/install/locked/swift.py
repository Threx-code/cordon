"""swift through Cordon: every dependency Package.resolved pins is held to its commit and scanned before SwiftPM evaluates its Package.swift,
and SwiftPM then runs with `--disable-automatic-resolution`, so it uses exactly the pinned commits."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cordon_scanner.cli.commands.install.context import InstallContext


class SwiftTools:
    @staticmethod
    def installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.managers.swift import SwiftPlanner

        return SwiftPlanner.installs(args)

    @staticmethod
    def swift(swift: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.managers.swift import SwiftPlanner
        from cordon_scanner.sources.install.plan import PrivateDirectory

        project = Path.cwd()
        plan = SwiftPlanner.plan(args, project)
        with PrivateDirectory.made("cordon-swift-") as scratch:
            files = scratch / "files"
            files.mkdir(mode=0o700)
            verdict = context.check(plan, files)
            if not verdict.ok:
                return context.blocked(verdict)
        return context.run([swift, *SwiftPlanner.arguments(args)], project)


__all__ = ["SwiftTools"]
