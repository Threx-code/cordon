"""Rscript and R through Cordon: every package renv.lock pins is held to the MD5 CRAN publishes (or the commit GitHub is pinned to) and
scanned before R builds it."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cordon_scanner.cli.commands.install.context import InstallContext


class CranTools:
    @staticmethod
    def installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.managers.cran import CranPlanner

        return CranPlanner.installs(args)

    @staticmethod
    def rscript(rscript: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.intel.registries.archive_sources.base import ArchiveFetch
        from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources
        from cordon_scanner.sources.install.managers.cran import CranPlanner
        from cordon_scanner.sources.install.plan import InstallRefused, PrivateDirectory
        from cordon_scanner.version import PROGRAM

        source = ArchiveSources.of("cran")
        if source is None:
            raise InstallRefused("CRAN has no archive source here")
        project = Path.cwd()
        plan = CranPlanner.plan(
            args, project, lambda name, version: ArchiveFetch.located(source, name, version)
        )
        if any(f.algorithm == "md5" for f in plan.files):
            print(f"{PROGRAM}: {CranPlanner.NOTE}", file=sys.stderr)
        with PrivateDirectory.made("cordon-cran-") as scratch:
            files = scratch / "files"
            files.mkdir(mode=0o700)
            verdict = context.check(plan, files)
            if not verdict.ok:
                return context.blocked(verdict)
        return context.run([rscript, *args], project)


__all__ = ["CranTools"]
