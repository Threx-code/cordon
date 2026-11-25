"""mix through Cordon: nothing the lock does not pin is fetched; every Hex package it pins is held to
its outer checksum, scanned and placed in Hex's cache, so the mix.exs Mix loads from each was scanned."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cordon_scanner.cli.commands.install.context import InstallContext


class HexTools:
    @staticmethod
    def installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.managers.hex import HexPlanner

        return HexPlanner.installs(args)

    @staticmethod
    def mix(mix: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.managers.hex import HexPlanner
        from cordon_scanner.sources.install.plan import (
            InstallRefused,
            PrivateDirectory,
            Subprocesses,
        )

        project = Path.cwd()
        plan = HexPlanner.plan(args, project)
        declared = Subprocesses.run([mix, "deps"], project, {**os.environ})
        if declared.returncode != 0:
            raise InstallRefused(
                "`mix deps` could not list the project's dependencies:\n"
                + (declared.stderr or declared.stdout or "").strip()[-2000:]
            )
        lock = (project / "mix.lock").read_text(encoding="utf-8", errors="replace")
        missing = HexPlanner.unpinned(declared.stdout or "", lock)
        if missing:
            raise InstallRefused(
                f"mix.lock does not pin {', '.join(missing[:10])}: Mix runs a package's mix.exs as "
                "it fetches it, so Cordon cannot scan it first. Pin it where you trust it, then "
                "run this again"
            )
        with PrivateDirectory.made("cordon-hex-") as scratch:
            files = scratch / "files"
            files.mkdir(mode=0o700)
            verdict = context.check(plan, files)
            if not verdict.ok:
                return context.blocked(verdict)
            HexPlanner.seed(plan.files, files, HexPlanner.cache())
        return context.run([mix, *args], project)


__all__ = ["HexTools"]
