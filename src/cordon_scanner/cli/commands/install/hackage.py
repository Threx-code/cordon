"""cabal through Cordon: every package cabal.project.freeze pins is held to the SHA-256 Hackage's signed index states and scanned before cabal builds it."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cordon_scanner.cli.commands.install.context import InstallContext


class HackageTools:
    ROOT = "https://hackage.haskell.org"

    @staticmethod
    def installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.managers.hackage import HackagePlanner

        return HackagePlanner.installs(args)

    @staticmethod
    def cache() -> Path:
        """The scanner's cache directory; the Hackage index is the one file kept in it."""
        base = os.environ.get("CORDON_CACHE_DIR") or os.environ.get("XDG_CACHE_HOME")
        root = Path(base) if base else Path.home() / ".cache"
        return root if os.environ.get("CORDON_CACHE_DIR") else root / "cordon"

    @staticmethod
    def cabal(cabal: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.managers.hackage import HackagePlanner
        from cordon_scanner.sources.install.managers.hackage_index import HackageIndex
        from cordon_scanner.sources.install.managers.hackage_repository import HackageRepository
        from cordon_scanner.sources.install.managers.hackage_trust import HackageTrust
        from cordon_scanner.sources.install.plan import PrivateDirectory

        project = Path.cwd()
        registries = context.registries
        index: list[Path] = []

        def get(name: str) -> bytes:
            url = f"{HackageTools.ROOT}/{name}"
            return registries.fetch(registries.admit("hackage", url, url), "hackage")

        def hashes(wanted: set[tuple[str, str]]) -> dict[tuple[str, str], dict[str, str]]:
            facts = HackageTrust.index(
                get("root.json"), get("timestamp.json"), get("snapshot.json"), now=datetime.now(UTC)
            )
            index[:] = [HackageIndex.current(HackageTools.cache(), facts)]
            return HackageIndex.targets(index[0], wanted)

        plan = HackagePlanner.plan(args, project, hashes)
        with PrivateDirectory.made("cordon-cabal-") as scratch:
            files = scratch / "files"
            files.mkdir(mode=0o700)
            verdict = context.check(plan, files)
            if not verdict.ok:
                return context.blocked(verdict)
            wanted = {(f.name, f.version) for f in plan.files}
            repository = scratch / "repository"
            HackageRepository.build(
                plan, files, HackageIndex.entries(index[0], wanted, "<name>.cabal"), repository
            )
            config = scratch / "config"
            config.write_text(HackageRepository.config(repository), encoding="utf-8")
            updated = context.run(
                [cabal, *HackageRepository.arguments(["update"], config)], project
            )
            if updated != 0:
                return updated
            return context.run([cabal, *HackageRepository.arguments(args, config)], project)


__all__ = ["HackageTools"]
