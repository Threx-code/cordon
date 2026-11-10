"""composer through Cordon: resolve in the project (composer.json and composer.lock saved first and
put back if anything blocks), scan every dist archive, then install offline from a cache holding
only the scanned files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cordon_scanner.cli.commands.install.context import InstallContext


class ComposerTools:
    @staticmethod
    def installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.composer import ComposerPlanner

        return ComposerPlanner.installs(args)

    @staticmethod
    def composer(composer: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.composer import ComposerPlanner
        from cordon_scanner.sources.install.plan import PrivateDirectory, Subprocesses

        project = Path.cwd()
        with PrivateDirectory.made("cordon-composer-") as scratch:
            plan = ComposerPlanner.project(
                args, Subprocesses.run, composer, project, scratch / "resolve"
            )
            saved = {
                k.removeprefix("saved:"): v
                for k, v in plan.manifests.items()
                if k.startswith("saved:")
            }
            files = scratch / "files"
            files.mkdir(mode=0o700)
            try:
                verdict = context.check(plan, files)
                if verdict.ok:
                    lock = json.loads((project / "composer.lock").read_text(encoding="utf-8"))
                    ComposerPlanner.seed(lock, files, scratch / "cache", dev="--no-dev" not in args)
            except BaseException:
                ComposerPlanner.restore(project, saved)
                raise
            if not verdict.ok:
                ComposerPlanner.restore(project, saved)
                return context.blocked(verdict)
            # Installed from the scanned files only: no network, a cache holding nothing else.
            return context.run(
                ComposerPlanner.install_command(composer, args),
                project,
                ComposerPlanner.offline_env(scratch / "cache"),
            )


__all__ = ["ComposerTools"]
