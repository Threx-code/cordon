"""nix through Cordon: every flake input flake.lock pins is held to its narHash and scanned before Nix evaluates its flake.nix, and Nix
then runs with `--no-update-lock-file`, checking the same hashes itself."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cordon_scanner.cli.commands.install.context import InstallContext


class NixTools:
    @staticmethod
    def installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.managers.nix import NixPlanner

        return NixPlanner.installs(args)

    @staticmethod
    def nix(nix: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.managers.nix import NixPlanner
        from cordon_scanner.sources.install.plan import PrivateDirectory

        project = Path.cwd()
        plan = NixPlanner.plan(args, project)
        with PrivateDirectory.made("cordon-nix-") as scratch:
            files = scratch / "files"
            files.mkdir(mode=0o700)
            verdict = context.check(plan, files)
            if not verdict.ok:
                return context.blocked(verdict)
        return context.run([nix, *NixPlanner.arguments(args)], project)


__all__ = ["NixTools"]
