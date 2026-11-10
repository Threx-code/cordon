"""terraform, tofu, helm and ansible-galaxy through Cordon: their fetch runs no package code, so it
runs as typed and what it wrote is scanned before anything can run it; a block removes it again."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cordon_scanner.cli.commands.install.context import InstallContext


class FetchedTools:
    @staticmethod
    def terraform_installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.managers.fetched import FetchedTree

        return FetchedTree.installs("terraform", args)

    @staticmethod
    def helm_installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.managers.fetched import FetchedTree

        return FetchedTree.installs("helm", args)

    @staticmethod
    def galaxy_installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.managers.fetched import FetchedTree

        return FetchedTree.installs("ansible-galaxy", args)

    @staticmethod
    def run(tool: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.managers.fetched import FetchedTree
        from cordon_scanner.sources.install.plan import InstallPlan, PrivateDirectory

        name = Path(tool).name
        with PrivateDirectory.made("cordon-fetched-") as scratch:

            def scan(staged: Path) -> bool:
                verdict = context.check(InstallPlan(name, local=[staged]), scratch / "check")
                if not verdict.ok:
                    context.blocked(verdict)
                return verdict.ok

            (scratch / "check").mkdir(mode=0o700)
            return FetchedTree.run(
                name, args, Path.cwd(), lambda: context.run([tool, *args]), scan, scratch
            )


__all__ = ["FetchedTools"]
