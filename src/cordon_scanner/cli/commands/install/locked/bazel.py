"""bazel through Cordon: every module file and archive MODULE.bazel.lock pins is held to its pin and scanned before Bazel
evaluates a dependency's MODULE.bazel or runs a repository rule, and Bazel then runs with `--lockfile_mode=error` so it checks the same pins."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cordon_scanner.cli.commands.install.context import InstallContext


class BazelTools:
    @staticmethod
    def installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.managers.bazel import BazelPlanner

        return BazelPlanner.installs(args)

    @staticmethod
    def bazel(bazel: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.managers.bazel import BazelPlanner
        from cordon_scanner.sources.install.plan import PrivateDirectory

        project = Path.cwd()
        plan = BazelPlanner.plan(
            project,
            lambda url: context.registries.fetch(
                context.registries.admit("bazel", url, url), "bazel"
            ),
        )
        with PrivateDirectory.made("cordon-bazel-") as scratch:
            files = scratch / "files"
            files.mkdir(mode=0o700)
            verdict = context.check(plan, files)
            if not verdict.ok:
                return context.blocked(verdict)
        return context.run([bazel, *BazelPlanner.arguments(args)], project)


__all__ = ["BazelTools"]
