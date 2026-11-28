"""pod through Cordon: every trunk podspec Podfile.lock pins is held to its checksum and scanned, and so is each pod source CocoaPods
checks itself (an archive with a sha1 or sha256, git at a commit); a pod whose source is a bare git tag is refused, and `pod install` runs
with `--deployment`. Many pods are refused for that reason: pin the commit, or run the real `pod` where you trust the pods."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cordon_scanner.cli.commands.install.context import InstallContext


class CocoaPodsTools:
    @staticmethod
    def installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.managers.cocoapods import CocoaPodsPlanner

        return CocoaPodsPlanner.installs(args)

    @staticmethod
    def pod(pod: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.managers.cocoapods import CocoaPodsPlanner
        from cordon_scanner.sources.install.plan import PrivateDirectory

        project = Path.cwd()
        registries = context.registries
        plan = CocoaPodsPlanner.plan(
            args,
            project,
            lambda url: registries.fetch(registries.admit("cocoapods", url, url), "cocoapods"),
        )
        with PrivateDirectory.made("cordon-pods-") as scratch:
            files = scratch / "files"
            files.mkdir(mode=0o700)
            verdict = context.check(plan, files)
            if not verdict.ok:
                return context.blocked(verdict)
        return context.run([pod, *CocoaPodsPlanner.arguments(args)], project)


__all__ = ["CocoaPodsTools"]
