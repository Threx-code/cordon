"""vcpkg through Cordon: every source archive the manifest's ports download is held to the SHA-512 its portfile states and scanned before vcpkg builds it."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cordon_scanner.cli.commands.install.context import InstallContext


class VcpkgTools:
    @staticmethod
    def installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.managers.vcpkg.planner import VcpkgPlanner

        return VcpkgPlanner.installs(args)

    @staticmethod
    def root(args: list[str]) -> Path:
        """The vcpkg clone the run reads: `--vcpkg-root=` or `$VCPKG_ROOT`."""
        from cordon_scanner.sources.install.plan import InstallRefused

        for arg in args:
            if arg.startswith("--vcpkg-root="):
                return Path(arg.split("=", 1)[1])
        if os.environ.get("VCPKG_ROOT"):
            return Path(os.environ["VCPKG_ROOT"])
        raise InstallRefused(
            "no vcpkg clone to read the baseline's ports from: set VCPKG_ROOT (or pass --vcpkg-root=) to your clone of microsoft/vcpkg"
        )

    @staticmethod
    def vcpkg(vcpkg: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.managers.vcpkg.planner import VcpkgPlanner
        from cordon_scanner.sources.install.managers.vcpkg.ports import VcpkgPorts
        from cordon_scanner.sources.install.plan import PrivateDirectory

        project = Path.cwd()
        root = VcpkgTools.root(args)
        plan = VcpkgPlanner.plan(args, project, lambda baseline: VcpkgPorts(root, baseline))
        with PrivateDirectory.made("cordon-vcpkg-") as scratch:
            files = scratch / "files"
            files.mkdir(mode=0o700)
            verdict = context.check(plan, files)
            if not verdict.ok:
                return context.blocked(verdict)
            seed = scratch / "assets"
            VcpkgPlanner.seed(plan, files, seed)
            env = VcpkgPlanner.environment(seed, os.environ)
            return context.run([vcpkg, *args], project, env)


__all__ = ["VcpkgTools"]
