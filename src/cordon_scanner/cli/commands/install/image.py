"""docker and podman through Cordon: `pull`, `run` and `create` check the image -- its manifest, config and
layers, each held to the sha256 the manifest names -- before the runtime pulls it, then run the command
with the image named by the digest that was scanned (a `pull` also leaves the tag that was asked for)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from cordon_scanner.cli.commands.install.context import InstallContext


class ImageTools:
    #: How each runtime says which platform it pulls for.
    PLATFORM_QUERY: ClassVar[dict[str, tuple[str, ...]]] = {
        "docker": ("version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"),
        "podman": ("info", "--format", "{{.Version.OsArch}}"),
    }

    @staticmethod
    def installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.managers.image import ImagePlanner

        return ImagePlanner.installs(args)

    @classmethod
    def platform(cls, runtime: str) -> str:
        """The platform the runtime pulls for, from the runtime itself (empty when it will not say)."""
        from cordon_scanner.sources.install.plan import Subprocesses

        query = cls.PLATFORM_QUERY.get(Path(runtime).name.removesuffix(".exe"), ())
        if not query:
            return ""
        done = Subprocesses.run([runtime, *query], Path.cwd(), {**os.environ})
        return (done.stdout or "").strip() if done.returncode == 0 else ""

    @classmethod
    def docker(cls, runtime: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.managers.image import ImagePlanner
        from cordon_scanner.sources.install.plan import PrivateDirectory

        command = ImagePlanner.locate(args)
        daemon = "" if command.platform else cls.platform(runtime)
        with PrivateDirectory.made("cordon-image-") as scratch:
            plan, image, digest = ImagePlanner.plan(command, daemon, scratch / "layout")
            files = scratch / "files"
            files.mkdir(mode=0o700)
            verdict = context.check(plan, files)
            if not verdict.ok:
                return context.blocked(verdict)
        pinned = ImagePlanner.pinned(image, digest)
        code = context.run([runtime, *ImagePlanner.arguments(args, command, pinned)])
        tag = ImagePlanner.tagged(image) if command.verb == "pull" else None
        if code == 0 and tag is not None:
            code = context.run([runtime, "tag", pinned, tag])
        return code


__all__ = ["ImageTools"]
