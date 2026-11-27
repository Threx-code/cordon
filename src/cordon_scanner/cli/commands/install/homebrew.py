"""brew through Cordon: the bottles `install`, `reinstall` and `upgrade` would pour are fetched from ghcr.io, held to the SHA-256
brew's own formula data names, and scanned; brew is then run from that same data (auto-update off), so it pours what was scanned."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.cli.commands.install.context import InstallContext


class HomebrewTools:
    #: brew reads its formula data once, as it was when Cordon read it.
    PINNED: ClassVar[dict[str, str]] = {"HOMEBREW_NO_AUTO_UPDATE": "1"}

    @staticmethod
    def installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.managers.homebrew import HomebrewPlanner

        return HomebrewPlanner.installs(args)

    @classmethod
    def brew(cls, brew: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.managers.homebrew import HomebrewPlanner
        from cordon_scanner.sources.install.plan import (
            InstallRefused,
            PrivateDirectory,
            Subprocesses,
        )

        env = {**os.environ, **cls.PINNED}

        def ask(argv: Sequence[str]) -> str:
            done = Subprocesses.run([brew, *argv], Path.cwd(), env)
            if done.returncode != 0:
                raise InstallRefused(
                    f"`brew {argv[0]}` could not resolve the install:\n"
                    + (done.stderr or done.stdout or "").strip()[-2000:]
                )
            return done.stdout or ""

        with PrivateDirectory.made("cordon-brew-") as scratch:
            result = HomebrewPlanner.plan(args, scratch / "bottles", ask)
            if result.plan is not None:
                files = scratch / "files"
                files.mkdir(mode=0o700)
                verdict = context.check(result.plan, files)
                if not verdict.ok:
                    return context.blocked(verdict)
        return context.run([brew, *args], None, env)


__all__ = ["HomebrewTools"]
