"""mvn through Cordon: every jar the build resolves, plugins included, scanned and placed in the local
repository before the build runs offline; an artifact a plugin asks for while it runs is fetched,
scanned and placed the same way, and the build runs again."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.version import PROGRAM

if TYPE_CHECKING:
    from cordon_scanner.cli.commands.install.context import InstallContext


class MavenTools:
    #: Offline builds a run may take to find what a plugin resolves while it runs.
    ROUNDS: ClassVar[int] = 6

    @staticmethod
    def installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.managers.maven import MavenPlanner

        return MavenPlanner.installs(args)

    @classmethod
    def mvn(cls, mvn: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.managers.maven import MavenPlanner
        from cordon_scanner.sources.install.plan import PrivateDirectory, Subprocesses

        project = Path.cwd()
        local = MavenPlanner.local_repository(args, project)
        known: set[str] = set()
        with PrivateDirectory.made("cordon-maven-") as scratch:
            repo = scratch / "repo"
            MavenPlanner.go_offline(args, Subprocesses.run, mvn, project, repo)
            code = 1
            for round_ in range(cls.ROUNDS):
                plan = MavenPlanner.plan(repo, known)
                if plan.files:
                    files = scratch / f"files-{round_}"
                    files.mkdir(mode=0o700)
                    verdict = context.check(plan, files)
                    if not verdict.ok:
                        return context.blocked(verdict)
                    MavenPlanner.seed(repo, plan.files, files, local)
                code, output = cls._run(MavenPlanner.offline(mvn, args), project)
                missing = MavenPlanner.missing(output)
                if code == 0 or not missing:
                    return code
                # A plugin asked for an artifact go-offline could not see: fetch it, scan, rerun.
                names = ", ".join(f"{g}:{a}:{v}" for g, a, v in missing)
                print(
                    f"{PROGRAM}: the build stopped on {names}, which a plugin resolves only while "
                    "it runs; fetching and scanning it, then running the build again",
                    file=sys.stderr,
                )
                MavenPlanner.fetch_missing(missing, Subprocesses.run, mvn, project, repo)
            return code

    @staticmethod
    def _run(argv: list[str], cwd: Path) -> tuple[int, str]:
        """The build, its output shown as it runs and kept to read what it could not resolve."""
        seen: list[str] = []
        with subprocess.Popen(  # noqa: S603 - the person's mvn, their own arguments
            argv,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        ) as process:
            assert process.stdout is not None  # noqa: S101 - piped above
            for line in process.stdout:
                sys.stdout.write(line)
                seen.append(line)
            code = process.wait()
        return code, "".join(seen[-400:])


__all__ = ["MavenTools"]
