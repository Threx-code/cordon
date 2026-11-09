"""`uv` through Cordon: `uv pip install|sync`, `uv add|remove|sync|lock|run`, `uv tool install`.

After the scan, every install reads only the scanned directory (`--no-index --find-links`). Building a
local project (the person's own, or `uv pip install -e .`) can need build tools its backend asks for
only while it runs (hatchling's `editables` for an editable install): uv names the missing one, Cordon
resolves it wheel-only, scans it, adds it to the directory, and lets uv try again.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.cli.commands.install.context import InstallContext
    from cordon_scanner.sources.install.pip import PipHooks
    from cordon_scanner.sources.install.plan import InstallPlan, PackageFile
    from cordon_scanner.sources.install.uv import UvPlan


@dataclass
class UvInstall:
    uv: str
    context: InstallContext
    hooks: PipHooks

    def run(self, args: list[str]) -> int:
        from cordon_scanner.sources.install.uv import UvPlanner

        if args[:1] == ["pip"]:
            return self.pip(args[1], args[2:])
        if args[:2] == ["tool", "install"]:
            return self.tool(args[2:])
        verb = args[0]
        if verb in UvPlanner.PROJECT_VERBS:
            return self.project(verb, args[1:])
        return self.context.run([self.uv, *args])

    # -- uv pip install / sync ------------------------------------------------------------------

    def pip(self, verb: str, args: list[str]) -> int:
        from cordon_scanner.sources.install.plan import PrivateDirectory, Subprocesses
        from cordon_scanner.sources.install.uv import UvPlanner

        cwd = Path.cwd()
        if verb == "sync":
            # `uv pip sync a.txt b.txt`: requirement files, read as `-r`.
            args = [x for a in args for x in (["-r", a] if not a.startswith("-") else [a])]
        planned = UvPlanner.pip_install(
            args, Subprocesses.run, self.uv, self.hooks, self.context.registries, cwd
        )
        python = ["--python", planned.target.executable]
        with PrivateDirectory.made("cordon-install-") as scratch:
            verdict = self.context.check(planned.plan, scratch)
            if not verdict.ok:
                return self.context.blocked(verdict)
            requirements = self._requirements(planned.plan, scratch)
            base = [self.uv, "pip", verb, "--no-index", "--find-links", str(scratch), *python]
            hashes = [] if verb == "sync" else ["--no-deps"]
            code = self.context.run([*base, "--require-hashes", *hashes, *requirements])
            for path in planned.local:
                code = code or self._building(
                    [*base[:2], "install", *base[3:], "--no-deps", path], scratch
                )
            for path in planned.editable:
                code = code or self._building(
                    [*base[:2], "install", *base[3:], "--no-deps", "-e", path], scratch
                )
            return code

    # -- uv add / remove / sync / lock / run -----------------------------------------------------

    def project(self, verb: str, args: list[str]) -> int:
        from cordon_scanner.sources.install.pip import BuildRequires
        from cordon_scanner.sources.install.plan import PrivateDirectory, Subprocesses
        from cordon_scanner.sources.install.uv import UvPlanner

        project = Path.cwd()
        if verb != "lock" and not (project / ".venv").exists():
            code = self.context.run([self.uv, "venv", "--quiet", *self._python(args)], project)
            if code != 0:
                return code
        planned = UvPlanner.project(
            verb, args, Subprocesses.run, self.uv, self.hooks, self.context.registries, project
        )
        if self._packaged(project):
            planned.plan.files += [
                f
                for f in self.hooks.build_tools(BuildRequires.of_project(project))
                if f not in planned.plan.files
            ]
        with PrivateDirectory.made("cordon-install-") as scratch:
            verdict = self.context.check(planned.plan, scratch)
            if not verdict.ok:
                return self.context.blocked(verdict)
            self.context.write(project, planned.plan)
            if verb == "lock":
                return 0
            code = self._dependencies(planned, scratch)
            sync = [self.uv, "sync", "--frozen", "--no-index", "--find-links", str(scratch)]
            code = code or self._building([*sync, *UvPlanner._export_flags(args)], scratch)
        if code or verb != "run":
            return code
        return self.context.run(
            [self.uv, "run", "--frozen", "--no-sync", *self._program(args)], project
        )

    def _dependencies(self, planned: UvPlan, scratch: Path) -> int:
        requirements = self._requirements(planned.plan, scratch)
        if not requirements:
            return 0
        return self.context.run(
            [
                self.uv,
                "pip",
                "install",
                "--no-index",
                "--find-links",
                str(scratch),
                "--python",
                planned.target.executable,
                "--require-hashes",
                "--no-deps",
                *requirements,
            ]
        )

    # -- uv tool install ------------------------------------------------------------------------

    def tool(self, args: list[str]) -> int:
        from cordon_scanner.sources.install.plan import PrivateDirectory, Subprocesses
        from cordon_scanner.sources.install.uv import UvPlanner

        specs = [a for a in args if not a.startswith("-")]
        planned = UvPlanner.pip_install(
            specs[:1], Subprocesses.run, self.uv, self.hooks, self.context.registries, Path.cwd()
        )
        with PrivateDirectory.made("cordon-install-") as scratch:
            verdict = self.context.check(planned.plan, scratch)
            if not verdict.ok:
                return self.context.blocked(verdict)
            # Only the scanned files exist for uv to install from: the tool's closure, exactly.
            return self.context.run(
                [self.uv, "tool", "install", *args, "--no-index", "--find-links", str(scratch)]
            )

    # -- shared ---------------------------------------------------------------------------------

    def _building(self, argv: list[str], scratch: Path) -> int:
        """Run a uv command that may build a local project; add each build tool it asks for (scanned)."""
        from cordon_scanner.cli.commands.install.python_hooks import BuildRetry

        return BuildRetry(self.hooks, self.context, scratch).run(argv)

    @staticmethod
    def _requirements(plan: InstallPlan, scratch: Path) -> list[str]:
        installed: list[PackageFile] = [f for f in plan.files if not f.build_only]
        if not installed:
            return []
        at = scratch / "cordon-requirements.txt"
        at.write_text(
            "".join(f"{f.name}=={f.version} --hash=sha256:{f.digest.hex()}\n" for f in installed),
            encoding="utf-8",
        )
        return ["-r", str(at)]

    @staticmethod
    def _packaged(project: Path) -> bool:
        """Whether uv installs the project itself (it declares a build system)."""
        import tomllib

        try:
            document = tomllib.loads((project / "pyproject.toml").read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
            return False
        return "build-system" in document

    @staticmethod
    def _python(args: Sequence[str]) -> list[str]:
        from cordon_scanner.sources.install.uv import UvPlanner

        python = UvPlanner._python_flag(args)
        return ["--python", python] if python else []

    @staticmethod
    def _program(args: Sequence[str]) -> list[str]:
        """`uv run` arguments without the ones Cordon already applied."""
        return [a for a in args if a not in {"--frozen", "--locked", "--no-sync"}]


__all__ = ["UvInstall"]
