"""dotnet through Cordon. A project restore resolves in the project (its project files and locks
saved first and put back if anything blocks), then runs as typed in locked mode against the scanned
lock; `dotnet tool install` installs exactly the scanned `.nupkg`, from a source holding only it."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from cordon_scanner.cli.commands.install.context import InstallContext


class DotnetTools:
    #: `dotnet tool install` options that take a value (the value is not a package id).
    TOOL_VALUED: ClassVar[frozenset[str]] = frozenset(
        {"--version", "--tool-path", "--framework", "-f", "--arch", "-a", "--verbosity", "-v"}
    )
    #: Options that would let dotnet fetch from somewhere Cordon did not check.
    OTHER_SOURCES: ClassVar[frozenset[str]] = frozenset(
        {"--add-source", "--configfile", "--source", "-s", "--interactive"}
    )

    @staticmethod
    def installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.managers.nuget import NuGetPlanner

        return NuGetPlanner.installs(args)

    @classmethod
    def dotnet(cls, dotnet: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.managers.nuget import NuGetPlanner
        from cordon_scanner.sources.install.plan import PrivateDirectory, Subprocesses

        if args[0] == "tool":
            return cls._tool(dotnet, args[1:], context)
        project = Path.cwd()
        with PrivateDirectory.made("cordon-nuget-") as scratch:
            plan = NuGetPlanner.project(
                args, Subprocesses.run, dotnet, project, scratch / "resolve", context.registries
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
            except BaseException:
                NuGetPlanner.restore(project, saved)
                raise
            if not verdict.ok:
                NuGetPlanner.restore(project, saved)
                return context.blocked(verdict)
            NuGetPlanner.scanned_source(plan.files, files, scratch / "source")
            config = scratch / "nuget.config"
            config.write_text(NuGetPlanner.source_config(scratch / "source"), encoding="utf-8")
            # Restored from the scanned packages only: the config's one source is their folder.
            return context.run([dotnet, *NuGetPlanner.locked(args, config)], project)

    @classmethod
    def _tool(cls, dotnet: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.managers.nuget import NuGetPlanner
        from cordon_scanner.sources.install.plan import InstallRefused, PrivateDirectory

        verb, rest = args[0], args[1:]
        if any(a.split("=", 1)[0] in cls.OTHER_SOURCES for a in rest):
            raise InstallRefused(
                "Cordon installs a tool from nuget.org only; --add-source, --configfile and "
                "--source would let dotnet fetch a package Cordon did not check"
            )
        names, version = cls._tool_args(rest)
        if len(names) != 1:
            raise InstallRefused("Cordon checks `dotnet tool install` of one tool at a time")
        plan = NuGetPlanner.tool(names[0], version, context.registries)
        package = plan.files[0]
        with PrivateDirectory.made("cordon-nuget-tool-") as scratch:
            files = scratch / "files"
            files.mkdir(mode=0o700)
            verdict = context.check(plan, files)
            if not verdict.ok:
                return context.blocked(verdict)
            NuGetPlanner.scanned_source(plan.files, files, scratch / "source")
            config = scratch / "nuget.config"
            config.write_text(NuGetPlanner.source_config(scratch / "source"), encoding="utf-8")
            pinned = cls._without_value(rest, "--version")
            # Installed from the scanned package only: the config's one source is its folder.
            return context.run(
                [
                    dotnet,
                    "tool",
                    verb,
                    *pinned,
                    "--version",
                    package.version,
                    "--configfile",
                    str(config),
                ]
            )

    @classmethod
    def _tool_args(cls, args: list[str]) -> tuple[list[str], str]:
        """(the package ids named, the `--version` asked for) of a `dotnet tool install` line."""
        names: list[str] = []
        version = ""
        values = iter(args)
        for arg in values:
            option, equals, value = arg.partition("=")
            if option == "--version":
                version = value if equals else next(values, "")
            elif option in cls.TOOL_VALUED:
                if not equals:
                    next(values, None)
            elif not arg.startswith("-"):
                names.append(arg)
        return names, version

    @staticmethod
    def _without_value(args: list[str], option: str) -> list[str]:
        out, skip = [], False
        for arg in args:
            if skip:
                skip = False
                continue
            if arg == option:
                skip = True
                continue
            if arg.startswith(option + "="):
                continue
            out.append(arg)
        return out


__all__ = ["DotnetTools"]
