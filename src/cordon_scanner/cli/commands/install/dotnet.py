"""dotnet through Cordon. A project restore resolves in the project (its project files and locks
saved first and put back if anything blocks), then runs as typed in locked mode against the scanned
lock; `dotnet tool install` installs exactly the scanned `.nupkg`, from a source holding only it."""

from __future__ import annotations

import functools
import shutil
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
        from cordon_scanner.sources.install.nuget import NuGetPlanner

        return NuGetPlanner.installs(args)

    @classmethod
    def dotnet(cls, dotnet: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.cli.commands.install.native import NativeTools
        from cordon_scanner.sources.install.nuget import NuGetPlanner
        from cordon_scanner.sources.install.plan import PrivateDirectory, Subprocesses

        if args[0] == "tool":
            return cls._tool(dotnet, args[1:], context)
        project = Path.cwd()
        with PrivateDirectory.made("cordon-nuget-") as packages:
            plan = NuGetPlanner.project(args, Subprocesses.run, dotnet, project, packages)
        command = NuGetPlanner.locked(args)
        return NativeTools._checked(
            plan,
            context,
            functools.partial(NuGetPlanner.restore, project, NativeTools._saved(plan)),
            [dotnet, *command] if command else [],
            project,
        )

    @classmethod
    def _tool(cls, dotnet: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.nuget import NuGetPlanner
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
            source = scratch / "source"
            source.mkdir(mode=0o700)
            shutil.copyfile(
                files / package.filename,
                source / f"{package.name.lower()}.{package.version.lower()}.nupkg",
            )
            config = scratch / "nuget.config"
            config.write_text(NuGetPlanner.tool_config(source), encoding="utf-8")
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
