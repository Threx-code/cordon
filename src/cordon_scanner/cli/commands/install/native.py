"""cargo, go, gem and bundle through Cordon. cargo, go and Bundler resolve in the project (their
manifests saved first and put back if anything blocks), then run as typed against the scanned lock;
RubyGems installs exactly the scanned `.gem` files."""

from __future__ import annotations

import functools
import os
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from collections.abc import Callable

    from cordon_scanner.cli.commands.install.context import InstallContext
    from cordon_scanner.sources.install.plan import InstallPlan


class NativeTools:
    GO_INSTALL: ClassVar[str] = "install"

    @staticmethod
    def cargo_installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.cargo import CargoPlanner

        return bool(args) and args[0] in CargoPlanner.GUARDED

    @staticmethod
    def go_installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.gomod import GoPlanner

        if args[:1] == ["mod"]:
            return args[1:2] != [] and args[1] in GoPlanner.MOD_VERBS
        return bool(args) and args[0] in GoPlanner.GUARDED

    @staticmethod
    def gem_installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.gem import GemPlanner

        return bool(args) and args[0] in GemPlanner.GEM_VERBS

    @staticmethod
    def bundle_installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.gem import GemPlanner

        # A bare `bundle` is `bundle install`.
        return not args or args[0] in GemPlanner.BUNDLE_VERBS

    # -- cargo ----------------------------------------------------------------------------------

    @classmethod
    def cargo(cls, cargo: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.cargo import CargoPlanner
        from cordon_scanner.sources.install.plan import Subprocesses

        if args[0] == "install" and not cls._local_install(args):
            return cls._cargo_install(cargo, args[1:], context)
        project = Path.cwd()
        plan = CargoPlanner.project(args[0], args[1:], Subprocesses.run, cargo, project)
        return cls._checked(
            plan,
            context,
            functools.partial(CargoPlanner.restore, project, cls._saved(plan)),
            [cargo, *CargoPlanner.locked(args[0], args[1:])],
            project,
        )

    #: `cargo install` options that take a value (the value is not a crate name).
    CARGO_VALUED: ClassVar[frozenset[str]] = frozenset(
        {
            "--version", "--vers", "--root", "--target", "--target-dir", "--features", "-F",
            "--profile", "--bin", "--example", "--jobs", "-j", "--config", "--color", "-Z",
            "--index", "--registry", "--branch", "--tag", "--rev",
        }
    )  # fmt: skip

    @classmethod
    def _cargo_install_args(cls, args: list[str]) -> tuple[list[str], list[str], str]:
        """(crate names, the options kept for the install, the `--version` asked for)."""
        names, options, version = [], [], ""
        it = iter(args)
        for arg in it:
            flag = arg.split("=", 1)[0]
            if flag in {"--version", "--vers"}:
                version = arg.split("=", 1)[1] if "=" in arg else next(it, "")
            elif arg == "--locked":
                continue
            elif flag in cls.CARGO_VALUED:
                options += [arg] if "=" in arg else [arg, next(it, "")]
            elif arg.startswith("-"):
                options.append(arg)
            else:
                names.append(arg)
        return names, options, version

    @staticmethod
    def _local_install(args: list[str]) -> bool:
        return any(a in {"--path", "--git"} or a.startswith(("--path=", "--git=")) for a in args)

    @classmethod
    def _cargo_install(cls, cargo: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.cargo import CargoPlanner, CrateArchive
        from cordon_scanner.sources.install.plan import (
            InstallRefused,
            PrivateDirectory,
            Subprocesses,
        )

        names, options, version = cls._cargo_install_args(args)
        if len(names) != 1:
            raise InstallRefused("Cordon checks `cargo install` of one crate at a time")
        spec, _, pinned = names[0].partition("@")
        version = version or pinned
        with PrivateDirectory.made("cordon-cargo-") as scratch:
            plan = CargoPlanner.install(spec, version, Subprocesses.run, cargo, scratch)
            files = scratch / "files"
            files.mkdir(mode=0o700)
            verdict = context.check(plan, files)
            if not verdict.ok:
                return context.blocked(verdict)
            crate = next(f for f in plan.files if f.name == spec)
            source = scratch / "crate"
            source.mkdir(mode=0o700)
            root = CrateArchive.extract(files / crate.filename, source)
            (root / "Cargo.lock").write_bytes(plan.manifests["Cargo.lock"])
            # Built from the scanned crate and the scanned lock: cargo fetches nothing else.
            return context.run([cargo, "install", "--path", str(root), "--locked", *options])

    # -- go -------------------------------------------------------------------------------------

    @classmethod
    def go(cls, go: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.gomod import GoPlanner
        from cordon_scanner.sources.install.plan import PrivateDirectory, Subprocesses

        project = Path.cwd()
        target = [a for a in args[1:] if not a.startswith("-")]
        if args[0] == cls.GO_INSTALL and target and "@" in target[0]:
            # `go install path@version`: resolved in a private module, installed as typed.
            with PrivateDirectory.made("cordon-go-") as scratch:
                Subprocesses.run(
                    [go, "mod", "init", "cordon.invalid/resolve"], scratch, {**os.environ}
                )
                plan = GoPlanner.module("get", [target[0]], Subprocesses.run, go, scratch)
                return cls._checked(plan, context, lambda: None, [go, *args], project)
        verb = "get" if args[0] == "get" else "download"
        plan = GoPlanner.module(verb, args[1:], Subprocesses.run, go, project)
        command = [] if args[0] == "get" else [go, *args]
        return cls._checked(
            plan,
            context,
            functools.partial(GoPlanner.restore, project, cls._saved(plan)),
            command,
            project,
        )

    # -- gem / bundle ---------------------------------------------------------------------------

    @classmethod
    def gem(cls, gem: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.gem import GemPlanner
        from cordon_scanner.sources.install.plan import PrivateDirectory, Subprocesses

        cwd = Path.cwd()
        plan = GemPlanner.gem_install(args[1:], Subprocesses.run, gem, context.registries, cwd)
        options = [a for a in args[1:] if a.startswith("-") and a not in {"-v", "--version"}]
        with PrivateDirectory.made("cordon-install-") as scratch:
            verdict = context.check(plan, scratch)
            if not verdict.ok:
                return context.blocked(verdict)
            gems = [str(scratch / f.filename) for f in plan.files]
            # In dependency order, from these files only: RubyGems fetches nothing.
            return context.run(
                [gem, "install", "--local", "--ignore-dependencies", *options, *gems]
            )

    @classmethod
    def bundle(cls, bundle: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.gem import GemPlanner
        from cordon_scanner.sources.install.plan import PrivateDirectory, Subprocesses

        project = Path.cwd()
        verb = args[0] if args else "install"
        plan = GemPlanner.bundle(
            verb, args[1:], Subprocesses.run, bundle, context.registries, project
        )
        with PrivateDirectory.made("cordon-install-") as scratch:
            verdict = context.check(plan, scratch)
            if not verdict.ok:
                GemPlanner.restore(project, cls._saved(plan))
                return context.blocked(verdict)
            for file in plan.files:
                (scratch / file.filename).replace(scratch / cls._gem_name(file.name, file.version))
            env = {**os.environ, "BUNDLE_CACHE_PATH": str(scratch)}
            code = context.run([bundle, "install", "--local"], project, env)
            if code != 0 or verb != "exec":
                return code
            return context.run([bundle, *args], project)

    @staticmethod
    def _gem_name(name: str, version: str) -> str:
        return f"{name}-{version}.gem"

    # -- shared ---------------------------------------------------------------------------------

    @staticmethod
    def _saved(plan: InstallPlan) -> dict[str, bytes]:
        return {
            k.removeprefix("saved:"): v for k, v in plan.manifests.items() if k.startswith("saved:")
        }

    @staticmethod
    def _checked(
        plan: InstallPlan,
        context: InstallContext,
        restore: Callable[[], None],
        command: list[str],
        cwd: Path,
    ) -> int:
        from cordon_scanner.sources.install.plan import PrivateDirectory

        with PrivateDirectory.made("cordon-install-") as scratch:
            try:
                verdict = context.check(plan, scratch)
            except BaseException:
                # A refusal while checking (a file that does not match its registry hash) leaves the
                # project as it was, as a block does.
                restore()
                raise
        if not verdict.ok:
            restore()
            return context.blocked(verdict)
        return context.run(command, cwd) if command else 0


__all__ = ["NativeTools"]
