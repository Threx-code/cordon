"""`npm`, `pnpm`, `yarn`, `pip`, `uv`, `poetry`, `cargo`, `go`, `gem`, `bundler`: the package manager,
with every package scanned before anything installs.

    cordon-scanner npm install express        cordon-scanner pip install requests
    cordon-scanner cargo build                cordon-scanner go get example.com/m@v1.2.3

Everything after the tool's name is the tool's own command line. An install is resolved without
running anything, every file is fetched and checked against its registry hash, the files are scanned
together, and only then installed -- exactly those files, pinned by hash. Any other subcommand
(`npm run test`, `pip list`) is handed to the tool unchanged. Cordon's own options go first and are
spelled `--cordon-fail-on SEVERITY`, `--cordon-config PATH`, `--cordon-registry-token URL=VAR` and
`--cordon-no-cache`, so they never collide with the tool's. The engine is `sources/install/`.
"""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.foundation.errors import ExitCode
from cordon_scanner.version import PROGRAM

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence


#: (the real tool's executable, its arguments, the context) -> exit code
Handler = "Callable[[str, list[str], InstallContext], int]"


class InstallGuardCommand:
    TOOLS: ClassVar[tuple[str, ...]] = (
        "npm", "pnpm", "yarn", "pip", "pip3", "uv", "poetry", "cargo", "go", "gem", "bundler",
        "dotnet", "dart", "flutter", "conda", "mamba", "composer", "mvn",
        "terraform", "tofu", "helm", "ansible-galaxy", "mix", "docker", "podman", "code", "codium", "cursor", "brew", "bazel", "bazelisk", "julia", "nix", "swift", "Rscript", "R", "pod", "cabal",
    )  # fmt: skip
    #: The executable each tool runs, where its name here differs (`bundle` is Cordon's own command).
    EXECUTABLES: ClassVar[dict[str, str]] = {"bundler": "bundle"}

    #: What a person should know about one tool before using it guarded, shown in its help.
    NOTES: ClassVar[dict[str, str]] = {
        "cabal": (
            "cabal builds from a private repository of only the scanned packages (cabal.project.freeze names them), so your own "
            "cabal config and extra repositories are not used for a guarded install; a project that sets its own repositories is refused."
        ),
        "pod": (
            "pod refuses often: any pod whose source is a bare git tag is refused (pin :commit), as is one from a podspec URL or "
            "another spec repository; pod runs with --deployment."
        ),
    }

    @classmethod
    def add_parser(cls, sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        for tool in cls.TOOLS:
            parser_ = sub.add_parser(
                tool,
                help=f"run {tool}, scanning every package before anything is installed",
                description=(
                    f"`{PROGRAM} {tool} ...`: resolve without running anything, fetch and verify every "
                    "file against its registry hash, scan them, and install exactly those files only "
                    "when nothing is malicious. Other subcommands run unchanged. Cordon's options go "
                    "first: --cordon-fail-on SEVERITY, --cordon-config PATH, --cordon-registry-token "
                    "URL=VAR, --cordon-no-cache."
                    + (f" {cls.NOTES[tool]}" if tool in cls.NOTES else "")
                ),
            )
            parser_.add_argument(
                "arguments", nargs=argparse.REMAINDER, help=f"{tool}'s own arguments"
            )

    @classmethod
    def main(cls, tool: str, argv: Sequence[str]) -> int:
        from cordon_scanner.cli.commands.install.context import InstallContext, SdistBlocked
        from cordon_scanner.sources.install.plan import InstallRefused, Subprocesses

        own, rest = InstallContext.options(list(argv))
        guarded, handler = cls._table()[tool]
        executable = Subprocesses.executable(cls.EXECUTABLES.get(tool, tool))
        if not guarded(rest):
            return InstallContext.run([executable, *rest])
        context = InstallContext.made(own)
        try:
            return handler(executable, rest, context)
        except SdistBlocked as blocked:
            context.lines(blocked.label, (), blocked.findings)
            print(
                f"\n{PROGRAM}: nothing was installed; {tool} never built {blocked.label}.",
                file=sys.stderr,
            )
            return int(ExitCode.FINDINGS)
        except InstallRefused as exc:
            hint = f"\n{exc.hint}" if getattr(exc, "hint", None) else ""
            print(f"{PROGRAM}: {exc}{hint}\nNothing was installed.", file=sys.stderr)
            return int(ExitCode.SCANNER_ERROR)

    @classmethod
    def _table(cls) -> dict[str, tuple[Callable[[list[str]], bool], Callable[..., int]]]:
        """Each tool: which of its command lines install, and what checks them."""
        from cordon_scanner.cli.commands.install.bazel import BazelTools
        from cordon_scanner.cli.commands.install.cocoapods import CocoaPodsTools
        from cordon_scanner.cli.commands.install.composer import ComposerTools
        from cordon_scanner.cli.commands.install.cran import CranTools
        from cordon_scanner.cli.commands.install.dotnet import DotnetTools
        from cordon_scanner.cli.commands.install.fetched import FetchedTools
        from cordon_scanner.cli.commands.install.hackage import HackageTools
        from cordon_scanner.cli.commands.install.hex import HexTools
        from cordon_scanner.cli.commands.install.homebrew import HomebrewTools
        from cordon_scanner.cli.commands.install.image import ImageTools
        from cordon_scanner.cli.commands.install.julia import JuliaTools
        from cordon_scanner.cli.commands.install.maven import MavenTools
        from cordon_scanner.cli.commands.install.native import NativeTools
        from cordon_scanner.cli.commands.install.nix import NixTools
        from cordon_scanner.cli.commands.install.node import NodeTools
        from cordon_scanner.cli.commands.install.python import PythonTools
        from cordon_scanner.cli.commands.install.swift import SwiftTools
        from cordon_scanner.cli.commands.install.vscode import VscodeTools

        return {
            "npm": (NodeTools.npm_installs, NodeTools.npm),
            "pnpm": (NodeTools.pnpm_installs, NodeTools.pnpm),
            "yarn": (NodeTools.yarn_installs, NodeTools.yarn),
            "pip": (PythonTools.pip_installs, PythonTools.pip),
            "pip3": (PythonTools.pip_installs, PythonTools.pip),
            "uv": (PythonTools.uv_installs, PythonTools.uv),
            "poetry": (PythonTools.poetry_installs, PythonTools.poetry),
            "cargo": (NativeTools.cargo_installs, NativeTools.cargo),
            "go": (NativeTools.go_installs, NativeTools.go),
            "gem": (NativeTools.gem_installs, NativeTools.gem),
            "bundler": (NativeTools.bundle_installs, NativeTools.bundle),
            "dotnet": (DotnetTools.installs, DotnetTools.dotnet),
            "dart": (NativeTools.pub_installs, NativeTools.pub),
            "flutter": (NativeTools.pub_installs, NativeTools.pub),
            "conda": (NativeTools.conda_installs, NativeTools.conda),
            "mamba": (NativeTools.conda_installs, NativeTools.conda),
            "composer": (ComposerTools.installs, ComposerTools.composer),
            "mvn": (MavenTools.installs, MavenTools.mvn),
            "terraform": (FetchedTools.terraform_installs, FetchedTools.run),
            "tofu": (FetchedTools.terraform_installs, FetchedTools.run),
            "helm": (FetchedTools.helm_installs, FetchedTools.run),
            "ansible-galaxy": (FetchedTools.galaxy_installs, FetchedTools.run),
            "mix": (HexTools.installs, HexTools.mix),
            "docker": (ImageTools.installs, ImageTools.docker),
            "podman": (ImageTools.installs, ImageTools.docker),
            "code": (VscodeTools.installs, VscodeTools.code),
            "codium": (VscodeTools.installs, VscodeTools.code),
            "cursor": (VscodeTools.installs, VscodeTools.code),
            "brew": (HomebrewTools.installs, HomebrewTools.brew),
            "bazel": (BazelTools.installs, BazelTools.bazel),
            "bazelisk": (BazelTools.installs, BazelTools.bazel),
            "julia": (JuliaTools.installs, JuliaTools.julia),
            "nix": (NixTools.installs, NixTools.nix),
            "swift": (SwiftTools.installs, SwiftTools.swift),
            "Rscript": (CranTools.installs, CranTools.rscript),
            "R": (CranTools.installs, CranTools.rscript),
            "pod": (CocoaPodsTools.installs, CocoaPodsTools.pod),
            "cabal": (HackageTools.installs, HackageTools.cabal),
        }


__all__ = ["InstallGuardCommand"]
