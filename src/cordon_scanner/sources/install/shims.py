"""Shell shims: a plain `npm install` goes through Cordon, as the git hooks do for git.

`cordon guard shims` writes one small script per package manager into a directory (default
`~/.cordon/shims`) that runs `cordon <tool> "$@"`. Put the directory first on PATH and every install
is checked; every other subcommand passes straight through. Cordon finds the real tool on PATH with
the shims skipped (each carries `SHIM_MARKER`), so a shim never calls itself. `--remove` deletes only
files that carry the marker. Cordon edits no shell profile: it prints the line to add.
"""

from __future__ import annotations

import os
import shlex
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from cordon_scanner.sources.install.plan import SHIM_MARKER, Subprocesses


@dataclass(frozen=True)
class ShimReport:
    directory: Path
    written: tuple[str, ...]
    removed: tuple[str, ...]
    #: Tools left alone because a file that is not Cordon's already has the name.
    kept: tuple[str, ...]


class Shims:
    #: Each tool a shim is written for, and the ecosystem whose packages it installs. One table keyed
    #: by tool, so an ecosystem's coverage is read from it and a tool cannot be added without one.
    ECOSYSTEM: ClassVar[dict[str, str]] = {
        "npm": "npm", "pnpm": "npm", "yarn": "npm",
        "pip": "pypi", "pip3": "pypi", "uv": "pypi", "poetry": "pypi",
        "cargo": "cargo", "go": "gomod", "gem": "rubygems", "bundle": "rubygems",
        "dotnet": "nuget", "dart": "pub", "flutter": "pub", "conda": "conda", "mamba": "conda",
        "composer": "composer", "mvn": "maven", "terraform": "terraform", "tofu": "terraform",
        "helm": "helm", "ansible-galaxy": "ansible", "mix": "hex",
        "docker": "image", "podman": "image",
        "code": "vscode", "codium": "vscode", "cursor": "vscode", "brew": "homebrew",
        "bazel": "bazel", "bazelisk": "bazel", "julia": "julia", "nix": "nix", "swift": "swift", "Rscript": "cran", "R": "cran", "pod": "cocoapods", "cabal": "hackage",
    }  # fmt: skip

    #: An ecosystem with no install tool, and why. Only where the thing itself does not exist.
    NO_TOOL: ClassVar[dict[str, str]] = {
        "actions": (
            "GitHub Actions has no install command: the runner resolves each `uses:` reference "
            "when a job starts, so there is nothing on the person's machine to put a shim in front of."
        ),
    }

    TOOLS: ClassVar[tuple[str, ...]] = tuple(ECOSYSTEM)

    #: The Cordon command a shim runs, where it differs from the tool's name (`bundle` is Cordon's own
    #: offline-bundle command, so Bundler is `bundler`).
    COMMANDS: ClassVar[dict[str, str]] = {"bundle": "bundler"}

    @staticmethod
    def default_directory() -> Path:
        return Path(os.environ.get("CORDON_SHIM_DIR") or Path.home() / ".cordon" / "shims")

    @classmethod
    def script(cls, tool: str, cordon: tuple[str, ...]) -> str:
        """POSIX sh; on Windows a `.cmd` beside it does the same."""
        name = cls.COMMANDS.get(tool, tool)
        return (
            f"#!/bin/sh\n{SHIM_MARKER}\n"
            f'exec {" ".join(shlex.quote(part) for part in cordon)} {name} "$@"\n'
        )

    @classmethod
    def install(cls, directory: Path, cordon: tuple[str, ...] | None = None) -> ShimReport:
        target = cordon or cls.cordon_executable()
        directory.mkdir(parents=True, exist_ok=True)
        written, kept = [], []
        for tool in cls.TOOLS:
            path = directory / tool
            if path.exists() and not Subprocesses.is_shim(path):
                kept.append(tool)
                continue
            path.write_text(cls.script(tool, target), encoding="utf-8")
            path.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
            if sys.platform == "win32":
                cmd = directory / f"{tool}.cmd"
                cmd.write_text(
                    f"@echo off\r\nrem {SHIM_MARKER}\r\n"
                    + " ".join(f'"{part}"' for part in target)
                    + f" {cls.COMMANDS.get(tool, tool)} %*\r\n",
                    encoding="utf-8",
                )
            written.append(tool)
        return ShimReport(directory, tuple(written), (), tuple(kept))

    @classmethod
    def remove(cls, directory: Path) -> ShimReport:
        removed = []
        for tool in cls.TOOLS:
            for path in (directory / tool, directory / f"{tool}.cmd"):
                if path.is_file() and Subprocesses.is_shim(path):
                    path.unlink()
                    removed.append(path.name)
        return ShimReport(directory, (), tuple(removed), ())

    @staticmethod
    def cordon_executable() -> tuple[str, ...]:
        """The Cordon the shims call: the one writing them (another on PATH may be older), else
        this interpreter's module."""
        from cordon_scanner.version import PROGRAM

        running = Path(sys.argv[0]) if sys.argv and sys.argv[0] else None
        if running is not None and running.name == PROGRAM and running.is_file():
            return (str(running.resolve()),)
        return (sys.executable, "-m", "cordon_scanner")

    @staticmethod
    def on_path(directory: Path) -> bool:
        entries = [Path(p).expanduser() for p in os.environ.get("PATH", "").split(os.pathsep) if p]
        return bool(entries) and entries[0].resolve() == directory.resolve()


__all__ = ["ShimReport", "Shims"]
