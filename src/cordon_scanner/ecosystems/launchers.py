"""How a command downloads a package of an ecosystem's registry and runs it in one step.

An MCP server is often launched that way (`npx -y pkg@1.2.3`, `uvx pkg==1.2.3`, `docker run image@sha256:...`): the configuration
names the package and its release, and nothing else installs it first. Each adapter declares the commands that do this for its own
registry (`Launcher`), or, where no command of the ecosystem downloads a release it names and runs it in one step, why none does
(`NoLauncher`). The scan of an MCP configuration, the AI bill of materials and the device's signed statement read the same
declarations (`detect/agents/mcp_servers/declarations.py`, `cloud/device_attestation.py`).
"""

from __future__ import annotations

from dataclasses import dataclass

from cordon_scanner.ecosystems.archive_shapes import PublishedArchive


@dataclass(frozen=True, slots=True)
class Launcher:
    """One family of commands that fetch a release and run it."""

    commands: tuple[tuple[str, ...], ...]
    """The words that start such a command: `("npx",)`, `("pnpm", "dlx")`. The program is its last path part, lower case."""
    spec: str
    """The kind of package spec the command names (`npm`, `pypi`, `image`, ...): `LaunchPackages`, `LaunchSpecs` and `LaunchPins` read, split and judge it."""
    page: str
    """The tool's own page that documents the command."""
    read: str = ""
    """The `LaunchPackages` reader of the words after the command, where it is not `<spec>_package`."""
    skip: tuple[str, ...] = ()
    """Words that may follow a two-word command before the package (`uv tool run pkg`)."""


@dataclass(frozen=True, slots=True)
class NoLauncher:
    """An ecosystem no command of which downloads a release the command names and runs it, and why not."""

    reason: str


McpLaunch = tuple[Launcher, ...] | NoLauncher
"""What an ecosystem declares of how an MCP server is launched from its packages."""


class Declarations:
    """What every adapter states itself, with no default: a new ecosystem cannot be added without saying each."""

    published_archive: PublishedArchive
    mcp_launch: McpLaunch


__all__ = ["Declarations", "Launcher", "McpLaunch", "NoLauncher"]
