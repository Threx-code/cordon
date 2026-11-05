"""Which paths a tool may read.

The server is started with one or more roots (by default the directory it was started in). A path a
tool is given is resolved -- symbolic links followed -- and must land inside a root, so an agent
steered by a malicious file cannot point the scanner at `~/.ssh` or `/etc` and have their contents
summarised back into its context. Nothing a tool does writes into a root: content tools write into
a private temporary directory of their own, removed when the call ends.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


class OutsideWorkspace(ValueError):
    """A path outside every root the server was started with."""


@dataclass(frozen=True, slots=True)
class Workspace:
    roots: tuple[Path, ...]

    @classmethod
    def of(cls, roots: list[str] | None) -> Workspace:
        if not roots:
            here = Path.cwd().resolve()
            # An agent that launches the server from a global configuration may start it in `/`
            # or the home directory. Neither is a project: start with no readable directory, and
            # let the path tools say how to name one, rather than read everything or refuse to run.
            if here == Path(here.anchor) or here == Path.home().resolve():
                return cls(())
        chosen = [Path(r).expanduser() for r in (roots or [str(Path.cwd())])]
        resolved: list[Path] = []
        for root in chosen:
            path = root.resolve(strict=True)
            if not path.is_dir():
                raise ValueError(f"--root {root}: not a directory")
            if path == Path(path.anchor):
                raise ValueError(
                    f"--root {root}: a filesystem root would let any path be read; name the projects instead"
                )
            resolved.append(path)
        return cls(tuple(dict.fromkeys(resolved)))

    def resolve(self, value: str | None) -> Path:
        """The real path for `value`, relative paths taken from the first root."""
        if not self.roots:
            raise OutsideWorkspace(
                "this server was started without a project directory (it was launched from / or the home "
                "directory), so it may read no paths. Add --root /path/to/project to its configuration. "
                "The content tools (check_skill, check_agent_file, scan_file_content, check_mcp_server, "
                "check_package) work without one."
            )
        raw = (value or ".").strip()
        if not raw or "\x00" in raw:
            raise OutsideWorkspace("an empty path or one containing a NUL byte")
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = self.roots[0] / candidate
        try:
            real = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise OutsideWorkspace(f"{raw}: does not exist") from exc
        for root in self.roots:
            if real == root or real.is_relative_to(root):
                return real
        raise OutsideWorkspace(
            f"{raw} is outside the directories this server may read ({', '.join(str(r) for r in self.roots)}). "
            "Start the server with --root to allow another directory."
        )

    def describe(self) -> list[str]:
        return [str(r) for r in self.roots]
