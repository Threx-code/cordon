"""The ports tree of a vcpkg clone at one commit, read through git (`GitRepository`, the one place Cordon runs git).

A manifest's `builtin-baseline` is the commit of microsoft/vcpkg whose `ports/` folder says what installs. Reading the files out of that commit
(never the working tree, which a person can edit) means a file read is the file git stores under that commit's SHA-1."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.git import GitRepository
from cordon_scanner.sources.install.plan import InstallRefused

if TYPE_CHECKING:
    from pathlib import Path


class VcpkgPorts:
    COMMIT: ClassVar[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}")

    def __init__(self, root: Path, baseline: str) -> None:
        if self.COMMIT.fullmatch(baseline) is None:
            raise InstallRefused(
                "the manifest's builtin-baseline is not a full 40-character commit"
            )
        self.baseline = baseline
        self._git = GitRepository(root)
        if self._git.run(["cat-file", "-t", baseline], check=False).strip() != "commit":
            raise InstallRefused(
                f"the vcpkg clone at {root} does not hold the baseline commit {baseline[:12]}: run `git fetch` there, then run this again"
            )

    def read(self, path: str) -> bytes | None:
        """The file `path` of the baseline commit, or None when it holds none."""
        return self._git.blob_at(self.baseline, path)

    def close(self) -> None:
        self._git.close()


__all__ = ["VcpkgPorts"]
