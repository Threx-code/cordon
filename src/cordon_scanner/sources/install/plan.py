"""What an install would put on the machine, as Cordon checks it: the files, their registry hashes, and
the verdict. Every package manager's planner (`npm.py`, `pip.py`, `cargo.py`, ...) produces an
`InstallPlan`; `guard.py` fetches, verifies and scans it; the command installs exactly those files.

Fail closed throughout: a file with no registry hash, a host the operator does not trust, a resolve the
package manager could not finish, a scan with nothing to read. Design: package
`reviews/install-guard/01-DESIGN.md`.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.parse
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Final

from cordon_scanner.foundation.errors import ConfigError, SourceError

if TYPE_CHECKING:
    from cordon_scanner.foundation.models import Finding

#: Runs a package manager: argv, working directory, environment. The real one is `subprocess.run`;
#: tests pass their own.
Runner = Callable[[Sequence[str], Path, dict[str, str]], "subprocess.CompletedProcess[str]"]
#: Fetches one file's bytes from a registry host: (url, ecosystem). The real one is host-pinned.
Fetcher = Callable[[str, str], bytes]
#: Scans a directory of fetched files and returns the findings that block the install.
Scanner = Callable[[Path], "tuple[Finding, ...]"]

UNATTRIBUTED: Final = "(the downloaded files)"
#: The line every shim Cordon writes carries, so it is never taken for the real tool.
SHIM_MARKER: Final = "# cordon-shim: runs the real tool through Cordon"


class InstallRefused(SourceError):
    """The install cannot be checked, so it does not happen. Safe to show."""


@dataclass(frozen=True, slots=True)
class PackageFile:
    """One file the package manager would install, and the hash the registry publishes for it."""

    ecosystem: str
    name: str
    version: str
    url: str
    algorithm: str  # "sha512" (npm integrity), "sha256" (PyPI, crates.io, RubyGems), "h1" (Go)
    digest: bytes
    requested: bool = False
    required_by: tuple[str, ...] = ()
    #: How the ecosystem writes a pinned version: `name@1.0` (npm), `name==1.0` (PyPI).
    separator: str = "@"
    #: Needed only to build an sdist (its `build-system.requires`): scanned and offered to the build,
    #: never installed into the person's environment.
    build_only: bool = False

    #: Registries whose file names are unique and must be kept as they are.
    OWN_NAMES: ClassVar[frozenset[str]] = frozenset({"pypi", "rubygems"})

    @property
    def label(self) -> str:
        return f"{self.name}{self.separator}{self.version}"

    @property
    def filename(self) -> str:
        """A name for the file on disk: the URL's own, made safe, prefixed so two packages never collide."""
        tail = urllib.parse.unquote(urllib.parse.urlsplit(self.url).path.rsplit("/", 1)[-1])
        safe = re.sub(r"[^A-Za-z0-9._+-]", "_", tail)[:150] or "package"
        if self.ecosystem in self.OWN_NAMES and safe == tail:
            # The installer reads the name and version from the file name itself (a wheel, a .gem),
            # and the registry keeps file names unique.
            return safe
        prefix = re.sub(r"[^A-Za-z0-9._-]", "_", f"{self.name}-{self.version}")[:80]
        return safe if safe.startswith(prefix) else f"{prefix}--{safe}"

    @property
    def key(self) -> str:
        """What identifies these exact bytes: the hash, whatever the file is called."""
        return f"{self.algorithm}:{self.digest.hex()}"

    def verify(self, data: bytes) -> None:
        from cordon_scanner.sources.install.hashes import ArchiveDigest

        try:
            matches = ArchiveDigest.of(self.algorithm, data) == self.digest
        except ValueError as exc:
            raise InstallRefused(f"{self.label}: {exc}") from exc
        if not matches:
            raise InstallRefused(
                f"{self.label} does not match the {self.algorithm} its registry publishes"
            )


@dataclass
class InstallPlan:
    """What a resolve says would be installed, and how to install exactly that afterwards."""

    ecosystem: str
    files: list[PackageFile] = field(default_factory=list)
    #: Files the resolve wrote (lockfiles, manifests), relative to the project: written into the
    #: project only after a clean scan, so a blocked install leaves the project as it was.
    manifests: dict[str, bytes] = field(default_factory=dict)
    #: Local code the install would build or run (a pip editable project, a workspace member): scanned
    #: with the packages, never fetched.
    local: list[Path] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class InstallVerdict:
    plan: InstallPlan
    blocking: dict[str, tuple[Finding, ...]]  # PackageFile.filename -> its blocking findings
    #: How many files a fresh clean verdict let through without a rescan.
    remembered: int = 0

    @property
    def ok(self) -> bool:
        return not self.blocking


class Subprocesses:
    """The package manager, run as the person who typed the command: their PATH, config and auth."""

    @staticmethod
    def run(
        argv: Sequence[str], cwd: Path, env: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - absolute executable, fixed argv, no shell
            list(argv), cwd=cwd, env=env, text=True, capture_output=True, check=False
        )

    @staticmethod
    def executable(tool: str, path: str | None = None) -> str:
        """The real `tool` on PATH: a Cordon shim (which would call Cordon again) is skipped."""
        for directory in (path if path is not None else os.environ.get("PATH", "")).split(
            os.pathsep
        ):
            found = shutil.which(tool, path=directory) if directory else None
            if found and not Subprocesses.is_shim(Path(found)):
                return found
        raise ConfigError(
            f"{tool} is not on PATH", hint=f"Install {tool}, or run Cordon where it is."
        )

    @staticmethod
    def is_shim(path: Path) -> bool:
        try:
            with path.open("rb") as handle:
                head = handle.read(512)
        except OSError:
            return False
        return SHIM_MARKER.encode() in head


class PrivateDirectory:
    @staticmethod
    @contextmanager
    def made(prefix: str) -> Iterator[Path]:
        """A 0700 temporary directory, removed however the block ends."""
        from cordon_scanner.foundation.files.trees import Trees

        directory = Path(tempfile.mkdtemp(prefix=prefix))
        try:
            directory.chmod(stat.S_IRWXU)
            yield directory
        finally:
            Trees.remove(directory)

    @staticmethod
    def copy(project: Path, scratch: Path, names: Sequence[str]) -> None:
        """The project files a resolve reads, copied (never linked) into the private directory."""
        for name in names:
            source = project / name
            if source.is_file() and not source.is_symlink():
                target = scratch / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)


__all__ = [
    "SHIM_MARKER",
    "UNATTRIBUTED",
    "Fetcher",
    "InstallPlan",
    "InstallRefused",
    "InstallVerdict",
    "PackageFile",
    "PrivateDirectory",
    "Runner",
    "Scanner",
    "Subprocesses",
]
