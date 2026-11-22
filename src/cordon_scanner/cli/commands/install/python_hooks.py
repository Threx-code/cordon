"""The pip planner's callbacks: an sdist, a local project, or a build's tools, each fetched (or read
from disk), verified and scanned before pip may build or read it."""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.version import PROGRAM

if TYPE_CHECKING:
    from cordon_scanner.cli.commands.install.context import InstallContext
    from cordon_scanner.sources.install.pip import PipHooks
    from cordon_scanner.sources.install.plan import PackageFile


@dataclass
class PythonHooks:
    pip: list[str]
    context: InstallContext

    def hooks(self) -> PipHooks:
        from cordon_scanner.sources.install.pip import PipHooks

        return PipHooks(self.scan_sdist, self.scan_local, self.build_tools)

    def scan_sdist(self, name: str, version: str) -> tuple[str, tuple[str, ...]]:
        """Fetch, verify and scan the sdist pip would build; its version and build requirements if
        it passes."""
        from cordon_scanner.cli.commands.install.context import SdistBlocked
        from cordon_scanner.intel.registries.registry_client import RegistryClient, RegistryError
        from cordon_scanner.sources.install.pip import BuildRequires
        from cordon_scanner.sources.install.plan import InstallRefused, PrivateDirectory

        try:
            archive = RegistryClient.package_archive("pypi", name, version or None)
        except RegistryError as exc:
            raise InstallRefused(
                f"{name} needs a source build and its sdist could not be fetched: {exc}"
            ) from exc
        if archive.filename.endswith(".whl"):
            raise InstallRefused(
                f"{name}=={archive.version} has no wheel for this machine and no sdist"
            )
        with PrivateDirectory.made("cordon-sdist-") as scratch:
            (scratch / archive.filename.replace("/", "_")).write_bytes(archive.data)
            blocking = self.context.scan(scratch)
        if blocking:
            raise SdistBlocked(f"{name}=={archive.version}", blocking)
        print(
            f"{PROGRAM}: {name}=={archive.version} has no wheel; its sdist was scanned and passed",
            file=sys.stderr,
        )
        return archive.version, BuildRequires.of(archive.filename, archive.data)

    def scan_local(self, path: Path) -> tuple[str, ...]:
        """A local project, wheel or sdist, scanned where it is (Cordon reads it, runs nothing)."""
        from cordon_scanner.cli.commands.install.context import SdistBlocked
        from cordon_scanner.sources.install.pip import BuildRequires
        from cordon_scanner.sources.install.plan import PrivateDirectory

        if path.is_dir():
            blocking = self.context.scan(path)
        else:
            with PrivateDirectory.made("cordon-local-") as scratch:
                (scratch / path.name).write_bytes(path.read_bytes())
                blocking = self.context.scan(scratch)
        if blocking:
            raise SdistBlocked(f"the local project {path}", blocking)
        print(f"{PROGRAM}: {path} was scanned and passed", file=sys.stderr)
        return BuildRequires.of_project(path)

    def build_tools(self, requires: tuple[str, ...]) -> list[PackageFile]:
        """The wheels that satisfy `requires`, resolved wheel-only, fetched and scanned: offered to
        the build only (`build_only`), never installed into the person's environment."""
        from cordon_scanner.cli.commands.install.context import SdistBlocked
        from cordon_scanner.sources.install.guard import InstallGuard
        from cordon_scanner.sources.install.pip import PipPlanner
        from cordon_scanner.sources.install.plan import (
            InstallPlan,
            InstallRefused,
            PrivateDirectory,
            Subprocesses,
        )

        if not requires:
            return []
        with PrivateDirectory.made("cordon-build-") as scratch:
            report = scratch / "build-report.json"
            argv = [
                *self.pip,
                "install",
                "--dry-run",
                "--quiet",
                "--ignore-installed",
                "--report",
                str(report),
                "--only-binary=:all:",
                *requires,
            ]
            done = Subprocesses.run(argv, scratch, {**os.environ, "PIP_NO_INPUT": "1"})
            if done.returncode != 0:
                raise InstallRefused(
                    "the build tools these sources need could not be resolved as wheels:\n"
                    f"{(done.stderr or '').strip()[-1500:]}"
                )
            files = PipPlanner.files(
                json.loads(report.read_text(encoding="utf-8")),
                self.context.registries,
                build_only=True,
            )
            fetched = scratch / "files"
            fetched.mkdir(mode=0o700)
            verdict = InstallGuard.check(
                InstallPlan("pypi", files),
                self.context.scan,
                self.context.registries.fetch,
                fetched,
                self.context.cache,
            )
        if not verdict.ok:
            findings = tuple(f for found in verdict.blocking.values() for f in found)
            raise SdistBlocked(f"the build tools {', '.join(requires)}", findings)
        return files


@dataclass
class BuildRetry:
    """Run an install that builds a local project, adding each build tool its backend asks for only
    while it runs (hatchling's `editables` for an editable install): the tool is resolved wheel-only,
    scanned, put beside the scanned files, and the install tried again. Nothing comes from an index."""

    hooks: PipHooks
    context: InstallContext
    scratch: Path

    #: pip's and uv's words for a build requirement the scanned directory does not have.
    MISSING: ClassVar[tuple[re.Pattern[str], ...]] = (
        re.compile(
            r"No matching distribution found for ([A-Za-z0-9][A-Za-z0-9._\-\[\],<>=!~]{0,150})"
        ),
        re.compile(r"you require ([A-Za-z0-9][A-Za-z0-9._\-\[\],<>=!~]{0,150}), we can conclude"),
    )
    ROUNDS: ClassVar[int] = 6

    def run(self, argv: list[str], cwd: Path | None = None) -> int:
        from cordon_scanner.sources.install.guard import InstallGuard
        from cordon_scanner.sources.install.plan import InstallPlan, Subprocesses

        done = None
        for _ in range(self.ROUNDS):
            done = Subprocesses.run(argv, cwd or Path.cwd(), {**os.environ})
            missing = next(
                (
                    m.group(1)
                    for pattern in self.MISSING
                    if (m := pattern.search(done.stderr or ""))
                ),
                None,
            )
            if done.returncode == 0 or missing is None:
                break
            have = {p.name for p in self.scratch.iterdir()}
            tools = [f for f in self.hooks.build_tools((missing,)) if f.filename not in have]
            if not tools:
                break
            InstallGuard.fetch(
                InstallPlan("pypi", tools), self.scratch, self.context.registries.fetch
            )
        if done is None:
            return 1
        for stream, text in ((sys.stdout, done.stdout), (self.context.out, done.stderr)):
            if text:
                print(text.rstrip()[-4000:], file=stream)
        return done.returncode


__all__ = ["BuildRetry", "PythonHooks"]
