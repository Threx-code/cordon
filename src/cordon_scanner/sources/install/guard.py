"""Fetch, verify and scan an `InstallPlan`; the command installs only if nothing blocks.

`clone` and `pull` scan code before git writes it; this does the same for a package manager, which
is the larger door. `npm install` runs every lifecycle script in the tree it resolves, `pip install`
runs an sdist's `setup.py` merely to learn its dependencies, `cargo build` runs every `build.rs`, so a
scan *after* the install is a scan of a machine that has already run the payload.
"""

from __future__ import annotations

import os
import shutil
from concurrent.futures import FIRST_EXCEPTION, ThreadPoolExecutor, wait
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.plan import (
    UNATTRIBUTED,
    Fetcher,
    InstallPlan,
    InstallRefused,
    InstallVerdict,
    PackageFile,
    Scanner,
)

if TYPE_CHECKING:
    from cordon_scanner.foundation.models import Finding
    from cordon_scanner.sources.install.cache import VerdictCache


class InstallGuard:
    """Fetch, verify and scan a plan's files; install them only if nothing blocks."""

    WORKERS: ClassVar[int] = 8
    SCAN_DIRECTORY: ClassVar[str] = ".cordon-scan"
    LOCAL_LABEL: ClassVar[str] = "your project"

    @classmethod
    def fetch(cls, plan: InstallPlan, into: Path, fetcher: Fetcher) -> dict[str, PackageFile]:
        """Every file once, up to `WORKERS` at a time, each verified before it is written. The first
        failure stops the install: nothing half-fetched is ever scanned or installed."""
        unique: dict[str, PackageFile] = {}
        for file in plan.files:
            unique.setdefault(file.filename, file)
        if not unique:
            return {}
        with ThreadPoolExecutor(max_workers=min(cls.WORKERS, len(unique))) as pool:
            futures = [pool.submit(cls._one, file, into, fetcher) for file in unique.values()]
            done, pending = wait(futures, return_when=FIRST_EXCEPTION)
            for future in pending:
                future.cancel()
            for future in done:
                future.result()  # re-raises the first failure
        return unique

    @staticmethod
    def _one(file: PackageFile, into: Path, fetcher: Fetcher) -> None:
        try:
            data = fetcher(file.url, file.ecosystem)
        except InstallRefused:
            raise
        except (RuntimeError, OSError, ValueError) as exc:
            # The registry clients raise RegistryError (a RuntimeError) with a safe message.
            raise InstallRefused(f"{file.label} could not be downloaded: {exc}") from exc
        file.verify(data)
        descriptor = os.open(
            into / file.filename,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)

    @classmethod
    def check(
        cls,
        plan: InstallPlan,
        scan: Scanner,
        fetcher: Fetcher,
        into: Path,
        cache: VerdictCache | None = None,
    ) -> InstallVerdict:
        """Fetch the plan's files into `into` (a private directory the caller keeps for the install)
        and scan the ones with no fresh clean verdict, plus any local code the install would build,
        with `scan` (the command layer's: this layer reaches no engine). Every blocking finding is
        attributed to the file it came from."""
        written = cls.fetch(plan, into, fetcher)
        fresh = {
            name: file
            for name, file in written.items()
            if cache is None or not cache.clean(file.key)
        }
        blocking: dict[str, list[Finding]] = {}
        if fresh:
            for finding in cls._scan_files(fresh, into, scan):
                top = finding.location.path.split("/", 1)[0].split("!", 1)[0]
                # A finding Cordon cannot attribute still blocks: it came from these files.
                blocking.setdefault(top if top in fresh else UNATTRIBUTED, []).append(finding)
        for local in plan.local:
            for finding in scan(local):
                blocking.setdefault(f"{cls.LOCAL_LABEL} ({local.name})", []).append(finding)
        if not blocking and cache is not None:
            cache.remember([file.key for file in fresh.values()])
        return InstallVerdict(
            plan, {k: tuple(v) for k, v in blocking.items()}, len(written) - len(fresh)
        )

    @classmethod
    def _scan_files(
        cls, files: dict[str, PackageFile], into: Path, scan: Scanner
    ) -> tuple[Finding, ...]:
        """The files to scan, linked (else copied) into their own directory beside the install's,
        so a remembered file is not read again and the install directory holds only package files."""
        if len(files) == len(list(into.iterdir())):
            return scan(into)
        view = into / cls.SCAN_DIRECTORY
        view.mkdir(mode=0o700)
        try:
            for name in files:
                try:
                    os.link(into / name, view / name)
                except OSError:
                    shutil.copyfile(into / name, view / name)
            return scan(view)
        finally:
            shutil.rmtree(view, ignore_errors=True)


__all__ = ["InstallGuard"]
