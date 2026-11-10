"""pub (`dart pub`, `flutter pub`): every package scanned before pub puts it in the cache a build
reads (a package's build hooks and builders run in the next build).

The resolve is pub's own and runs no package code: `pub get` (or `add`, `upgrade`, `downgrade` as
typed) in the project, with a private `PUB_CACHE` Cordon deletes, writes `pubspec.lock`. `pubspec.yaml`
and `pubspec.lock` are saved first and put back if anything blocks. Each hosted package's `sha256` in
the lock is the sha256 pub.dev publishes for its archive, which Cordon fetches, verifies and scans. pub
then runs `get --enforce-lockfile`, which fetches into the real cache and checks every archive
against the same hash.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused, PackageFile, Runner

if TYPE_CHECKING:
    from collections.abc import Sequence


class PubPlanner:
    GUARDED: ClassVar[frozenset[str]] = frozenset({"get", "upgrade", "downgrade", "add"})
    HOST: ClassVar[str] = "https://pub.dev"
    SAVED: ClassVar[tuple[str, ...]] = ("pubspec.yaml", "pubspec.lock")
    #: The fields of a `pubspec.lock` package entry this reads.
    FIELDS: ClassVar[frozenset[str]] = frozenset({"name", "sha256", "url", "source", "version"})

    @staticmethod
    def installs(args: Sequence[str]) -> bool:
        return len(args) >= 2 and args[0] == "pub" and args[1] in PubPlanner.GUARDED

    @classmethod
    def project(
        cls, args: Sequence[str], runner: Runner, tool: str, project: Path, cache: Path
    ) -> InstallPlan:
        """Resolve in the project into `cache` (saved first: `saved:` entries are what to restore)."""
        saved = {n: (project / n).read_bytes() for n in cls.SAVED if (project / n).is_file()}
        if "pubspec.yaml" not in saved:
            raise InstallRefused("no pubspec.yaml here: pub has nothing to resolve")
        done = runner(
            [tool, *args],
            project,
            {**os.environ, "PUB_CACHE": str(cache), "PUB_ENVIRONMENT": "cordon"},
        )
        if done.returncode != 0:
            cls.restore(project, saved)
            raise InstallRefused(
                f"pub could not resolve:\n{(done.stderr or done.stdout or '').strip()[-2000:]}"
            )
        lock = project / "pubspec.lock"
        try:
            plan = InstallPlan("pub", cls.files(lock.read_text(encoding="utf-8")))
        except (InstallRefused, OSError) as exc:
            cls.restore(project, saved)
            raise (
                exc
                if isinstance(exc, InstallRefused)
                else InstallRefused("pub wrote no pubspec.lock")
            ) from exc
        plan.manifests = {f"saved:{n}": data for n, data in saved.items()}
        return plan

    @classmethod
    def files(cls, text: str) -> list[PackageFile]:
        """The hosted packages of a `pubspec.lock`; SDK and path packages are the person's own."""
        entries: dict[str, dict[str, str]] = {}
        current = ""
        inside = False
        for line in text.splitlines():
            if line and not line.startswith(" "):
                inside = line.strip() == "packages:"
                continue
            if not inside:
                continue
            indent = len(line) - len(line.lstrip(" "))
            key, colon, value = line.strip().partition(":")
            if not colon:
                continue
            if indent == 2:
                current = key
                entries[current] = {}
            elif current and indent >= 4 and key in cls.FIELDS:
                entries[current].setdefault(key, value.strip().strip('"'))
        out: list[PackageFile] = []
        for package, fields in entries.items():
            source = fields.get("source", "")
            if source in ("sdk", "path"):
                continue
            if source != "hosted":
                raise InstallRefused(
                    f"{package} comes from a {source or 'unknown'} source: not checked"
                )
            if fields.get("url", "").rstrip("/") != cls.HOST:
                raise InstallRefused(
                    f"{package} comes from {fields.get('url', '')[:100]}: not pub.dev"
                )
            sha256 = fields.get("sha256", "")
            version = fields.get("version", "")
            if not re.fullmatch(r"[0-9a-f]{64}", sha256):
                raise InstallRefused(f"{package} has no sha256 in pubspec.lock")
            if not re.fullmatch(r"[0-9A-Za-z.+-]{1,64}", version):
                raise InstallRefused(f"{package} has no version pub.dev serves")
            out.append(
                PackageFile(
                    "pub",
                    package,
                    version,
                    f"{cls.HOST}/api/archives/{package}-{version}.tar.gz",
                    "sha256",
                    bytes.fromhex(sha256),
                    separator=" ",
                )
            )
        return out

    @staticmethod
    def restore(project: Path, saved: dict[str, bytes]) -> None:
        for name in PubPlanner.SAVED:
            target = project / name
            if name in saved:
                target.write_bytes(saved[name])
            elif target.is_file():
                target.unlink()

    @staticmethod
    def locked(tool: str) -> list[str]:
        """What runs once every package passed: a get that fetches only what the lock records and
        checks each archive against the lock's hash."""
        return [tool, "pub", "get", "--enforce-lockfile"]


__all__ = ["PubPlanner"]
