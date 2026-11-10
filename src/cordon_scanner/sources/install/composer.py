"""Composer (`composer install`, `update`, `require`): every package scanned before Composer unpacks
it into `vendor/`, where its plugins run during the install and its code runs on the first request.

The resolve is Composer's own and runs no package code: `update`/`require` as typed with
`--no-install --no-scripts --no-plugins`, against a private cache, writes `composer.lock`;
`install` reads the lock that is there. `composer.json` and `composer.lock` are saved first and put
back if anything blocks.

Packagist publishes no file hash for the GitHub archives nearly every package is served from (the
lock's `shasum` is empty), so each file is held to the commit the lock pins instead: fetched from
codeload.github.com by that commit, and refused unless GitHub's archive names the same commit
(`hashes.CommitArchive`). A dist that does carry a `shasum` (a private repository, a mirror) is held
to it, as Composer itself does. The install then runs offline against a cache holding only the
scanned files, under the names Composer looks for (the sha1 of the lock's URL), so the bytes that
install are the bytes that were scanned.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused, PackageFile, Runner

if TYPE_CHECKING:
    from collections.abc import Sequence


class ComposerPlanner:
    RESOLVING: ClassVar[frozenset[str]] = frozenset({"update", "upgrade", "require"})
    GUARDED: ClassVar[frozenset[str]] = RESOLVING | {"install"}
    SAVED: ClassVar[tuple[str, ...]] = ("composer.json", "composer.lock")
    GITHUB: ClassVar[re.Pattern[str]] = re.compile(
        r"https://api\.github\.com/repos/([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100})/zipball/([0-9a-f]{40})"
    )
    NAME: ClassVar[re.Pattern[str]] = re.compile(r"[a-z0-9_.-]{1,100}/[a-z0-9_.-]{1,100}")
    #: The install's own options, kept when an update or require is followed by the install.
    KEPT: ClassVar[frozenset[str]] = frozenset(
        {"--no-dev", "-o", "--optimize-autoloader", "-a", "--classmap-authoritative",
         "--apcu-autoloader", "--ignore-platform-reqs", "-n", "--no-interaction", "-q", "--quiet",
         "-v", "-vv", "-vvv", "--no-progress", "--no-scripts", "--no-plugins", "--no-autoloader"}
    )  # fmt: skip

    @staticmethod
    def installs(args: Sequence[str]) -> bool:
        return bool(args) and args[0] in ComposerPlanner.GUARDED and "--dry-run" not in args

    @classmethod
    def project(
        cls, args: Sequence[str], runner: Runner, composer: str, project: Path, cache: Path
    ) -> InstallPlan:
        """The lock to install: Composer's resolve for update/require, the lock as it is for
        install (resolved first when there is none). `saved:` manifests are what to restore."""
        saved = {n: (project / n).read_bytes() for n in cls.SAVED if (project / n).is_file()}
        if "composer.json" not in saved:
            raise InstallRefused("no composer.json here: Composer has nothing to install")
        if args[0] in cls.RESOLVING or "composer.lock" not in saved:
            verb = list(args) if args[0] in cls.RESOLVING else ["update"]
            done = runner(
                [composer, *verb, "--no-install", "--no-scripts", "--no-plugins", "-n"],
                project,
                {**os.environ, "COMPOSER_CACHE_DIR": str(cache)},
            )
            if done.returncode != 0:
                cls.restore(project, saved)
                raise InstallRefused(
                    "Composer could not resolve:\n"
                    + (done.stderr or done.stdout or "").strip()[-2000:]
                )
        try:
            lock = json.loads((project / "composer.lock").read_text(encoding="utf-8"))
            plan = InstallPlan("composer", cls.files(lock, dev="--no-dev" not in args))
        except (OSError, ValueError, InstallRefused) as exc:
            cls.restore(project, saved)
            if isinstance(exc, InstallRefused):
                raise
            raise InstallRefused("Composer wrote no composer.lock Cordon can read") from exc
        plan.manifests = {f"saved:{n}": data for n, data in saved.items()}
        return plan

    @classmethod
    def entries(cls, lock: dict[str, Any], *, dev: bool) -> list[dict[str, Any]]:
        sections = ("packages", "packages-dev") if dev else ("packages",)
        return [p for s in sections for p in (lock.get(s) or []) if isinstance(p, dict)]

    @classmethod
    def files(cls, lock: dict[str, Any], *, dev: bool = True) -> list[PackageFile]:
        return [cls.package_file(entry) for entry in cls.entries(lock, dev=dev)]

    @classmethod
    def package_file(cls, entry: dict[str, Any]) -> PackageFile:
        name = str(entry.get("name") or "")
        version = str(entry.get("version") or "")
        if not cls.NAME.fullmatch(name):
            raise InstallRefused(f"{name[:100]!r} is not a Composer package name")
        dist = entry.get("dist") or {}
        if not dist:
            raise InstallRefused(f"{name} installs from source only: Cordon checks dist archives")
        url = str(dist.get("url") or "")
        shasum = str(dist.get("shasum") or "")
        if re.fullmatch(r"[0-9a-f]{40}", shasum):
            return PackageFile(
                "composer", name, version, url, "sha1", bytes.fromhex(shasum), separator=":"
            )
        github = cls.GITHUB.fullmatch(url)
        reference = str(dist.get("reference") or "")
        if github is None or github.group(3) != reference:
            raise InstallRefused(
                f"{name} {version} comes from {url[:120]} with no hash to hold it to: Cordon "
                "checks GitHub archives by their commit, and other dists by the shasum in the lock"
            )
        owner, repo, commit = github.groups()
        return PackageFile(
            "composer",
            name,
            version,
            f"https://codeload.github.com/{owner}/{repo}/legacy.zip/{commit}",
            "commit",
            bytes.fromhex(commit),
            separator=":",
        )

    @classmethod
    def seed(cls, lock: dict[str, Any], scanned: Path, cache: Path, *, dev: bool) -> None:
        """The scanned files where Composer's cache looks for them: `files/<name>/<sha1 of the
        lock's URL>.<type>`."""
        for entry in cls.entries(lock, dev=dev):
            file = cls.package_file(entry)
            dist = entry["dist"]
            kind = re.sub(r"[^a-z0-9]", "", str(dist.get("type") or "zip"))[:10] or "zip"
            key = hashlib.sha1(str(dist["url"]).encode(), usedforsecurity=False).hexdigest()
            target = cache / "files" / file.name / f"{key}.{kind}"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((scanned / file.filename).read_bytes())

    @classmethod
    def install_command(cls, composer: str, args: Sequence[str]) -> list[str]:
        """What runs once every package passed: `install` itself as typed, or the install a resolve
        leads to, with the person's install options."""
        if args[0] == "install":
            return [composer, *args]
        return [composer, "install", *(a for a in args[1:] if a in cls.KEPT)]

    @staticmethod
    def offline_env(cache: Path) -> dict[str, str]:
        """Composer with no network and only the scanned files in its cache."""
        return {**os.environ, "COMPOSER_CACHE_DIR": str(cache), "COMPOSER_DISABLE_NETWORK": "1"}

    @staticmethod
    def restore(project: Path, saved: dict[str, bytes]) -> None:
        for name in ComposerPlanner.SAVED:
            target = project / name
            if name in saved:
                target.write_bytes(saved[name])
            elif target.is_file():
                target.unlink()


__all__ = ["ComposerPlanner"]
