"""conda (and mamba): every package scanned before conda links it into an environment, where its
pre-link and post-link scripts run.

The resolve is conda's own and runs no package code: the command as typed with `--dry-run --json`,
against a private package cache Cordon deletes, so conda lists every package it would fetch with its
URL and sha256. Cordon fetches each from its channel, verifies and scans it, and places the scanned
files in conda's own package cache under the names conda gives them. The install then runs from an
`@EXPLICIT` file naming exactly those files, `--offline`: conda solves nothing, reads no
channel, and links exactly the scanned files.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused, PackageFile, Runner

if TYPE_CHECKING:
    from collections.abc import Sequence


class CondaPlanner:
    GUARDED: ClassVar[frozenset[str]] = frozenset({"install", "create", "update", "upgrade"})
    #: Channel hosts Cordon fetches from: conda-forge and the other anaconda.org channels, and
    #: Anaconda's own defaults.
    HOSTS: ClassVar[frozenset[str]] = frozenset({"conda.anaconda.org", "repo.anaconda.com"})
    ARCHIVE: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_.+-]{1,200}\.(?:conda|tar\.bz2)")

    @staticmethod
    def installs(args: Sequence[str]) -> bool:
        if args[:1] == ["env"]:
            return len(args) > 1 and args[1] in ("create", "update")
        return bool(args) and args[0] in CondaPlanner.GUARDED and "--dry-run" not in args

    @classmethod
    def plan(cls, args: Sequence[str], runner: Runner, conda: str, cache: Path) -> InstallPlan:
        """What the command would fetch, read from conda's dry run into an empty private cache."""
        if args[:1] == ["env"]:
            raise InstallRefused(
                "Cordon does not check `conda env create/update` yet; create the environment with "
                "`conda create --file` or `conda install` through Cordon"
            )
        done = runner(
            [conda, *args, "--dry-run", "--json"],
            Path.cwd(),
            {**os.environ, "CONDA_PKGS_DIRS": str(cache)},
        )
        try:
            answer: dict[str, Any] = json.loads(done.stdout or "{}")
        except ValueError as exc:
            raise InstallRefused(
                f"conda's dry run could not be read:\n{(done.stderr or '').strip()[-2000:]}"
            ) from exc
        if done.returncode != 0 or answer.get("error") or answer.get("exception_name"):
            message = str(answer.get("message") or answer.get("error") or done.stderr or "")
            raise InstallRefused(f"conda could not resolve the install:\n{message.strip()[-2000:]}")
        fetch = (answer.get("actions") or {}).get("FETCH") or []
        return InstallPlan("conda", [cls.package_file(entry) for entry in fetch])

    @classmethod
    def package_file(cls, entry: dict[str, Any]) -> PackageFile:
        url = str(entry.get("url") or "")
        parsed = urllib.parse.urlsplit(url)
        name = str(entry.get("name") or "")
        if parsed.scheme != "https" or parsed.hostname not in cls.HOSTS:
            raise InstallRefused(
                f"{name or url[:80]} comes from {parsed.hostname or url[:80]}: Cordon fetches "
                "from conda.anaconda.org and repo.anaconda.com only"
            )
        sha256 = str(entry.get("sha256") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise InstallRefused(f"{name} has no sha256 in its channel's index")
        if not cls.ARCHIVE.fullmatch(cls.archive_name(url)):
            raise InstallRefused(f"{name}: {url[:120]} is not a conda package file")
        return PackageFile(
            "conda",
            name,
            f"{entry.get('version', '')}-{entry.get('build', '')}",
            url,
            "sha256",
            bytes.fromhex(sha256),
            separator="=",
        )

    @staticmethod
    def archive_name(url: str) -> str:
        return urllib.parse.unquote(urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1])

    @staticmethod
    def package_cache(runner: Runner, conda: str) -> Path:
        """conda's own first package cache, where `--offline` finds the scanned files."""
        done = runner([conda, "info", "--json"], Path.cwd(), {**os.environ})
        try:
            directories = json.loads(done.stdout or "{}").get("pkgs_dirs") or []
        except ValueError:
            directories = []
        for directory in directories:
            path = Path(str(directory))
            path.mkdir(parents=True, exist_ok=True)
            if os.access(path, os.W_OK):
                return path
        raise InstallRefused("conda has no package cache Cordon can write the scanned files to")

    @classmethod
    def place(cls, files: Sequence[PackageFile], scanned: Path, cache: Path) -> None:
        """The scanned files, under the names conda gives them, in its package cache, each with its
        URL in the cache's `urls.txt`, which is how conda knows which channel a cached file is."""
        for file in files:
            (cache / cls.archive_name(file.url)).write_bytes((scanned / file.filename).read_bytes())
        urls = cache / "urls.txt"
        known = set(urls.read_text(encoding="utf-8").split()) if urls.is_file() else set()
        new = [f.url for f in files if f.url not in known]
        if new:
            with urls.open("a", encoding="utf-8") as out:
                out.writelines(url + "\n" for url in new)

    #: Options kept from the person's command: where the environment is, and how conda talks.
    KEPT_FLAGS: ClassVar[frozenset[str]] = frozenset(
        {"-y", "--yes", "-q", "--quiet", "-v", "--verbose"}
    )
    KEPT_VALUED: ClassVar[frozenset[str]] = frozenset({"-n", "--name", "-p", "--prefix"})
    #: Options that take a value: their value is neither kept nor a package spec.
    VALUED: ClassVar[frozenset[str]] = frozenset(
        {"-c", "--channel", "--file", "--repodata-fn", "--solver", "--platform", "--subdir"}
    )

    @staticmethod
    def explicit(files: Sequence[PackageFile], scanned: Path) -> str:
        """An `@EXPLICIT` file: each package by its URL and the md5 of the scanned bytes Cordon
        placed (the key conda's package cache matches a cached file by; the sha256 was checked
        against the channel before the scan), so nothing is solved and only those bytes link."""
        lines = (
            f"{f.url}#{hashlib.md5((scanned / f.filename).read_bytes(), usedforsecurity=False).hexdigest()}\n"
            for f in files
        )
        return "@EXPLICIT\n" + "".join(lines)

    @classmethod
    def explicit_command(cls, args: Sequence[str], spec_file: Path) -> list[str]:
        """The person's command, installing from the explicit file offline: where the environment
        is and how conda talks are kept; package specs and channels are the file's now."""
        verb = "create" if args[0] == "create" else "install"
        kept: list[str] = []
        values = iter(args[1:])
        for arg in values:
            option, equals, _ = arg.partition("=")
            if option in cls.KEPT_VALUED:
                kept += [arg] if equals else [arg, next(values, "")]
            elif arg in cls.KEPT_FLAGS:
                kept.append(arg)
            elif option in cls.VALUED and not equals:
                next(values, None)
        return [verb, *kept, "--file", str(spec_file), "--offline"]


__all__ = ["CondaPlanner"]
