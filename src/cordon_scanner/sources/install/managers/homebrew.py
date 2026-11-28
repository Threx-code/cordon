"""Homebrew (`brew install|reinstall|upgrade`): every bottle scanned before brew pours it.

A bottle is a file with a published SHA-256, and Homebrew checks that hash itself before it pours one, so the hash
brew's own formula data names is the one Cordon checks. The resolve is brew's, which runs no formula code: `brew deps`
names what each formula needs and `brew info --json=v2` gives each one's version and its bottle's blob on ghcr.io. Each blob is
fetched from `ghcr.io/v2/homebrew/core/<formula>`, held to that SHA-256, and the lot is scanned (a bottle carries the formula
as it will be installed, `.brew/<formula>.rb`, whose `post_install` brew runs). Brew is then run with its auto-update
switched off, so it works from the same formula data that was read: the bottles it pours are the bottles that were scanned.

Refused, because brew would run code Cordon has not scanned: a cask (a vendor's installer, downloaded from the vendor's own
host), a formula with no bottle for this machine or `--build-from-source` (the formula's build runs), `--HEAD`, a formula from
any tap but `homebrew/core`, and any option Cordon does not know.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from cordon_scanner.intel.registries.registry_image import RegistryImage


@dataclass(frozen=True)
class HomebrewPlan:
    plan: InstallPlan | None
    #: The formulae whose bottles were scanned, with their versions.
    formulae: tuple[str, ...]


class HomebrewPlanner:
    VERBS: ClassVar[frozenset[str]] = frozenset({"install", "reinstall", "upgrade"})
    FLAGS: ClassVar[frozenset[str]] = frozenset(
        {
            "--formula",
            "--formulae",
            "-q",
            "--quiet",
            "-v",
            "--verbose",
            "-d",
            "--debug",
            "-f",
            "--force",
        }
    )
    DRY_RUN: ClassVar[frozenset[str]] = frozenset({"-n", "--dry-run"})
    REFUSED: ClassVar[dict[str, str]] = {
        "--cask": "a cask is a vendor's installer, downloaded from the vendor's own host, which Cordon cannot check",
        "--casks": "a cask is a vendor's installer, downloaded from the vendor's own host, which Cordon cannot check",
        "-s": "a formula built from source runs its build, and Cordon scans bottles",
        "--build-from-source": "a formula built from source runs its build, and Cordon scans bottles",
        "--HEAD": "a formula's head is built from source and has no published hash",
        "--head": "a formula's head is built from source and has no published hash",
    }
    NAME: ClassVar[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9@+._-]{0,99}")
    DIGEST: ClassVar[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")
    MAX_FORMULAE: ClassVar[int] = 200
    ROOT: ClassVar[str] = "https://ghcr.io/v2/homebrew/core"

    @classmethod
    def installs(cls, args: Sequence[str]) -> bool:
        if args and args[0].startswith("-"):
            return any(a in cls.VERBS for a in args) and not cls.DRY_RUN & set(args)
        return bool(args) and args[0] in cls.VERBS and not cls.DRY_RUN & set(args)

    @classmethod
    def names(cls, args: Sequence[str]) -> tuple[str, list[str]]:
        """The verb and the formula names the command names; an option it does not know is refused."""
        if args[0].startswith("-"):
            raise InstallRefused(
                "an option before the command is not read by Cordon: put it after `install`"
            )
        names: list[str] = []
        for word in args[1:]:
            if word in cls.REFUSED:
                raise InstallRefused(f"`{word}` is refused: {cls.REFUSED[word]}")
            if word.startswith("-"):
                if word in cls.FLAGS:
                    continue
                raise InstallRefused(
                    f"Cordon does not know the option {word}; it could change what brew installs, "
                    "so it cannot say what will be pulled"
                )
            if not cls.NAME.fullmatch(word):
                raise InstallRefused(
                    f"{word} is not a homebrew/core formula name (a tap, a path or a URL runs a formula Cordon cannot check)"
                )
            names.append(word)
        return args[0], names

    @classmethod
    def plan(
        cls,
        args: Sequence[str],
        directory: Path,
        brew: Callable[[Sequence[str]], str],
        make: Callable[[str, str], RegistryImage] | None = None,
    ) -> HomebrewPlan:
        """The bottles of what `args` would install, fetched and checked into `directory` for scanning."""
        verb, requested = cls.names(args)
        if not requested:
            if verb != "upgrade":
                raise InstallRefused(f"`{verb}` names no formula")
            requested = [n for n in brew(["outdated", "--formula", "--quiet"]).split() if n]
            if not requested:
                return HomebrewPlan(None, ())
        needed = brew(["deps", "--formula", "--union", *requested]).split()
        wanted = list(dict.fromkeys([*requested, *needed]))
        if len(wanted) > cls.MAX_FORMULAE:
            raise InstallRefused(f"more than {cls.MAX_FORMULAE} formulae would be installed")
        try:
            document = json.loads(brew(["info", "--json=v2", *wanted]))
        except ValueError as exc:
            raise InstallRefused(f"`brew info` gave something that is not JSON: {exc}") from exc
        known = cls.formulae(document, requested)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        labels: list[str] = []
        for name in wanted:
            entry = known.get(name)
            if entry is None:
                raise InstallRefused(f"brew knows no formula named {name}")
            labels.append(cls.pour(entry, directory, make or cls.registry))
        return HomebrewPlan(InstallPlan("homebrew", local=[directory]), tuple(labels))

    @classmethod
    def formulae(cls, document: Any, requested: Sequence[str]) -> dict[str, dict[str, Any]]:
        """Each formula in a `brew info --json=v2` answer by name; a cask among the requested is refused."""
        if not isinstance(document, dict):
            raise InstallRefused("`brew info` gave an answer Cordon cannot read")
        known = {
            str(f["name"]): f
            for f in document.get("formulae") or ()
            if isinstance(f, dict) and isinstance(f.get("name"), str)
        }
        asked = {n.lower() for n in requested}
        for cask in document.get("casks") or ():
            names = {
                str(cask.get("token", "")).lower(),
                *(str(n).lower() for n in cask.get("old_tokens") or ()),
            }
            if names & asked:
                raise InstallRefused(f"{cask.get('token')} is a cask: {cls.REFUSED['--cask']}")
        for name in requested:
            if name not in known:
                alias = next(
                    (n for n, f in known.items() if name in (f.get("aliases") or ())), None
                )
                if alias is not None:
                    known[name] = known[alias]
        return known

    @classmethod
    def pour(
        cls, entry: dict[str, Any], directory: Path, make: Callable[[str, str], RegistryImage]
    ) -> str:
        """Fetch one formula's bottle, held to its published SHA-256; the label `name@version`."""
        from cordon_scanner.intel.registries.registry_image import Pull, RegistryImageError

        name = str(entry["name"])
        versions = entry.get("versions")
        version = str(versions.get("stable") or "") if isinstance(versions, dict) else ""
        revision = entry.get("revision")
        if isinstance(revision, int) and revision:
            version = f"{version}_{revision}"
        if not version or not cls.NAME.fullmatch(name):
            raise InstallRefused(f"{name}: brew names no stable version to install")
        stable = (entry.get("bottle") or {}).get("stable") or {}
        files = stable.get("files") if isinstance(stable, dict) else None
        if not isinstance(files, dict) or not files:
            raise InstallRefused(
                f"{name} has no bottle: brew would build it, which runs its build before Cordon "
                "can scan it"
            )
        tag = "all" if "all" in files else (next(iter(files)) if len(files) == 1 else "")
        if not tag:
            raise InstallRefused(
                f"{name} has bottles for {len(files)} platforms and brew's data does not say "
                "which this machine takes"
            )
        bottle = files[tag]
        digest = str(bottle.get("sha256", "")) if isinstance(bottle, dict) else ""
        expected = f"{cls.ROOT}/{name.replace('@', '/')}/blobs/sha256:{digest}"
        if not cls.DIGEST.fullmatch(digest) or bottle.get("url") != expected:
            raise InstallRefused(
                f"{name}'s bottle does not come from homebrew/core on ghcr.io: not checked"
            )
        client = make("ghcr.io", f"homebrew/core/{name.replace('@', '/')}")
        try:
            data = client.blob(f"sha256:{digest}", Pull())
        except RegistryImageError as exc:
            raise InstallRefused(f"{name}: {exc}") from exc
        safe = re.sub(r"[^A-Za-z0-9._+-]", "_", f"{name}-{version}")
        target = directory / f"{safe}.bottle.tar.gz"
        target.write_bytes(data)
        target.chmod(0o600)
        return f"{name}@{version}"

    @staticmethod
    def registry(registry: str, repository: str) -> RegistryImage:
        from cordon_scanner.intel.registries.registry_image import RegistryImage

        return RegistryImage(registry, repository)


__all__ = ["HomebrewPlan", "HomebrewPlanner"]
