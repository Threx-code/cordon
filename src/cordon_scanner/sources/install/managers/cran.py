"""R (`renv::restore()`): every package renv.lock pins, scanned before R builds it.

R runs a package's `configure` and `cleanup` scripts, and compiles its C, C++ and Fortran sources, as it installs it, so the code of a
dependency runs while dependencies are being got. What Cordon checks is `renv.lock`, which pins every package to a version and the
repository it came from. A CRAN package is fetched from CRAN's own file (its archive when the version is no longer current) and held to
the MD5 CRAN publishes for it: CRAN publishes no stronger hash and no size, so the check is by MD5 alone and says so; a mismatch is a
refusal, never a pass. A GitHub package is fetched as GitHub's tarball of the commit the lock pins, held to that commit. Anything else
(Bioconductor, a local file, another repository) is refused: nothing publishes a hash for it. A command that chooses versions
(`install.packages`, `renv::install`, `remotes::`, `pak::`, `devtools::install`) is refused for the same reason as in the other
planners. The R that then runs fetches the package again by its own means; renv checks a package only after it is installed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused, PackageFile

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from cordon_scanner.intel.registries.archive_sources.base import Located


class CranPlanner:
    RESTORES: ClassVar[re.Pattern[str]] = re.compile(r"\brenv::restore\b")
    CHOOSES: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:install\.packages|renv::(?:install|update|upgrade|hydrate)|remotes::install_\w+|pak::(?:pkg_install|pak)|"
        r"devtools::install\w*|BiocManager::install)\b"
    )
    NAME: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z][A-Za-z0-9.]{0,100}")
    VERSION: ClassVar[re.Pattern[str]] = re.compile(r"[0-9][0-9A-Za-z._-]{0,64}")
    REMOTE: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
    SHA: ClassVar[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}")
    NOTE: ClassVar[str] = (
        "CRAN publishes only an MD5 of each package and no size: its packages are verified by MD5 alone"
    )

    @classmethod
    def installs(cls, args: Sequence[str]) -> bool:
        text = " ".join(args)
        return bool(cls.RESTORES.search(text) or cls.CHOOSES.search(text))

    @classmethod
    def plan(
        cls, args: Sequence[str], project: Path, locate: Callable[[str, str], Located]
    ) -> InstallPlan:
        text = " ".join(args)
        chosen = cls.CHOOSES.search(text)
        if chosen:
            raise InstallRefused(
                f"`{chosen.group(0)}` chooses package versions, and R builds what it fetches (configure scripts, compiled code): "
                "Cordon cannot scan them first. Write renv.lock where you trust the packages, then run `renv::restore()` through Cordon"
            )
        lock = project / "renv.lock"
        if not lock.is_file():
            raise InstallRefused(
                "no renv.lock here: Cordon checks R installs against the packages the lock pins"
            )
        return InstallPlan(
            "cran", cls.files(lock.read_text(encoding="utf-8", errors="replace"), locate)
        )

    @classmethod
    def files(cls, text: str, locate: Callable[[str, str], Located]) -> list[PackageFile]:
        try:
            document = json.loads(text)
        except ValueError as exc:
            raise InstallRefused("renv.lock is not JSON Cordon can read") from exc
        packages = document.get("Packages") if isinstance(document, dict) else None
        if not isinstance(packages, dict):
            raise InstallRefused("renv.lock pins no packages Cordon can read")
        return [cls.entry(e, locate) for e in packages.values() if isinstance(e, dict)]

    @classmethod
    def entry(cls, entry: dict[str, object], locate: Callable[[str, str], Located]) -> PackageFile:
        name, version = str(entry.get("Package") or ""), str(entry.get("Version") or "")
        if not (cls.NAME.fullmatch(name) and cls.VERSION.fullmatch(version)):
            raise InstallRefused(
                f"{name[:60] or 'a package'}: an renv.lock entry Cordon cannot read"
            )
        source = str(entry.get("Source") or "")
        if source == "Repository" and str(entry.get("Repository") or "") == "CRAN":
            return cls.cran(name, version, locate)
        if source == "GitHub" and entry.get("RemoteHost") in (None, "api.github.com"):
            return cls.github(name, version, entry)
        raise InstallRefused(
            f"{name} {version} comes from {source[:30] or 'an unknown source'}"
            f"{' ' + str(entry.get('Repository'))[:30] if entry.get('Repository') else ''}: Cordon checks R packages from CRAN "
            "(by MD5) and GitHub (by commit) only; nothing publishes a hash for the rest"
        )

    @classmethod
    def cran(cls, name: str, version: str, locate: Callable[[str, str], Located]) -> PackageFile:
        from cordon_scanner.intel.registries.registry_request import RegistryError

        try:
            found = locate(name, version)
        except RegistryError as exc:
            raise InstallRefused(f"{name} {version}: {exc}") from exc
        digest = next((h for a, h in found.digests if a == "md5"), None)
        if digest is None:
            raise InstallRefused(
                f"{name} {version}: CRAN states no MD5 for it, so nothing verifies it"
            )
        return PackageFile("cran", name, version, found.url, "md5", bytes.fromhex(digest))

    @classmethod
    def github(cls, name: str, version: str, entry: dict[str, object]) -> PackageFile:
        owner, repo, sha = (
            str(entry.get(k) or "") for k in ("RemoteUsername", "RemoteRepo", "RemoteSha")
        )
        if not (
            cls.REMOTE.fullmatch(owner) and cls.REMOTE.fullmatch(repo) and cls.SHA.fullmatch(sha)
        ):
            raise InstallRefused(
                f"{name}: a GitHub entry in renv.lock Cordon cannot read (it needs the user, the repository and a commit)"
            )
        return PackageFile(
            "cran",
            name,
            version,
            f"https://codeload.github.com/{owner}/{repo}/tar.gz/{sha}",
            "git-commit",
            bytes.fromhex(sha),
        )


__all__ = ["CranPlanner"]
