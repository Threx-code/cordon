"""What an upstream look-up returns and reads: an upstream named or not, its result, and the archives
(a repository snapshot or a registry tarball) the content checks open.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, ClassVar, Final

VCPKG_RAW: Final = "https://raw.githubusercontent.com/microsoft/vcpkg"


@dataclass(frozen=True)
class Upstream:
    """What OSV is asked about: a repository at a tag, a commit, or a Go module at a version."""

    query: dict[str, Any]
    how: str
    """For the finding: what the package was matched through."""
    inferred: bool = False
    """Whether the tag was found in the repository (`TagInference`) rather than named."""
    tag: str = ""
    """The tag an inferred upstream was found as."""


@dataclass(frozen=True)
class Unnamed:
    reason: str
    nothing: bool = False
    """Nothing to check: the package installs no code (an empty vcpkg port wrapping a system
    component). Counted as checked, with nothing to match."""
    homes: tuple[str, ...] = ()
    """The homepage and download URLs its ecosystem gives, read on the way to this answer: what
    `intel/nvd` ties a package to a CPE product by when no repository route named it."""
    version: str = ""
    """The release the route resolved where the lockfile names none (a vcpkg port at its
    baseline): what `intel/nvd` compares NVD's ranges with."""


class RepositoryArchive:
    """A repository and ref from an archive URL, in the fixed forms the forges serve them."""

    ARCHIVE: ClassVar[str] = r"(?:\.tar\.gz|\.tgz|\.tar\.bz2|\.tar\.xz|\.zip)"
    FORMS: ClassVar[tuple[re.Pattern[str], ...]] = (
        re.compile(rf"^https://github\.com/([\w.-]+)/([\w.-]+)/archive/refs/tags/(.+?){ARCHIVE}$"),
        re.compile(rf"^https://github\.com/([\w.-]+)/([\w.-]+)/archive/(?!refs/)(.+?){ARCHIVE}$"),
        re.compile(r"^https://github\.com/([\w.-]+)/([\w.-]+)/releases/download/([^/]+)/[^/]+$"),
        re.compile(
            r"^https://codeload\.github\.com/([\w.-]+)/([\w.-]+)/(?:tar\.gz|zip|legacy\.tar\.gz)"
            r"/(?:refs/tags/)?(?!refs/)(.+)$"
        ),
        re.compile(
            r"^https://api\.github\.com/repos/([\w.-]+)/([\w.-]+)/(?:tarball|zipball)/(.+)$"
        ),  # One file at a commit (glext's `.../raw/<sha>/api/GL/glext.h`): the commit is exact.
        re.compile(r"^https://github\.com/([\w.-]+)/([\w.-]+)/(?:raw|blob)/([0-9a-f]{40})/"),
        re.compile(r"^https://raw\.githubusercontent\.com/([\w.-]+)/([\w.-]+)/([0-9a-f]{40})/"),
    )
    #: cgit's snapshot of a commit (savannah's gnu-config: `cgit/config.git/snapshot/
    #: config-<sha>.tar.gz`): the commit is exact, on the snapshot's own repository.
    CGIT_SNAPSHOT: ClassVar[re.Pattern[str]] = re.compile(
        r"^https?://([\w.-]+)/((?:cgit/)?[\w./+-]+?)/snapshot/[\w.+-]*?-([0-9a-f]{40})"
        r"\.(?:tar\.gz|tar\.xz|tar\.bz2|zip)$"
    )
    #: Codeberg (Forgejo): `/<owner>/<repo>/archive/<ref>.tar.gz`.
    CODEBERG: ClassVar[re.Pattern[str]] = re.compile(
        r"^https://codeberg\.org/([\w.-]+)/([\w.-]+)/archive/(.+?)(?:\.tar\.gz|\.zip)$"
    )
    #: A GitLab release's asset, on any GitLab: `<project>/-/releases/<tag>/downloads/<file>`.
    GITLAB_RELEASE: ClassVar[re.Pattern[str]] = re.compile(
        r"^(https://[\w.-]+(?::\d+)?/[\w.~-]+(?:/[\w.~-]+){1,8}?)/-/releases/([^/]+)/downloads/[^/]+$"
    )
    #: One file at a ref that is not a commit: a tag, or a branch, which `from_urls` tells apart.
    RAW_AT_REF: ClassVar[re.Pattern[str]] = re.compile(
        r"^https://raw\.githubusercontent\.com/([\w.-]+)/([\w.-]+)/(?!refs/)([^/]+)/"
    )
    GITLAB: ClassVar[re.Pattern[str]] = re.compile(
        # On any GitLab (gitlab.com, gitlab.freedesktop.org, gitlab.gnome.org): the form is GitLab's.
        r"^(https://[\w.-]+(?::\d+)?/[\w.-][\w./-]{0,200}?)/-/archive/([^/]+)/[^/]+$"
    )

    @staticmethod
    def parse(url: str) -> tuple[str, str] | None:
        """`(https repository URL, ref)`, or None for any other URL."""
        # GitHub serves the same archive over http as https (re2's conda recipe writes http).
        url = re.sub(
            r"^http://(github\.com|codeload\.github\.com|raw\.githubusercontent\.com)/",
            r"https://\1/",
            url,
        )
        for form in RepositoryArchive.FORMS:
            found = form.match(url)
            if found:
                owner, repo, ref = found.groups()
                return (
                    f"https://github.com/{owner}/{repo.removesuffix('.git')}",
                    urllib.parse.unquote(ref),
                )
        found = RepositoryArchive.CGIT_SNAPSHOT.match(url)
        if found:
            return f"https://{found.group(1)}/{found.group(2)}", found.group(3)
        found = RepositoryArchive.CODEBERG.match(url)
        if found:
            return (
                f"https://codeberg.org/{found.group(1)}/{found.group(2)}",
                urllib.parse.unquote(found.group(3)),
            )
        found = RepositoryArchive.GITLAB_RELEASE.match(url)
        if found:
            return found.group(1), urllib.parse.unquote(found.group(2))
        found = RepositoryArchive.GITLAB.match(url)
        if found:
            return found.group(1), urllib.parse.unquote(found.group(2))
        return None

    @staticmethod
    def repository(url: str) -> str | None:
        """`https://github.com/owner/repo` for a git URL on GitHub or GitLab, else None."""
        found = re.match(
            r"^(?:git\+)?(?:https://|git://|ssh://git@|git@)(github\.com|gitlab\.com)[/:]"
            r"([\w.-]+)/([\w.-]+?)(?:\.git)?/?$",
            url.strip(),
        )
        return f"https://{found.group(1)}/{found.group(2)}/{found.group(3)}" if found else None

    @staticmethod
    def upstream(repository: str, ref: str, how: str) -> Upstream:
        """A commit is asked by itself (it names the same code in every fork); a tag with its
        repository."""
        if re.fullmatch(r"[0-9a-f]{40}", ref):
            return Upstream({"commit": ref}, f"{how}, at commit {ref[:12]}")
        return Upstream(
            {"package": {"name": repository, "ecosystem": "GIT"}, "version": ref},
            f"{how}, at {ref}",
        )


class RegistryArchive:
    """A package and version from a registry's own download URL, which OSV covers by name: the
    PyPI sdist a conda recipe builds from, the crate a Homebrew formula downloads."""

    FORMS: ClassVar[tuple[tuple[str, re.Pattern[str]], ...]] = (
        (
            "PyPI",
            re.compile(
                r"^https?://(?:pypi\.io|pypi\.org|pypi\.python\.org|files\.pythonhosted\.org)/packages/"
                r"(?:source/[^/]/[^/]+|[0-9a-f]{2}/[0-9a-f]{2}/[0-9a-f]{60})/"
                r"([A-Za-z0-9][\w.-]*?)-(\d[\w.!+]*)\.(?:tar\.gz|zip|tar\.bz2)$"
            ),
        ),
        (
            "npm",
            re.compile(
                r"^https://registry\.npmjs\.org/((?:@[\w.-]+/)?[\w.-]+)/-/[\w.-]+?-(\d[\w.+-]*)\.tgz$"
            ),
        ),
        (
            "crates.io",
            re.compile(
                r"^https://(?:static\.)?crates\.io/(?:api/v1/)?crates/([\w-]+)/(\d[\w.+-]*)/download$"
            ),
        ),
        (
            "crates.io",
            re.compile(r"^https://static\.crates\.io/crates/([\w-]+)/[\w-]+?-(\d[\w.+-]*)\.crate$"),
        ),
        (
            "NuGet",
            re.compile(r"^https://(?:www\.)?nuget\.org/api/v2/package/([\w.-]+?)/(\d[\w.+-]*)$"),
        ),
        (
            "RubyGems",
            re.compile(r"^https://rubygems\.org/(?:downloads|gems)/([\w.-]+?)-(\d[\w.]*)\.gem$"),
        ),
        (
            "CRAN",
            re.compile(
                r"^https://cran\.r-project\.org/src/contrib/(?:Archive/[\w.]+/)?([\w.]+)_(\d[\w.-]*)\.tar\.gz$"
            ),
        ),
        (
            "Hackage",
            re.compile(
                r"^https://hackage\.haskell\.org/package/[\w.-]+/([\w-]+?)-(\d[\d.]*)\.tar\.gz$"
            ),
        ),
    )

    GO_RELEASE: ClassVar[re.Pattern[str]] = re.compile(
        r"^https://(?:go\.dev|golang\.org|dl\.google\.com/go|storage\.googleapis\.com/golang)"
        r"/(?:dl/)?go(\d+\.\d+(?:\.\d+)?)\.src\.tar\.gz$"
    )

    @staticmethod
    def parse(url: str) -> tuple[str, str, str] | None:
        """`(OSV ecosystem, name, version)`, or None."""
        # Go's own source release: the standard library, which the Go vulnerability database
        # (in OSV) covers as `stdlib`, versioned `1.23.3` -- `go1.20` is 1.20.0. Stable releases
        # only: a beta or release candidate is spelled otherwise there.
        toolchain = RegistryArchive.GO_RELEASE.match(url)
        if toolchain:
            parts = toolchain.group(1).split(".")
            return "Go", "stdlib", ".".join(parts + ["0"] * (3 - len(parts)))
        for ecosystem, form in RegistryArchive.FORMS:
            found = form.match(url)
            if found:
                return ecosystem, found.group(1), found.group(2)
        return None


@dataclass(frozen=True)
class Archive:
    """A release archive a recipe pins: where it is downloaded from, and its digest."""

    urls: tuple[str, ...]
    digest: str
    """`sha256:<hex>`, `sha512:<hex>`, or an SRI value (`sha256-<base64>`)."""


__all__ = ["VCPKG_RAW", "Archive", "RegistryArchive", "RepositoryArchive", "Unnamed", "Upstream"]
