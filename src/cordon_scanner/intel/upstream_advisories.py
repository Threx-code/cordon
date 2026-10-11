"""Advisories for ecosystems no advisory source covers, matched through each package's upstream.

OSV publishes no Bazel, vcpkg, Conan, Homebrew, CocoaPods, Terraform or Nix ecosystem (its
`ecosystems.txt`, October 2026). Each of those packages is built from an upstream repository the
ecosystem's own data names exactly, and OSV does cover upstream repositories: its GIT ecosystem
keys advisories by repository and tag (`https://github.com/madler/zlib` at `v1.2.11` names
CVE-2018-25032), and its commit query by commit. Terraform providers are Go modules, which OSV's Go
ecosystem covers. So a package is matched through what its own ecosystem says it was built from:

    bazel      BCR's `modules/<name>/<version>/source.json`: the archive URL, or a git commit
    conan      Conan Center's recipe export for the locked revision: `conandata.yml`'s source URLs
    cocoapods  the podspec on trunk's CDN: `source.git` with its `tag` or `commit`
    homebrew   formulae.brew.sh: the stable URL, when the version installed is the stable one
    vcpkg      the port at the baseline commit, when it is the version installed: the REPO and REF
               of its `vcpkg_from_github`
    terraform  the registry's provider record: its source repository, as a Go module
    nix        a flake input's locked commit
    conda      the recipe inside the package itself (`info/recipe`): its source URL, or git URL and rev

Nothing is guessed. An archive URL is read only in GitHub's and GitLab's fixed forms; a ref that is
a branch, a version the source no longer serves, a download from a project's own site, a port
whose REF uses anything but its version -- each leaves the package unchecked, and says why.
Network use is the scan's `--online` only, over HTTPS, to the hosts above and api.osv.dev.
"""

from __future__ import annotations

import collections
import contextlib
import http.client
import io
import json
import re
import tarfile
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.intel.advisories import Advisory

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from cordon_scanner.core.models import Dependency

OSV_QUERYBATCH: Final = "https://api.osv.dev/v1/querybatch"
OSV_VULN: Final = "https://api.osv.dev/v1/vulns/"
BCR: Final = "https://bcr.bazel.build/modules"
CONAN_CENTER: Final = "https://center2.conan.io/v2/conans"
HOMEBREW_API: Final = "https://formulae.brew.sh/api/formula"
TERRAFORM_REGISTRY: Final = "https://registry.terraform.io/v1/providers"
VCPKG_RAW: Final = "https://raw.githubusercontent.com/microsoft/vcpkg"
MAX_PACKAGES: Final = 20_000
#: Packages whose upstream is looked up at once: each is a few HTTP requests, and a proof one
#: download, so a conda lock of a thousand artifacts is not read one at a time.
WORKERS: Final = 8
"""Packages resolved per scan. Past it the rest are reported unchecked, never silently skipped."""
MAX_EXPORT_BYTES: Final = 1 << 20
SUPPORTED: Final = frozenset(
    {"bazel", "conan", "cocoapods", "homebrew", "vcpkg", "terraform", "nix", "conda", "ansible"}
)


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


@dataclass
class UpstreamResult:
    advisories: dict[str, tuple[Advisory, ...]] = field(default_factory=dict)
    """By purl: what OSV names for each package whose upstream was named."""
    checked: set[str] = field(default_factory=set)
    """The purls asked of OSV, whether or not anything matched."""
    unchecked: dict[str, str] = field(default_factory=dict)
    """By purl: why the package could not be matched."""
    homes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    """By purl: the homepage and download URLs read for a package left unchecked."""
    versions: dict[str, str] = field(default_factory=dict)
    """By purl: the release resolved for a package left unchecked whose lockfile names none."""


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
                r"^https://(?:pypi\.io|pypi\.org|files\.pythonhosted\.org)/packages/"
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


class CondaPackage:
    """The rendered recipe inside a conda package, read without downloading the package.

    A `.conda` file is a zip whose `info-*.tar.zst` member holds `info/`; its central directory is
    at the end, so two range requests reach it: the tail, then the member. That member is zstd,
    which the standard library reads from Python 3.14 (`compression.zstd`); before it, the
    `zstandard` package if installed, else the core's own decoder (`intel/zstd`).
    A legacy `.tar.bz2` is read as a stream, to a bound.
    """

    RECIPES: ClassVar[tuple[str, ...]] = (
        "info/recipe/meta.yaml",
        "info/recipe/rendered_recipe.yaml",
    )
    MAX_INFO_BYTES: ClassVar[int] = 16 << 20
    MAX_STREAM_BYTES: ClassVar[int] = 64 << 20

    @staticmethod
    def _range(url: str, header: str, limit: int) -> tuple[bytes, int]:
        import urllib.request

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args: Any, **kwargs: Any) -> None:
                return None

        request = urllib.request.Request(  # noqa: S310 - https, checked by the caller
            url, headers={"Range": header, "User-Agent": "cordon-scanner"}
        )
        with urllib.request.build_opener(NoRedirect).open(request, timeout=60) as response:
            if response.status != 206:
                raise ValueError("the server does not answer a byte range")
            total = int(str(response.headers.get("Content-Range", "/0")).rpartition("/")[2] or 0)
            body: bytes = response.read(limit + 1)
        if len(body) > limit:
            raise ValueError("range too large")
        return body, total

    @staticmethod
    def _zstd_stream(blob: bytes) -> io.RawIOBase:
        """`blob` decompressed as it is read, to at most MAX_STREAM_BYTES."""
        try:
            from compression import zstd  # type: ignore[import-not-found]  # Python 3.14+

            stream: Any = zstd.ZstdFile(io.BytesIO(blob))
        except ImportError:
            try:
                import zstandard  # type: ignore[import-not-found]

                stream = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(blob))
            except ImportError:
                from cordon_scanner.intel.zstd import Zstd

                # The core's own decoder: no third-party dependency (CONSTRAINT C1).
                stream = Zstd.Reader(blob, CondaPackage.MAX_STREAM_BYTES)
        return CondaPackage._Bounded(stream, CondaPackage.MAX_STREAM_BYTES)

    class _Bounded(io.RawIOBase):
        """A stream that fails once more than `limit` bytes are read from it."""

        def __init__(self, inner: Any, limit: int) -> None:
            self.inner, self.left = inner, limit

        def readable(self) -> bool:
            return True

        def readinto(self, buffer: Any) -> int:
            data = self.inner.read(len(buffer))
            self.left -= len(data)
            if self.left < 0:
                raise ValueError("info too large")
            buffer[: len(data)] = data
            return len(data)

    @staticmethod
    def _from_tar(archive: tarfile.TarFile, seen: dict[str, int] | None = None) -> str | None:
        """The recipe; and, into `seen`, how many files `info/paths.json` lists where it comes before
        the recipe. With `seen["want_paths"]` set, read on past the recipe to paths.json (for a
        package whose recipe names no source; a metapackage's info/ is small)."""
        recipe: str | None = None
        for member in archive:
            if member.name == "info/paths.json" and member.isfile() and seen is not None:
                handle = archive.extractfile(member)
                if handle is not None:
                    with contextlib.suppress(ValueError):
                        listed = json.loads(handle.read(CondaPackage.MAX_INFO_BYTES))
                        if isinstance(listed, dict) and isinstance(listed.get("paths"), list):
                            seen["paths"] = len(listed["paths"])
                continue
            if member.name in CondaPackage.RECIPES and member.isfile() and recipe is None:
                handle = archive.extractfile(member)
                if handle is not None:
                    recipe = handle.read(CondaPackage.MAX_INFO_BYTES).decode("utf-8", "replace")
            if recipe is not None and not (seen and seen.get("want_paths") and "paths" not in seen):
                return recipe
        return recipe

    @staticmethod
    def recipe(url: str, seen: dict[str, int] | None = None) -> str | None:
        import struct

        if url.endswith(".tar.bz2"):
            import urllib.request

            request = urllib.request.Request(url, headers={"User-Agent": "cordon-scanner"})  # noqa: S310
            with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310

                class Bounded(io.RawIOBase):
                    read_so_far = 0

                    def readable(self) -> bool:
                        return True

                    def readinto(self, buffer: Any) -> int:
                        chunk = response.read(min(len(buffer), 1 << 16))
                        Bounded.read_so_far += len(chunk)
                        if Bounded.read_so_far > CondaPackage.MAX_STREAM_BYTES:
                            raise ValueError("package too large to read its recipe")
                        buffer[: len(chunk)] = chunk
                        return len(chunk)

                with tarfile.open(fileobj=io.BufferedReader(Bounded()), mode="r|bz2") as archive:
                    return CondaPackage._from_tar(archive, seen)
        if not url.endswith(".conda"):
            return None
        tail, total = CondaPackage._range(url, "bytes=-65536", 65536)
        end = tail.rfind(b"PK\x05\x06")
        if end < 0:
            raise ValueError("no zip directory at the end of the package")
        size, offset = struct.unpack("<II", tail[end + 12 : end + 20])
        if 0xFFFFFFFF in (size, offset):
            # ZIP64 (APPNOTE 4.3.14-15): the locator just before the end record names the ZIP64
            # end record, which holds the directory's 8-byte size and offset.
            locator = tail.rfind(b"PK\x06\x07", 0, end)
            record_at = (
                struct.unpack("<Q", tail[locator + 8 : locator + 16])[0] if locator >= 0 else -1
            )
            start = record_at - (total - len(tail))
            if locator < 0 or start < 0 or not tail.startswith(b"PK\x06\x06", start):
                raise ValueError("a ZIP64 package whose directory could not be found")
            size, offset = struct.unpack("<QQ", tail[start + 40 : start + 56])
        start_of_tail = total - len(tail)
        if offset >= start_of_tail:
            directory = tail[offset - start_of_tail : offset - start_of_tail + size]
        else:
            directory, _ = CondaPackage._range(url, f"bytes={offset}-{offset + size - 1}", size)
        position = 0
        while directory.startswith(b"PK\x01\x02", position):
            method, compressed = (
                struct.unpack("<H", directory[position + 10 : position + 12])[0],
                struct.unpack("<I", directory[position + 20 : position + 24])[0],
            )
            name_len, extra_len, comment_len = struct.unpack(
                "<HHH", directory[position + 28 : position + 34]
            )
            local = struct.unpack("<I", directory[position + 42 : position + 46])[0]
            name = directory[position + 46 : position + 46 + name_len].decode("utf-8", "replace")
            # ZIP64 (APPNOTE 4.5.3): a field written 0xFFFFFFFF is in the extra field's 0x0001
            # block, 8 bytes each, in the order uncompressed size, compressed size, offset.
            uncompressed = struct.unpack("<I", directory[position + 24 : position + 28])[0]
            extra = directory[position + 46 + name_len : position + 46 + name_len + extra_len]
            at = 0
            while at + 4 <= len(extra):
                kind, length = struct.unpack("<HH", extra[at : at + 4])
                if kind == 1:
                    wide = iter(
                        struct.unpack(
                            f"<{min(length, 24) // 8}Q",
                            extra[at + 4 : at + 4 + length // 8 * 8][:24],
                        )
                    )
                    fields = [uncompressed, compressed, local]
                    fields = [next(wide, f) if f == 0xFFFFFFFF else f for f in fields]
                    uncompressed, compressed, local = fields
                at += 4 + length
            position += 46 + name_len + extra_len + comment_len
            if not (name.startswith("info-") and name.endswith(".tar.zst")) or method != 0:
                continue
            if compressed > CondaPackage.MAX_INFO_BYTES:
                raise ValueError("info too large")
            head, _ = CondaPackage._range(url, f"bytes={local}-{local + 29}", 30)
            skip = 30 + sum(struct.unpack("<HH", head[26:30]))
            body, _ = CondaPackage._range(
                url, f"bytes={local + skip}-{local + skip + compressed - 1}", compressed
            )
            # Read as a stream, to the recipe: info/ may hold far more than the recipe (a test
            # suite, every path), so it is never decompressed whole.
            with tarfile.open(fileobj=CondaPackage._zstd_stream(body), mode="r|") as archive:
                return CondaPackage._from_tar(archive, seen)
        return None


class VcpkgVersions:
    """vcpkg's version ordering, per scheme (its versioning reference): `version` is dot-separated
    numbers with an optional `-prerelease` and `+build`; `version-semver` is SemVer, ordered the
    same way here; `version-date` is `YYYY-MM-DD` and dotted numbers; `version-string` has none."""

    @staticmethod
    def key(scheme: str, text: str) -> tuple[Any, ...] | None:
        text = text.split("#", 1)[0]
        if scheme == "version-string":
            return None
        if scheme == "version-date":
            found = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})((?:\.\d+)*)", text)
            if not found:
                return None
            rest = tuple(int(p) for p in found.group(4).split(".")[1:])
            return (int(found.group(1)), int(found.group(2)), int(found.group(3)), *rest)
        core, _, pre = text.split("+", 1)[0].partition("-")
        if not re.fullmatch(r"\d+(?:\.\d+)*", core):
            return None
        numbers = tuple(int(p) for p in core.split("."))
        # A release orders after its prereleases; prerelease parts compare as SemVer's do.
        tail: tuple[Any, ...] = (
            (1,)
            if not pre
            else (0, *((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")))
        )
        return (numbers, tail)

    @staticmethod
    def compare(scheme: str, a: str, b: str) -> int | None:
        left, right = VcpkgVersions.key(scheme, a), VcpkgVersions.key(scheme, b)
        if left is None or right is None:
            return None
        if scheme != "version-date":
            # `1.2` and `1.2.0` are the same version.
            width = max(len(left[0]), len(right[0]))
            left = (left[0] + (0,) * (width - len(left[0])), left[1])
            right = (right[0] + (0,) * (width - len(right[0])), right[1])
        return (left > right) - (left < right)


class VcpkgPorts:
    """A vcpkg port's files at a version, and the source its portfile fetches."""

    REPOSITORY: ClassVar[str] = "https://github.com/microsoft/vcpkg"

    @staticmethod
    def _cached(kind: str, key: str, fetch: Any) -> bytes:
        """A git object by its id never changes, so it is kept: a project's pinned ports cost the
        GitHub API (sixty anonymous requests an hour) once."""
        from cordon_scanner.core.cache import ScanCache

        path = ScanCache.default_cache_dir() / "upstream" / f"vcpkg-{kind}-{key}"
        try:
            return path.read_bytes()
        except (OSError, http.client.HTTPException):
            pass
        body: bytes = fetch()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        except (OSError, http.client.HTTPException):
            pass
        return body

    #: Anything that brings code into a port from outside the registry.
    #: Anything that may bring code into a port from outside the registry: a fetch, a download,
    #: an acquired tool, a pip install, or any helper whose name says it does one of these.
    DOWNLOADS: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)\b(?:\w*(?:download|fetch|acquire|from_git|from_github|from_gitlab|from_bitbucket"
        r"|from_sourceforge|python_packages|submodule)\w*|ExternalProject_Add)\s*\("
        r"|\bfile\s*\(\s*DOWNLOAD\b"
    )

    @staticmethod
    def manifest(baseline: str, port: str) -> dict[str, Any]:
        """The port's manifest at the baseline: its vcpkg.json, or before 2021 its CONTROL file
        (`Source:`, `Version:`, `Port-Version:`, `Homepage:`), read as the same fields."""
        from cordon_scanner.intel.registry_client import PackageNotFound

        try:
            data = json.loads(Upstreams._get(f"{VCPKG_RAW}/{baseline}/ports/{port}/vcpkg.json"))
            return data if isinstance(data, dict) else {}
        except PackageNotFound:
            control = Upstreams._get(f"{VCPKG_RAW}/{baseline}/ports/{port}/CONTROL").decode(
                "utf-8", "replace"
            )
        # The first paragraph is the port's own; later ones are its features.
        fields = dict(
            re.findall(r"^([A-Za-z-]+):[ \t]*(.*?)\s*$", control.split("\n\n", 1)[0], re.MULTILINE)
        )
        out: dict[str, Any] = {}
        if fields.get("Version"):
            out["version-string"] = fields["Version"]
        if fields.get("Port-Version", "").isdigit():
            out["port-version"] = int(fields["Port-Version"])
        if fields.get("Homepage"):
            out["homepage"] = fields["Homepage"]
        return out

    @staticmethod
    def at_version(baseline: str, port: str, version: str) -> tuple[str, str] | Unnamed:
        """The portfile of `port` at `version`: the git tree the version database names for it,
        read from GitHub's API by that tree's id."""
        from cordon_scanner.intel.registry_client import PackageNotFound

        name = urllib.parse.quote(port, safe="")
        wanted = version.split("#", 1)[0]
        entries: list[dict[str, Any]] = []
        # The baseline's version database, then the registry's current one: vcpkg reads the
        # database of the checkout it runs from, which a `version>=` above the baseline needs to
        # be newer. Entries are only ever added, never changed, so a version's git tree is the
        # same in every database that lists it.
        for at in (baseline, "HEAD"):
            try:
                database = json.loads(
                    Upstreams._get(f"{VCPKG_RAW}/{at}/versions/{port[0]}-/{name}.json")
                )
            except PackageNotFound:
                continue
            entries = [
                e
                for e in database.get("versions") or []
                if isinstance(e, dict)
                and wanted
                in (
                    e.get("version"),
                    e.get("version-semver"),
                    e.get("version-date"),
                    e.get("version-string"),
                )
            ]
            if entries:
                break
        if not entries:
            return Unnamed(f"vcpkg's version database holds no {wanted}")
        # An override names no port-version, which vcpkg reads as 0.
        entry = next((e for e in entries if not e.get("port-version")), entries[0])
        tree = str(entry.get("git-tree") or "")
        if not re.fullmatch(r"[0-9a-f]{40}", tree):
            return Unnamed("the version database names no git tree for it")
        # By git's own protocol, which GitHub serves without the API's rate limit: the tree by
        # its id, then the portfile by the blob id the tree names. Both are immutable, so cached.
        from cordon_scanner.intel.gitfetch import GitFetch, GitFetchError

        try:
            listing = json.loads(
                VcpkgPorts._cached(
                    "tree",
                    tree,
                    lambda: json.dumps(GitFetch.tree(VcpkgPorts.REPOSITORY, tree)).encode(),
                )
            )
            blob = str(listing.get("portfile.cmake") or "")
            if not re.fullmatch(r"[0-9a-f]{40}", blob):
                return Unnamed("the port's tree holds no portfile.cmake")
            text = VcpkgPorts._cached(
                "blob", blob, lambda: GitFetch.blob(VcpkgPorts.REPOSITORY, blob)
            ).decode("utf-8", "replace")
        except GitFetchError as exc:
            return Unnamed(f"the port at that version could not be fetched ({exc})")
        return text, wanted

    @staticmethod
    def file_at_version(baseline: str, port: str, version: str, filename: str) -> str:
        """Another file of the port at that version (a Qt port's port.data.cmake), from the same
        tree, by git."""
        from cordon_scanner.intel.gitfetch import GitFetch

        name = urllib.parse.quote(port, safe="")
        database = json.loads(
            Upstreams._get(f"{VCPKG_RAW}/{baseline}/versions/{port[0]}-/{name}.json")
        )
        wanted = version.split("#", 1)[0]
        entries = [
            e
            for e in database.get("versions") or []
            if isinstance(e, dict)
            and wanted
            in (
                e.get("version"),
                e.get("version-semver"),
                e.get("version-date"),
                e.get("version-string"),
            )
        ]
        entry = next(
            (e for e in entries if not e.get("port-version")), entries[0] if entries else {}
        )
        tree = str(entry.get("git-tree") or "")
        listing = json.loads(
            VcpkgPorts._cached(
                "tree",
                tree,
                lambda: json.dumps(GitFetch.tree(VcpkgPorts.REPOSITORY, tree)).encode(),
            )
        )
        blob = str(listing.get(filename) or "")
        if not re.fullmatch(r"[0-9a-f]{40}", blob):
            raise ValueError(f"the port has no {filename}")
        return VcpkgPorts._cached(
            "blob", blob, lambda: GitFetch.blob(VcpkgPorts.REPOSITORY, blob)
        ).decode("utf-8", "replace")

    @staticmethod
    def qt(port: str, version: str, other: Any, how: str, qtbase: Any = None) -> Upstream | Unnamed:
        """A Qt module, fetched by vcpkg's Qt helpers from what its port.data.cmake records --
        written by vcpkg's own generator (`qt_port_details.cmake`), which resolves the tag
        `v<version>` in `code.qt.io/qt/<module>.git`: a commit (`<module>_REF`), or the release
        tarballs and their SHA-512 (`<module>_URL`, `<module>_HASH`)."""
        from cordon_scanner.intel.registry_client import RegistryError

        field = re.escape(port)
        try:
            data = other("port.data.cmake")
        except (RegistryError, OSError, ValueError):
            # Before port.data.cmake (2025), every module's SHA-512 was in qtbase's
            # cmake/qt_port_data.cmake, and its URL was built from QT_VERSION by
            # qt_port_details.cmake.
            return VcpkgPorts.qt_before_port_data(port, version, how, qtbase)
        ref = re.search(rf"set\({field}_REF\s+\"?([0-9a-f]{{40}})\"?\)", data)
        repositories = [f"https://code.qt.io/qt/{port}.git", f"https://github.com/qt/{port}"]
        if ref:
            return RepositoryArchive.upstream(
                repositories[1], ref.group(1), f"{how} ({repositories[0]})"
            )
        urls = re.search(rf"set\({field}_URL\s+\"([^\"]+)\"\)", data)
        sha512 = re.search(rf"set\({field}_HASH\s+\"([0-9a-f]{{128}})\"\)", data)
        archive = (
            Archive(tuple(u for u in urls.group(1).split(";") if u), f"sha512:{sha512.group(1)}")
            if urls and sha512
            else None
        )
        return Upstreams.inferred(
            Unnamed("a Qt module, fetched by vcpkg's Qt helpers"),
            repositories,
            version,
            (port,),
            how,
            archive,
        )

    @staticmethod
    def qt_before_port_data(port: str, version: str, how: str, qtbase: Any) -> Upstream | Unnamed:
        """A Qt module in vcpkg's older layout. qt_port_details.cmake names the one QT_VERSION
        all modules are built at, the modules fetched from GitHub by tag (`QT_FROM_GITHUB`), and
        otherwise the release tarball on download.qt.io, whose SHA-512 qt_port_data.cmake holds.
        That tarball's address is built here as vcpkg builds it; the digest is what makes it the
        release, so a wrong address can only fail to prove, never prove the wrong tag."""
        if qtbase is None:
            return Unnamed("the Qt port's data could not be read")
        from cordon_scanner.intel.registry_client import RegistryError

        try:
            details, data = (
                qtbase("cmake/qt_port_details.cmake"),
                qtbase("cmake/qt_port_data.cmake"),
            )
        except (RegistryError, OSError, ValueError):
            return Unnamed("the Qt port's data could not be read")
        stated = re.search(r"set\(QT_VERSION\s+([\w.]+)\)", details)
        if not stated or stated.group(1) != version:
            return Unnamed(f"qtbase's port details at this baseline name no Qt {version}")
        field = re.escape(port)
        repositories = [f"https://code.qt.io/qt/{port}.git", f"https://github.com/qt/{port}"]
        github = re.search(r"set\(QT_FROM_GITHUB\s+([^)]*)\)", details)
        if github and port in github.group(1).split():
            return RepositoryArchive.upstream(
                repositories[1], f"v{version}", f"{how} ({repositories[1]})"
            )
        ref = re.search(rf"set\({field}_REF\s+\"?([0-9a-f]{{40}})\"?\)", data)
        if ref:
            return RepositoryArchive.upstream(
                repositories[1], ref.group(1), f"{how} ({repositories[0]})"
            )
        sha512 = re.search(rf"set\({field}_HASH\s+\"([0-9a-f]{{128}})\"\)", data)
        major_minor = ".".join(version.split(".")[:2])
        filename = f"{port}-everywhere-src-{version}.tar.xz"
        urls = tuple(
            f"{mirror}{kind}/qt/{major_minor}/{version}/submodules/{filename}"
            for kind in ("archive", "official_releases")
            for mirror in ("https://download.qt.io/", "https://mirrors.ocf.berkeley.edu/qt/")
        )
        return Upstreams.inferred(
            Unnamed("a Qt module, fetched by vcpkg's Qt helpers"),
            repositories,
            version,
            (port,),
            how,
            Archive(urls, f"sha512:{sha512.group(1)}") if sha512 else None,
        )

    FETCHES: ClassVar[frozenset[str]] = frozenset(
        {
            "vcpkg_from_github",
            "vcpkg_from_gitlab",
            "vcpkg_from_bitbucket",
            "vcpkg_from_git",
            "vcpkg_download_distfile",
        }
    )
    KEYWORDS: ClassVar[frozenset[str]] = frozenset(
        {
            "OUT_SOURCE_PATH",
            "REPO",
            "REF",
            "SHA512",
            "HEAD_REF",
            "PATCHES",
            "GITHUB_HOST",
            "AUTHORIZATION_TOKEN",
            "FILE_DISAMBIGUATOR",
            "GITLAB_URL",
            "URL",
            "URLS",
            "FILENAME",
            "ARCHIVE",
            "SKIP_SHA512",
            "QUIET",
            "FETCH_REF",
            "LFS",
            "HEADERS",
            "ALWAYS_REDOWNLOAD",
            "USE_TARBALL_API",
        }
    )

    @staticmethod
    def commands(text: str) -> list[tuple[str, str]]:
        """`(name, arguments)` of each CMake command, in order: a name, `(`, and the text to the
        matching `)`, quotes and nested parentheses respected, comments outside quotes skipped."""
        out: list[tuple[str, str]] = []
        index, length = 0, len(text)
        name = re.compile(r"[A-Za-z_][A-Za-z0-9_]*[ \t]*\(")
        while index < length:
            character = text[index]
            if character == "#":
                newline = text.find("\n", index)
                index = length if newline < 0 else newline
                continue
            if character == '"':
                index += 1
                while index < length and text[index] != '"':
                    index += 2 if text[index] == "\\" else 1
                index += 1
                continue
            found = name.match(text, index)
            if not found or (index and (text[index - 1].isalnum() or text[index - 1] == "_")):
                index += 1
                continue
            start, depth, index = found.end(), 1, found.end()
            while index < length and depth:
                if text[index] == '"':
                    index += 1
                    while index < length and text[index] != '"':
                        index += 2 if text[index] == "\\" else 1
                elif text[index] == "#":
                    newline = text.find("\n", index)
                    index = length - 1 if newline < 0 else newline
                elif text[index] == "(":
                    depth += 1
                elif text[index] == ")":
                    depth -= 1
                index += 1
            command = found.group(0).rstrip("( \t").lower()
            out.append((command, text[start : index - 1]))
        return out

    @staticmethod
    def _arguments(raw: str, values: dict[str, str | None]) -> list[str | None]:
        """CMake's arguments: quoted or not, `${VAR}` expanded; None for one naming a variable
        whose value is not known."""
        out: list[str | None] = []
        escapes = {"n": "\n", "t": "\t", "r": "\r", "0": "\0"}
        index, length = 0, len(raw)

        def evaluate(text: str) -> str | None:
            """CMake's escape sequences and `${VAR}` references, in one pass: an escaped `\\$`
            is a dollar sign, never a reference (7zip's `"[.]([0-9])\\$"`)."""
            result: list[str] = []
            position = 0
            while position < len(text):
                character = text[position]
                if character == "\\" and position + 1 < len(text):
                    following = text[position + 1]
                    result.append(escapes.get(following, following))
                    position += 2
                elif text.startswith("${", position):
                    end = text.find("}", position)
                    if end < 0:
                        return None
                    value = values.get(text[position + 2 : end])
                    if value is None:
                        return None
                    result.append(value)
                    position = end + 1
                else:
                    result.append(character)
                    position += 1
            return "".join(result)

        while index < length:
            character = raw[index]
            if character.isspace() or character in "()":
                # Whitespace, or a nested parenthesis (`if(A AND (B OR C))`), separates arguments.
                index += 1
            elif character == "#":
                newline = raw.find("\n", index)
                index = length if newline < 0 else newline
            elif character == '"':
                end = index + 1
                while end < length and raw[end] != '"':
                    end += 2 if raw[end] == "\\" else 1
                out.append(evaluate(raw[index + 1 : end]))
                index = end + 1
            elif (bracket := re.match(r"\[(=*)\[", raw[index:])) is not None:
                # A bracket argument (`[[^[0-9]+]]`): taken as written, nothing expanded.
                closing = f"]{bracket.group(1)}]"
                end = raw.find(closing, index + len(bracket.group(0)))
                end = length if end < 0 else end
                out.append(raw[index + len(bracket.group(0)) : end])
                index = end + len(closing)
            else:
                end = index
                while end < length and not raw[end].isspace() and raw[end] not in '"#()':
                    end += 2 if raw[end] == "\\" else 1
                out.append(evaluate(raw[index:end]))
                index = end
        return out

    @staticmethod
    def _regex(pattern: str, text: str, replacement: str | None) -> str | None:
        """CMake's `string(REGEX ...)` in Python's `re`, which reads every construct CMake's
        regular expressions have. A replacement's `\\0`..`\\9` name the match and its groups.
        None when the pattern does not compile -- never a guessed value."""
        if len(pattern) > 512 or len(text) > 4096:
            return None
        try:
            compiled = re.compile(pattern)
        except re.error:
            return None
        if replacement is None:
            found = compiled.search(text)
            return found.group(0) if found else ""
        template = re.sub(
            r"\\([0-9])", lambda m: f"\\g<{m.group(1)}>", replacement.replace("\\\\", "\0")
        )
        try:
            return compiled.sub(template.replace("\0", "\\\\"), text)
        except (re.error, IndexError):
            return None

    @staticmethod
    def source(portfile: str, version: str, port: str, how: str) -> Upstream | Unnamed:
        return VcpkgPorts.read(portfile, version, port, how)[0]

    @staticmethod
    def read(
        portfile: str, version: str, port: str, how: str
    ) -> tuple[Upstream | Unnamed, Archive | None]:
        """The port's upstream, and the archive it pins (for `ContentProof`). Every fetch is read,
        under an `if()` too: when they all name one source -- ace downloads from one release
        whichever features are on -- that is the port's; when they differ, it depends on the
        platform or features, which a lock does not record."""
        values: dict[str, str | None] = {"VERSION": version, "PORT": port}
        depth = 0
        results: list[tuple[int, Upstream | Unnamed]] = []
        archive: Archive | None = None
        for name, raw in VcpkgPorts.commands(portfile):
            if name == "if":
                depth += 1
                continue
            if name == "endif":
                depth = max(0, depth - 1)
                continue
            args = VcpkgPorts._arguments(raw, values)
            if name == "set" and args and args[0]:
                # Set under a condition, a value is not known for every build.
                values[args[0]] = (
                    None
                    if depth or any(a is None for a in args[1:])
                    else ";".join(a for a in args[1:] if a is not None)
                )
            elif name == "string" and len(args) >= 2 and args[0]:
                operation = args[0].upper()
                if operation == "REPLACE" and len(args) >= 5 and args[3]:
                    inputs = args[4:]
                    known = not depth and None not in (args[1], args[2], *inputs)
                    values[args[3]] = (
                        "".join(i for i in inputs if i is not None).replace(
                            str(args[1]), str(args[2])
                        )
                        if known
                        else None
                    )
                elif (
                    operation == "REGEX"
                    and len(args) >= 5
                    and str(args[1]).upper() == "MATCH"
                    and args[3]
                ):
                    # `string(REGEX MATCH <regex> <out> <input>...)`: the first match, or "".
                    pattern, inputs = args[2], args[4:]
                    values[args[3]] = (
                        None
                        if depth or pattern is None or None in inputs
                        else VcpkgPorts._regex(pattern, "".join(i for i in inputs if i), None)
                    )
                elif (
                    operation == "REGEX"
                    and len(args) >= 6
                    and str(args[1]).upper() == "REPLACE"
                    and args[4]
                ):
                    # `string(REGEX REPLACE <regex> <replace> <out> <input>...)`: every match.
                    pattern, replacement, inputs = args[2], args[3], args[5:]
                    values[args[4]] = (
                        None
                        if depth or pattern is None or replacement is None or None in inputs
                        else VcpkgPorts._regex(
                            pattern, "".join(i for i in inputs if i), replacement
                        )
                    )
                elif operation in ("TOLOWER", "TOUPPER") and len(args) >= 3 and args[2]:
                    given = args[1]
                    values[args[2]] = (
                        None
                        if depth or given is None
                        else given.lower()
                        if operation == "TOLOWER"
                        else given.upper()
                    )
                elif len(args) >= 3 and args[-1]:
                    values[args[-1]] = None  # any other string() result is not evaluated here
            elif name in VcpkgPorts.FETCHES or name == "vcpkg_from_sourceforge":
                keyed: dict[str, list[str | None]] = {}
                current = ""
                for a in args:
                    if a is not None and a in VcpkgPorts.KEYWORDS:
                        current = a
                        keyed.setdefault(a, [])
                    elif current:
                        keyed[current].append(a)
                if VcpkgPorts.patch(name, keyed):
                    # A patch it applies (g2o's upstream commits as `.patch` downloads before its
                    # `vcpkg_from_github`), not its source.
                    continue
                results.append((depth, VcpkgPorts._fetched(name, keyed, how)))
                sha512 = (keyed.get("SHA512") or [None])[0]
                if archive is None and sha512 and re.fullmatch(r"[0-9a-f]{128}", sha512):
                    urls = VcpkgPorts._archive_urls(name, keyed)
                    if urls:
                        archive = Archive(tuple(urls), f"sha512:{sha512}")
        if not results:
            if re.search(r"(?i)set\s*\(\s*VCPKG_POLICY_EMPTY_PACKAGE\s+enabled", portfile):
                return Unnamed("an empty port: it installs no code", nothing=True), archive
            return Unnamed("its portfile fetches its source in no form read here"), archive
        # The first fetch made unconditionally always runs: the source. Later ones are a licence
        # file or a feature's extra (amd-amf downloads its licence after its headers).
        unconditional = [result for level, result in results if level == 0]
        if unconditional:
            return unconditional[0], archive
        # Every fetch under a condition: one source only if they all name it (ace).
        found = [result for _, result in results]
        named = [r for r in found if isinstance(r, Upstream)]
        if len(named) == len(found) and all(r.query == named[0].query for r in named):
            return named[0], archive
        if named:
            return Unnamed("its portfile fetches different sources by platform or feature"), archive
        return found[0], archive

    @staticmethod
    def patch(name: str, keyed: dict[str, list[str | None]]) -> bool:
        """A distfile that is a patch: its file name, or every URL's path, ends `.patch` or `.diff`."""
        if name != "vcpkg_download_distfile":
            return False
        filename = (keyed.get("FILENAME") or [None])[0]
        if filename and re.search(r"\.(?:patch|diff)$", filename):
            return True
        urls = [u for u in keyed.get("URLS") or [] if u]
        return bool(urls) and all(
            re.search(r"\.(?:patch|diff)$", urllib.parse.urlsplit(u).path) for u in urls
        )

    @staticmethod
    def _archive_urls(name: str, keyed: dict[str, list[str | None]]) -> list[str]:
        """Where a pinned archive is downloaded from: a distfile's URLS, or SourceForge's address
        for a project, path and file (`vcpkg_from_sourceforge`)."""
        if name == "vcpkg_download_distfile":
            return [u for u in keyed.get("URLS") or [] if u]
        if name == "vcpkg_from_sourceforge":
            project = (keyed.get("REPO") or [None])[0]
            ref = (keyed.get("REF") or [""])[0]
            filename = (keyed.get("FILENAME") or [None])[0]
            if project and filename and ref is not None:
                path = f"{ref}/{filename}" if ref else filename
                return [f"https://downloads.sourceforge.net/project/{project}/{path}"]
        return []

    @staticmethod
    def _fetched(name: str, keyed: dict[str, list[str | None]], how: str) -> Upstream | Unnamed:
        ref = (keyed.get("REF") or [None])[0]
        if name == "vcpkg_download_distfile":
            urls = keyed.get("URLS") or []
            if any(u is None for u in urls):
                return Unnamed("its portfile's download URL is computed")
            return Upstreams.from_urls([u for u in urls if u], how)
        if name == "vcpkg_from_sourceforge":
            return Unnamed("its portfile downloads from SourceForge, which names no repository")
        if ref is None:
            return Unnamed(f"its portfile's REF is computed or missing ({name})")
        repo = (keyed.get("REPO") or [None])[0]
        if name == "vcpkg_from_github":
            host = (keyed.get("GITHUB_HOST") or ["https://github.com"])[0]
            if host != "https://github.com" or not repo:
                return Unnamed("its portfile fetches from a GitHub host other than github.com")
            repository = f"https://github.com/{repo}"
        elif name == "vcpkg_from_gitlab":
            # The host is named exactly: gitlab.com, or gitlab.freedesktop.org (fontconfig).
            host = (keyed.get("GITLAB_URL") or [None])[0]
            # A group may be part of it (`GITLAB_URL https://gitlab.com/inivation`): vcpkg joins it
            # and REPO with a slash.
            if (
                not host
                or not repo
                or not re.fullmatch(r"https://[\w.-]+(?::\d+)?(?:/[\w.~-]+){0,8}/?", host)
            ):
                return Unnamed("its portfile's GitLab host or repository is computed")
            repository = f"{host.rstrip('/')}/{repo}"
        elif name == "vcpkg_from_bitbucket":
            if not repo:
                return Unnamed("its portfile's Bitbucket repository is computed")
            repository = f"https://bitbucket.org/{repo}"
        else:
            given = (keyed.get("URL") or [None])[0]
            named = RepositoryArchive.repository(given or "")
            if not named:
                # Any other git server (chromium.googlesource.com's libyuv): a commit names the same
                # code wherever it is fetched from, and a tag is that server's own.
                if given and re.fullmatch(r"https://[\w.-]+(?::\d+)?/[\w.~+/-]{1,200}", given):
                    named = given.removesuffix("/").removesuffix(".git")
                else:
                    return Unnamed("its portfile's git URL is not an https git URL")
            repository = named
        return RepositoryArchive.upstream(repository, ref, f"{how} ({repository})")


class PodSiblings:
    """A binary pod published from the repository another pod of the same lockfile comes from.

    Firebase's FirebaseAnalytics and GoogleAppMeasurement are closed binaries on dl.google.com,
    but their podspecs live in github.com/firebase/firebase-ios-sdk beside FirebaseCore's, and are
    published from it at each release tag. So a pod whose trunk source is only a download is looked
    for in the repositories its lockfile's other pods resolved to, at tags that name its version
    (FirebaseCore 10.6.0 is at `CocoaPods-10.6.0`): `<repository>/<tag>/<Name>.podspec`. It is that
    release only if that podspec declares the locked version and names the very download trunk
    gives (`https://dl.google.com/firebase/ios/analytics/c549faaa5cd321b5/FirebaseAnalytics-10.6.0
    .tar.gz`) -- the same file, published from that commit."""

    MAX_CANDIDATES: ClassVar[int] = 6

    @staticmethod
    def http(text: str, version: str) -> str | None:
        """A podspec's `source = { :http => '...' }`, `#{s.version}` read as the version."""
        found = re.search(r"\.source\s*=\s*\{((?:[^{}]|#\{[^{}]*\})*)\}", text)
        if not found:
            return None
        for entry in NpmPodspec.FIELD.finditer(found.group(1)):
            if (entry.group(1) or entry.group(2)) == "http":
                value = entry.group(3) if entry.group(3) is not None else entry.group(4)
                if value is not None:
                    return re.sub(r"#\{\w+\.version(?:\.to_s)?\}", version, value)
        return None

    @staticmethod
    def resolve(
        dependencies: Sequence[Dependency], answers: Sequence[Upstream | Unnamed]
    ) -> list[Upstream | Unnamed]:
        tags: dict[str, set[str]] = collections.defaultdict(set)
        for dependency, answer in zip(dependencies, answers, strict=True):
            if not isinstance(answer, Upstream):
                continue
            package = answer.query.get("package")
            if (
                dependency.ecosystem == "cocoapods"
                and isinstance(package, dict)
                and package.get("ecosystem") == "GIT"
                and str(package.get("name") or "").startswith("https://github.com/")
            ):
                tags[str(package["name"])].add(str(answer.query.get("version") or ""))
        out = list(answers)
        if not tags:
            return out
        for i, (dependency, answer) in enumerate(zip(dependencies, answers, strict=True)):
            if (
                dependency.ecosystem == "cocoapods"
                and dependency.resolved_from is None
                and dependency.version
                and isinstance(answer, Unnamed)
                and answer.reason.startswith(
                    ("its source is downloaded from", "a prebuilt binary", "an umbrella of headers")
                )
            ):
                try:
                    found = PodSiblings.find(dependency, tags)
                except (OSError, ValueError, http.client.HTTPException):
                    found = None
                if found is not None:
                    out[i] = found
                    # A fact of the pod at its version, whichever lockfile asks next.
                    UpstreamAdvisories._cache[
                        (
                            dependency.ecosystem,
                            dependency.name,
                            dependency.version,
                            dependency.integrity,
                        )
                    ] = found
        return out

    @staticmethod
    def find(dependency: Dependency, tags: Mapping[str, set[str]]) -> Upstream | None:
        from cordon_scanner.intel.more_registries import HOSTS, MoreRegistries
        from cordon_scanner.intel.registry_client import PackageNotFound

        name, version = dependency.name.split("/", 1)[0], dependency.version or ""
        if not re.fullmatch(r"[\w.+-]+", name):
            return None
        naming = re.compile(rf"(?<![\w.]){re.escape(version)}$")
        candidates = sorted(
            (repository, tag)
            for repository, refs in tags.items()
            for tag in refs
            if naming.search(tag)
        )[: PodSiblings.MAX_CANDIDATES]
        if not candidates:
            return None
        a, b, c = MoreRegistries.cocoapods_shard(name)
        spec = json.loads(
            MoreRegistries._cocoapods_spec(
                f"{HOSTS['cocoapods']}/Specs/{a}/{b}/{c}/{name}/{version}/{name}.podspec.json"
            )
        )
        source = spec.get("source") if isinstance(spec, dict) else None
        given = source.get("http") if isinstance(source, dict) else None
        if not isinstance(given, str) or not given:
            return None
        matched: list[tuple[str, str]] = []
        for repository, tag in candidates:
            raw = repository.replace("https://github.com/", "https://raw.githubusercontent.com/")
            try:
                text = Upstreams._get(
                    f"{raw}/{urllib.parse.quote(tag, safe='')}/{name}.podspec"
                ).decode("utf-8", "replace")
            except PackageNotFound:
                continue
            if NpmPodspec.declared(text, version, {}) == version and (
                PodSiblings.http(text, version) == given
            ):
                matched.append((repository, tag))
        if not matched or len({repository for repository, _ in matched}) > 1:
            return None
        repository, tag = matched[0]
        return RepositoryArchive.upstream(
            repository,
            tag,
            f"the {name} {version} podspec, published from {repository} at {tag} with the same "
            "download",
        )


class CondaSiblings:
    """A conda package naming no source of its own -- one output of a multi-output recipe
    (glib-tools of glib) -- built in the same feedstock commit as another package of the same
    lock that does name one: the same recipe, built once, from the same source.

    conda-smithy writes the feedstock and commit a package was built from into its rendered
    recipe (`extra: remote_url, sha`); two packages with the same pair came from one build."""

    _built: ClassVar[dict[str, tuple[str, str]]] = {}

    @staticmethod
    def record(url: str, data: object) -> None:
        extra = data.get("extra") if isinstance(data, dict) else None
        if not isinstance(extra, dict):
            return
        remote, sha = str(extra.get("remote_url") or ""), str(extra.get("sha") or "")
        repository = RepositoryArchive.repository(remote)
        if repository and re.fullmatch(r"[0-9a-f]{40}", sha):
            CondaSiblings._built[url] = (repository, sha)

    @staticmethod
    def resolve(
        dependencies: Sequence[Dependency], answers: Sequence[Upstream | Unnamed]
    ) -> list[Upstream | Unnamed]:
        named: dict[tuple[str, str], Upstream] = {}
        for dependency, answer in zip(dependencies, answers, strict=True):
            build = CondaSiblings._built.get(dependency.resolved_from or "")
            if dependency.ecosystem == "conda" and build and isinstance(answer, Upstream):
                named.setdefault(build, answer)
        out = list(answers)
        for i, (dependency, answer) in enumerate(zip(dependencies, answers, strict=True)):
            build = CondaSiblings._built.get(dependency.resolved_from or "")
            if (
                dependency.ecosystem == "conda"
                and build in named
                and isinstance(answer, Unnamed)
                and answer.reason.startswith("its source names no URL")
            ):
                found = named[build]
                out[i] = Upstream(
                    found.query,
                    f"{found.how}; {dependency.name} is another output of the same build "
                    f"({build[0]} at {build[1][:12]})",
                    found.inferred,
                    found.tag,
                )
                UpstreamAdvisories._cache[
                    (
                        dependency.ecosystem,
                        dependency.name,
                        dependency.version,
                        dependency.integrity,
                    )
                ] = out[i]
        return out


class HomebrewBottles:
    """A homebrew-core formula as it was when a version was bottled: the bottle's OCI manifest on
    ghcr.io names the commit and file (`org.opencontainers.image.source`)."""

    @staticmethod
    def _ghcr(path: str, accept: str, token: str | None) -> bytes:
        import urllib.request

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args: Any, **kwargs: Any) -> None:
                return None

        headers = {"User-Agent": "cordon-scanner", "Accept": accept}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(f"https://ghcr.io{path}", headers=headers)
        with urllib.request.build_opener(NoRedirect).open(request, timeout=60) as response:
            body: bytes = response.read(4 << 20)
        return body

    MAX_BOTTLE_BYTES: ClassVar[int] = 128 << 20

    _renames: ClassVar[dict[str, str] | None] = None

    @staticmethod
    def formula_data(name: str, installed: str) -> tuple[str, dict[str, Any]] | Unnamed:
        """`(formula, its formulae.brew.sh record)` for the name a Brewfile wrote. That may be an
        alias (`python3`, `gpg`, `pkg-config`), which homebrew-core keeps as a symlink in
        Aliases/, or an old name in its formula_renames.json. An alias to a versioned formula
        (`python3` -> `python@3.15`) is first looked for at the installed version's series
        (`python@3.13`), which exists only if Homebrew has it; the bottle then says exactly."""
        from cordon_scanner.intel.registry_client import PackageNotFound

        def record(formula: str) -> dict[str, Any] | None:
            try:
                answer = json.loads(
                    Upstreams._get(f"{HOMEBREW_API}/{urllib.parse.quote(formula, safe='@+')}.json")
                )
            except PackageNotFound:
                return None
            return answer if isinstance(answer, dict) else None

        data = record(name)
        if data is not None:
            return name, data
        target = ""
        try:
            link = Upstreams._get(
                f"https://raw.githubusercontent.com/Homebrew/homebrew-core/HEAD/Aliases/"
                f"{urllib.parse.quote(name, safe='@+')}"
            ).decode("utf-8", "replace")
            pointed = re.fullmatch(r"\.\./Formula/(?:[\w]/)?([\w@+.-]+)\.rb\s*", link)
            target = pointed.group(1) if pointed else ""
        except PackageNotFound:
            pass
        if not target:
            if HomebrewBottles._renames is None:
                try:
                    renames = json.loads(
                        Upstreams._get(
                            "https://raw.githubusercontent.com/Homebrew/homebrew-core/HEAD/"
                            "formula_renames.json"
                        )
                    )
                except (PackageNotFound, ValueError):
                    renames = {}
                HomebrewBottles._renames = {
                    str(k): str(v) for k, v in (renames or {}).items() if isinstance(v, str)
                }
            target = HomebrewBottles._renames.get(name, "")
        if not target:
            return Unnamed("Homebrew no longer has this formula, under this name or another")
        series = re.fullmatch(r"([\w+.-]+)@[\d.]+", target)
        numbers = re.match(r"(\d+)(?:\.(\d+))?", installed)
        candidates = []
        if series and numbers:
            major, minor = numbers.group(1), numbers.group(2)
            candidates += [f"{series.group(1)}@{major}.{minor}"] if minor else []
            candidates += [f"{series.group(1)}@{major}"]
        for formula in [*candidates, target]:
            data = record(formula)
            if data is not None:
                return formula, data
        return Unnamed(f"Homebrew's formula for {name}, {target}, could not be read")

    @staticmethod
    def head(data: dict[str, Any], installed: str, name: str) -> Upstream | Unnamed:
        """A `--HEAD` install: brew names it `HEAD-<the first seven of the commit>`, built from the
        formula's head repository. GitHub resolves the abbreviation to its commit (and refuses an
        ambiguous one); elsewhere it is not resolved."""
        from cordon_scanner.intel.homebrew_provenance import HomebrewProvenance

        short = installed.removeprefix("HEAD-").split("_", 1)[0]
        head = str(((data.get("urls") or {}).get("head") or {}).get("url") or "")
        repository = RepositoryArchive.repository(head)
        if not re.fullmatch(r"[0-9a-f]{7,40}", short) or not repository:
            return Unnamed(f"a HEAD build ({installed}) of a head repository off GitHub, or none")
        host, _, owner_repo = repository.removeprefix("https://").partition("/")
        try:
            if host == "github.com":
                record = HomebrewProvenance._get(
                    f"https://api.github.com/repos/{owner_repo}/commits/{short}"
                )
                key = "sha"
            else:
                # GitLab (qemu's head is gitlab.com/qemu-project/qemu): its API resolves it too.
                record = json.loads(
                    Upstreams._get(
                        f"https://{host}/api/v4/projects/{urllib.parse.quote(owner_repo, safe='')}"
                        f"/repository/commits/{short}"
                    )
                )
                key = "id"
        except (OSError, ValueError, http.client.HTTPException) as exc:
            return Unnamed(
                f"a HEAD build ({installed}): {host} could not resolve {short} ({type(exc).__name__})"
            )
        commit = str((record or {}).get(key) or "") if isinstance(record, dict) else ""
        if not re.fullmatch(r"[0-9a-f]{40}", commit) or not commit.startswith(short):
            return Unnamed(
                f"a HEAD build ({installed}): {short} names no one commit of {repository}"
            )
        return RepositoryArchive.upstream(
            repository, commit, f"the {name} HEAD build {short} ({repository})"
        )

    @staticmethod
    def cask(token: str) -> Unnamed:
        """A cask: a macOS application, which no repository route reaches. Its homepage and
        download, from formulae.brew.sh's cask record, go with the answer for `intel/nvd`."""
        reason = "a cask: a macOS application, which no repository route reaches"
        try:
            data = json.loads(
                Upstreams._get(
                    f"https://formulae.brew.sh/api/cask/{urllib.parse.quote(token, safe='@+')}.json"
                )
            )
        except (OSError, ValueError, http.client.HTTPException):
            return Unnamed(reason)
        if not isinstance(data, dict):
            return Unnamed(reason)
        return Unnamed(
            reason,
            homes=tuple(str(data[k]) for k in ("homepage", "url") if isinstance(data.get(k), str)),
        )

    @staticmethod
    def current_formula(data: dict[str, Any]) -> str:
        """The formula file formulae.brew.sh describes now, at the commit it names."""
        head, path = str(data.get("tap_git_head") or ""), str(data.get("ruby_source_path") or "")
        if not re.fullmatch(r"[0-9a-f]{40}", head) or not re.fullmatch(
            r"Formula/[\w@+./-]+\.rb", path
        ):
            return ""
        return Upstreams._get(
            f"https://raw.githubusercontent.com/Homebrew/homebrew-core/{head}/{path}"
        ).decode("utf-8", "replace")

    @staticmethod
    def tap_formula(tap: str, formula: str, installed: str) -> Upstream | Unnamed:
        """A formula from a third-party tap (`<owner>/<tap>`), read from the tap's own repository,
        `github.com/<owner>/homebrew-<tap>`, where brew finds it: `Formula/<name>.rb`,
        `Formula/<letter>/<name>.rb`, `HomebrewFormula/<name>.rb` or `<name>.rb`."""
        owner, name = tap.split("/")
        repository = f"https://github.com/{owner}/homebrew-{name.removeprefix('homebrew-')}"
        base = (
            repository.replace("https://github.com/", "https://raw.githubusercontent.com/")
            + "/HEAD"
        )
        text = ""
        for path in (
            f"Formula/{formula}.rb",
            f"Formula/{formula[:1]}/{formula}.rb",
            f"HomebrewFormula/{formula}.rb",
            f"{formula}.rb",
        ):
            try:
                text = Upstreams._get(f"{base}/{path}").decode("utf-8", "replace")
                break
            except (OSError, ValueError, http.client.HTTPException):
                continue
        if not text:
            return Unnamed(f"the tap {tap} holds no formula {formula}")
        version = re.sub(r"_\d+$", "", installed)
        how = f"the {formula} formula in {repository}"
        source = HomebrewBottles.source(text, how)
        # The tap's formula is as it is now: its source is the installed one only if it names
        # that version; otherwise the version's tag is looked for in the repository it names.
        names_installed = bool(version) and version in text
        heads = re.findall(r'^\s*(?:head\s+|url\s+)"([^"]+?)(?:\.git)?"', text, re.MULTILINE)
        return Upstreams.inferred(
            source
            if names_installed
            else Unnamed(f"the tap's formula now builds another version than {version}"),
            heads,
            version,
            (formula,),
            how,
            HomebrewBottles.archive(text) if names_installed else None,
        )

    @staticmethod
    def formula(name: str, version: str) -> str:
        """The formula a bottle was built from, as the bottle carries it (`<name>/<version>/.brew/
        <name>.rb`): the smallest platform's bottle, read as a stream to that file. The commit its
        manifest names may be gone from homebrew-core (a pull request's, squashed); the file in
        the bottle is not."""
        import urllib.request

        repository = f"homebrew/core/{name.replace('@', '/')}"
        token = json.loads(
            HomebrewBottles._ghcr(
                f"/token?scope=repository:{repository}:pull", "application/json", None
            )
        ).get("token")
        bearer = str(token) if token else None
        index = json.loads(
            HomebrewBottles._ghcr(
                f"/v2/{repository}/manifests/{urllib.parse.quote(version, safe='._')}",
                "application/vnd.oci.image.index.v1+json",
                bearer,
            )
        )
        layers: list[tuple[int, str]] = []
        for entry in index.get("manifests") or []:
            manifest = json.loads(
                HomebrewBottles._ghcr(
                    f"/v2/{repository}/manifests/{entry.get('digest')}",
                    "application/vnd.oci.image.manifest.v1+json",
                    bearer,
                )
            )
            layers += [
                (int(layer.get("size") or 0), str(layer.get("digest")))
                for layer in manifest.get("layers") or []
                if re.fullmatch(r"sha256:[0-9a-f]{64}", str(layer.get("digest")))
            ]
            break  # every platform's bottle carries the same formula
        if not layers:
            raise ValueError("the bottle has no layer")
        size, digest = min(layers)
        if size > HomebrewBottles.MAX_BOTTLE_BYTES:
            raise ValueError("bottle too large to read its formula")
        request = urllib.request.Request(
            f"https://ghcr.io/v2/{repository}/blobs/{digest}",
            headers={
                "User-Agent": "cordon-scanner",
                **({"Authorization": f"Bearer {bearer}"} if bearer else {}),
            },
        )
        # A blob redirects to ghcr's storage host; urllib follows it and drops nothing it needs.
        with (
            urllib.request.urlopen(request, timeout=120) as response,  # noqa: S310
            tarfile.open(fileobj=response, mode="r|gz") as archive,
        ):
            for member in archive:
                if member.isfile() and re.fullmatch(r"[^/]+/[^/]+/\.brew/[^/]+\.rb", member.name):
                    handle = archive.extractfile(member)
                    if handle is not None:
                        return handle.read(1 << 20).decode("utf-8", "replace")
        raise ValueError("the bottle carries no formula")

    @staticmethod
    def archive(text: str) -> Archive | None:
        """The stable source a formula pins: its URL, its mirrors (brew checks each against the
        same digest) and its sha256."""
        found = re.search(
            r'^([ \t]*)url\s+"([^"]+)"[^\n]*\n((?:\1(?:mirror|version)\s+"[^"]*"[^\n]*\n)*)\1sha256\s+"([0-9a-f]{64})"',
            text,
            re.MULTILINE,
        )
        if not found:
            return None
        mirrors = re.findall(r'mirror\s+"([^"]+)"', found.group(3))
        return Archive((found.group(2), *mirrors), f"sha256:{found.group(4)}")

    @staticmethod
    def source(text: str, how: str) -> Upstream | Unnamed:
        """A formula's stable source, read by Cordon's formula reader; a git source's `tag:` and
        `revision:` from the same statement."""
        from cordon_scanner.core.content import FileContent
        from cordon_scanner.ecosystems.homebrew import Formula

        manifest = Formula.parse(FileContent.from_bytes("Formula/x.rb", text.encode()), "homebrew")
        url = next(
            (
                s[len("source ") :]
                for s in manifest.sources
                if s.startswith("source ") and not s.startswith("source sha256")
            ),
            "",
        )
        if not url:
            return Unnamed("the formula names no stable source")
        repository = RepositoryArchive.repository(url)
        if repository:
            statement = re.search(rf'url\s+"{re.escape(url)}"((?:\s*,\s*\w+:\s*"[^"]*")*)', text)
            fields = dict(
                re.findall(r'(\w+):\s*"([^"]*)"', statement.group(1) if statement else "")
            )
            ref = fields.get("revision") or fields.get("tag")
            if ref:
                return RepositoryArchive.upstream(repository, ref, f"{how} ({repository})")
        # Its mirrors serve the same file (brew checks every one against the one sha256), and one
        # is often the forge's own release asset.
        indent = re.search(rf'^([ \t]*)url\s+"{re.escape(url)}"', text, re.MULTILINE)
        mirrors = (
            re.findall(rf'^{re.escape(indent.group(1))}mirror\s+"([^"]+)"', text, re.MULTILINE)
            if indent
            else []
        )
        return Upstreams.from_urls([url, *mirrors], how)


class HomebrewHistory:
    """A homebrew-core formula as it was when a bottle was built, found in the repository's history
    by the bottle's SHA-256. Homebrew writes each bottle's digest into the formula (`bottle do`,
    `sha256 "<digest>" => :catalina`), and a Brewfile.lock.json records the digest of the bottle it
    installed, so the revision holding that digest is the formula the bottle was built from. This
    reaches a formula Homebrew has since deleted (curl-openssl) and a version bottled before bottles
    moved to ghcr.io (cmake 3.18.1), where no bottle remains to carry its formula.

        GET https://api.github.com/repos/Homebrew/homebrew-core/commits?path=Formula/<name>.rb
        GET https://raw.githubusercontent.com/Homebrew/homebrew-core/<commit>/Formula/<name>.rb

    Only commits whose message names the version are read (`cmake: update 3.18.1 bottle.`); the
    file is used only if it holds the digest. GitHub's API allows 60 requests an hour without a
    token; `GITHUB_TOKEN`, when set, is sent to it alone."""

    COMMITS: ClassVar[str] = "https://api.github.com/repos/Homebrew/homebrew-core/commits"
    RAW: ClassVar[str] = "https://raw.githubusercontent.com/Homebrew/homebrew-core"
    MAX_PAGES: ClassVar[int] = 10

    @staticmethod
    def paths(name: str) -> tuple[str, ...]:
        """Where homebrew-core has kept the formula: `Formula/<name>.rb`, and since 2023
        `Formula/<first letter>/<name>.rb` (`lib` formulae under `Formula/lib/`)."""
        shard = "lib" if name.startswith("lib") else name[:1]
        return (f"Formula/{name}.rb", f"Formula/{shard}/{name}.rb")

    @staticmethod
    def formula(name: str, installed: str, digest: str) -> tuple[str, str, str] | None:
        """`(formula text, commit, path)` of the revision holding the bottle digest, or None.
        With no digest (a lock written without bottles), the newest revision that builds the
        installed version: its stable source names the version, and its `revision` is the
        installed one's (`1.6.0_1` is revision 1)."""
        from cordon_scanner.intel.homebrew_provenance import HomebrewProvenance
        from cordon_scanner.intel.registry_client import PackageNotFound

        if digest and not re.fullmatch(r"[0-9a-f]{64}", digest):
            return None
        if not re.fullmatch(r"[\w@+.-]+", name):
            return None
        # The installed version as written, revision and all: `update 3.18.1_1 bottle.`
        names = re.compile(rf"(?<![\w.]){re.escape(installed)}(?![\w.]*\d)")
        for path in HomebrewHistory.paths(name):
            for page in range(1, HomebrewHistory.MAX_PAGES + 1):
                commits = HomebrewProvenance._get(
                    f"{HomebrewHistory.COMMITS}?path={urllib.parse.quote(path, safe='/@+')}"
                    f"&per_page=100&page={page}"
                )
                if not isinstance(commits, list) or not commits:
                    break
                for commit in commits:
                    sha = str((commit or {}).get("sha") or "")
                    message = str(((commit or {}).get("commit") or {}).get("message") or "")
                    if not re.fullmatch(r"[0-9a-f]{40}", sha) or not names.search(message):
                        continue
                    try:
                        text = Upstreams._get(f"{HomebrewHistory.RAW}/{sha}/{path}").decode(
                            "utf-8", "replace"
                        )
                    except PackageNotFound:
                        continue  # the commit that deleted it
                    if (
                        (f'"{digest}"' in text)
                        if digest
                        else HomebrewHistory.builds(text, installed)
                    ):
                        return text, sha, path
                if len(commits) < 100:
                    break
        return None

    @staticmethod
    def builds(text: str, installed: str) -> bool:
        """Whether a formula builds `installed`: its stable source, or `version`, names the version,
        and its `revision` is the installed one's."""
        found = re.fullmatch(r"(.+?)(?:_(\d+))?", installed)
        if not found:
            return False
        version, revision = found.group(1), int(found.group(2) or 0)
        archive = HomebrewBottles.archive(text)
        declared = re.search(r'^\s*version\s+"([^"]+)"', text, re.MULTILINE)
        named = (
            (declared.group(1) == version)
            if declared
            else bool(
                archive
                and re.search(
                    rf"(?<![\d.]){re.escape(version)}(?![A-Za-z0-9]|\.\d)", archive.urls[0]
                )
            )
        )
        stated = re.search(r"^\s*revision\s+(\d+)\s*$", text, re.MULTILINE)
        return named and int(stated.group(1) if stated else 0) == revision

    @staticmethod
    def homepage(text: str) -> str | None:
        found = re.search(r'^\s*homepage\s+"([^"]+)"', text, re.MULTILINE)
        return found.group(1) if found else None

    @staticmethod
    def upstream(dependency: Dependency, otherwise: Unnamed) -> Upstream | Unnamed:
        """The upstream the formula in the history names, read as any formula is; `otherwise`,
        with why, when the history holds no revision with the bottle's digest."""
        installed = dependency.version or ""
        digest = (dependency.integrity or "").removeprefix("sha256:")
        if not installed or installed.startswith("HEAD"):
            return otherwise
        try:
            found = HomebrewHistory.formula(dependency.name, installed, digest)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            return Unnamed(
                f"{otherwise.reason}; homebrew-core's history could not be read ({type(exc).__name__})",
                homes=otherwise.homes,
            )
        if found is None:
            return Unnamed(
                f"{otherwise.reason}; no revision of its formula in homebrew-core's history "
                + ("holds its bottle's digest" if digest else f"builds {installed}"),
                homes=otherwise.homes,
            )
        text, commit, _ = found
        how = f"the {dependency.name} {installed} formula at homebrew-core {commit[:12]}, " + (
            "which holds its bottle's digest"
            if digest
            else f"the newest revision building {installed} (the lock records no bottle)"
        )
        heads = re.findall(r'^\s*(?:head\s+|url\s+)"([^"]+\.git)"', text, re.MULTILINE)
        return Upstreams.inferred(
            HomebrewBottles.source(text, how),
            [*heads, HomebrewHistory.homepage(text)],
            re.sub(r"_\d+$", "", installed),
            (dependency.name.split("@", 1)[0],),
            how,
            HomebrewBottles.archive(text),
        )


class TagInference:
    """A version's tag in the repository a package's own ecosystem names, where nothing names the
    tag itself (a source downloaded from the project's own site, a Galaxy collection).

    An inference, kept narrow and stated in every finding it produces: the repository's tags are
    read from the repository itself (git's smart-HTTP ref advertisement, what `git ls-remote`
    asks), only a tag spelled as the version -- `1.2.3`, `v1.2.3`, `<project>-1.2.3`,
    `<project>-v1.2.3`, `release-1.2.3` -- counts, and the candidates must all name one commit.
    OSV is then asked by that commit.
    """

    MAX_REFS_BYTES: ClassVar[int] = 32 << 20
    _refs: ClassVar[dict[str, dict[str, str] | None]] = {}
    _tips: ClassVar[dict[str, dict[str, str]]] = {}
    """`repository -> tag -> the object the tag ref points at` (a tag object or a commit): what a
    fetch asks for, since a ref's tip is fetchable from every server."""

    @staticmethod
    def repository(url: str) -> str | None:
        """An https repository address from what an ecosystem writes (`github:owner/repo`, a
        homepage on a forge, a `.git` clone URL), or None for anything that is not one."""
        text = url.strip()
        text = re.sub(r"^github:", "https://github.com/", text)
        text = re.sub(r"^gitlab:", "https://gitlab.com/", text)
        text = re.sub(r"^git\+", "", text)
        text = re.sub(r"^git://", "https://", text)
        if "/-/" in text:
            # A GitLab page (`https://gitlab.gnome.org/GNOME/libxml2/-/wikis/home`): the project
            # is everything before `/-/`, on any GitLab.
            project = text.split("/-/", 1)[0]
            if re.fullmatch(r"https://[\w.-]+(?::\d+)?/[\w.~-]+(?:/[\w.~-]+){1,8}", project):
                return project
        found = re.match(
            r"^https://(github\.com|gitlab\.com|codeberg\.org|bitbucket\.org)/([\w.-]+)/([\w.-]+?)(?:\.git)?/?(?:[#?].*)?$",
            text,
        )
        if found:
            return f"https://{found.group(1)}/{found.group(2)}/{found.group(3)}"
        # A self-hosted git server's clone URL (savannah, sourceware, gitlab.gnome.org).
        found = re.match(r"^https://[\w.-]+(?::\d+)?/[\w./~-]+\.git/?$", text)
        return found.group(0).rstrip("/") if found else None

    @staticmethod
    def refs(repository: str) -> dict[str, str] | None:
        """`tag -> commit` (annotated tags peeled), or None when the server does not speak git's
        smart HTTP."""
        if repository in TagInference._refs:
            return TagInference._refs[repository]
        import urllib.request

        base = repository if repository.endswith(".git") else f"{repository}.git"
        request = urllib.request.Request(  # noqa: S310 - https, from TagInference.repository
            f"{base}/info/refs?service=git-upload-pack",
            headers={"User-Agent": "git/2.45.0 (cordon-scanner)"},
        )
        found: dict[str, str] | None = None
        try:
            # Once more on a failure: a busy forge (savannah) drops a request now and then, and a
            # failure is kept for the whole scan.
            for attempt in (1, 2):
                try:
                    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
                        kind = str(response.headers.get("Content-Type") or "")
                        body: bytes = response.read(TagInference.MAX_REFS_BYTES + 1)
                        final = str(response.geturl())
                    break
                except (OSError, http.client.HTTPException):
                    if attempt == 2:
                        raise
            if (
                "git-upload-pack-advertisement" in kind
                and b"version 2" in body[:64]
                and final.startswith("https://")
            ):
                # A server that answers in protocol v2 unasked (git.postgresql.org) lists no
                # refs here: they are asked for with `ls-refs`, peeled.
                found = TagInference.ls_refs(final.split("/info/refs", 1)[0])
                TagInference._tips[repository] = dict(found)
            elif (
                "git-upload-pack-advertisement" in kind and len(body) <= TagInference.MAX_REFS_BYTES
            ):
                found = {}
                peeled: dict[str, str] = {}
                for line in re.findall(rb"[0-9a-f]{4}([0-9a-f]{40}) (refs/tags/[^\x00\n]+)", body):
                    commit, ref = line[0].decode(), line[1].decode()
                    name = ref[len("refs/tags/") :]
                    if name.endswith("^{}"):
                        peeled[name[:-3]] = commit
                    else:
                        found[name] = commit
                found.update(peeled)
                TagInference._tips[repository] = dict(found)
                found.update(peeled)
            elif (
                final.startswith("https://")
                and len(body) <= TagInference.MAX_REFS_BYTES
                and re.match(rb"[0-9a-f]{40}\trefs/", body)
            ):
                # Git's "dumb" HTTP (git.joeyh.name): `info/refs` is the plain list `<id>\t<ref>`,
                # an annotated tag followed by its `^{}` peeled line. Tags only: no tree is fetched
                # this way, so what it names is never proved, only inferred.
                found = {}
                peeled = {}
                for raw_id, raw_ref in re.findall(rb"(?m)^([0-9a-f]{40})\trefs/tags/(\S+)$", body):
                    name = raw_ref.decode("utf-8", "replace")
                    if name.endswith("^{}"):
                        peeled[name[:-3]] = raw_id.decode()
                    else:
                        found[name] = raw_id.decode()
                found.update(peeled)
        except (OSError, ValueError, http.client.HTTPException):
            found = None
        TagInference._refs[repository] = found
        return found

    @staticmethod
    def ls_refs(base: str) -> dict[str, str]:
        """`tag -> commit` by protocol v2's `ls-refs`, annotated tags peeled."""
        import urllib.request

        from cordon_scanner.intel.gitfetch import GitFetch

        body = b"".join(
            [
                GitFetch._pkt("command=ls-refs\n"),
                GitFetch._pkt("agent=git/2.45.0 (cordon-scanner)\n"),
                b"0001",
                GitFetch._pkt("peel\n"),
                GitFetch._pkt("ref-prefix refs/tags/\n"),
                b"0000",
            ]
        )
        request = urllib.request.Request(  # noqa: S310 - https, checked by the caller
            f"{base}/git-upload-pack",
            data=body,
            headers={
                "User-Agent": "git/2.45.0 (cordon-scanner)",
                "Git-Protocol": "version=2",
                "Content-Type": "application/x-git-upload-pack-request",
                "Accept": "application/x-git-upload-pack-result",
            },
        )
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            answer: bytes = response.read(TagInference.MAX_REFS_BYTES + 1)
        if len(answer) > TagInference.MAX_REFS_BYTES:
            raise ValueError("ref listing too large")
        found: dict[str, str] = {}
        for line in GitFetch._lines(answer):
            listed = re.match(
                rb"([0-9a-f]{40}) refs/tags/(\S+)(?: peeled:([0-9a-f]{40}))?", line or b""
            )
            if listed:
                found[listed.group(2).decode()] = (listed.group(3) or listed.group(1)).decode()
        return found

    @staticmethod
    def infer(repository: str, version: str, names: Iterable[str], how: str) -> Upstream | Unnamed:
        tags = TagInference.refs(repository)
        if tags is None:
            return Unnamed(f"{repository} could not be read as a git repository")
        # The version as written, and with its dots as underscores (Ruby's `v3_2_2`, curl's
        # `curl-8_0_0`): the same version, spelled the way some projects tag.
        forms = {version, version.replace(".", "_")}
        spellings = {s for v in forms for s in (v, f"v{v}", f"release-{v}", f"version-{v}")}
        # PostgreSQL's `REL_14_5`, `REL9_6_24`: the underscore form behind its own prefix.
        spellings |= {f"REL_{version.replace('.', '_')}", f"REL{version.replace('.', '_')}"}
        spellings |= {f"n{version}", f"VER-{version.replace('.', '-')}"}
        for name in names:
            if name:
                spellings |= {
                    s
                    for v in forms
                    # GCC's `releases/gcc-15.2.0`.
                    for s in (f"{name}-{v}", f"{name}-v{v}", f"{name}_{v}", f"releases/{name}-{v}")
                }
        # Spelled in any case (OpenSSL's `OpenSSL_1_1_1n` for openssl 1.1.1n): every tag that
        # matches still has to name the one commit.
        wanted = {spelling.lower() for spelling in spellings}
        matched = {tag: commit for tag, commit in tags.items() if tag.lower() in wanted}
        if not matched:
            return Unnamed(f"{repository} has no tag spelled as version {version}")
        commits = set(matched.values())
        if len(commits) != 1:
            return Unnamed(f"{repository}'s tags for {version} name different commits")
        tag = sorted(matched)[0]
        commit = commits.pop()
        return Upstream(
            {"commit": commit},
            f"{how}, inferred: the tag {tag} in {repository}, the only commit a tag spelled as "
            f"version {version} names",
            inferred=True,
            tag=tag,
        )


class Conventions:
    """Repositories a download host's own layout implies for a release it serves: GNU's
    `ftp.gnu.org/gnu/<name>/` and savannah's `<name>.git`, sourceware's `pub/<name>/` and its
    `git/<name>.git`, GNOME's `sources/<name>/` and its GitLab. A guess by itself, so used only
    to be proved against the release (`ContentProof`), never as an inference."""

    #: GNU's release directories (ftp.gnu.org and its mirrors), for the projects below.
    GNU: ClassVar[str] = (
        r"^https?://(?:mirror\.bazel\.build/)?(?:ftp\.gnu\.org/(?:pub/)?gnu|ftpmirror\.gnu\.org(?:/gnu)?|mirrors\.kernel\.org/gnu)/"
    )
    FORMS: ClassVar[tuple[tuple[re.Pattern[str], str], ...]] = (
        # GNU projects whose repository is not savannah's.
        (re.compile(GNU + r"gcc/"), "https://gcc.gnu.org/git/gcc.git"),
        (re.compile(GNU + r"(?:binutils|gdb)/"), "https://sourceware.org/git/binutils-gdb.git"),
        (re.compile(GNU + r"glibc/"), "https://sourceware.org/git/glibc.git"),
        (re.compile(GNU + r"(mpc|mpfr)/"), "https://gitlab.inria.fr/{0}/{0}.git"),
        # XZ Utils: SourceForge's lzmautils and tukaani.org serve its releases.
        (
            re.compile(
                r"^https?://(?:(?:downloads\.)?sourceforge\.net/projects?/lzmautils/"
                r"|tukaani\.org/xz/|github\.com/tukaani-project/xz/releases/)"
            ),
            "https://github.com/tukaani-project/xz",
        ),
        (
            re.compile(
                r"^https?://(?:mirror\.bazel\.build/)?(?:ftp\.gnu\.org/gnu|ftpmirror\.gnu\.org(?:/gnu)?"
                r"|mirrors\.kernel\.org/gnu|ftp\.gnu\.org/pub/gnu)/([\w.+-]+)/"
            ),
            "https://git.savannah.gnu.org/git/{0}.git",
        ),
        (
            re.compile(
                r"^https?://(?:mirror\.bazel\.build/)?(?:www\.)?sourceware\.org/pub/([\w.+-]+)/"
            ),
            "https://sourceware.org/git/{0}.git",
        ),
        (
            re.compile(
                r"^https?://(?:download-mirror\.savannah\.(?:gnu|nongnu)\.org"
                r"|download\.savannah\.gnu\.org)/releases/([\w.+-]+)/"
            ),
            "https://git.savannah.gnu.org/git/{0}.git",
        ),
        # SourceForge's git: `git.code.sf.net/p/<project>/code` (or `/git`), where a project
        # keeps one.
        (
            re.compile(
                r"^https?://(?:downloads\.)?sourceforge\.net/projects?/([\w.-]+)/"
                r"|^https?://prdownloads\.sourceforge\.net/([\w.-]+)/"
            ),
            "https://git.code.sf.net/p/{}/code",
        ),
        (
            re.compile(
                r"^https?://(?:downloads\.)?sourceforge\.net/projects?/([\w.-]+)/"
                r"|^https?://prdownloads\.sourceforge\.net/([\w.-]+)/"
            ),
            "https://git.code.sf.net/p/{}/git",
        ),
        # The Apache Software Foundation's releases, and its mirrors of each project on GitHub.
        (
            re.compile(
                r"^https?://(?:archive\.apache\.org/dist|downloads\.apache\.org|dlcdn\.apache\.org"
                r"|www\.apache\.org/dist)/([\w.-]+)/"
            ),
            "https://github.com/apache/{}",
        ),
        (
            re.compile(r"^https?://(?:www\.)?netfilter\.org/projects/([\w.-]+)/files/"),
            "https://git.netfilter.org/{}",
        ),
        (
            re.compile(r"^https?://ftp\.postgresql\.org/pub/source/v[\d.]+/(postgresql)-"),
            "https://git.postgresql.org/git/{}.git",
        ),
        (
            re.compile(r"^https?://(?:www\.)?gnupg\.org/ftp/gcrypt/([\w.+-]+)/"),
            "https://dev.gnupg.org/source/{}.git",
        ),
        (
            re.compile(r"^https?://(?:www\.)?python\.org/ftp/(python)/"),
            "https://github.com/python/cpython",
        ),
        (
            re.compile(r"^https?://(?:www\.)?sqlite\.org/\d{4}/(sqlite)-"),
            "https://github.com/sqlite/sqlite",
        ),
        (
            re.compile(r"^https?://distfiles\.(?:ariadne\.space|dereferenced\.org)/(pkgconf)/"),
            "https://github.com/pkgconf/pkgconf",
        ),
        (
            re.compile(r"^https?://(?:www\.)?nasm\.us/pub/(nasm)/"),
            "https://github.com/netwide-assembler/nasm",
        ),
        (
            re.compile(r"^https?://(?:www\.)?tortall\.net/projects/(yasm)/"),
            "https://github.com/yasm/yasm",
        ),
        (
            re.compile(
                r"^https?://(?:download|downloads)\.sourceforge\.net/(?:project/)?(libpng)/"
            ),
            "https://github.com/pnggroup/libpng",
        ),
        (
            re.compile(r"^https?://download\.osgeo\.org/(libtiff)/"),
            "https://gitlab.com/libtiff/libtiff",
        ),
        (
            re.compile(
                r"^https?://storage\.googleapis\.com/downloads\.webmproject\.org/releases/webp/(libwebp)-"
            ),
            "https://github.com/webmproject/libwebp",
        ),
        (
            re.compile(r"^https?://downloads\.videolan\.org/(?:pub/)?videolan/(dav1d)/"),
            "https://code.videolan.org/videolan/dav1d",
        ),
        (
            re.compile(r"^https?://(?:www\.)?ffmpeg\.org/+releases/(ffmpeg)-"),
            "https://git.ffmpeg.org/ffmpeg.git",
        ),
        (
            re.compile(r"^https?://storage\.googleapis\.com/aom-releases/(libaom)-"),
            "https://aomedia.googlesource.com/aom",
        ),
        (
            re.compile(r"^https?://download\.open-mpi\.org/release/(hwloc)/"),
            "https://github.com/open-mpi/hwloc",
        ),
        (
            re.compile(r"^https?://download\.open-mpi\.org/release/(open-mpi)/"),
            "https://github.com/open-mpi/ompi",
        ),
        (
            re.compile(
                r"^https?://(?:download|downloads)\.videolan\.org/(?:pub/)?videolan/(x265)/"
            ),
            "https://bitbucket.org/multicoreware/x265_git",
        ),
        (
            re.compile(r"^https?://(?:www\.)?libsdl\.org/projects/(SDL_\w+)/release/"),
            "https://github.com/libsdl-org/{0}",
        ),
        (
            re.compile(r"^https?://(?:www\.)?fftw\.org/(fftw)-"),
            "https://github.com/FFTW/fftw3",
        ),
        (
            re.compile(r"^https?://dri\.freedesktop\.org/(libdrm)/"),
            "https://gitlab.freedesktop.org/mesa/drm",
        ),
        (
            re.compile(r"^https?://(?:www\.)?sourceware\.org/(elfutils)/ftp/"),
            "https://sourceware.org/git/elfutils.git",
        ),
        (
            re.compile(
                r"^https?://(?:cdn|mirrors\.edge|www)\.kernel\.org/pub/linux/utils/(util-linux)/"
            ),
            "https://github.com/util-linux/util-linux",
        ),
        (
            re.compile(r"^https?://download\.savannah\.(?:gnu|nongnu)\.org/releases/(freetype)/"),
            "https://gitlab.freedesktop.org/freetype/freetype",
        ),
        (re.compile(r"^https?://(?:www\.)?lua\.org/ftp/(lua)-"), "https://github.com/lua/lua"),
        (
            re.compile(r"^https?://(?:www\.)?openssl\.org/source/(?:old/[\w.]+/)?(openssl)-"),
            "https://github.com/openssl/openssl",
        ),
        (
            re.compile(r"^https?://cache\.ruby-lang\.org/pub/(ruby)/"),
            "https://github.com/ruby/{0}",
        ),
        (
            re.compile(
                r"^https?://(?:download\.gnome\.org|ftp\.gnome\.org/pub/(?:gnome|GNOME))/sources/([\w.+-]+)/"
            ),
            "https://gitlab.gnome.org/GNOME/{0}",
        ),
        # Small tools whose own sites serve the releases their public repositories tag.
        (
            re.compile(r"^https?://mama\.indstate\.edu/users/ice/(tree)/"),
            "https://gitlab.com/OldManProgrammer/unix-tree",
        ),
        (
            re.compile(r"^https?://(?:www\.)?ivarch\.com/programs/sources/(pv)-"),
            "https://github.com/a-j-wood/pv",
        ),
        (
            re.compile(r"^https?://(?:www\.)?colordiff\.org/(colordiff)-"),
            "https://github.com/daveewart/colordiff",
        ),
        (
            re.compile(r"^https?://zsync\.moria\.org\.uk/download/(zsync)-"),
            "https://github.com/cph6/zsync",
        ),
        # XCB's utility libraries, released as xcb-util-*, from xorg/lib/libxcb-*.
        (
            re.compile(
                r"^https?://xcb\.freedesktop\.org/dist/xcb-util-(image|cursor|keysyms|wm)-\d"
            ),
            "https://gitlab.freedesktop.org/xorg/lib/libxcb-{0}",
        ),
        (
            re.compile(r"^https?://xcb\.freedesktop\.org/dist/xcb-util-renderutil-\d"),
            "https://gitlab.freedesktop.org/xorg/lib/libxcb-render-util",
        ),
        (
            re.compile(r"^https?://xcb\.freedesktop\.org/dist/xcb-util-\d"),
            "https://gitlab.freedesktop.org/xorg/lib/libxcb-util",
        ),
        (
            re.compile(r"^https?://(?:www\.)?gaia-gis\.it/gaia-sins/(librttopo)-"),
            "https://git.osgeo.org/gitea/rttopo/librttopo",
        ),
        (
            re.compile(r"^https?://download\.libsodium\.org/libsodium/releases/"),
            "https://github.com/jedisct1/libsodium",
        ),
        (
            re.compile(
                r"^https?://downloads\.xiph\.org/releases/(ogg|vorbis|flac|opus|theora|speex)/"
            ),
            "https://gitlab.xiph.org/xiph/{0}",
        ),
        (
            re.compile(r"^https?://icon-theme\.freedesktop\.org/releases/hicolor-icon-theme-"),
            "https://gitlab.freedesktop.org/xdg/default-icon-theme",
        ),
        (
            re.compile(r"^https?://download\.osgeo\.org/geotiff/libgeotiff/"),
            "https://github.com/OSGeo/libgeotiff",
        ),
        (
            re.compile(
                r"^https?://(?:www\.)?freedesktop\.org/software/pulseaudio/releases/pulseaudio-"
            ),
            "https://gitlab.freedesktop.org/pulseaudio/pulseaudio",
        ),
        (
            re.compile(r"^https?://confluence\.ecmwf\.int/download/attachments/\d+/eccodes-"),
            "https://github.com/ecmwf/eccodes",
        ),
        (
            re.compile(r"^https?://(?:downloads\.)?sourceforge\.net/projects?/freeglut/"),
            "https://github.com/freeglut/freeglut",
        ),
        # XCB's libpthread-stubs is released under that name from `xorg/lib/pthread-stubs`.
        (
            re.compile(
                r"^https?://(?:www\.x\.org|xorg\.freedesktop\.org|xcb\.freedesktop\.org)/(?:releases/individual/xcb/|archive/individual/xcb/|dist/)libpthread-stubs-\d"
            ),
            "https://gitlab.freedesktop.org/xorg/lib/pthread-stubs",
        ),
        # X.org's util-macros is released under that name from its repository `xorg/util/macros`.
        (
            re.compile(
                r"^https?://(?:www\.)?x\.org/(?:releases|archive)/+individual/util/util-macros-\d"
            ),
            "https://gitlab.freedesktop.org/xorg/util/macros",
        ),
        (
            re.compile(r"^https?://ziglang\.org/download/[\d.]+/(zig)-"),
            "https://github.com/ziglang/zig",
        ),
        (
            re.compile(r"^https?://(?:www\.)?spice-space\.org/download/gtk/(spice-gtk)-"),
            "https://gitlab.freedesktop.org/spice/spice-gtk",
        ),
        (
            re.compile(
                r"^https?://(?:www\.)?x\.org/(?:releases|archive)/+individual/([\w-]+)/([\w.+-]+?)-\d"
            ),
            "https://gitlab.freedesktop.org/xorg/{0}/{1}",
        ),
        (
            re.compile(
                r"^https?://xorg\.freedesktop\.org/(?:releases|archive)/individual/([\w-]+)/([\w.+-]+?)-\d"
            ),
            "https://gitlab.freedesktop.org/xorg/{0}/{1}",
        ),
    )

    @staticmethod
    def repositories(urls: Iterable[str]) -> list[str]:
        out: list[str] = []
        for url in urls:
            for form, template in Conventions.FORMS:
                found = form.match(url)
                if found:
                    # A form with alternatives has a group per alternative: those that matched.
                    out.append(template.format(*(g for g in found.groups() if g is not None)))
        return list(dict.fromkeys(out))


@dataclass(frozen=True)
class Archive:
    """A release archive a recipe pins: where it is downloaded from, and its digest."""

    urls: tuple[str, ...]
    digest: str
    """`sha256:<hex>`, `sha512:<hex>`, or an SRI value (`sha256-<base64>`)."""


class ContentProof:
    """Whether an inferred tag IS the source a recipe builds: the release archive the recipe pins,
    checked against its digest, beside the tag's tree fetched by git's own protocol, compared by
    git blob id (dot-files aside).

    Refuted when any file both hold differs -- which is how a neighbouring version's tag fails:
    whatever changed between the two is shipped. Exactly two differences are git's own, not
    different source: its end-of-line conversion (`text eol=crlf`), and a file the tag holds
    empty that the release fills in (GNU's ChangeLog, written by `make dist`). A release may also
    add files (`configure`, generated docs) and leave some out (tests, fuzzing inputs).

    Proven when nothing differs and enough is shared to mean something: at least `MIN_SHARED`
    identical files, or, for a small project, at least `MIN_SMALL` that are `MIN_SHARE` of the
    tag's. A wrong tag could pass only by differing in files the release does not ship -- the same
    shipped code, so the same vulnerabilities."""

    MIN_SHARED: ClassVar[int] = 100
    MIN_SMALL: ClassVar[int] = 5
    MIN_SHARE: ClassVar[float] = 0.9
    EMPTY_BLOB: ClassVar[str] = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    """Git's id for an empty file."""
    MAX_ARCHIVE_BYTES: ClassVar[int] = 256 << 20
    SOCKET_SECONDS: ClassVar[float] = 30.0
    DOWNLOAD_SECONDS: ClassVar[float] = 300.0
    _running: ClassVar[threading.BoundedSemaphore] = threading.BoundedSemaphore(2)
    _results: ClassVar[dict[tuple[str, str, str], tuple[str, str]]] = {}

    @staticmethod
    def _digest_matches(body: bytes, digest: str) -> bool:
        import base64
        import hashlib

        if "-" in digest and ":" not in digest:  # SRI
            algorithm, _, encoded = digest.partition("-")
            try:
                expected = base64.b64decode(encoded).hex()
            except ValueError:
                return False
        else:
            algorithm, _, expected = digest.partition(":")
        if algorithm not in ("sha256", "sha512"):
            return False
        return hashlib.new(algorithm, body).hexdigest() == expected.lower()

    @staticmethod
    def _download(url: str) -> bytes:
        import urllib.request

        # Plain http is allowed here only: what is read is used only if it hashes to the digest
        # the recipe pins (zlib's conda recipe names http://zlib.net/), so the transport cannot
        # change what is compared.
        if not url.startswith(("https://", "http://")):
            raise ValueError("not http(s)")
        import time

        request = urllib.request.Request(url, headers={"User-Agent": "cordon-scanner"})  # noqa: S310
        # Each connect and read has its own short timeout -- a host that drops packets fails in
        # seconds, not after the read timeout for every address it resolves to -- and the whole
        # download a deadline, so a server trickling bytes cannot hold a scan.
        deadline = time.monotonic() + ContentProof.DOWNLOAD_SECONDS
        chunks: list[bytes] = []
        size = 0
        with urllib.request.urlopen(request, timeout=ContentProof.SOCKET_SECONDS) as response:  # noqa: S310
            while True:
                chunk: bytes = response.read(1 << 20)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > ContentProof.MAX_ARCHIVE_BYTES:
                    raise ValueError("archive too large")
                if time.monotonic() > deadline:
                    raise TimeoutError("the release archive took too long to download")
        return b"".join(chunks)

    @staticmethod
    def blobs(body: bytes) -> dict[str, tuple[str, str | None]]:
        """`path -> (git blob id, blob id with CRLF made LF, where it has a CRLF)` of each regular
        file, the archive's one top-level folder removed. Each file is hashed as it is read and
        not kept: a toolchain's release (gcc, llvm) is gigabytes once inflated."""
        import zipfile

        from cordon_scanner.intel.gitfetch import GitPack

        def ids(data: bytes) -> tuple[str, str | None]:
            converted = GitPack.blob_id(data.replace(b"\r\n", b"\n")) if b"\r\n" in data else None
            return GitPack.blob_id(data), converted

        out: dict[str, tuple[str, str | None]] = {}
        if body[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(body)) as zipped:
                for info in zipped.infolist():
                    if not info.is_dir():
                        out[info.filename] = ids(zipped.read(info))
        else:
            with tarfile.open(fileobj=io.BytesIO(body), mode="r|*") as archive:
                for member in archive:
                    if member.isfile():
                        handle = archive.extractfile(member)
                        if handle is not None:
                            out[member.name] = ids(handle.read())
        tops = {path.split("/", 1)[0] for path in out}
        if len(tops) == 1 and all("/" in path for path in out):
            out = {path.split("/", 1)[1]: found for path, found in out.items()}
        return out

    @staticmethod
    def tree_archive(repository: str, commit: str) -> str | None:
        """The forge's archive of exactly this commit, where the forge has a fixed form for one."""
        if repository.startswith("https://github.com/"):
            return f"https://codeload.github.com/{repository[len('https://github.com/') :]}/tar.gz/{commit}"
        host = urllib.parse.urlsplit(repository).hostname or ""
        if (
            repository.startswith("https://")
            and "gitlab" in host
            and not repository.endswith(".git")
        ):
            # GitLab: `/-/archive/<sha>/<name>-<sha>.tar.gz` (gitlab.com, gitlab.gnome.org, ...).
            name = repository.rstrip("/").rsplit("/", 1)[-1]
            return f"{repository.rstrip('/')}/-/archive/{commit}/{name}-{commit}.tar.gz"
        if host == "codeberg.org":
            return f"{repository.rstrip('/')}/archive/{commit}.tar.gz"
        found = re.fullmatch(
            r"https://git\.savannah\.(?:gnu|nongnu)\.org/git/([\w.+-]+)\.git", repository
        )
        if found:
            # Savannah runs cgit: `/cgit/<repo>.git/snapshot/<repo>-<sha>.tar.gz`.
            host_root = repository.split("/git/", 1)[0]
            return (
                f"{host_root}/cgit/{found.group(1)}.git/snapshot/{found.group(1)}-{commit}.tar.gz"
            )
        return None

    @staticmethod
    def check(archive: Archive, repository: str, commit: str, tag: str = "") -> tuple[str, str]:
        """`(outcome, detail)`: `proven`, `refuted`, or `unprovable`."""
        key = (repository, commit, archive.digest)
        cached = ContentProof._results.get(key)
        if cached is not None:
            return cached
        # A release archive and its tag's tree are held at once: two proofs at a time, whatever
        # the number of lookups running.
        with ContentProof._running:
            result = ContentProof._check(archive, repository, commit, tag)
        ContentProof._results[key] = result
        return result

    @staticmethod
    def _check(archive: Archive, repository: str, commit: str, tag: str) -> tuple[str, str]:
        from cordon_scanner.intel.gitfetch import GitFetch, GitFetchError

        tip = next(
            (
                TagInference._tips.get(repository, {}).get(tag, "")
                for tag, peeled in (TagInference._refs.get(repository) or {}).items()
                if peeled == commit and tag in TagInference._tips.get(repository, {})
            ),
            commit,
        )
        release: bytes | None = None
        # A recipe's URL may have moved (zlib.net keeps only its newest release there); the same
        # file published as the GitHub release's asset is tried too. Only bytes that hash to the
        # recipe's digest are ever used, so another address cannot change what is compared.
        candidates = list(archive.urls)
        if tag and repository.startswith("https://github.com/"):
            candidates += [
                f"{repository}/releases/download/{tag}/{url.rsplit('/', 1)[-1]}"
                for url in archive.urls
            ]
        # GNU's own mirror redirector for a file on ftp.gnu.org, which is often too loaded to answer.
        candidates += [
            re.sub(r"^https?://ftp\.gnu\.org/(?:pub/)?gnu/", "https://ftpmirror.gnu.org/gnu/", url)
            for url in archive.urls
            if re.match(r"^https?://ftp\.gnu\.org/(?:pub/)?gnu/", url)
        ]
        for url in dict.fromkeys(candidates):
            try:
                body = ContentProof._download(url)
            except (OSError, ValueError, http.client.HTTPException):
                continue
            if ContentProof._digest_matches(body, archive.digest):
                release = body
                break
        if release is None:
            return "unprovable", "no release archive matching the recipe's digest could be read"
        try:
            hashed = ContentProof.blobs(release)
            release = body = b""  # the archive is not needed past its files' ids
            ours = {path: found[0] for path, found in hashed.items()}
        except (OSError, ValueError, tarfile.TarError, EOFError, http.client.HTTPException) as exc:
            return "unprovable", f"the release archive could not be read ({type(exc).__name__})"
        try:
            # The tag's tree by git's own protocol: blob ids, compared with the release's files
            # hashed the way git hashes them.
            theirs = GitFetch.tree(repository, tip)
        except (GitFetchError, OSError, ValueError, http.client.HTTPException) as exc:
            return (
                "unprovable",
                f"the tag's tree could not be fetched ({type(exc).__name__}: {exc})"[:200],
            )
        source = {
            path: blob
            for path, blob in theirs.items()
            if not any(part.startswith(".") for part in path.split("/"))
        }
        # Files paired by path; where that pairs too few, by name -- a release laid out in other
        # directories than its tag (Lua's tarball keeps src/ and doc/, its repository is flat),
        # paired only where a name is unique on both sides.
        pairs = [(path, path) for path in source if path in ours]
        relocated = False
        if not ContentProof._enough(len(pairs), len(source)):

            def unique(paths: Iterable[str]) -> dict[str, str]:
                names = collections.Counter(path.rsplit("/", 1)[-1] for path in paths)
                return {
                    path.rsplit("/", 1)[-1]: path
                    for path in paths
                    if names[path.rsplit("/", 1)[-1]] == 1
                }

            mine, tagged = unique(ours), unique(source)
            by_name = [(mine[name], tagged[name]) for name in mine if name in tagged]
            if len(by_name) > len(pairs):
                pairs, relocated = by_name, True
        differing = [(a, b) for a, b in pairs if ours[a] != source[b]]
        # Git writes a file marked `text eol=crlf` out with CRLF and stores it with LF (git's .bat
        # files): the same content by git's own conversion, which nothing else is excused by.
        converted = [
            (a, b) for a, b in differing if hashed[a][1] is not None and hashed[a][1] == source[b]
        ]
        differing = [pair for pair in differing if pair not in converted]
        # A file the tag holds empty that the release fills in (GNU's ChangeLog, written from the
        # git log by `make dist`): a placeholder for something generated, not different source.
        filled = [(a, b) for a, b in differing if source[b] == ContentProof.EMPTY_BLOB]
        differing = [pair for pair in differing if pair not in filled]
        if differing:
            return "refuted", f"{len(differing)} of the files both hold differ ({differing[0][1]})"
        if not ContentProof._enough(len(pairs), len(source)):
            return (
                "unprovable",
                f"the release holds {len(pairs)} of the tag's {len(source)} files",
            )
        return (
            "proven",
            f"the release archive holds {len(pairs)} of its {len(source)} files, each with the same git blob id"
            + (" (paired by file name: the release lays them out elsewhere)" if relocated else "")
            + (f" ({len(converted)} after git's end-of-line conversion)" if converted else "")
            + (f" ({len(filled)} empty in the tag, filled by the release)" if filled else ""),
        )

    @staticmethod
    def _enough(shared: int, tagged: int) -> bool:
        """Enough identical files to mean something: MIN_SHARED, or for a small project MIN_SMALL
        that are MIN_SHARE of the tag's -- or all of the tag's but one (X.org's renderproto: 8 of
        its 9, the release leaving out a build file of the tag's)."""
        return shared >= ContentProof.MIN_SHARED or (
            shared >= ContentProof.MIN_SMALL
            and (shared >= ContentProof.MIN_SHARE * tagged or tagged - shared <= 1)
        )


#: Where a React Native release pins the Hermes it was built from: a tag of facebook/hermes whose
#: name ends in its commit (`hermes-2024-11-12-RNv0.76.2-5b4aa20c...`).
HERMES_PIN: Final = "sdks/.hermesversion"
#: The Hermes versions React Native 0.83 and later build or download (`HERMES_VERSION_NAME`, and
#: `HERMES_V1_VERSION_NAME` for Hermes V1), which hermes-engine.podspec reads as its version.
HERMES_PROPERTIES: Final = "sdks/hermes-engine/version.properties"


class NpmPodspec:
    """A podspec installed from inside an npm package (React Native's `third-party-podspecs/
    DoubleConversion.podspec`), read from that package as the npm registry serves it.

    The CocoaPods reader names the package, the podspec's path in it, and the versions the pods at
    the package's own root are at (React Native's `React-Core` is versioned as the package). For
    each, the registry's tarball is checked against the SHA-512 the registry gives, and the podspec
    in it is used only if it declares the very version the lockfile locks; its `source` is then read
    as any podspec's. Values a podspec takes from the package's own Ruby helpers -- React Native's
    `glog_git_url = get_glog_config()[:git]`, defined as `@@glog_config = { :git => ... }` in its
    `scripts/cocoapods/helpers.rb` -- are read from that same release. Every version tried must
    agree."""

    NOTE: ClassVar[re.Pattern[str]] = re.compile(
        r"the podspec (\S+) of the npm package (\S+), at ([^\s]+(?: or [^\s]+){0,16})$"
    )
    REGISTRY: ClassVar[str] = "https://registry.npmjs.org"
    MAX_TARBALL: ClassVar[int] = 96 << 20
    MAX_TEXT: ClassVar[int] = 1 << 20
    #: `@@<name>_config = { :key => 'value', key: "value", ... }`, simple string values only.
    CONSTANT: ClassVar[re.Pattern[str]] = re.compile(r"@@(\w+_config)\s*=\s*\{([^{}]*)\}")
    #: The same hash returned by a method (React Native 0.74's `def self.folly_config` in
    #: `Helpers::Constants`, which `get_folly_config()` returns).
    METHOD: ClassVar[re.Pattern[str]] = re.compile(
        r"def self\.(\w+_config)\s*(?:\(\s*\))?\s*return\s*\{([^{}]*)\}\s*end"
    )
    #: Podspecs that are the package's own code, whatever source they compute: React Native's
    #: React-Core-prebuilt is its core, built from source or downloaded as the Maven artefact
    #: `com.facebook.react:react-native-artifacts` of the same version (`scripts/cocoapods/rncore.rb`).
    OWN_CODE: ClassVar[frozenset[tuple[str, str]]] = frozenset(
        {("react-native", "React-Core-prebuilt.podspec")}
    )
    FIELD: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?::(\w+)\s*=>|\b(\w+):)\s*(?:'([^']*)'|"([^"]*)"|(\w+)\b)"""
    )
    _packages: ClassVar[dict[tuple[str, str], dict[str, str] | None]] = {}

    @staticmethod
    def download(url: str) -> bytes:
        """The tarball's bytes as served -- not inflated, which the shared fetch does to a gzip
        answer: the registry's SHA-512 is over the file itself."""
        import urllib.request

        if not url.startswith("https://"):
            raise ValueError("not an https tarball")
        request = urllib.request.Request(  # noqa: S310 - https, from the registry's own record
            url, headers={"User-Agent": "cordon-scanner", "Accept-Encoding": "identity"}
        )
        with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
            body: bytes = response.read(NpmPodspec.MAX_TARBALL + 1)
        if len(body) > NpmPodspec.MAX_TARBALL:
            raise ValueError("tarball too large")
        return body

    @staticmethod
    def package(package: str, version: str) -> dict[str, str] | None:
        """`path -> text` of the package's podspecs and Ruby scripts, from the registry's tarball
        once its SHA-512 matches the registry's record; None when it does not or cannot be read."""
        key = (package, version)
        if key in NpmPodspec._packages:
            return NpmPodspec._packages[key]
        import base64
        import hashlib

        meta = json.loads(
            Upstreams._get(
                f"{NpmPodspec.REGISTRY}/{urllib.parse.quote(package, safe='@')}/"
                f"{urllib.parse.quote(version, safe='')}"
            )
        )
        dist = (meta or {}).get("dist") or {}
        tarball, integrity = str(dist.get("tarball") or ""), str(dist.get("integrity") or "")
        files: dict[str, str] | None = None
        if tarball.startswith("https://") and integrity.startswith("sha512-"):
            body = NpmPodspec.download(tarball)
            if hashlib.sha512(body).digest() == base64.b64decode(integrity.removeprefix("sha512-")):
                files = {}
                with tarfile.open(fileobj=io.BytesIO(body), mode="r:*") as archive:
                    for member in archive:
                        path = member.name.split("/", 1)[-1]
                        if member.isfile() and (
                            path.endswith((".podspec", ".rb"))
                            or path in (HERMES_PIN, HERMES_PROPERTIES)
                        ):
                            handle = archive.extractfile(member)
                            if handle is not None:
                                files[path] = handle.read(NpmPodspec.MAX_TEXT).decode(
                                    "utf-8", "replace"
                                )
        NpmPodspec._packages[key] = files
        return files

    @staticmethod
    def constants(files: Mapping[str, str]) -> dict[str, dict[str, str]]:
        """The `@@<name>_config` hashes the package's Ruby defines, by name."""
        out: dict[str, dict[str, str]] = {}
        for path, text in files.items():
            if not path.endswith(".rb"):
                continue
            for found in [*NpmPodspec.CONSTANT.finditer(text), *NpmPodspec.METHOD.finditer(text)]:
                out[found.group(1)] = {
                    m.group(1) or m.group(2): m.group(3) if m.group(3) is not None else m.group(4)
                    for m in NpmPodspec.FIELD.finditer(found.group(2))
                    if m.group(3) is not None or m.group(4) is not None
                }
        return out

    @staticmethod
    def variables(
        text: str, constants: Mapping[str, Mapping[str, str]], version: str = ""
    ) -> dict[str, str]:
        """`name = get_<x>_config()` and `name = <config>[:key]` lines, resolved; and
        `name = package['version']`, the package's own version."""
        configs = {
            m.group(1): m.group(2) + "_config"
            for m in re.finditer(r"^\s*(\w+)\s*=\s*get_(\w+)_config\(\)\s*$", text, re.MULTILINE)
        }
        # Literals first (`folly_release_version = '2021.06.28.00'`), then config lookups.
        out: dict[str, str] = {
            m.group(1): m.group(2) if m.group(2) is not None else m.group(3)
            for m in re.finditer(
                r"""^(\w+)\s*=\s*(?:'([^'#]*)'|"([^"#]*)")\s*$""", text, re.MULTILINE
            )
        }
        for m in re.finditer(r"^\s*(\w+)\s*=\s*(\w+)\[:(\w+)\]\s*$", text, re.MULTILINE):
            value = constants.get(configs.get(m.group(2), ""), {}).get(m.group(3))
            if value is not None:
                out[m.group(1)] = value
        if version:
            for m in re.finditer(
                r"""^\s*(\w+)\s*=\s*package\[['"]version['"]\]\s*$""", text, re.MULTILINE
            ):
                out[m.group(1)] = version
        return out

    @staticmethod
    def declared(text: str, version: str, variables: Mapping[str, str]) -> str | None:
        """The version the podspec declares: a literal, `package['version']`, or a variable."""
        found = re.search(
            r"""^\s*\w+\.version\s*=\s*(?:'([^']*)'|"([^"]*)"|package\[['"]version['"]\]|(\w+))\s*$""",
            text,
            re.MULTILINE,
        )
        joined = re.search(
            r"""^\s*\w+\.version\s*=\s*(\w+)\s*\+\s*(?:'([^']*)'|"([^"]*)")\s*$""",
            text,
            re.MULTILINE,
        )
        if joined and joined.group(1) in variables:
            # `folly_release_version + '-v2'`
            return variables[joined.group(1)] + (joined.group(2) or joined.group(3) or "")
        if not found:
            return None
        if found.group(1) is not None or found.group(2) is not None:
            return found.group(1) if found.group(1) is not None else found.group(2)
        if found.group(3):
            return variables.get(found.group(3))
        return version

    @staticmethod
    def source(
        text: str, locked: str, variables: Mapping[str, str], how: str
    ) -> Upstream | Unnamed:
        """The podspec's `source = { :git => ..., :tag|:commit => ... }` or `{ :http => ... }`:
        `#{<spec>.version}` is the locked version and a bare name a resolved variable; anything
        else computed is unknown, never guessed."""
        # The hash may hold interpolations (`"v#{spec.version}"`), whose braces are not its own.
        found = re.search(r"\.source\s*=\s*\{((?:[^{}]|#\{[^{}]*\})*)\}", text)
        if not found:
            return Unnamed("its podspec's source is computed")
        fields: dict[str, str] = {}
        for m in NpmPodspec.FIELD.finditer(found.group(1)):
            key = m.group(1) or m.group(2)
            if m.group(5) is not None:
                if m.group(5) not in variables:
                    return Unnamed(f"its podspec's source names {m.group(5)}, computed elsewhere")
                value = variables[m.group(5)]
            else:
                value = m.group(3) if m.group(3) is not None else m.group(4)
            value = re.sub(r"#\{\w+\.version\}", locked, value)
            fields[key] = re.sub(
                r"#\{(\w+)\}", lambda m: variables.get(m.group(1), m.group(0)), value
            )
        if any("#{" in v for v in fields.values()):
            return Unnamed("its podspec's source names a value computed elsewhere")
        repository = RepositoryArchive.repository(fields.get("git", ""))
        ref = fields.get("commit") or fields.get("tag")
        if repository and ref:
            return RepositoryArchive.upstream(repository, ref, f"{how} ({repository})")
        page = re.search(r"""\.homepage\s*=\s*['"]([^'"]+)['"]""", text)
        homes = tuple(u for u in (fields.get("http"), page.group(1) if page else None) if u)
        if fields.get("http"):
            downloaded = Upstreams.from_urls([fields["http"]], how)
            if isinstance(downloaded, Upstream):
                return downloaded
            return Unnamed(downloaded.reason, homes=homes)
        return Unnamed("its podspec names no git tag or commit, or download", homes=homes)

    @staticmethod
    def _answers(
        package: str, inside: str, versions: list[str], locked: str, how: str
    ) -> list[Upstream | Unnamed]:
        from cordon_scanner.intel.registry_client import PackageNotFound

        answers: list[Upstream | Unnamed] = []
        for version in versions:
            try:
                files = NpmPodspec.package(package, version)
            except PackageNotFound:
                continue
            if files is None:
                continue
            text = files.get(inside)
            pinned = re.fullmatch(r"\s*(\S*-([0-9a-f]{40}))\s*", files.get(HERMES_PIN, ""))
            if inside.endswith("hermes-engine.podspec") and locked == version and pinned:
                # hermes-engine at React Native's own version is the release build, which React
                # Native's release scripts make from the tag `sdks/.hermesversion` names.
                answers.append(
                    RepositoryArchive.upstream(
                        "https://github.com/facebook/hermes",
                        pinned.group(2),
                        f"{how}@{version}: its sdks/.hermesversion pins the tag {pinned.group(1)}",
                    )
                )
                continue
            properties = dict(
                re.findall(
                    r"^\s*(HERMES_\w*VERSION_NAME)\s*=\s*(\S+)\s*$",
                    files.get(HERMES_PROPERTIES, ""),
                    re.MULTILINE,
                )
            )
            if inside.endswith("hermes-engine.podspec") and locked in properties.values():
                # React Native 0.83 and later: the Hermes release its version.properties names,
                # downloaded from Maven (`com.facebook.hermes:hermes-ios`) or built from that tag.
                answers.append(
                    TagInference.infer(
                        "https://github.com/facebook/hermes",
                        locked,
                        ("hermes",),
                        f"{how}@{version}: its version.properties names Hermes {locked}",
                    )
                )
                continue
            if text is None:
                continue
            variables = NpmPodspec.variables(text, NpmPodspec.constants(files), version)
            if NpmPodspec.declared(text, version, variables) != locked:
                continue
            answer = NpmPodspec.source(text, locked, variables, f"{how}@{version}")
            if isinstance(answer, Unnamed) and (package, inside) in NpmPodspec.OWN_CODE:
                answer = Upstream(
                    {"package": {"name": package, "ecosystem": "npm"}, "version": version},
                    f"{how}@{version}: {package}'s own code, versioned as it",
                )
            answers.append(answer)
        return answers

    @staticmethod
    def read(
        package: str, inside: str, versions: list[str], locked: str, how: str
    ) -> Upstream | Unnamed:
        answers = NpmPodspec._answers(package, inside, versions, locked, how)
        if not answers and locked not in versions and re.fullmatch(r"\d+\.\d+\.\d+[\w.-]*", locked):
            # The pod at a release of its own: hermes-engine 0.72.5 in a lock whose React pods
            # are at 0.72.6 is React Native 0.72.5's, pinned by that release.
            answers = NpmPodspec._answers(package, inside, [locked], locked, how)
        if not answers:
            return Unnamed(
                f"no {package} release among {', '.join(versions)} holds {inside} at {locked}"
            )
        named = {json.dumps(a.query, sort_keys=True) for a in answers if isinstance(a, Upstream)}
        if len(named) == 1 and all(isinstance(a, Upstream) for a in answers):
            return next(a for a in answers if isinstance(a, Upstream))
        if len(named) > 1:
            return Unnamed(f"{package}'s releases name different sources for {inside}")
        return next(a for a in answers if isinstance(a, Unnamed))


class ConanCenter:
    """A Conan Center recipe's sources, in the shapes its conandata.yml writes them."""

    INDEX: ClassVar[str] = (
        "https://raw.githubusercontent.com/conan-io/conan-center-index/HEAD/recipes"
    )

    @staticmethod
    def leaves(source: object) -> tuple[list[str], Archive | None]:
        """Every URL under a version's source, however it is keyed -- by platform and
        architecture for a binary tool (cmake: `Linux: armv8: url`) -- and the first one pinned
        with a sha256, for the proof."""
        urls: list[str] = []
        archive: Archive | None = None
        stack: list[object] = [source]
        while stack:
            node = stack.pop(0)
            if isinstance(node, list):
                stack.extend(node)
            elif isinstance(node, dict):
                given = node.get("url")
                found = (
                    [given]
                    if isinstance(given, str)
                    else [u for u in given or [] if isinstance(u, str)]
                    if isinstance(given, list)
                    else []
                )
                urls += found
                sha256 = node.get("sha256")
                if archive is None and found and isinstance(sha256, str):
                    archive = Archive(tuple(found), f"sha256:{sha256}")
                stack.extend(v for k, v in node.items() if k not in ("url", "sha256"))
        return list(dict.fromkeys(urls)), archive

    @staticmethod
    def committed(source: object, how: str) -> Upstream | None:
        """A source cloned at a commit (gnu-config: `url: <git repository>`, `commit: <sha>`):
        that commit, exactly -- on any host, since a commit names the same code everywhere."""
        if not isinstance(source, dict):
            return None
        commit, url = source.get("commit"), source.get("url")
        if isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit):
            return Upstream({"commit": commit}, f"{how} ({url}), at commit {commit[:12]}")
        return None

    @staticmethod
    def exact(urls: list[str], how: str) -> Upstream | Unnamed:
        """The repository and tag every forge URL names -- one, or the sources disagree."""
        named = {parsed for url in urls if (parsed := RepositoryArchive.parse(url))}
        if len(named) == 1:
            repository, ref = named.pop()
            return RepositoryArchive.upstream(repository, ref, how)
        if len(named) > 1:
            return Unnamed("its sources name different repositories or tags by platform")
        return Upstreams.from_urls(urls, how)

    _index: ClassVar[dict[str, dict[str, object] | None]] = {}

    @staticmethod
    def index(name: str) -> dict[str, object] | None:
        """`version -> source` from the package's current recipe in conan-center-index, across
        all its recipe folders; None when the index cannot be read."""
        if name in ConanCenter._index:
            return ConanCenter._index[name]
        from cordon_scanner.core.datayaml import DataYaml

        package = urllib.parse.quote(name, safe="")
        found: dict[str, object] | None = {}
        try:
            config = DataYaml.load(
                Upstreams._get(f"{ConanCenter.INDEX}/{package}/config.yml").decode()
            )
            folders = {
                str(entry.get("folder"))
                for entry in ((config or {}).get("versions") or {}).values()
                if isinstance(entry, dict) and entry.get("folder")
            }
            sources: dict[str, object] = {}
            for folder in sorted(folders):
                if name not in ConanCenter._homepages:
                    # The recipe's homepage, for NVD (`intel/nvd`) when no repository is named.
                    with contextlib.suppress(OSError, ValueError, http.client.HTTPException):
                        recipe = Upstreams._get(
                            f"{ConanCenter.INDEX}/{package}/{folder}/conanfile.py"
                        ).decode("utf-8", "replace")
                        page = re.search(
                            r"""^\s*homepage\s*=\s*["']([^"']+)["']""", recipe, re.MULTILINE
                        )
                        ConanCenter._homepages[name] = page.group(1) if page else ""
                data = DataYaml.load(
                    Upstreams._get(f"{ConanCenter.INDEX}/{package}/{folder}/conandata.yml").decode()
                )
                given = (data or {}).get("sources") if isinstance(data, dict) else None
                if isinstance(given, dict):
                    sources.update({str(k): v for k, v in given.items()})
            found = sources
        except (OSError, ValueError, http.client.HTTPException):
            found = None
        ConanCenter._index[name] = found
        return found

    @staticmethod
    def repositories(name: str) -> set[str] | None:
        """The repositories the current recipe's sources name, across all its versions."""
        sources = ConanCenter.index(name)
        if sources is None:
            return None
        urls, _ = ConanCenter.leaves(list(sources.values()))
        return {parsed[0] for url in urls if (parsed := RepositoryArchive.parse(url))}

    _homepages: ClassVar[dict[str, str]] = {}

    @staticmethod
    def removed(name: str, version: str) -> Upstream | Unnamed:
        found = ConanCenter._removed(name, version)
        page = ConanCenter._homepages.get(name)
        if isinstance(found, Unnamed) and page and page not in found.homes:
            return Unnamed(found.reason, found.nothing, (*found.homes, page))
        return found

    @staticmethod
    def _removed(name: str, version: str) -> Upstream | Unnamed:
        """A version Conan Center no longer serves. conan-center-index's current recipe may
        still list it -- its sources and their digest, read as for any recipe; otherwise, when
        its other versions all name one repository, the version's tag is looked for in it -- an
        inference, with nothing pinned to prove it by."""
        sources = ConanCenter.index(name)
        if sources is None:
            return Unnamed(
                "Conan Center no longer serves this version, and its index could not be read"
            )
        how = f"conan-center-index's {name} recipe, for {version}"
        repositories = ConanCenter.repositories(name) or set()
        homes = sorted(repositories) if len(repositories) == 1 else []
        if version in sources:
            urls, pinned = ConanCenter.leaves(sources[version])
            return Upstreams.inferred(
                ConanCenter.exact(urls, how), homes, version, (name,), how, pinned
            )
        if len(repositories) != 1:
            return Unnamed(
                "Conan Center no longer serves this version, and its current recipe names "
                + ("no repository" if not repositories else "more than one repository")
            )
        return Upstreams.inferred(
            Unnamed("Conan Center no longer serves this version"),
            homes,
            version,
            (name,),
            f"the repository Conan Center's current {name} recipe names",
        )


class Upstreams:
    """What each ecosystem says a package was built from."""

    @staticmethod
    def _get(url: str, limit: int = 4 << 20) -> bytes:
        from cordon_scanner.intel.more_registries import MoreRegistries

        body = MoreRegistries._get(url)
        if len(body) > limit:
            raise ValueError("response too large")
        return body

    @staticmethod
    def from_urls(urls: Iterable[str], how: str) -> Upstream | Unnamed:
        listed = list(urls)
        for url in listed:
            parsed = RepositoryArchive.parse(url)
            if parsed:
                return RepositoryArchive.upstream(parsed[0], parsed[1], how)
        for url in listed:
            # A file read at a ref (`raw.githubusercontent.com/<owner>/<repo>/v1.8.2505/LICENSE.TXT`):
            # the ref only once the repository shows it is a tag -- a branch moves.
            # A helper borrowed from another project (a patch, a file of another repository the
            # same recipe also names) is not the package: only the one repository its URLs name.
            raw = RepositoryArchive.RAW_AT_REF.match(url)
            named = {
                m.group(1).lower() + "/" + m.group(2).lower()
                for m in (
                    re.match(
                        r"^https://(?:raw\.githubusercontent\.com|github\.com|codeload\.github\.com)"
                        r"/([\w.-]+)/([\w.-]+)/",
                        u,
                    )
                    for u in listed
                )
                if m
            }
            if raw and len(named) == 1 and not re.search(r"\.(?:patch|diff)$", url):
                repository = f"https://github.com/{raw.group(1)}/{raw.group(2)}"
                ref = urllib.parse.unquote(raw.group(3))
                if ref in (TagInference.refs(repository) or {}):
                    return RepositoryArchive.upstream(repository, ref, how)
        for url in listed:
            package = RegistryArchive.parse(url)
            if package:
                ecosystem, name, version = package
                return Upstream(
                    {"package": {"name": name, "ecosystem": ecosystem}, "version": version},
                    f"{how}, {ecosystem}'s {name} {version}",
                )
        return Unnamed(
            f"its source is downloaded from {listed[0]}, which names no repository and tag"
            if listed
            else "its source names no URL"
        )

    @staticmethod
    def inferred(
        first: Upstream | Unnamed,
        homes: Iterable[object],
        version: str,
        names: Iterable[str],
        how: str,
        archive: Archive | None = None,
    ) -> Upstream | Unnamed:
        """`first` when it named the upstream exactly; else a version's tag inferred in the
        repository the ecosystem itself names (`TagInference`), then proved against the release
        archive the recipe pins where it can be (`ContentProof`): proven, it is as good as named;
        refuted, the tag is not used; unprovable, it stays an inference and says so. Every reason
        is kept when nothing names the upstream."""
        if isinstance(first, Upstream):
            return first
        tried: list[str] = []
        # The release file's own name is a tag prefix too: conda's libgcc-ng is built from
        # gcc-15.2.0.tar.gz, tagged `releases/gcc-15.2.0`.
        names = [
            *names,
            *(
                stem.group(1)
                for url in (archive.urls if archive and version else ())
                if (
                    stem := re.match(
                        rf"([A-Za-z][\w+.-]*?)-v?{re.escape(version)}(?:[._-]|$)",
                        url.rsplit("/", 1)[-1],
                    )
                )
            ),
        ]
        named = [TagInference.repository(h) if isinstance(h, str) else None for h in homes]
        # Then the repositories a download host's own layout implies (`Conventions`): tried only
        # to be proved -- a wrong one fails the proof, and none is ever used as a bare inference.
        conventional = [
            r for r in Conventions.repositories(archive.urls if archive else ()) if r not in named
        ]
        candidates = [(r, True) for r in named if r] + [(r, False) for r in conventional]
        for repository, may_infer in candidates:
            if not version:
                break
            found = TagInference.infer(repository, version, names, how)
            if not isinstance(found, Upstream):
                tried.append(found.reason)
                continue
            if archive is None:
                if not may_infer:
                    continue
                return Upstream(
                    found.query,
                    f"{found.how} (no release archive to prove it against)",
                    inferred=True,
                    tag=found.tag,
                )
            outcome, detail = ContentProof.check(
                archive, repository, str(found.query["commit"]), found.tag
            )
            if outcome == "proven":
                return Upstream(
                    found.query,
                    found.how.replace(", inferred: ", ", proved: ", 1).split(", the only commit")[0]
                    + f" -- {detail}",
                    tag=found.tag,
                )
            if outcome == "refuted":
                tried.append(f"the version's tag in {repository} is not the release: {detail}")
                continue
            if may_infer:
                return Upstream(
                    found.query,
                    f"{found.how} (not proved: {detail})",
                    inferred=True,
                    tag=found.tag,
                )
            tried.append(f"{repository}: {detail}")
        return Unnamed(
            "; ".join([first.reason, *tried]),
            homes=tuple(
                dict.fromkeys(
                    [
                        *(str(h) for h in homes if isinstance(h, str) and h),
                        *(archive.urls if archive else ()),
                        *first.homes,
                    ]
                )
            ),
            version=version,
        )

    @staticmethod
    def bazel(dependency: Dependency) -> Upstream | Unnamed:
        name, version = dependency.name, dependency.version or ""
        given = dependency.resolved_from or ""
        if given and (RepositoryArchive.parse(given) or RegistryArchive.parse(given)):
            # Bazel 7.0-7.1's lock records the module's archive itself.
            return Upstreams.from_urls(
                [given], f"the archive the lock records for {name} {version}"
            )
        # Any registry has BCR's layout, and the lock names the one it used: BCR, its git source
        # (`raw.githubusercontent.com/bazelbuild/bazel-central-registry/main/`), or another.
        registry = (
            given.rstrip("/") if given.startswith("https://") else BCR.removesuffix("/modules")
        )
        data = json.loads(
            Upstreams._get(
                f"{registry}/modules/{urllib.parse.quote(name, safe='')}/"
                f"{urllib.parse.quote(version, safe='')}/source.json"
            )
        )
        how = f"{registry}'s source.json for {name} {version}"
        if data.get("type") == "git_repository":
            repository = RepositoryArchive.repository(str(data.get("remote") or ""))
            commit = str(data.get("commit") or "")
            if repository and re.fullmatch(r"[0-9a-f]{40}", commit):
                return RepositoryArchive.upstream(repository, commit, f"{how} ({repository})")
            return Unnamed("its source is a git repository BCR names without a commit")
        urls = [data["url"]] if isinstance(data.get("url"), str) else []
        urls += [u for u in data.get("mirror_urls") or [] if isinstance(u, str)]
        first = Upstreams.from_urls(urls, how)
        if isinstance(first, Upstream):
            return first
        # The module's metadata.json names its repository (`github:madler/zlib`); BCR versions a
        # module `<upstream>.bcr.<n>` when it patches one.
        try:
            meta = json.loads(
                Upstreams._get(
                    f"{registry}/modules/{urllib.parse.quote(name, safe='')}/metadata.json"
                )
            )
        except (OSError, ValueError, http.client.HTTPException):
            return first
        homes = [*(meta.get("repository") or []), meta.get("homepage")]
        integrity = str(data.get("integrity") or "")
        return Upstreams.inferred(
            first,
            homes,
            re.sub(r"\.bcr\.\d+$", "", version),
            (name,),
            how,
            Archive(tuple(urls), integrity) if urls and integrity else None,
        )

    @staticmethod
    def conan(dependency: Dependency) -> Upstream | Unnamed:
        if dependency.resolved_from not in (None, "conancenter"):
            return Unnamed("it is not from Conan Center")
        name, version = dependency.name, dependency.version or ""
        base = f"{CONAN_CENTER}/{urllib.parse.quote(name, safe='')}/{urllib.parse.quote(version, safe='')}/_/_/revisions"
        from cordon_scanner.intel.registry_client import RegistryError

        locked = (dependency.integrity or "").removeprefix("md5:")
        try:
            if not re.fullmatch(r"[0-9a-f]{32}", locked):
                revisions = json.loads(Upstreams._get(base)).get("revisions") or []
                if not revisions:
                    return Unnamed("Conan Center holds no recipe for this version")
                locked = str(revisions[0].get("revision") or "")
            export = Upstreams._get(f"{base}/{locked}/files/conan_export.tgz", MAX_EXPORT_BYTES)
        except (RegistryError, OSError, ValueError):
            # A version Conan Center has since dropped (ruby 3.2.2): the package's current recipe
            # still names its repository.
            return ConanCenter.removed(name, version)
        # `MoreRegistries._get` inflates a gzip answer itself, so this may already be a plain tar.
        with tarfile.open(fileobj=io.BytesIO(export), mode="r:*") as archive:
            member = archive.extractfile("conandata.yml")
            text = member.read(MAX_EXPORT_BYTES).decode("utf-8", "replace") if member else ""
            try:
                recipe = archive.extractfile("conanfile.py")
            except KeyError:
                recipe = None
            conanfile = recipe.read(MAX_EXPORT_BYTES).decode("utf-8", "replace") if recipe else ""
        if not conanfile:
            # Conan 2 serves the recipe beside the export, not in it (conan_export.tgz holds
            # conandata.yml alone): its homepage is what NVD ties the package by.
            with contextlib.suppress(RegistryError, OSError, ValueError, http.client.HTTPException):
                conanfile = Upstreams._get(
                    f"{base}/{locked}/files/conanfile.py", MAX_EXPORT_BYTES
                ).decode("utf-8", "replace")
        from cordon_scanner.core.datayaml import DataYaml

        data = DataYaml.load(text) if text else {}
        sources = (data.get("sources") or {}) if isinstance(data, dict) else {}
        source = sources.get(version) if isinstance(sources, dict) else None
        how = f"Conan Center's recipe {name}/{version}#{locked[:8]}"
        homepage = re.search(r'^\s*homepage\s*=\s*["\']([^"\']+)["\']', conanfile, re.MULTILINE)
        urls, pinned = ConanCenter.leaves(source)
        # Where this version's sources name no repository (zlib 1.2.11: only zlib.net), the
        # recipe's other versions may: one repository named across them is a candidate.
        exact = ConanCenter.committed(source, how) or ConanCenter.exact(urls, how)
        if isinstance(exact, Upstream):
            return exact
        current = ConanCenter.repositories(name) or set()
        return Upstreams.inferred(
            exact,
            [
                *([homepage.group(1)] if homepage else []),
                *(sorted(current) if len(current) == 1 else []),
            ],
            version,
            (name,),
            how,
            pinned,
        )

    @staticmethod
    def cocoapods(dependency: Dependency) -> Upstream | Unnamed:
        from cordon_scanner.core.models import Scope
        from cordon_scanner.intel.more_registries import HOSTS, MoreRegistries

        if dependency.scope == Scope.TOOL and dependency.name == "cocoapods":
            # Podfile.lock's COCOAPODS line: the version of CocoaPods itself, a RubyGem.
            return Upstream(
                {
                    "package": {"name": "cocoapods", "ecosystem": "RubyGems"},
                    "version": dependency.version or "",
                },
                f"CocoaPods {dependency.version}, the RubyGem",
            )
        given = dependency.resolved_from
        if given is not None:
            # `pod 'X', :git => ..., :commit|:tag => ...`: Podfile.lock's CHECKOUT OPTIONS hold
            # what was checked out: a commit is exact; a ref only once the repository shows it is
            # a tag -- a branch moves, so it is no fixed point.
            git = re.fullmatch(r"git\+(\S+)#(\S+)", given)
            repository = RepositoryArchive.repository(git.group(1)) if git else None
            if git and repository:
                ref, how = git.group(2), f"the {dependency.name} checkout ({repository})"
                if re.fullmatch(r"[0-9a-f]{40}", ref) or ref in (
                    TagInference.refs(repository) or {}
                ):
                    return RepositoryArchive.upstream(repository, ref, how)
                return Unnamed(f"its checkout names {ref}, which is not a tag of {repository}")
            within = NpmPodspec.NOTE.search(dependency.resolution_note or "")
            if within:
                return NpmPodspec.read(
                    within.group(2),
                    within.group(1),
                    within.group(3).split(" or "),
                    dependency.version or "",
                    f"the {dependency.name} podspec in npm's {within.group(2)}",
                )
            return Unnamed("it is not from CocoaPods trunk")
        name, version = dependency.name.split("/", 1)[0], dependency.version or ""
        a, b, c = MoreRegistries.cocoapods_shard(name)
        spec = json.loads(
            MoreRegistries._cocoapods_spec(
                f"{HOSTS['cocoapods']}/Specs/{a}/{b}/{c}/{name}/{version}/{name}.podspec.json"
            )
        )
        source = spec.get("source") if isinstance(spec, dict) else None
        how = f"the {name} {version} podspec"
        if isinstance(source, dict) and isinstance(source.get("git"), str):
            repository = RepositoryArchive.repository(source["git"])
            ref = source.get("commit") or source.get("tag")
            if repository and isinstance(ref, str) and ref:
                return RepositoryArchive.upstream(repository, ref, f"{how} ({repository})")
            first: Upstream | Unnamed = Unnamed(
                "its podspec names a git source off GitHub and GitLab, or no tag"
            )
        elif isinstance(source, dict) and isinstance(source.get("http"), str):
            first = Upstreams.from_urls([source["http"]], how)
        else:
            first = Unnamed("its podspec names no source")
        homes = [
            (source or {}).get("git") if isinstance(source, dict) else None,
            spec.get("homepage") if isinstance(spec, dict) else None,
        ]
        pinned = (
            Archive((source["http"],), f"sha256:{source['sha256']}")
            if isinstance(source, dict)
            and isinstance(source.get("http"), str)
            and isinstance(source.get("sha256"), str)
            else None
        )
        answer = Upstreams.inferred(first, homes, version, (name,), how, pinned)
        if (
            isinstance(answer, Unnamed)
            and isinstance(source, dict)
            and isinstance(source.get("http"), str)
            and Upstreams.prebuilt(spec)
        ):
            # A vendor's closed binary (Google's FirebaseAnalytics before firebase-ios-sdk held
            # its podspec, Agora's SDKs): no source exists to name, so said as what it is.
            return Unnamed(
                f"a prebuilt binary its vendor ships from {source['http']} (its podspec vends "
                "frameworks or libraries and builds no source), with no repository to name",
                homes=answer.homes,
            )
        if (
            isinstance(answer, Unnamed)
            and isinstance(source, dict)
            and isinstance(source.get("http"), str)
            and Upstreams.umbrella(spec)
        ):
            # Firebase 3 to 6: the pod is a header and a module map over its subspecs' pods, from
            # the vendor's binary distribution.
            return Unnamed(
                f"an umbrella of headers from {source['http']} (its podspec builds only headers "
                "and vends nothing; the code is in the pods it depends on), with no repository to "
                "name",
                homes=answer.homes,
            )
        return answer

    @staticmethod
    def patterns(value: object) -> list[str]:
        if isinstance(value, str):
            return [value]
        return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []

    @staticmethod
    def header(pattern: str) -> bool:
        """A file pattern that matches headers only: `*.h`, `X.hpp`, `**/*.{h,hh}`."""
        found = re.search(r"\.(\w+|\{[\w,]+\})$", pattern.strip())
        if not found:
            return False
        extensions = found.group(1).strip("{}").split(",")
        return all(e in ("h", "hh", "hpp", "hxx", "inl", "modulemap") for e in extensions)

    @staticmethod
    def umbrella(spec: object) -> bool:
        """Whether a podspec, with its subspecs, vends nothing and builds headers alone."""
        vends, headers, builds = False, False, False
        stack: list[object] = [spec]
        while stack:
            node = stack.pop()
            if not isinstance(node, dict):
                continue
            for platform in (node, *(node.get(p) for p in ("ios", "osx", "tvos", "watchos"))):
                if isinstance(platform, dict):
                    vends |= bool(
                        platform.get("vendored_frameworks") or platform.get("vendored_libraries")
                    )
                    for pattern in Upstreams.patterns(platform.get("source_files")):
                        headers |= Upstreams.header(pattern)
                        builds |= not Upstreams.header(pattern)
            stack += [s for s in node.get("subspecs") or [] if isinstance(s, dict)]
        return headers and not vends and not builds

    @staticmethod
    def prebuilt(spec: object) -> bool:
        """Whether a podspec, with its subspecs, vends frameworks or libraries and builds no
        source files: a binary distribution. Headers alone are not source built (Crashlytics
        3.x ships `Crashlytics.framework/Headers/*.h` beside its framework)."""
        vends, builds = False, False
        stack: list[object] = [spec]
        while stack:
            node = stack.pop()
            if not isinstance(node, dict):
                continue
            for platform in (node, *(node.get(p) for p in ("ios", "osx", "tvos", "watchos"))):
                if isinstance(platform, dict):
                    vends |= bool(
                        platform.get("vendored_frameworks") or platform.get("vendored_libraries")
                    )
                    builds |= any(
                        not Upstreams.header(pattern)
                        for pattern in Upstreams.patterns(platform.get("source_files"))
                    )
            stack += [s for s in node.get("subspecs") or [] if isinstance(s, dict)]
        return vends and not builds

    @staticmethod
    def homebrew(dependency: Dependency) -> Upstream | Unnamed:
        name = dependency.name
        installed = dependency.version or ""
        if "cask" in dependency.platform:
            return HomebrewBottles.cask(name)
        if name.count("/") == 1 and re.fullmatch(r"[0-9a-f]{40}", installed):
            # A tap, locked to a commit of its repository (`<owner>/homebrew-<tap>`).
            owner, tap = name.split("/")
            repository = f"https://github.com/{owner}/homebrew-{tap.removeprefix('homebrew-')}"
            return RepositoryArchive.upstream(
                repository, installed, f"the tap {name} at its locked commit"
            )
        given = dependency.resolved_from or ""
        if given.startswith("registry:") and given.count("/") == 1:
            return HomebrewBottles.tap_formula(given.removeprefix("registry:"), name, installed)
        if "/" in name or dependency.resolved_from is not None:
            return Unnamed("it is from a tap, which formulae.brew.sh does not describe")
        found = HomebrewBottles.formula_data(name, installed)
        if isinstance(found, Unnamed):
            if found.reason.startswith("Homebrew no longer has this formula"):
                return HomebrewHistory.upstream(dependency, found)
            return found
        name, data = found
        if installed.startswith("HEAD-"):
            return HomebrewBottles.head(data, installed, name)
        stable = str((data.get("versions") or {}).get("stable") or "")
        if not installed or re.sub(r"_\d+$", "", installed) == stable:
            # The formula the API describes, at the commit it names, checked against the SHA-256
            # it gives: its mirrors are read too (curl's include GitHub's release asset).
            import hashlib

            head, path = (
                str(data.get("tap_git_head") or ""),
                str(data.get("ruby_source_path") or ""),
            )
            expected = str((data.get("ruby_source_checksum") or {}).get("sha256") or "")
            if not re.fullmatch(r"[0-9a-f]{40}", head) or not re.fullmatch(
                r"Formula/[\w@+./-]+\.rb", path
            ):
                return Unnamed("formulae.brew.sh names no formula file for it")
            body = Upstreams._get(
                f"https://raw.githubusercontent.com/Homebrew/homebrew-core/{head}/{path}"
            )
            if expected and hashlib.sha256(body).hexdigest() != expected:
                return Unnamed(
                    "the formula file does not hash to the SHA-256 formulae.brew.sh gives"
                )
            text, version = body.decode("utf-8", "replace"), stable
            how = f"the {name} {stable} formula"
        else:
            # An older version: the formula its bottle was built from, which the bottle carries.
            version = re.sub(r"_\d+$", "", installed)
            try:
                text = HomebrewBottles.formula(name, installed)
                how = f"the {name} {installed} formula its bottle carries"
            except (OSError, ValueError, tarfile.TarError, EOFError, http.client.HTTPException):
                # No bottle (one from before ghcr.io): the current formula still names the
                # repository, in which the installed version's tag is looked for. Nothing pins
                # the old release archive, so it cannot be proved: an inference, said as one.
                historical = HomebrewHistory.upstream(
                    dependency,
                    Unnamed(f"no bottle of {installed} remains to read its formula from"),
                )
                if isinstance(historical, Upstream):
                    return historical
                current = HomebrewBottles.current_formula(data)
                heads = re.findall(
                    r'^\s*(?:head\s+|url\s+)"([^"]+?)(?:\.git)?"', current, re.MULTILINE
                )
                return Upstreams.inferred(
                    historical,
                    [*heads, data.get("homepage")],
                    version,
                    (name.split("@", 1)[0],),
                    f"the {name} formula's repository",
                )
        # Where the stable source names no tag, the formula's `head` and homepage name the
        # repository to look for the version's tag in.
        heads = re.findall(r'^\s*(?:head\s+|url\s+)"([^"]+\.git)"', text, re.MULTILINE)
        return Upstreams.inferred(
            HomebrewBottles.source(text, how),
            [*heads, data.get("homepage")],
            version,
            (name.split("@", 1)[0],),
            how,
            HomebrewBottles.archive(text),
        )

    #: Cordon's own wording for a port read at a baseline (`ecosystems/vcpkg.py`).
    VCPKG_BASELINE: ClassVar[re.Pattern[str]] = re.compile(r"\bat baseline ([0-9a-f]{40})\b")

    @staticmethod
    def vcpkg(dependency: Dependency) -> Upstream | Unnamed:
        if dependency.resolved_from is not None:
            return Unnamed("it is not from vcpkg's built-in registry")
        found = Upstreams.VCPKG_BASELINE.search(dependency.resolution_note or "")
        if not found:
            return Unnamed("no baseline commit says which port it is")
        baseline, port = found.group(1), urllib.parse.quote(dependency.name, safe="")
        manifest = VcpkgPorts.manifest(baseline, port)
        scheme, at_baseline = next(
            (
                (k, str(manifest[k]))
                for k in ("version", "version-semver", "version-date", "version-string")
                if isinstance(manifest.get(k), str)
            ),
            ("version", ""),
        )
        wanted = dependency.version
        spec = dependency.declared_spec or ""
        if not wanted and spec and spec != "*" and not spec.startswith(">="):
            # An override names the version exactly, whatever the baseline and constraints say.
            wanted = spec
        if not wanted:
            # vcpkg installs the greater of the baseline's version and every `version>=`.
            minimum = spec.removeprefix(">=")
            if minimum and minimum != "*":
                ordered = VcpkgVersions.compare(scheme, at_baseline, minimum)
                if ordered is None:
                    return Unnamed(f"a version>= constraint on a {scheme}, which is not ordered")
                if ordered < 0:
                    wanted = minimum
        if wanted and wanted != at_baseline:
            files = VcpkgPorts.at_version(baseline, dependency.name, wanted)
            if isinstance(files, Unnamed):
                return files
            portfile, version = files

            def other(filename: str) -> str:
                return VcpkgPorts.file_at_version(baseline, dependency.name, wanted or "", filename)

        else:
            portfile = Upstreams._get(f"{VCPKG_RAW}/{baseline}/ports/{port}/portfile.cmake").decode(
                "utf-8", "replace"
            )
            version = at_baseline

            def other(filename: str) -> str:
                return Upstreams._get(f"{VCPKG_RAW}/{baseline}/ports/{port}/{filename}").decode(
                    "utf-8", "replace"
                )

        how = f"the {dependency.name} {version} port"
        if re.search(
            r"\bqt_(?:install_submodule|submodule_installation|download_submodule)\s*\(", portfile
        ):

            def qtbase(filename: str) -> str:
                return Upstreams._get(f"{VCPKG_RAW}/{baseline}/ports/qtbase/{filename}").decode(
                    "utf-8", "replace"
                )

            return VcpkgPorts.qt(dependency.name, version.split("#", 1)[0], other, how, qtbase)
        first, archive = VcpkgPorts.read(portfile, version, dependency.name, how)
        if isinstance(first, Unnamed) and first.nothing:
            return first
        if isinstance(first, Unnamed) and not VcpkgPorts.DOWNLOADS.search(portfile):
            # A port that downloads nothing (vcpkg-cmake, a helper of CMake scripts; cuda, which
            # finds the system's): what it installs is the registry's own files, so its upstream
            # is the vcpkg repository at the baseline -- exactly.
            return RepositoryArchive.upstream(
                VcpkgPorts.REPOSITORY, baseline, f"{how}: its files are vcpkg's own"
            )
        return Upstreams.inferred(
            first,
            [manifest.get("homepage")],
            version.split("#", 1)[0],
            (dependency.name,),
            how,
            archive,
        )

    @staticmethod
    def terraform(dependency: Dependency) -> Upstream | Unnamed:
        parts = dependency.name.split("/")
        if len(parts) != 2 or dependency.resolved_from is not None:
            return Unnamed("it is not a provider from registry.terraform.io")
        data = json.loads(
            Upstreams._get(
                f"{TERRAFORM_REGISTRY}/{urllib.parse.quote(parts[0], safe='')}/"
                f"{urllib.parse.quote(parts[1], safe='')}"
            )
        )
        repository = RepositoryArchive.repository(str(data.get("source") or ""))
        if not repository or not repository.startswith("https://github.com/"):
            return Unnamed("the registry names no GitHub source repository for it")
        module = repository.removeprefix("https://")
        return Upstream(
            {"package": {"name": module, "ecosystem": "Go"}, "version": dependency.version},
            f"its source repository's Go module, {module} {dependency.version}",
        )

    @staticmethod
    def conda(dependency: Dependency) -> Upstream | Unnamed:
        """The recipe a conda package carries (`info/recipe/meta.yaml`, rendered, or rattler-build's
        `rendered_recipe.yaml`): its source URLs, or its git URL and revision."""
        url = dependency.resolved_from or ""
        if not re.match(r"^https://(?:conda\.anaconda\.org|repo\.anaconda\.com)/", url):
            return Unnamed("it is not from a public conda channel")
        seen: dict[str, int] = {}
        recipe = CondaPackage.recipe(url, seen)
        if recipe is None:
            return Unnamed("its package carries no rendered recipe")
        from cordon_scanner.core.datayaml import DataYaml

        data = DataYaml.load(recipe)
        finalized: list[object] = []
        if isinstance(data, dict) and isinstance(data.get("recipe"), dict):
            # rattler-build's rendered_recipe.yaml wraps the recipe, and records the sources the
            # build used, rendered: its own, and a multi-output recipe's shared stage's (glib-tools
            # names none of its own; the stage it was built from fetched glib's release).
            for key in ("finalized_sources", "finalized_cache_sources"):
                listed = data.get(key)
                finalized += listed if isinstance(listed, list) else []
            data = data["recipe"]
        CondaSiblings.record(url, data)
        source = data.get("source") if isinstance(data, dict) else None
        sources = [
            *(source if isinstance(source, list) else [source] if source else []),
            *finalized,
        ]
        urls: list[str] = []
        how = f"the recipe inside {url.rsplit('/', 1)[-1]}"
        for one in sources:
            if not isinstance(one, dict):
                continue
            git = one.get("git_url") or one.get("git")
            rev = one.get("git_rev") or one.get("rev") or one.get("tag")
            repository = RepositoryArchive.repository(str(git or ""))
            if repository and isinstance(rev, str) and rev:
                return RepositoryArchive.upstream(repository, rev, f"{how} ({repository})")
            given = one.get("url")
            urls += (
                [given]
                if isinstance(given, str)
                else [u for u in given or [] if isinstance(u, str)]
            )
        sourceless = not urls and not any(
            isinstance(s, dict) and (s.get("git_url") or s.get("git")) for s in sources
        )
        if sourceless and "paths" not in seen:
            # Its recipe came before paths.json: read on to it, which a small info/ allows.
            seen["want_paths"] = 1
            CondaPackage.recipe(url, seen)
        if sourceless and seen.get("paths") == 0:
            # A metapackage (python_abi, fonts-conda-ecosystem): no source, and its paths.json
            # lists no file it installs.
            return Unnamed("a metapackage: it names no source and installs no files", nothing=True)
        about = data.get("about") if isinstance(data, dict) else None
        homes = [about.get("dev_url"), about.get("home")] if isinstance(about, dict) else []
        sha256 = next(
            (
                str(one["sha256"])
                for one in sources
                if isinstance(one, dict) and isinstance(one.get("sha256"), str)
            ),
            "",
        )
        answer = Upstreams.inferred(
            Upstreams.from_urls(urls, how),
            homes,
            dependency.version or "",
            (dependency.name,),
            how,
            Archive(tuple(urls), f"sha256:{sha256}") if urls and sha256 else None,
        )
        licence = Upstreams.proprietary(about)
        if isinstance(answer, Unnamed) and licence:
            # NVIDIA's CUDA, Intel's MKL, Microsoft's runtimes: a vendor's binaries, under its
            # own licence, with no public source to name.
            return Unnamed(
                f"a vendor's proprietary distribution (licensed {licence}), with no public "
                "source to name",
                homes=answer.homes,
            )
        return answer

    #: A licence that is a vendor's own, not an open one (`LicenseRef-` alone is not: the Ubuntu
    #: Font Licence is one).
    PROPRIETARY: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)proprietary|end[-_ ]user[-_ ]licen[cs]e|\bEULA\b|LicenseRef-Microsoft"
    )

    @staticmethod
    def proprietary(about: object) -> str:
        """The recipe's licence where it, or its family, says proprietary; else empty."""
        if not isinstance(about, dict):
            return ""
        licence = str(about.get("license") or "")
        family = str(about.get("license_family") or "")
        if family.lower() == "proprietary" or Upstreams.PROPRIETARY.search(licence):
            return licence or family
        return ""

    @staticmethod
    def ansible(dependency: Dependency) -> Upstream | Unnamed:
        """A collection on galaxy.ansible.com: its version record names the git commit it was
        built from (`git_url`, `git_commit_sha`)."""
        namespace, _, collection = dependency.name.partition(".")
        if dependency.resolved_from is not None or not collection or "." in collection:
            return Unnamed("it is not a collection from galaxy.ansible.com")
        record = json.loads(
            Upstreams._get(
                "https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/"
                f"index/{urllib.parse.quote(namespace, safe='')}/"
                f"{urllib.parse.quote(collection, safe='')}/versions/"
                f"{urllib.parse.quote(dependency.version or '', safe='')}/"
            )
        )
        repository = RepositoryArchive.repository(str(record.get("git_url") or ""))
        commit = str(record.get("git_commit_sha") or "")
        if repository and re.fullmatch(r"[0-9a-f]{40}", commit):
            return RepositoryArchive.upstream(
                repository, commit, f"Galaxy's record of {dependency.name} {dependency.version}"
            )
        return Upstreams.inferred(
            Unnamed("Galaxy's record names no commit"),
            [
                (record.get("metadata") or {}).get("repository"),
                (record.get("metadata") or {}).get("homepage"),
            ],
            dependency.version or "",
            (dependency.name, collection),
            f"Galaxy's record of {dependency.name} {dependency.version}",
            # The collection artefact Galaxy serves, by the SHA-256 its record gives.
            Archive(
                (urllib.parse.urljoin("https://galaxy.ansible.com", str(record["download_url"])),),
                f"sha256:{(record.get('artifact') or {}).get('sha256')}",
            )
            if isinstance(record.get("download_url"), str)
            and isinstance((record.get("artifact") or {}).get("sha256"), str)
            else None,
        )

    @staticmethod
    def nix(dependency: Dependency) -> Upstream | Unnamed:
        commit = dependency.version or ""
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            return Unnamed("it is locked to no git commit")
        return Upstream({"commit": commit}, f"its locked commit {commit[:12]}")


class UpstreamAdvisories:
    """Name each package's upstream, ask OSV, and return what it names, as `Advisory` records."""

    _cache: ClassVar[dict[tuple[str, str, str | None, str | None], Upstream | Unnamed]] = {}
    _records: ClassVar[dict[str, dict[str, Any]]] = {}

    @staticmethod
    def name(dependency: Dependency) -> Upstream | Unnamed:
        key = (dependency.ecosystem, dependency.name, dependency.version, dependency.integrity)
        cached = UpstreamAdvisories._cache.get(key)
        if cached is not None:
            return cached
        resolver = getattr(Upstreams, dependency.ecosystem, None)
        if resolver is None:
            return Unnamed("no upstream is read for this ecosystem")
        if dependency.ecosystem != "vcpkg" and not dependency.version:
            result: Upstream | Unnamed = Unnamed("no version is locked")
        else:
            from cordon_scanner.intel.gitfetch import GitFetchError
            from cordon_scanner.intel.registry_client import RegistryError

            try:
                result = resolver(dependency)
            except RegistryError as exc:
                result = Unnamed(f"its ecosystem's source could not be read ({exc})")
            except (
                OSError,
                ValueError,
                KeyError,
                TypeError,
                AttributeError,
                tarfile.TarError,
                # A response cut short mid-body (`IncompleteRead`): not an OSError.
                http.client.HTTPException,
                # The git client's own refusals (a tree it could not fetch).
                GitFetchError,
            ) as exc:
                result = Unnamed(f"its ecosystem's source could not be read ({type(exc).__name__})")
        UpstreamAdvisories._cache[key] = result
        return result

    @staticmethod
    def _post(url: str, body: dict[str, Any]) -> dict[str, Any]:
        import urllib.request

        request = urllib.request.Request(  # noqa: S310 - a fixed https URL
            url,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "cordon-scanner"},
        )
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            data = json.loads(response.read(64 << 20))
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _record(identifier: str) -> dict[str, Any]:
        cached = UpstreamAdvisories._records.get(identifier)
        if cached is None:
            cached = json.loads(
                Upstreams._get(OSV_VULN + urllib.parse.quote(identifier, safe=""), 16 << 20)
            )
            UpstreamAdvisories._records[identifier] = cached
        return cached

    @staticmethod
    def check(dependencies: Iterable[Dependency]) -> UpstreamResult:
        from concurrent.futures import ThreadPoolExecutor

        from cordon_scanner.intel.osv_import import OsvImport

        result = UpstreamResult()
        named: list[tuple[Dependency, Upstream]] = []
        listed = list(dependencies)
        for dependency in listed[MAX_PACKAGES:]:
            result.unchecked[dependency.purl] = (
                f"past the {MAX_PACKAGES}-package ceiling for one scan"
            )
        within = listed[:MAX_PACKAGES]
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            answers = list(pool.map(UpstreamAdvisories.name, within))
        # A binary pod published from the repository a sibling pod resolved to (Firebase's).
        answers = PodSiblings.resolve(within, answers)
        # A conda output naming no source, built in the same feedstock commit as one that does.
        answers = CondaSiblings.resolve(within, answers)
        for dependency, upstream in zip(within, answers, strict=True):
            if isinstance(upstream, Unnamed):
                if upstream.nothing:
                    result.checked.add(dependency.purl)
                    continue
                result.unchecked[dependency.purl] = upstream.reason
                if upstream.homes:
                    result.homes[dependency.purl] = upstream.homes
                if upstream.version and not dependency.version:
                    result.versions[dependency.purl] = upstream.version
            else:
                named.append((dependency, upstream))
        if not named:
            return result
        found: list[list[str]] = [[] for _ in named]
        try:
            for start in range(0, len(named), 1000):
                pending = {
                    i: named[i][1].query for i in range(start, min(start + 1000, len(named)))
                }
                while pending:
                    answer = UpstreamAdvisories._post(
                        OSV_QUERYBATCH, {"queries": list(pending.values())}
                    )
                    following: dict[int, dict[str, Any]] = {}
                    for i, entry in zip(pending, answer.get("results") or [], strict=False):
                        found[i] += [str(v["id"]) for v in entry.get("vulns") or [] if "id" in v]
                        if entry.get("next_page_token"):
                            following[i] = {
                                **named[i][1].query,
                                "page_token": entry["next_page_token"],
                            }
                    pending = following
        except (OSError, ValueError, http.client.HTTPException) as exc:
            for dependency, _ in named:
                result.unchecked[dependency.purl] = f"OSV could not be asked ({type(exc).__name__})"
            return result
        for (dependency, upstream), identifiers in zip(named, found, strict=True):
            result.checked.add(dependency.purl)
            advisories: list[Advisory] = []
            for identifier in dict.fromkeys(identifiers):
                try:
                    record = UpstreamAdvisories._record(identifier)
                except (OSError, ValueError, http.client.HTTPException) as exc:
                    result.checked.discard(dependency.purl)
                    result.unchecked[dependency.purl] = (
                        f"OSV's record {identifier} could not be read ({type(exc).__name__})"
                    )
                    break
                summary = str(record.get("summary") or record.get("details") or "").strip()
                summary = summary.splitlines()[0][:300] if summary else ""
                advisories.append(
                    Advisory(
                        ecosystem=dependency.ecosystem,
                        name=dependency.name,
                        versions=(dependency.version,) if dependency.version else (),
                        summary=f"{summary} Matched through {upstream.how}.".strip(),
                        reference=OsvImport._reference_of(record),
                        identifier=identifier,
                        severity=OsvImport._severity_of(record),
                        aliases=tuple(str(a) for a in record.get("aliases") or ()),
                        matched_through="inferred" if upstream.inferred else "upstream",
                    )
                )
            else:
                result.advisories[dependency.purl] = tuple(advisories)
        return result


__all__ = ["RepositoryArchive", "UpstreamAdvisories", "UpstreamResult", "Upstreams"]
