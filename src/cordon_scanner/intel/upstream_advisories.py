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

import io
import json
import re
import tarfile
import urllib.parse
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.intel.advisories import Advisory

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.core.models import Dependency

OSV_QUERYBATCH: Final = "https://api.osv.dev/v1/querybatch"
OSV_VULN: Final = "https://api.osv.dev/v1/vulns/"
BCR: Final = "https://bcr.bazel.build/modules"
CONAN_CENTER: Final = "https://center2.conan.io/v2/conans"
HOMEBREW_API: Final = "https://formulae.brew.sh/api/formula"
TERRAFORM_REGISTRY: Final = "https://registry.terraform.io/v1/providers"
VCPKG_RAW: Final = "https://raw.githubusercontent.com/microsoft/vcpkg"
MAX_PACKAGES: Final = 400
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


@dataclass
class UpstreamResult:
    advisories: dict[str, tuple[Advisory, ...]] = field(default_factory=dict)
    """By purl: what OSV names for each package whose upstream was named."""
    checked: set[str] = field(default_factory=set)
    """The purls asked of OSV, whether or not anything matched."""
    unchecked: dict[str, str] = field(default_factory=dict)
    """By purl: why the package could not be matched."""


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
        ),
    )
    #: Codeberg (Forgejo): `/<owner>/<repo>/archive/<ref>.tar.gz`.
    CODEBERG: ClassVar[re.Pattern[str]] = re.compile(
        r"^https://codeberg\.org/([\w.-]+)/([\w.-]+)/archive/(.+?)(?:\.tar\.gz|\.zip)$"
    )
    GITLAB: ClassVar[re.Pattern[str]] = re.compile(
        r"^https://gitlab\.com/([\w.-][\w./-]{0,200}?)/-/archive/([^/]+)/[^/]+$"
    )

    @staticmethod
    def parse(url: str) -> tuple[str, str] | None:
        """`(https repository URL, ref)`, or None for any other URL."""
        for form in RepositoryArchive.FORMS:
            found = form.match(url)
            if found:
                owner, repo, ref = found.groups()
                return (
                    f"https://github.com/{owner}/{repo.removesuffix('.git')}",
                    urllib.parse.unquote(ref),
                )
        found = RepositoryArchive.CODEBERG.match(url)
        if found:
            return (
                f"https://codeberg.org/{found.group(1)}/{found.group(2)}",
                urllib.parse.unquote(found.group(3)),
            )
        found = RepositoryArchive.GITLAB.match(url)
        if found:
            return f"https://gitlab.com/{found.group(1)}", urllib.parse.unquote(found.group(2))
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

    @staticmethod
    def parse(url: str) -> tuple[str, str, str] | None:
        """`(OSV ecosystem, name, version)`, or None."""
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
    `zstandard` package if installed. A legacy `.tar.bz2` is read as a stream, to a bound.
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
    def _zstd(blob: bytes) -> bytes:
        try:
            from compression import zstd  # type: ignore[import-not-found]  # Python 3.14+

            out: bytes = zstd.decompress(blob)
        except ImportError:
            try:
                import zstandard  # type: ignore[import-not-found]
            except ImportError as exc:
                raise CondaPackage.NeedsZstd from exc
            out = zstandard.ZstdDecompressor().decompress(
                blob, max_output_size=CondaPackage.MAX_INFO_BYTES
            )
        if len(out) > CondaPackage.MAX_INFO_BYTES:
            raise ValueError("info too large")
        return out

    class NeedsZstd(Exception):
        """Neither Python 3.14's zstd nor the `zstandard` package is available."""

    @staticmethod
    def _from_tar(archive: tarfile.TarFile) -> str | None:
        for member in archive:
            if member.name in CondaPackage.RECIPES and member.isfile():
                handle = archive.extractfile(member)
                if handle is not None:
                    return handle.read(CondaPackage.MAX_INFO_BYTES).decode("utf-8", "replace")
        return None

    @staticmethod
    def recipe(url: str) -> str | None:
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
                    return CondaPackage._from_tar(archive)
        if not url.endswith(".conda"):
            return None
        tail, total = CondaPackage._range(url, "bytes=-65536", 65536)
        end = tail.rfind(b"PK\x05\x06")
        if end < 0:
            raise ValueError("no zip directory at the end of the package")
        size, offset = struct.unpack("<II", tail[end + 12 : end + 20])
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
            with tarfile.open(fileobj=io.BytesIO(CondaPackage._zstd(body)), mode="r:") as archive:
                return CondaPackage._from_tar(archive)
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
        except OSError:
            pass
        body: bytes = fetch()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        except OSError:
            pass
        return body

    @staticmethod
    def at_version(baseline: str, port: str, version: str) -> tuple[str, str] | Unnamed:
        """The portfile of `port` at `version`: the git tree the version database names for it,
        read from GitHub's API by that tree's id."""
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
        if not entries:
            return Unnamed(f"the version database at the baseline holds no {wanted}")
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
        for quoted, bare in re.findall(
            r'"((?:\\.|[^"\\])*)"|([^\s"#()]+)', re.sub(r"#[^\n]*", "", raw)
        ):
            text = quoted if quoted or not bare else bare
            unknown = False

            def expand(match: re.Match[str]) -> str:
                nonlocal unknown
                value = values.get(match.group(1))
                if value is None:
                    unknown = True
                    return ""
                return value

            expanded = re.sub(r"\$\{([A-Za-z0-9_.+-]+)\}", expand, text)
            out.append(None if unknown else expanded.replace('\\"', '"'))
        return out

    @staticmethod
    def source(portfile: str, version: str, port: str, how: str) -> Upstream | Unnamed:
        values: dict[str, str | None] = {"VERSION": version, "PORT": port}
        depth = 0
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
            elif name in VcpkgPorts.FETCHES and not depth:
                keyed: dict[str, list[str | None]] = {}
                current = ""
                for a in args:
                    if a is not None and a in VcpkgPorts.KEYWORDS:
                        current = a
                        keyed.setdefault(a, [])
                    elif current:
                        keyed[current].append(a)
                ref = (keyed.get("REF") or [None])[0]
                if name == "vcpkg_download_distfile":
                    urls = keyed.get("URLS") or []
                    if any(u is None for u in urls):
                        return Unnamed("its portfile's download URL is computed")
                    return Upstreams.from_urls([u for u in urls if u], how)
                if ref is None:
                    return Unnamed(f"its portfile's REF is computed or missing ({name})")
                repo = (keyed.get("REPO") or [None])[0]
                if name == "vcpkg_from_github":
                    host = (keyed.get("GITHUB_HOST") or ["https://github.com"])[0]
                    if host != "https://github.com" or not repo:
                        return Unnamed(
                            "its portfile fetches from a GitHub host other than github.com"
                        )
                    repository = f"https://github.com/{repo}"
                elif name == "vcpkg_from_gitlab":
                    # The host is named exactly: gitlab.com, or gitlab.freedesktop.org (fontconfig).
                    host = (keyed.get("GITLAB_URL") or [None])[0]
                    if (
                        not host
                        or not repo
                        or not re.fullmatch(r"https://[\w.-]+(?::\d+)?/?", host)
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
                        return Unnamed("its portfile's git URL is not on GitHub or GitLab")
                    repository = named
                return RepositoryArchive.upstream(repository, ref, f"{how} ({repository})")
        return Unnamed("its portfile fetches its source in no form read here")


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
                    break
                except OSError:
                    if attempt == 2:
                        raise
            if "git-upload-pack-advertisement" in kind and len(body) <= TagInference.MAX_REFS_BYTES:
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
        except (OSError, ValueError):
            found = None
        TagInference._refs[repository] = found
        return found

    @staticmethod
    def infer(repository: str, version: str, names: Iterable[str], how: str) -> Upstream | Unnamed:
        tags = TagInference.refs(repository)
        if tags is None:
            return Unnamed(f"{repository} could not be read as a git repository")
        spellings = {version, f"v{version}", f"release-{version}"}
        for name in names:
            if name:
                spellings |= {f"{name}-{version}", f"{name}-v{version}"}
        matched = {tag: tags[tag] for tag in spellings if tag in tags}
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

    FORMS: ClassVar[tuple[tuple[re.Pattern[str], str], ...]] = (
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
            re.compile(r"^https?://download\.gnome\.org/sources/([\w.+-]+)/"),
            "https://gitlab.gnome.org/GNOME/{0}",
        ),
        (
            re.compile(r"^https?://(?:www\.)?x\.org/releases/individual/([\w-]+)/([\w.+-]+?)-\d"),
            "https://gitlab.freedesktop.org/xorg/{0}/{1}",
        ),
        (
            re.compile(
                r"^https?://xorg\.freedesktop\.org/releases/individual/([\w-]+)/([\w.+-]+?)-\d"
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
                    out.append(template.format(*found.groups()))
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
        request = urllib.request.Request(url, headers={"User-Agent": "cordon-scanner"})  # noqa: S310
        with urllib.request.urlopen(request, timeout=300) as response:  # noqa: S310
            body: bytes = response.read(ContentProof.MAX_ARCHIVE_BYTES + 1)
        if len(body) > ContentProof.MAX_ARCHIVE_BYTES:
            raise ValueError("archive too large")
        return body

    @staticmethod
    def files(body: bytes) -> dict[str, bytes]:
        """`path -> bytes` of each regular file, the archive's one top-level folder removed."""
        import zipfile

        out: dict[str, bytes] = {}
        if body[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(body)) as archive:
                for info in archive.infolist():
                    if not info.is_dir():
                        out[info.filename] = archive.read(info)
        else:
            with tarfile.open(fileobj=io.BytesIO(body), mode="r:*") as archive:
                for member in archive:
                    if member.isfile():
                        handle = archive.extractfile(member)
                        if handle is not None:
                            out[member.name] = handle.read()
        tops = {path.split("/", 1)[0] for path in out}
        if len(tops) == 1 and all("/" in path for path in out):
            out = {path.split("/", 1)[1]: data for path, data in out.items()}
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
        result = ContentProof._check(archive, repository, commit, tag)
        ContentProof._results[key] = result
        return result

    @staticmethod
    def _check(archive: Archive, repository: str, commit: str, tag: str) -> tuple[str, str]:
        from cordon_scanner.intel.gitfetch import GitFetch, GitFetchError, GitPack

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
        for url in dict.fromkeys(candidates):
            try:
                body = ContentProof._download(url)
            except (OSError, ValueError):
                continue
            if ContentProof._digest_matches(body, archive.digest):
                release = body
                break
        if release is None:
            return "unprovable", "no release archive matching the recipe's digest could be read"
        try:
            raw = ContentProof.files(release)
            ours = {path: GitPack.blob_id(data) for path, data in raw.items()}
        except (OSError, ValueError, tarfile.TarError, EOFError) as exc:
            return "unprovable", f"the release archive could not be read ({type(exc).__name__})"
        try:
            # The tag's tree by git's own protocol: blob ids, compared with the release's files
            # hashed the way git hashes them.
            theirs = GitFetch.tree(repository, tip)
        except (GitFetchError, OSError, ValueError) as exc:
            return (
                "unprovable",
                f"the tag's tree could not be fetched ({type(exc).__name__}: {exc})"[:200],
            )
        source = {
            path: blob
            for path, blob in theirs.items()
            if not any(part.startswith(".") for part in path.split("/"))
        }
        common = [path for path in source if path in ours]
        differing = [path for path in common if ours[path] != source[path]]
        # Git writes a file marked `text eol=crlf` out with CRLF and stores it with LF (git's .bat
        # files): the same content by git's own conversion, which nothing else is excused by.
        converted = [
            path
            for path in differing
            if b"\r\n" in raw[path]
            and GitPack.blob_id(raw[path].replace(b"\r\n", b"\n")) == source[path]
        ]
        differing = [path for path in differing if path not in converted]
        # A file the tag holds empty that the release fills in (GNU's ChangeLog, written from the
        # git log by `make dist`): a placeholder for something generated, not different source.
        filled = [path for path in differing if source[path] == ContentProof.EMPTY_BLOB]
        differing = [path for path in differing if path not in filled]
        if differing:
            return "refuted", f"{len(differing)} of the files both hold differ ({differing[0]})"
        enough = len(common) >= ContentProof.MIN_SHARED or (
            len(common) >= ContentProof.MIN_SMALL
            and len(common) >= ContentProof.MIN_SHARE * len(source)
        )
        if not enough:
            return (
                "unprovable",
                f"the release holds {len(common)} of the tag's {len(source)} files",
            )
        return (
            "proven",
            f"the release archive holds {len(common)} of its {len(source)} files, each with the same git blob id"
            + (f" ({len(converted)} after git's end-of-line conversion)" if converted else "")
            + (f" ({len(filled)} empty in the tag, filled by the release)" if filled else ""),
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
        return Unnamed("; ".join([first.reason, *tried]))

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
        except (OSError, ValueError):
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
        locked = (dependency.integrity or "").removeprefix("md5:")
        if not re.fullmatch(r"[0-9a-f]{32}", locked):
            revisions = json.loads(Upstreams._get(base)).get("revisions") or []
            if not revisions:
                return Unnamed("Conan Center holds no recipe for this version")
            locked = str(revisions[0].get("revision") or "")
        export = Upstreams._get(f"{base}/{locked}/files/conan_export.tgz", MAX_EXPORT_BYTES)
        # `MoreRegistries._get` inflates a gzip answer itself, so this may already be a plain tar.
        with tarfile.open(fileobj=io.BytesIO(export), mode="r:*") as archive:
            member = archive.extractfile("conandata.yml")
            text = member.read(MAX_EXPORT_BYTES).decode("utf-8", "replace") if member else ""
            try:
                recipe = archive.extractfile("conanfile.py")
            except KeyError:
                recipe = None
            conanfile = recipe.read(MAX_EXPORT_BYTES).decode("utf-8", "replace") if recipe else ""
        from cordon_scanner.core.datayaml import DataYaml

        data = DataYaml.load(text) if text else {}
        sources = (data.get("sources") or {}) if isinstance(data, dict) else {}
        source = sources.get(version) if isinstance(sources, dict) else None
        urls: list[str] = []
        if isinstance(source, dict):
            given = source.get("url")
            urls = (
                [given]
                if isinstance(given, str)
                else [u for u in given or [] if isinstance(u, str)]
            )
        how = f"Conan Center's recipe {name}/{version}#{locked[:8]}"
        homepage = re.search(r'^\s*homepage\s*=\s*["\']([^"\']+)["\']', conanfile, re.MULTILINE)
        sha256 = source.get("sha256") if isinstance(source, dict) else None
        return Upstreams.inferred(
            Upstreams.from_urls(urls, how),
            [homepage.group(1)] if homepage else [],
            version,
            (name,),
            how,
            Archive(tuple(urls), f"sha256:{sha256}") if urls and isinstance(sha256, str) else None,
        )

    @staticmethod
    def cocoapods(dependency: Dependency) -> Upstream | Unnamed:
        from cordon_scanner.intel.more_registries import HOSTS, MoreRegistries

        if dependency.resolved_from is not None:
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
        return Upstreams.inferred(first, homes, version, (name,), how, pinned)

    @staticmethod
    def homebrew(dependency: Dependency) -> Upstream | Unnamed:
        name = dependency.name
        if "cask" in dependency.platform:
            return Unnamed("a cask: a macOS application, which no advisory source covers by name")
        if "/" in name or dependency.resolved_from is not None:
            return Unnamed("it is from a tap, which formulae.brew.sh does not describe")
        data = json.loads(
            Upstreams._get(f"{HOMEBREW_API}/{urllib.parse.quote(name, safe='@+')}.json")
        )
        stable = str((data.get("versions") or {}).get("stable") or "")
        installed = dependency.version or ""
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
            text, version = (
                HomebrewBottles.formula(name, installed),
                re.sub(r"_\d+$", "", installed),
            )
            how = f"the {name} {installed} formula its bottle carries"
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
        manifest = json.loads(Upstreams._get(f"{VCPKG_RAW}/{baseline}/ports/{port}/vcpkg.json"))
        scheme, at_baseline = next(
            (
                (k, str(manifest[k]))
                for k in ("version", "version-semver", "version-date", "version-string")
                if isinstance(manifest.get(k), str)
            ),
            ("version", ""),
        )
        wanted = dependency.version
        if not wanted:
            # vcpkg installs the greater of the baseline's version and every `version>=`.
            minimum = (dependency.declared_spec or "").removeprefix(">=")
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
        else:
            portfile = Upstreams._get(f"{VCPKG_RAW}/{baseline}/ports/{port}/portfile.cmake").decode(
                "utf-8", "replace"
            )
            version = at_baseline
        how = f"the {dependency.name} {version} port"
        return Upstreams.inferred(
            VcpkgPorts.source(portfile, version, dependency.name, how),
            [manifest.get("homepage")],
            version.split("#", 1)[0],
            (dependency.name,),
            how,
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
        recipe = CondaPackage.recipe(url)
        if recipe is None:
            return Unnamed("its package carries no rendered recipe")
        from cordon_scanner.core.datayaml import DataYaml

        data = DataYaml.load(recipe)
        if isinstance(data, dict) and isinstance(data.get("recipe"), dict):
            data = data["recipe"]  # rattler-build's rendered_recipe.yaml wraps it
        source = data.get("source") if isinstance(data, dict) else None
        sources = source if isinstance(source, list) else [source] if source else []
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
        return Upstreams.inferred(
            Upstreams.from_urls(urls, how),
            homes,
            dependency.version or "",
            (dependency.name,),
            how,
            Archive(tuple(urls), f"sha256:{sha256}") if urls and sha256 else None,
        )

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
            from cordon_scanner.intel.registry_client import RegistryError

            try:
                result = resolver(dependency)
            except CondaPackage.NeedsZstd:
                result = Unnamed(
                    "reading a .conda package's recipe needs Python 3.14 or the zstandard package"
                )
            except RegistryError as exc:
                result = Unnamed(f"its ecosystem's source could not be read ({exc})")
            except (
                OSError,
                ValueError,
                KeyError,
                TypeError,
                AttributeError,
                tarfile.TarError,
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
        from cordon_scanner.intel.osv_import import OsvImport

        result = UpstreamResult()
        named: list[tuple[Dependency, Upstream]] = []
        for index, dependency in enumerate(dependencies):
            if index >= MAX_PACKAGES:
                result.unchecked[dependency.purl] = (
                    f"past the {MAX_PACKAGES}-package ceiling for one scan"
                )
                continue
            upstream = UpstreamAdvisories.name(dependency)
            if isinstance(upstream, Unnamed):
                result.unchecked[dependency.purl] = upstream.reason
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
        except (OSError, ValueError) as exc:
            for dependency, _ in named:
                result.unchecked[dependency.purl] = f"OSV could not be asked ({type(exc).__name__})"
            return result
        for (dependency, upstream), identifiers in zip(named, found, strict=True):
            result.checked.add(dependency.purl)
            advisories: list[Advisory] = []
            for identifier in dict.fromkeys(identifiers):
                try:
                    record = UpstreamAdvisories._record(identifier)
                except (OSError, ValueError) as exc:
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
