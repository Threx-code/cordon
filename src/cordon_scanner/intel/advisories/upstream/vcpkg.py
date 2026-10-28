"""vcpkg ports: the versions database and the port files, read to find the upstream each port builds."""

from __future__ import annotations

import http.client
import json
import re
import urllib.parse
from typing import Any, ClassVar

from cordon_scanner.intel.advisories.upstream.base import (
    VCPKG_RAW,
    Archive,
    RepositoryArchive,
    Unnamed,
    Upstream,
)
from cordon_scanner.intel.advisories.upstream.fetch import Fetch
from cordon_scanner.intel.advisories.upstream.inference import Inference


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
        from cordon_scanner.foundation.paths import StatePaths

        path = StatePaths.default_cache_dir() / "upstream" / f"vcpkg-{kind}-{key}"
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
        from cordon_scanner.intel.registries.registry_client import PackageNotFound

        try:
            data = json.loads(Fetch.get(f"{VCPKG_RAW}/{baseline}/ports/{port}/vcpkg.json"))
            return data if isinstance(data, dict) else {}
        except PackageNotFound:
            control = Fetch.get(f"{VCPKG_RAW}/{baseline}/ports/{port}/CONTROL").decode(
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
        from cordon_scanner.intel.registries.registry_client import PackageNotFound

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
                    Fetch.get(f"{VCPKG_RAW}/{at}/versions/{port[0]}-/{name}.json")
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
        from cordon_scanner.intel.provenance.gitfetch import GitFetch, GitFetchError

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
        from cordon_scanner.intel.provenance.gitfetch import GitFetch

        name = urllib.parse.quote(port, safe="")
        database = json.loads(Fetch.get(f"{VCPKG_RAW}/{baseline}/versions/{port[0]}-/{name}.json"))
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
        from cordon_scanner.intel.registries.registry_client import RegistryError

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
        return Inference.inferred(
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
        from cordon_scanner.intel.registries.registry_client import RegistryError

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
        return Inference.inferred(
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
                VcpkgPorts._string_command(args, depth, values)
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
    def _string_command(args: list[str | None], depth: int, values: dict[str, str | None]) -> None:
        """A portfile's string() command: the value it builds, kept in the variables it sets."""
        first = args[0]
        if first is None:  # the caller's test, restated for the type
            return
        operation = first.upper()
        if operation == "REPLACE" and len(args) >= 5 and args[3]:
            inputs = args[4:]
            known = not depth and None not in (args[1], args[2], *inputs)
            values[args[3]] = (
                "".join(i for i in inputs if i is not None).replace(str(args[1]), str(args[2]))
                if known
                else None
            )
        elif (
            operation == "REGEX" and len(args) >= 5 and str(args[1]).upper() == "MATCH" and args[3]
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
                else VcpkgPorts._regex(pattern, "".join(i for i in inputs if i), replacement)
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
            return Inference.from_urls([u for u in urls if u], how)
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


__all__ = ["VcpkgPorts", "VcpkgVersions"]
