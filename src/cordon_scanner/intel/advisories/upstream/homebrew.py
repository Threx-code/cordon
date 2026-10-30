"""Homebrew formulae: the bottles a formula ships and the history of the formula file, read to find
the upstream release it builds.
"""

from __future__ import annotations

import http.client
import json
import re
import tarfile
import urllib.parse
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.foundation.network.downloads import Download
from cordon_scanner.foundation.network.redirects import NoRedirects
from cordon_scanner.intel.advisories.upstream.base import (
    Archive,
    RepositoryArchive,
    Unnamed,
    Upstream,
)
from cordon_scanner.intel.advisories.upstream.fetch import Fetch
from cordon_scanner.intel.advisories.upstream.inference import Inference

if TYPE_CHECKING:
    from cordon_scanner.foundation.results import Dependency


HOMEBREW_API: Final = "https://formulae.brew.sh/api/formula"


class HomebrewBottles:
    """A homebrew-core formula as it was when a version was bottled: the bottle's OCI manifest on
    ghcr.io names the commit and file (`org.opencontainers.image.source`)."""

    #: A `name: "value"` field of a formula's url statement. Anchored at a word's start, so a long word
    #: with no `:` after it is not rescanned from every position: linear, and the same fields as
    #: `(\w+):\s*"([^"]*)"`.
    URL_FIELD: ClassVar[re.Pattern[str]] = re.compile(r'(?<!\w)(\w+):\s*"([^"]*)"')

    @staticmethod
    def _ghcr(path: str, accept: str, token: str | None) -> bytes:
        import urllib.request

        headers = {"User-Agent": "cordon-scanner", "Accept": accept}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(f"https://ghcr.io{path}", headers=headers)
        with urllib.request.build_opener(NoRedirects).open(request, timeout=60) as response:
            body: bytes = Download.read(response, 4 << 20)
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
        from cordon_scanner.intel.registries.registry_client import PackageNotFound

        def record(formula: str) -> dict[str, Any] | None:
            try:
                answer = json.loads(
                    Fetch.get(f"{HOMEBREW_API}/{urllib.parse.quote(formula, safe='@+')}.json")
                )
            except PackageNotFound:
                return None
            return answer if isinstance(answer, dict) else None

        data = record(name)
        if data is not None:
            return name, data
        target = ""
        try:
            link = Fetch.get(
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
                        Fetch.get(
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
        from cordon_scanner.intel.provenance.homebrew_provenance import HomebrewProvenance

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
                    Fetch.get(
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
                Fetch.get(
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
        return Fetch.get(
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
                text = Fetch.get(f"{base}/{path}").decode("utf-8", "replace")
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
        return Inference.inferred(
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
        from cordon_scanner.ecosystems.packages.homebrew import Formula
        from cordon_scanner.foundation.content import FileContent

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
                HomebrewBottles.URL_FIELD.findall(statement.group(1) if statement else "")
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
        return Inference.from_urls([url, *mirrors], how)


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
        from cordon_scanner.intel.provenance.homebrew_provenance import HomebrewProvenance
        from cordon_scanner.intel.registries.registry_client import PackageNotFound

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
                        text = Fetch.get(f"{HomebrewHistory.RAW}/{sha}/{path}").decode(
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
        return Inference.inferred(
            HomebrewBottles.source(text, how),
            [*heads, HomebrewHistory.homepage(text)],
            re.sub(r"_\d+$", "", installed),
            (dependency.name.split("@", 1)[0],),
            how,
            HomebrewBottles.archive(text),
        )


__all__ = ["HOMEBREW_API", "HomebrewBottles", "HomebrewHistory"]
