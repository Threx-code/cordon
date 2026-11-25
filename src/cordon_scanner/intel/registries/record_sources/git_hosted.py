"""The registry record of the ecosystems whose registry is a git repository, or whose packages are repositories.

Two shapes, one reader:

* A registry kept in git (the Bazel Central Registry, Julia's General, vcpkg, opam-repository, Conan Center's index,
  Homebrew's core tap): the release list is a file in the registry (`metadata.json`, `Versions.toml`, a versions file, a
  directory, `config.yml`, the formula), read raw; a release's date and who added it are the registry's own history,
  the commits that touched the package's path. The commit that adds a release names it, by each registry's convention
  (`rules_cc@0.2.28`, `New version: JSON v1.13.4`, `[zlib] Update to 1.4`, `[new release] yojson (3.0.0)`,
  `zlib: publish version 1.4`, `jq 1.8.2`): the earliest commit naming a release dates it. A release no commit names
  (a revision of a port, a message in another convention) is placed by its position in the release list, between the
  dated releases around it, never given a date of its own.
* A package that is a repository (a GitHub Action, a Swift package, a Nix input: `owner/repo`): its releases are the
  repository's releases, or for a Nix input pinned at a commit, its commits; the repository's own answer says when it
  was created and whether it is archived.

Every document is a public answer of the host: raw files, and the host's API without a token (rate-limited per
address; a configured token raises the limit and is never needed for a record). Every parser is pure.
"""

from __future__ import annotations

import re
import urllib.parse
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.intel.registries.record_sources.base import (
    Document,
    PublisherKind,
    RecordBuilder,
    RecordSource,
    Release,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from cordon_scanner.intel.registries.registry_record import RegistryRecord


class GitHub:
    """The documents a git host serves, and reading them."""

    API: ClassVar[str] = "https://api.github.com"
    RAW: ClassVar[str] = "https://raw.githubusercontent.com"
    #: Pages of a path's history read (100 commits each): with the release list, the record's documents stay within
    #: `RecordFetch.MAX_DOCUMENTS`. A path with more history has its oldest releases placed by position.
    PAGES: ClassVar[int] = 5

    @staticmethod
    def q(part: str) -> str:
        return urllib.parse.quote(part, safe="/")

    @classmethod
    def raw(cls, repo: str, ref: str, path: str, kind: str = "json") -> Document:
        return Document(f"{cls.RAW}/{repo}/{ref}/{cls.q(path)}", kind=kind)  # type: ignore[arg-type]

    @classmethod
    def api(cls, path: str, *, required: bool = True) -> Document:
        return Document(f"{cls.API}/{path}", required=required)

    @classmethod
    def history(cls, repo: str, path: str) -> tuple[Document, ...]:
        """The commits that touched `path`, newest first, a page at a time; pages after the first are optional."""
        return tuple(
            cls.api(
                f"repos/{repo}/commits?path={cls.q(path)}&per_page=100&page={page}",
                required=page == 1,
            )
            for page in range(1, cls.PAGES + 1)
        )

    @staticmethod
    def when(text: Any) -> datetime | None:
        if not isinstance(text, str) or not text:
            return None
        try:
            stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        return stamp if stamp.tzinfo else stamp.replace(tzinfo=UTC)

    @classmethod
    def commits(cls, documents: Mapping[str, Any], prefix: str) -> list[dict[str, Any]]:
        """Every commit in the documents whose URL starts with `prefix`, in the order served."""
        found: list[dict[str, Any]] = []
        for url, document in documents.items():
            if url.startswith(prefix) and isinstance(document, list):
                found.extend(c for c in document if isinstance(c, dict))
        return found

    @classmethod
    def commit_fact(cls, commit: Mapping[str, Any]) -> tuple[str, datetime | None, str]:
        """(first line of the message, the commit's date, the author's account or name)."""
        raw = commit.get("commit")
        body: dict[str, Any] = raw if isinstance(raw, dict) else {}
        message = str(body.get("message") or "").split("\n", 1)[0]
        stamp = None
        for role in ("author", "committer"):
            part = body.get(role)
            if isinstance(part, dict):
                stamp = stamp or cls.when(part.get("date"))
        account = commit.get("author")
        login = account.get("login") if isinstance(account, dict) else None
        if not login and isinstance(body.get("author"), dict):
            login = body["author"].get("name")
        return message, stamp, str(login or "")


class History:
    """A release list dated by the registry's own commits."""

    @staticmethod
    def token(version: str) -> re.Pattern[str]:
        # `v1.2` names `1.2` (Julia's `JSON v0.21.4`); `x1.2` or `1.2.3` does not name `1.2`.
        return re.compile(rf"(?<![\w.])v?{re.escape(version.removeprefix('v'))}(?![\w]|\.\d)")

    @classmethod
    def dated(
        cls,
        versions: list[str],
        commits: list[dict[str, Any]],
        names: Iterable[str] = (),
    ) -> dict[str, tuple[datetime, str]]:
        """Each release's date and author: the earliest commit whose message names it (and, when `names` is given, the
        package too, so a shared path's commits about another package never date this one)."""
        wanted = [n.lower() for n in names]
        facts = [GitHub.commit_fact(c) for c in commits]
        facts = [f for f in facts if f[1] is not None]
        found: dict[str, tuple[datetime, str]] = {}
        for version in versions:
            pattern = cls.token(version)
            hits = [
                (stamp, who)
                for message, stamp, who in facts
                if stamp is not None
                and pattern.search(message)
                and (not wanted or any(n in message.lower() for n in wanted))
            ]
            if hits:
                found[version] = min(hits, key=lambda hit: hit[0])
        return found

    @staticmethod
    def releases(
        versions: list[str],
        dated: Mapping[str, tuple[datetime, str]],
        withdrawn: Mapping[str, str] | None = None,
    ) -> list[Release]:
        """The releases, oldest first as `versions` lists them. A release no commit dates sits just after the dated
        release before it (or just before the first dated one): its place in the order, never a date of its own."""
        if not dated:
            return []
        withdrawn = withdrawn or {}
        out: list[Release] = []
        first = min(stamp for stamp, _ in dated.values())
        anchor = first - timedelta(seconds=len(versions) + 1)
        for version in versions:
            if version in dated:
                stamp, who = dated[version]
                anchor = max(anchor, stamp)
            else:
                anchor, who = anchor + timedelta(seconds=1), ""
                stamp = anchor
            out.append(Release(version, stamp, who, withdrawn.get(version, "")))
        return out


class GitRegistrySource(RecordSource):
    """A registry kept in a git repository: the release list from one of its files, the dates from its history."""

    publisher_kind: ClassVar[PublisherKind] = "committer"
    repo: ClassVar[str]
    ref: ClassVar[str] = "master"

    def path(self, name: str) -> str:
        raise NotImplementedError

    def listing(self, name: str) -> Document:
        return GitHub.raw(self.repo, self.ref, self.path(name))

    def history_path(self, name: str) -> str:
        return self.path(name)

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        return (self.listing(name), *GitHub.history(self.repo, self.history_path(name)))

    def versions(self, name: str, listing: Any) -> tuple[list[str], dict[str, str], dict[str, Any]]:
        """(releases oldest first, each withdrawn release's word for it, the record's other facts)."""
        raise NotImplementedError

    def names(self, name: str) -> tuple[str, ...]:
        return ()

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        listing = documents.get(self.listing(name).url)
        if listing is None:
            return None
        versions, withdrawn, facts = self.versions(name, listing)
        if version not in versions:
            return None
        commits = GitHub.commits(documents, f"{GitHub.API}/repos/{self.repo}/commits")
        dated = History.dated(versions, commits, self.names(name))
        releases = History.releases(versions, dated, withdrawn)
        return RecordBuilder.from_history(self, name, version, releases, **facts)


class BazelSource(GitRegistrySource):
    """The Bazel Central Registry: `modules/<name>/metadata.json` (versions, yanked versions, maintainers)."""

    ecosystem: ClassVar[str] = "bazel"
    repo: ClassVar[str] = "bazelbuild/bazel-central-registry"
    ref: ClassVar[str] = "main"

    def path(self, name: str) -> str:
        return f"modules/{name}/metadata.json"

    def history_path(self, name: str) -> str:
        return f"modules/{name}"

    def names(self, name: str) -> tuple[str, ...]:
        return (f"{name}@",)

    def versions(self, name: str, listing: Any) -> tuple[list[str], dict[str, str], dict[str, Any]]:
        if not isinstance(listing, dict):
            return [], {}, {}
        versions = [str(v) for v in listing.get("versions") or () if isinstance(v, str)]
        yanked = listing.get("yanked_versions")
        withdrawn = {str(v): "yanked" for v in yanked} if isinstance(yanked, dict) else {}
        maintainers = listing.get("maintainers")
        return (
            versions,
            withdrawn,
            {
                "maintainers": len(maintainers) if isinstance(maintainers, list) else 0,
                "has_repository": bool(listing.get("repository")),
                "owners": tuple(
                    sorted(
                        str(m.get("github"))
                        for m in maintainers or ()
                        if isinstance(m, dict) and m.get("github")
                    )
                ),
            },
        )


class JuliaSource(GitRegistrySource):
    """Julia's General registry: `<L>/<Name>/Versions.toml` (each release, and whether it is yanked), `Package.toml`."""

    ecosystem: ClassVar[str] = "julia"
    repo: ClassVar[str] = "JuliaRegistries/General"
    SECTION: ClassVar[re.Pattern[str]] = re.compile(r'^\["([^"]+)"\]\s*$')

    def path(self, name: str) -> str:
        return f"{name[:1].upper()}/{name}/Versions.toml"

    def listing(self, name: str) -> Document:
        return GitHub.raw(self.repo, self.ref, self.path(name), kind="text")

    def names(self, name: str) -> tuple[str, ...]:
        return (f"{name} v",)

    def versions(self, name: str, listing: Any) -> tuple[list[str], dict[str, str], dict[str, Any]]:
        versions: list[str] = []
        withdrawn: dict[str, str] = {}
        for line in str(listing).splitlines():
            match = self.SECTION.match(line.strip())
            if match:
                versions.append(match.group(1))
            elif versions and re.match(r"^\s*yanked\s*=\s*true\s*$", line):
                withdrawn[versions[-1]] = "yanked"
        return versions, withdrawn, {"has_repository": True}


class VcpkgSource(GitRegistrySource):
    """vcpkg's registry: `versions/<l>-/<name>.json`, newest first; a port revision is `<version>#<n>`."""

    ecosystem: ClassVar[str] = "vcpkg"
    repo: ClassVar[str] = "microsoft/vcpkg"
    FIELDS: ClassVar[tuple[str, ...]] = (
        "version",
        "version-semver",
        "version-date",
        "version-string",
    )

    def path(self, name: str) -> str:
        return f"versions/{name[:1]}-/{name}.json"

    def names(self, name: str) -> tuple[str, ...]:
        return (f"[{name}",)

    def versions(self, name: str, listing: Any) -> tuple[list[str], dict[str, str], dict[str, Any]]:
        entries = listing.get("versions") if isinstance(listing, dict) else None
        versions: list[str] = []
        for entry in entries if isinstance(entries, list) else ():
            if not isinstance(entry, dict):
                continue
            base = next((str(entry[f]) for f in self.FIELDS if isinstance(entry.get(f), str)), "")
            revision = entry.get("port-version")
            if base:
                versions.append(
                    f"{base}#{revision}" if isinstance(revision, int) and revision else base
                )
        return list(reversed(versions)), {}, {}

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        listing = documents.get(self.listing(name).url)
        if listing is None:
            return None
        versions, _, _ = self.versions(name, listing)
        if version not in versions:
            return None
        commits = GitHub.commits(documents, f"{GitHub.API}/repos/{self.repo}/commits")
        # A revision `1.3.2#3` is dated by the commits naming its release `1.3.2`, the first of them.
        bases = [v.split("#", 1)[0] for v in versions]
        by_base = History.dated(sorted(set(bases)), commits, self.names(name))
        dated = {
            v: by_base[b]
            for v, b in zip(versions, bases, strict=True)
            if "#" not in v and b in by_base
        }
        return RecordBuilder.from_history(self, name, version, History.releases(versions, dated))


class OpamSource(GitRegistrySource):
    """opam-repository: `packages/<name>/<name>.<version>/` directories, listed by the host's contents answer."""

    ecosystem: ClassVar[str] = "opam"
    repo: ClassVar[str] = "ocaml/opam-repository"

    def path(self, name: str) -> str:
        return f"packages/{name}"

    def listing(self, name: str) -> Document:
        return GitHub.api(f"repos/{self.repo}/contents/{GitHub.q(self.path(name))}")

    def names(self, name: str) -> tuple[str, ...]:
        return (name,)

    def versions(self, name: str, listing: Any) -> tuple[list[str], dict[str, str], dict[str, Any]]:
        from cordon_scanner.intel.advisories.versions import Versions

        prefix = f"{name}."
        entries = listing if isinstance(listing, list) else []
        found = [
            str(entry["name"])[len(prefix) :]
            for entry in entries
            if isinstance(entry, dict) and str(entry.get("name", "")).startswith(prefix)
        ]
        ordered = sorted(found, key=_Sort.key(lambda a, b: Versions.compare("opam", a, b)))
        return ordered, {}, {}


class ConanSource(GitRegistrySource):
    """Conan Center: the index (`recipes/<name>/config.yml`) lists the versions the centre still builds, and its history
    names every version ever added (`zlib: add 1.3.1`, `zlib: publish version 1.4`), which stay published after the
    index drops them; the centre's own answer (`/v2/conans/<name>/<version>/_/_/revisions`) dates a version's first
    revision exactly."""

    ecosystem: ClassVar[str] = "conan"
    repo: ClassVar[str] = "conan-io/conan-center-index"
    CENTER: ClassVar[str] = "https://center2.conan.io/v2/conans"
    VERSION: ClassVar[re.Pattern[str]] = re.compile(r"^  ['\"]?([^'\":\s]+)['\"]?\s*:")
    ADDED: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:add(?:ed)?|publish|bump(?:ed)?(?: to)?|update(?:d)? to|new)\s+(?:version\s+)?v?(\d[\w.+-]*\w)",
        re.IGNORECASE,
    )

    def path(self, name: str) -> str:
        return f"recipes/{name}/config.yml"

    def listing(self, name: str) -> Document:
        return GitHub.raw(self.repo, self.ref, self.path(name), kind="text")

    def history_path(self, name: str) -> str:
        return f"recipes/{name}"

    def revisions(self, name: str, version: str) -> Document:
        quoted = "/".join(urllib.parse.quote(p, safe="") for p in (name, version))
        return Document(f"{self.CENTER}/{quoted}/_/_/revisions", required=False)

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        return (
            self.listing(name),
            self.revisions(name, version),
            *GitHub.history(self.repo, self.history_path(name))[: GitHub.PAGES - 1],
        )

    def names(self, name: str) -> tuple[str, ...]:
        return (name,)

    def versions(self, name: str, listing: Any) -> tuple[list[str], dict[str, str], dict[str, Any]]:
        inside, found = False, []
        for line in str(listing).splitlines():
            if not line.startswith(" "):
                inside = line.strip() == "versions:"
                continue
            match = self.VERSION.match(line) if inside else None
            if match:
                found.append(match.group(1))
        return found, {}, {}

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from cordon_scanner.intel.advisories.versions import Versions

        listing = documents.get(self.listing(name).url)
        if listing is None:
            return None
        commits = GitHub.commits(documents, f"{GitHub.API}/repos/{self.repo}/commits")
        named = {
            match.group(1)
            for commit in commits
            for match in [self.ADDED.search(GitHub.commit_fact(commit)[0])]
            if match and name.lower() in GitHub.commit_fact(commit)[0].lower()
        }
        versions = sorted(
            set(self.versions(name, listing)[0]) | named,
            key=_Sort.key(lambda a, b: Versions.compare("conan", a, b)),
        )
        if version not in versions:
            return None
        dated = History.dated(versions, commits, self.names(name))
        first = self.first_revision(documents.get(self.revisions(name, version).url))
        if first is not None:
            dated[version] = (first, dated.get(version, (first, ""))[1])
        return RecordBuilder.from_history(self, name, version, History.releases(versions, dated))

    @staticmethod
    def first_revision(answer: Any) -> datetime | None:
        revisions = answer.get("revisions") if isinstance(answer, dict) else None
        stamps = [
            GitHub.when(str(r.get("time", "")).replace("+0000", "+00:00"))
            for r in (revisions if isinstance(revisions, list) else [])
            if isinstance(r, dict)
        ]
        found = [s for s in stamps if s is not None]
        return min(found) if found else None


class HomebrewSource(GitRegistrySource):
    """Homebrew's core tap: the formula's answer (`formulae.brew.sh/api/formula/<name>.json`: the current version,
    deprecated or disabled); every earlier version is a commit of the formula's file (`<name> <version>`)."""

    ecosystem: ClassVar[str] = "homebrew"
    repo: ClassVar[str] = "Homebrew/homebrew-core"
    API: ClassVar[str] = "https://formulae.brew.sh/api/formula"

    def path(self, name: str) -> str:
        return f"Formula/{name[:1]}/{name}.rb"

    def listing(self, name: str) -> Document:
        return Document(f"{self.API}/{urllib.parse.quote(name, safe='')}.json")

    def versions(self, name: str, listing: Any) -> tuple[list[str], dict[str, str], dict[str, Any]]:
        stable = listing.get("versions", {}).get("stable") if isinstance(listing, dict) else None
        if not isinstance(stable, str):
            return [], {}, {}
        word = "deprecated" if listing.get("deprecated") or listing.get("disabled") else ""
        return (
            [stable],
            {stable: word} if word else {},
            {"has_repository": bool(listing.get("homepage"))},
        )

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        listing = documents.get(self.listing(name).url)
        if listing is None:
            return None
        current, withdrawn, facts = self.versions(name, listing)
        commits = GitHub.commits(documents, f"{GitHub.API}/repos/{self.repo}/commits")
        bump = re.compile(rf"^{re.escape(name)} (\S+?)(?: \(new formula\))?$")
        earlier: list[str] = []
        for commit in reversed(commits):
            match = bump.match(GitHub.commit_fact(commit)[0])
            if match and match.group(1) not in earlier:
                earlier.append(match.group(1))
        versions = [v for v in earlier if v not in current] + current
        if version not in versions:
            return None
        dated = History.dated(versions, commits, (name,))
        return RecordBuilder.from_history(
            self, name, version, History.releases(versions, dated, withdrawn), **facts
        )


class RepositorySource(RecordSource):
    """A package that is a repository (`owner/repo`): its releases, and the repository's own answer."""

    publisher_kind: ClassVar[PublisherKind] = "account"
    PAGES: ClassVar[int] = 3

    def repository(self, name: str) -> Document:
        return GitHub.api(f"repos/{GitHub.q(name)}")

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        return (
            self.repository(name),
            *(
                GitHub.api(
                    f"repos/{GitHub.q(name)}/releases?per_page=100&page={p}", required=p == 1
                )
                for p in range(1, self.PAGES + 1)
            ),
            GitHub.api(f"repos/{GitHub.q(name)}/commits/{GitHub.q(version)}", required=False),
        )

    @staticmethod
    def facts(repository: Any) -> tuple[dict[str, Any], datetime | None, str]:
        if not isinstance(repository, dict):
            return {}, None, ""
        description = repository.get("description")
        return (
            {
                "has_repository": True,
                "description_length": len(description) if isinstance(description, str) else 0,
            },
            GitHub.when(repository.get("created_at")),
            "archived" if repository.get("archived") else "",
        )

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        facts, created, archived = self.facts(documents.get(self.repository(name).url))
        releases: list[Release] = []
        for url, page in documents.items():
            if "/releases?" not in url or not isinstance(page, list):
                continue
            for item in page:
                stamp = GitHub.when(item.get("published_at")) if isinstance(item, dict) else None
                if stamp is None or item.get("draft"):
                    continue
                author = item.get("author") if isinstance(item.get("author"), dict) else {}
                releases.append(
                    Release(
                        str(item.get("tag_name") or ""),
                        stamp,
                        str(author.get("login") or ""),
                        archived,
                    )
                )
        tags = {r.version for r in releases}
        wanted = next(
            (t for t in (version, f"v{version}", version.removeprefix("v")) if t in tags), None
        )
        if wanted is None:
            # A tag with no release: dated by its commit, the one release the record can then place.
            commit = documents.get(
                f"{GitHub.API}/repos/{GitHub.q(name)}/commits/{GitHub.q(version)}"
            )
            _, stamp, who = (
                GitHub.commit_fact(commit) if isinstance(commit, dict) else ("", None, "")
            )
            if stamp is None:
                return None
            releases.append(Release(version, stamp, who, archived))
            wanted = version
        record = RecordBuilder.from_history(self, name, wanted, releases, created=created, **facts)
        return _Rename.to(record, version)


class ActionsSource(RepositorySource):
    """A GitHub Action, `owner/repo` (an action in a subfolder is its repository's): its releases."""

    ecosystem: ClassVar[str] = "actions"

    def repository(self, name: str) -> Document:
        return GitHub.api(f"repos/{GitHub.q('/'.join(name.split('/')[:2]))}")

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        return super().documents("/".join(name.split("/")[:2]), version)

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        record = super().record("/".join(name.split("/")[:2]), version, documents)
        return _Rename.name(record, name)


class SwiftSource(RepositorySource):
    """A Swift package resolved from its repository, `owner/repo`: its releases, a tag with or without its `v`."""

    ecosystem: ClassVar[str] = "swift"


class NixSource(RecordSource):
    """A Nix input pinned at a commit of `owner/repo`: the commit and the ones before it; the repository's answer."""

    ecosystem: ClassVar[str] = "nix"
    publisher_kind: ClassVar[PublisherKind] = "committer"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        return (
            GitHub.api(f"repos/{GitHub.q(name)}"),
            GitHub.api(f"repos/{GitHub.q(name)}/commits?sha={GitHub.q(version)}&per_page=100"),
        )

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        facts, created, archived = RepositorySource.facts(
            documents.get(f"{GitHub.API}/repos/{GitHub.q(name)}")
        )
        releases = []
        for commit in GitHub.commits(documents, f"{GitHub.API}/repos/{GitHub.q(name)}/commits"):
            _, stamp, who = GitHub.commit_fact(commit)
            sha = str(commit.get("sha") or "")
            if stamp is not None and sha:
                releases.append(Release(sha, stamp, who, archived))
        match = next((r.version for r in releases if r.version.startswith(version.lower())), None)
        if match is None or len(version) < 7:
            return None
        record = RecordBuilder.from_history(self, name, match, releases, created=created, **facts)
        return _Rename.to(record, version)


class _Sort:
    @staticmethod
    def key(compare: Any) -> Any:
        import functools

        return functools.cmp_to_key(compare)


class _Rename:
    """A record asked for under one spelling and found under another (`5.8.1` as the tag `v5.8.1`)."""

    @staticmethod
    def to(record: RegistryRecord | None, version: str) -> RegistryRecord | None:
        from dataclasses import replace

        return replace(record, version=version) if record is not None else None

    @staticmethod
    def name(record: RegistryRecord | None, name: str) -> RegistryRecord | None:
        from dataclasses import replace

        return replace(record, name=name) if record is not None else None


SOURCES: tuple[RecordSource, ...] = (
    BazelSource(),
    JuliaSource(),
    VcpkgSource(),
    OpamSource(),
    ConanSource(),
    HomebrewSource(),
    ActionsSource(),
    SwiftSource(),
    NixSource(),
)
