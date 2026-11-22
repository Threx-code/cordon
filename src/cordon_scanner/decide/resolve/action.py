"""BP-3-5: a CI action's artifact is the commit its reference points at, resolved through the SCM API.

`uses: actions/checkout@v4` names a tag, and a tag can be moved. The artifact a decision binds to is the commit the tag points at now
(`ArtifactDigests.of_git_commit`), so a moved tag is a new artifact with no decision yet, never the old one's. A reference already
written as a full commit id needs no call: it is its own commit. Anything else (a tag, a branch, an abbreviated id) is asked of the
SCM API, which answers with the commit; if it cannot be asked the name is `unresolved` (`source_unreachable`), and `decide()` fails
closed on that (`R203`).

`GitHubScm` is the SCM API over an injected `fetch(url, headers) -> (status, body)`, so no network is needed to run it; the
caller supplies the HTTP call (and a token where one is wanted).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import ClassVar, Final, NamedTuple, Protocol

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.contracts.subjects import CanonicalIds, InvalidSubject, SubjectKind
from cordon_scanner.decide.resolve.resolution import NotFound, Resolution, SourceUnavailable

HEX: Final = frozenset("0123456789abcdef")


class ScmApi(Protocol):
    def commit_of(self, owner: str, repo: str, ref: str) -> str:
        """The commit id `ref` (a tag, a branch or an abbreviated id) points at.

        Raises `NotFound` when there is no such ref and `SourceUnavailable` when the API could not be asked."""


class ActionRef(NamedTuple):
    owner: str
    repo: str
    path: str
    ref: str


class ActionResolver:
    @staticmethod
    def parse(uses: str) -> ActionRef | None:
        """`owner/repo[/path]@ref` as its parts, or None for anything else (a local `./x`, `docker://image`, no `@ref`)."""
        text = uses.strip()
        if not text or text.startswith(("./", "../", "/", "docker://")) or text.count("@") != 1:
            return None
        where, _, ref = text.partition("@")
        pieces = where.split("/")
        if len(pieces) < 2 or not ref or any(not piece or piece in (".", "..") for piece in pieces):
            return None
        if any(char.isspace() for char in text):
            return None
        return ActionRef(pieces[0], pieces[1], "/".join(pieces[2:]), ref)

    @staticmethod
    def is_commit(ref: str) -> bool:
        """Whether `ref` is a full commit id (40 or 64 hex digits, any case)."""
        return len(ref) in (40, 64) and set(ref.lower()) <= HEX

    @classmethod
    def resolve(cls, uses: str, scm: ScmApi) -> Resolution:
        """`uses` as (subject, ref, commit digest), or why not."""
        parsed = cls.parse(uses)
        if parsed is None:
            reason = "local_action" if uses.strip().startswith(("./", "../")) else "unparseable"
            if uses.strip().startswith("docker://"):
                reason = "not_a_registry_package"
            return Resolution.failed(
                SubjectKind.CI_ACTION.value, Resolution.stand_in("ci", uses), reason
            )
        try:
            subject = CanonicalIds.canonical_id(
                SubjectKind.CI_ACTION,
                {
                    "host": "github",
                    "owner": parsed.owner,
                    "repo": parsed.repo,
                    **({"path": parsed.path} if parsed.path else {}),
                },
            )
        except InvalidSubject:
            return Resolution.failed(
                SubjectKind.CI_ACTION.value, Resolution.stand_in("ci", uses), "unparseable"
            )
        kind = SubjectKind.CI_ACTION.value
        if cls.is_commit(parsed.ref):
            commit = parsed.ref.lower()
            return Resolution(
                kind=kind,
                subject_id=subject,
                status="resolved",
                digest=ArtifactDigests.of_git_commit(commit),
                commit=commit,
            )
        try:
            commit = scm.commit_of(parsed.owner, parsed.repo, parsed.ref).strip().lower()
            digest = ArtifactDigests.of_git_commit(commit)
        except SourceUnavailable:
            return Resolution.failed(kind, subject, "source_unreachable", version=parsed.ref)
        except NotFound:
            return Resolution.failed(kind, subject, "not_found", version=parsed.ref)
        except ValueError:  # an answer that is not a commit id is no answer
            return Resolution.failed(kind, subject, "source_unreachable", version=parsed.ref)
        return Resolution(
            kind=kind,
            subject_id=subject,
            status="resolved",
            version=parsed.ref,
            digest=digest,
            commit=commit,
        )


class GitHubScm:
    """The GitHub REST API as an `ScmApi`: `GET /repos/{owner}/{repo}/commits/{ref}` with the `sha` media type answers with the
    commit id alone, for a tag (annotated ones followed to their commit), a branch or an abbreviated id."""

    API: ClassVar[str] = "https://api.github.com"

    def __init__(self, fetch: Callable[[str, dict[str, str]], tuple[int, bytes]]) -> None:
        self._fetch = fetch

    def commit_of(self, owner: str, repo: str, ref: str) -> str:
        url = f"{self.API}/repos/{owner}/{repo}/commits/{ref}"
        try:
            status, body = self._fetch(
                url,
                {
                    "Accept": "application/vnd.github.sha",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
        except Exception as problem:
            raise SourceUnavailable(str(problem)) from problem
        if status in (404, 422):
            raise NotFound(ref)
        if status != 200:
            raise SourceUnavailable(f"the API answered {status}")
        return body.decode("ascii", errors="replace").strip()


__all__ = ["ActionRef", "ActionResolver", "GitHubScm", "ScmApi"]
