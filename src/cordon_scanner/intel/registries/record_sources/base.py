"""The shared interface of the registry record: one `RecordSource` per ecosystem, the same shape for every registry.

A registry's record (`RegistryRecord`: who published a release, when the name and the release appeared, what came before,
whether it was withdrawn) is read from documents a registry serves. What differs between registries is where those
documents are and what they say; what is the same is the record that comes out and how a record is built from a release's
history. So an ecosystem supplies exactly two things:

* `documents(name, version)`: the documents to fetch, as `Document`s (an https URL, and whether it is JSON or text, and
  whether the record needs it);
* `record(name, version, documents)`: the record, from those documents, as of `version`'s publish time. Pure: no network,
  no clock, no file. The same documents give the same record.

and `RecordBuilder.from_history` turns a release history (`ReleaseHistory`) into the record's counts, so no parser repeats
the arithmetic. `RecordFetch.documents` fetches through the registry client's bounded, https-only, redirect-free reader.

A registry that is a git repository (the Bazel Central Registry, Julia's General, opam-repository, vcpkg, ...) is read the
same way: its `Document`s are raw files (`raw.githubusercontent.com/<owner>/<repo>/<ref>/<path>`), so no clone and no API
limit; the commit dates that only the host's API gives are added when a token is configured (`Document.needs_token`).

What a record says about WHO published is stated by `publisher_kind`: `account` (the registry names the publishing account),
`namespace` (it names the namespace's owner, not the account), `committer` (a git-hosted registry: the committer of the
commit that added the release) or `none` (the registry says nothing). A release's withdrawal (`withdrawn`) is the registry's
own word for it: `yanked`, `retracted`, `deprecated`, `unlisted`, `archived`, or `""`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, ClassVar, Literal

if TYPE_CHECKING:
    from cordon_scanner.intel.registries.registry_record import RegistryRecord

PublisherKind = Literal["account", "namespace", "committer", "none"]


@dataclass(frozen=True)
class Document:
    """One document a record is read from."""

    url: str
    """An https URL; the fetcher refuses anything else."""
    kind: Literal["json", "text"] = "json"
    required: bool = True
    """A record is not made without a required document; an optional one that is missing is passed as None."""
    needs_token: bool = False
    """A document only the host's authenticated API serves (a commit date): fetched only when a token is configured."""


@dataclass(frozen=True)
class Release:
    """One release in a name's history, as the registry states it."""

    version: str
    published: datetime
    publisher: str = ""
    withdrawn: str = ""


class RecordSource(ABC):
    """What an ecosystem supplies to make its registry record."""

    ecosystem: ClassVar[str]
    publisher_kind: ClassVar[PublisherKind]

    @abstractmethod
    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        """The documents the record of `name` at `version` is read from."""

    @abstractmethod
    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        """The record as of `version`'s publish time, or None when `version` is not among the name's releases.
        `documents` maps each `Document.url` to its parsed JSON or its text; a missing optional one is None."""


class RecordBuilder:
    """The record's counts, from a release history: shared, so each parser extracts raw facts and nothing else."""

    @staticmethod
    def from_history(
        source: RecordSource,
        name: str,
        version: str,
        releases: list[Release],
        *,
        created: datetime | None = None,
        **facts: Any,
    ) -> RegistryRecord | None:
        """The record of `version` among `releases` (all of the name's releases, in any order), or None when it is not one of them.
        `created` is when the name itself first appeared where the registry states it; else the first release's time.
        `facts` are the record's other fields (maintainers, hooks, has_repository, ...)."""
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        this = next((r for r in releases if r.version == version), None)
        if this is None:
            return None
        earlier = sorted(
            (r for r in releases if r.published < this.published and r.version != version),
            key=lambda r: r.published,
        )
        first = earlier[0].published if earlier else this.published
        return RegistryRecord(
            ecosystem=source.ecosystem,
            name=name,
            version=version,
            published=RegistryRecord._iso(this.published),
            created=RegistryRecord._iso(min(created, first) if created else first),
            prior_versions=len(earlier),
            prior_24h=sum(
                1 for r in earlier if this.published - r.published <= timedelta(hours=24)
            ),
            previous_version=earlier[-1].version if earlier else "",
            publisher=this.publisher,
            prior_publishers=tuple(sorted({r.publisher for r in earlier if r.publisher})),
            withdrawn=this.withdrawn,
            publisher_kind=source.publisher_kind,
            **facts,
        )


class RecordFetch:
    """Fetching a source's documents: https only, bounded, no redirect, and the registry client's own readers."""

    MAX_DOCUMENTS: ClassVar[int] = 8

    @classmethod
    def documents(
        cls, source: RecordSource, name: str, version: str, *, token: str | None = None
    ) -> dict[str, Any] | None:
        """The documents by URL, or None when a required one is missing (the registry does not hold the name)."""
        from cordon_scanner.intel.registries.registry_client import RegistryClient
        from cordon_scanner.intel.registries.registry_http import RegistryHttp
        from cordon_scanner.intel.registries.registry_request import PackageNotFound

        wanted = source.documents(name, version)
        if len(wanted) > cls.MAX_DOCUMENTS:
            raise ValueError(f"a record is read from at most {cls.MAX_DOCUMENTS} documents")
        found: dict[str, Any] = {}
        for document in wanted:
            if document.needs_token and not token:
                found[document.url] = None
                continue
            try:
                found[document.url] = (
                    RegistryClient._fetch(document.url)
                    if document.kind == "json"
                    else RegistryHttp.text(document.url)
                )
            except PackageNotFound:
                if document.required:
                    return None
                found[document.url] = None
        return found
