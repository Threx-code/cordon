"""Inferring the upstream a package was built from: from the URLs its metadata names, and from the
tags of the repository they point to.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import TYPE_CHECKING

from cordon_scanner.intel.advisories.upstream.base import (
    Archive,
    RegistryArchive,
    RepositoryArchive,
    Unnamed,
    Upstream,
)
from cordon_scanner.intel.advisories.upstream.tags import ContentProof, Conventions, TagInference

if TYPE_CHECKING:
    from collections.abc import Iterable


class Inference:
    """Infers a package's upstream release."""

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


__all__ = ["Inference"]
