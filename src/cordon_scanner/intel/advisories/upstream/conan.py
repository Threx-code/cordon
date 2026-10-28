"""Conan Center: the recipe a package was built from, and the upstream it names."""

from __future__ import annotations

import contextlib
import http.client
import re
import urllib.parse
from typing import ClassVar

from cordon_scanner.intel.advisories.upstream.base import (
    Archive,
    RepositoryArchive,
    Unnamed,
    Upstream,
)
from cordon_scanner.intel.advisories.upstream.fetch import Fetch
from cordon_scanner.intel.advisories.upstream.inference import Inference


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
        return Inference.from_urls(urls, how)

    _index: ClassVar[dict[str, dict[str, object] | None]] = {}

    @staticmethod
    def index(name: str) -> dict[str, object] | None:
        """`version -> source` from the package's current recipe in conan-center-index, across
        all its recipe folders; None when the index cannot be read."""
        if name in ConanCenter._index:
            return ConanCenter._index[name]
        from cordon_scanner.foundation.formats.datayaml import DataYaml

        package = urllib.parse.quote(name, safe="")
        found: dict[str, object] | None = {}
        try:
            config = DataYaml.load(Fetch.get(f"{ConanCenter.INDEX}/{package}/config.yml").decode())
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
                        recipe = Fetch.get(
                            f"{ConanCenter.INDEX}/{package}/{folder}/conanfile.py"
                        ).decode("utf-8", "replace")
                        page = re.search(
                            r"""^\s*homepage\s*=\s*["']([^"']+)["']""", recipe, re.MULTILINE
                        )
                        ConanCenter._homepages[name] = page.group(1) if page else ""
                data = DataYaml.load(
                    Fetch.get(f"{ConanCenter.INDEX}/{package}/{folder}/conandata.yml").decode()
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
            return Inference.inferred(
                ConanCenter.exact(urls, how), homes, version, (name,), how, pinned
            )
        if len(repositories) != 1:
            return Unnamed(
                "Conan Center no longer serves this version, and its current recipe names "
                + ("no repository" if not repositories else "more than one repository")
            )
        return Inference.inferred(
            Unnamed("Conan Center no longer serves this version"),
            homes,
            version,
            (name,),
            f"the repository Conan Center's current {name} recipe names",
        )


__all__ = ["ConanCenter"]
