"""Known vulnerabilities from NVD, for packages no other source names: what the ecosystems with no
advisory feed of their own -- Homebrew's formulae and casks, vcpkg, Conan, conda, CocoaPods -- are
checked against once the exact route (`intel/upstream_advisories`) has found no repository, tag or
registry package to ask OSV about. SQLite's tarball, Lua's, a closed binary, a macOS application.

NVD keys its records by CPE (`cpe:2.3:a:<vendor>:<product>:...`), not by any ecosystem's package
names, so a package is first tied to a CPE product, in one of two ways:

- **curated** (`Confidence.HIGH`): a published, human-maintained mapping from a package name to its
  CPE, shipped as `nvd-cpe.json.gz`'s `curated` table per ecosystem. Empty unless a mapping whose
  terms allow redistribution has been added; the scan says which way each package was tied.
- **the guarded rule** (`Confidence.MEDIUM`, reported as inferred): NVD's own CPE dictionary lists,
  for each product, reference links -- its website, its repository, its advisories. A package is
  tied to a product only when BOTH the product's name, normalised, is the package's name (or one of
  the names its ecosystem gives it), AND one of the product's references is on the same site as the
  package's own homepage or download -- the same repository on a forge, the same registrable
  domain elsewhere. Exactly one product may pass; two is ambiguity, and nothing is matched.

Then NVD's own configuration ranges decide whether the version is affected -- `versionStart`/
`versionEnd`, inclusive or exclusive, or an exact version -- compared by Repology's libversion
(`intel/versions.LibVersion`), with the ecosystem's packaging revision left out.

The data is NVD's bulk feeds, built by `intel/nvd_import` on the same schedule and under the same
digest manifest as the OSV data: bundled filtered (high, critical, unrated, exploited), complete
after `cordon-scanner advisories sync`. Read offline; nothing here uses the network.
"""

from __future__ import annotations

import gzip
import json
import re
import urllib.parse
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.foundation.once import OneOff
from cordon_scanner.intel.advisories.advisories import DATA_DIR, Advisory, AdvisoryFiles
from cordon_scanner.intel.advisories.versions import LibVersion

if TYPE_CHECKING:
    from cordon_scanner.foundation.results import Dependency

CVES_NAME: Final = "nvd-cves.json.gz"
CPE_NAME: Final = "nvd-cpe.json.gz"
NVD_DETAIL: Final = "https://nvd.nist.gov/vuln/detail/"
#: The ecosystems this source is asked about: those no advisory feed covers by name.
ECOSYSTEMS: Final = frozenset({"homebrew", "vcpkg", "conan", "conda", "cocoapods"})


class CpeRule:
    """The guarded rule: a CPE product tied to a package by its name and its site together."""

    #: Forges, where the site is the repository (`github.com/<owner>/<repo>`), not the host.
    FORGES: ClassVar[frozenset[str]] = frozenset(
        {"github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "git.sr.ht", "launchpad.net"}
    )
    #: Second-level labels under a country code (`example.co.uk`).
    SECOND_LEVEL: ClassVar[frozenset[str]] = frozenset(
        {"co", "com", "org", "net", "ac", "gov", "edu"}
    )
    #: SourceForge's download hosts, where the project is in the path.
    SF_DOWNLOADS: ClassVar[frozenset[str]] = frozenset(
        {"downloads.sourceforge.net", "prdownloads.sourceforge.net", "download.sourceforge.net"}
    )

    @staticmethod
    def name(text: str) -> str:
        """A name compared by its letters and digits alone, in lower case."""
        return re.sub(r"[^a-z0-9]", "", text.lower())

    @staticmethod
    def site(url: str) -> str | None:
        """The site a URL belongs to: a forge repository, a SourceForge project, a `*.github.io`
        page, or the registrable domain."""
        try:
            parts = urllib.parse.urlsplit(url.strip())
        except ValueError:
            return None
        host = (parts.hostname or "").lower().removeprefix("www.")
        if not host or "." not in host:
            return None
        path = [p for p in parts.path.split("/") if p]
        if host in CpeRule.FORGES:
            if len(path) < 2:
                return None
            return f"{host}/{path[0].lower()}/{path[1].lower().removesuffix('.git')}"
        if host.endswith(".github.io"):
            return host
        if host in CpeRule.SF_DOWNLOADS or host.endswith(".dl.sourceforge.net"):
            # `downloads.sourceforge.net/project/<name>/...` or the short `/<name>/...`.
            if len(path) >= 2 and path[0] in ("project", "projects"):
                return f"sourceforge.net/{path[1].lower()}"
            return f"sourceforge.net/{path[0].lower()}" if path else None
        if host == "sourceforge.net" and len(path) >= 2 and path[0] in ("projects", "project", "p"):
            return f"sourceforge.net/{path[1].lower()}"
        project = re.fullmatch(r"([\w-]+)\.(?:sourceforge\.net|sf\.net|sourceforge\.io)", host)
        if project:
            return f"sourceforge.net/{project.group(1)}"
        labels = host.split(".")
        count = (
            3
            if len(labels) >= 3 and labels[-2] in CpeRule.SECOND_LEVEL and len(labels[-1]) == 2
            else 2
        )
        return ".".join(labels[-count:])

    @staticmethod
    def match(
        index: Mapping[str, Sequence[Sequence[Any]]], names: Iterable[str], urls: Iterable[str]
    ) -> tuple[str | None, str]:
        """`(product, why)`: the one CPE product whose name is one of `names` and which has a
        reference on the site of one of `urls`; None, and why not, otherwise."""
        sites = {s for s in (CpeRule.site(u) for u in urls if u) if s}
        if not sites:
            return None, "no homepage or download to tie it to a CPE product by"
        found: dict[str, set[str]] = {}
        # A packager's trailing major version (vcpkg's and Conan's `sqlite3`, `gtk3`) is the same
        # name: still under the site guard, and still only one product may pass.
        wanted_names = {CpeRule.name(n) for n in names if n}
        wanted_names |= {re.sub(r"(?<=[a-z])\d$", "", n) for n in wanted_names}
        # A library's `lib` is the packager's or NVD's spelling, not a different name (Conan's
        # expat is NVD's libexpat).
        wanted_names |= {n.removeprefix("lib") for n in wanted_names if n.startswith("lib")}
        wanted_names |= {f"lib{n}" for n in wanted_names if not n.startswith("lib")}
        # And a packager's `utils` or `tools` (Conan's xz_utils is NVD's xz).
        wanted_names |= {re.sub(r"(?:utils|tools)$", "", n) for n in wanted_names} - {""}
        # And JavaScript's `.js` (Homebrew's node is NVD's nodejs:node.js).
        wanted_names |= {f"{n}js" for n in wanted_names if n and not n.endswith("js")}
        for wanted in wanted_names:
            for product, references in index.get(wanted, ()):
                shared = sites & set(references)
                if shared:
                    found[str(product)] = shared
        # A packager's `<vendor>_<product>` (Conan's nlohmann_json is NVD's nlohmann:json): the rest
        # of the name, only for a product of that very vendor, and still under the site guard.
        for raw in names:
            vendor, _, rest = re.sub(r"[-_.]", "_", raw.lower()).partition("_")
            for product, references in index.get(CpeRule.name(rest), ()) if rest else ():
                if CpeRule.name(str(product).split(":", 1)[0]) == CpeRule.name(vendor):
                    shared = sites & set(references)
                    if shared:
                        found[str(product)] = shared
        if not found:
            return CpeRule.by_project_site(index, sites)
        common = set.intersection(*found.values())
        # Several CPE names with the package's name on one of its sites are NVD's duplicates of one
        # product, whatever vendor each was filed under: poco is both macchina:poco and
        # pocoproject:poco on github.com/pocoproject/poco; curl is curl:curl, haxx:curl and
        # daniel_stenberg:curl on haxx.se. Products with no site of the package's in common are
        # different products, and no tie.
        if not common:
            return (
                None,
                f"more than one CPE product has its name and its site ({', '.join(sorted(found))})",
            )
        site = min(common)
        return " ".join(
            sorted(found)
        ), f"NVD's {', '.join(sorted(found))} has its name and lists its site, {site}"

    ARCHIVE: ClassVar[re.Pattern[str]] = re.compile(
        r"\.(?:tar\.gz|tgz|tar\.bz2|tbz2?|tar\.xz|txz|tar\.zst|tar\.lz|tar|zip|7z)$", re.IGNORECASE
    )

    @staticmethod
    def release_names(urls: Iterable[str], version: str) -> tuple[str, ...]:
        """The names an upstream gives its release files, `<name>-<version>.<archive>`, for the
        locked version: Conan's libmp3lame downloads `lame-3.100.tar.gz`, Homebrew's curl-openssl
        `curl-7.68.0.tar.bz2`. A file named for another version names nothing."""
        release = re.sub(r"(?:_\d+|#\d+|,.*)$", "", version)
        if not release:
            return ()
        found: list[str] = []
        for url in urls:
            base = urllib.parse.unquote(urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1])
            stem = CpeRule.ARCHIVE.sub("", base)
            if stem == base:
                continue
            named = re.fullmatch(
                rf"(.+?)[-_]v?{re.escape(release)}(?:[-_.]?src|[-_.]source)?", stem, re.IGNORECASE
            )
            if named and CpeRule.name(named.group(1)):
                found.append(named.group(1))
        return tuple(dict.fromkeys(found))

    _sites: ClassVar[list[tuple[Mapping[str, Sequence[Sequence[Any]]], dict[str, set[str]]]]] = []

    @staticmethod
    def project(site: str) -> bool:
        """A site that is one project's alone: a forge repository, a SourceForge project, a
        `*.github.io` page -- never a domain, which hosts a vendor's many products."""
        return "/" in site or site.endswith(".github.io")

    @staticmethod
    def by_project_site(
        index: Mapping[str, Sequence[Sequence[Any]]], sites: set[str]
    ) -> tuple[str | None, str]:
        """When no product has the package's name: the one CPE product that lists the package's
        own project site (Conan's libmp3lame downloads from sourceforge.net/projects/lame, which
        NVD's lame_project:lame alone lists). Two products listing it (curl and libcurl, one
        repository) are not told apart, and are no tie."""
        if not CpeRule._sites or CpeRule._sites[0][0] is not index:
            reverse: dict[str, set[str]] = defaultdict(set)
            for entries in index.values():
                for product, references in entries:
                    for site in references:
                        if CpeRule.project(site):
                            reverse[site].add(str(product))
            CpeRule._sites[:] = [(index, dict(reverse))]
        reverse = CpeRule._sites[0][1]
        found = {
            (site, product)
            for site in sites
            if CpeRule.project(site)
            for product in reverse.get(site, ())
        }
        products = {product for _, product in found}
        if len(products) == 1:
            site, product = min(found)
            return product, f"NVD's {product} alone lists its project's site, {site}"
        names = sorted((CpeRule.name(p.split(":", 1)[1]) for p in products), key=len)
        if (
            len(products) > 1
            and len({product.split(":", 1)[0] for product in products}) == 1
            # One project's names: the shortest within every other (curl in libcurl), not two
            # products the vendor keeps on one site (Tcl and Tk share sourceforge.net/tcl).
            and all(names[0] in other for other in names[1:])
        ):
            # One vendor's names for its one project (nlohmann:json and
            # nlohmann:json-for-modern-cpp, haxx:curl and haxx:libcurl): its products together.
            site = min(site for site, _ in found)
            joined = ", ".join(sorted(products))
            return " ".join(
                sorted(products)
            ), f"NVD's {joined}, one vendor's, alone list its project's site, {site}"
        if len(products) > 1:
            return (
                None,
                f"its project's site is listed by more than one CPE product ({', '.join(sorted(products))})",
            )
        return None, "no CPE product in NVD has its name and its site"


@dataclass
class NvdResult:
    checked: set[str] = field(default_factory=set)
    advisories: dict[str, tuple[Advisory, ...]] = field(default_factory=dict)
    unchecked: dict[str, str] = field(default_factory=dict)
    tied: dict[str, str] = field(default_factory=dict)
    """How each checked package was tied to its CPE product, for the report."""


class NvdData:
    """The two bundled files, read once, from the synced copy when this install wrote it and it is
    newer, else the wheel's -- each checked against its root's digest manifest first."""

    @staticmethod
    def _path(name: str) -> Path | None:
        best: tuple[float, Path] | None = None
        for root in (AdvisoryFiles.user_sync_dir(), DATA_DIR):
            path = root / name
            if root != DATA_DIR and path.exists() and AdvisoryFiles.trusted_user_file(name) is None:
                continue
            try:
                mtime = path.stat().st_mtime
            except OSError:
                continue
            if best is None or mtime > best[0]:
                best = (mtime, path)
        return best[1] if best else None

    @staticmethod
    @OneOff.cache
    def load(name: str) -> dict[str, Any]:
        path = NvdData._path(name)
        if path is None:
            return {}
        recorded = AdvisoryFiles._digest_manifest(path.parent)
        try:
            if recorded and recorded.get(name) not in (None, AdvisoryFiles.digest_of(path)):
                return {}
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError, EOFError):
            return {}
        return data if isinstance(data, dict) else {}

    @staticmethod
    def reset() -> None:
        NvdData.load.cache_clear()


class NvdRange:
    """One NVD configuration range, applied to a package's version."""

    @staticmethod
    def release(version: str) -> str:
        """The upstream release a package version names: Homebrew's `_1` and vcpkg's `#2` are
        packaging revisions, not part of it, and a cask's `6.8.9,abc123` is its version and a
        build id."""
        return re.sub(r"(?:_\d+|#\d+)$", "", version.split(",", 1)[0])

    @staticmethod
    def affects(bounds: Mapping[str, str], version: str) -> bool:
        release = NvdRange.release(version)
        if "v" in bounds:
            return LibVersion.compare(release, bounds["v"] + bounds.get("u", "")) == 0
        allowed: dict[str, tuple[int, ...]] = {
            "versionStartIncluding": (0, 1),
            "versionStartExcluding": (1,),
            "versionEndIncluding": (-1, 0),
            "versionEndExcluding": (-1,),
        }
        return all(
            LibVersion.compare(release, bounds[key]) in outcomes
            for key, outcomes in allowed.items()
            if key in bounds
        )


class NvdAdvisories:
    """Checking packages against NVD once each is tied to a CPE product."""

    @staticmethod
    def names(dependency: Dependency) -> tuple[str, str]:
        """`(curated table, name)`: a cask is not the formula of the same name (Homebrew's
        `docker` formula is the CLI; its `docker` cask is Docker Desktop)."""
        table = (
            "homebrew-cask"
            if dependency.ecosystem == "homebrew" and "cask" in dependency.platform
            else str(dependency.ecosystem)
        )
        return table, dependency.name.split("/")[-1]

    @staticmethod
    def check(
        dependencies: Iterable[Dependency],
        homes: Mapping[str, Sequence[str]] | None = None,
        versions: Mapping[str, str] | None = None,
    ) -> NvdResult:
        result = NvdResult()
        cves = NvdData.load(CVES_NAME)
        mapping = NvdData.load(CPE_NAME)
        if not cves or not mapping:
            for dependency in dependencies:
                result.unchecked[dependency.purl] = (
                    "NVD's data is not installed (cordon-scanner advisories sync fetches it)"
                )
            return result
        products: Mapping[str, list[list[Any]]] = cves.get("products") or {}
        text: Mapping[str, str] = cves.get("text") or {}
        curated: Mapping[str, Mapping[str, list[str]]] = mapping.get("curated") or {}
        index: Mapping[str, list[list[Any]]] = mapping.get("index") or {}
        for dependency in dependencies:
            # The lockfile's version, or the release the upstream route resolved (a vcpkg port
            # at its baseline).
            version = dependency.version or (versions or {}).get(dependency.purl, "")
            if not version:
                result.unchecked[dependency.purl] = "no version is locked"
                continue
            table, name = NvdAdvisories.names(dependency)
            chosen = list(curated.get(table, {}).get(name, ()))
            if chosen:
                through, tied = "nvd", f"the curated CPE {', '.join(chosen)}"
            else:
                urls = (homes or {}).get(dependency.purl, ())
                names = (name, *CpeRule.release_names(urls, version))
                product, why = CpeRule.match(index, names, urls)
                if product is None:
                    result.unchecked[dependency.purl] = why
                    continue
                chosen, through, tied = product.split(), "nvd-inferred", why
            found: list[Advisory] = []
            for product in chosen:
                for identifier, severity, bounds in products.get(product, ()):
                    if not NvdRange.affects(bounds, version):
                        continue
                    found.append(
                        Advisory(
                            ecosystem=str(dependency.ecosystem),
                            name=dependency.name,
                            versions=(version,) if "v" in bounds else (),
                            summary=(
                                text.get(identifier, "")
                                + (
                                    f" (matched through NVD: {tied})"
                                    if through == "nvd-inferred"
                                    else ""
                                )
                            ).strip(),
                            reference=NVD_DETAIL + identifier,
                            identifier=identifier,
                            severity=severity,
                            aliases=(identifier,),
                            introduced=bounds.get("versionStartIncluding")
                            or bounds.get("versionStartExcluding"),
                            fixed=bounds.get("versionEndExcluding"),
                            last_affected=bounds.get("versionEndIncluding"),
                            matched_through=through,
                        )
                    )
            result.checked.add(dependency.purl)
            result.tied[dependency.purl] = tied
            if found:
                unique = {a.identifier: a for a in found}
                result.advisories[dependency.purl] = tuple(unique.values())
        return result


__all__ = ["CpeRule", "NvdAdvisories", "NvdData", "NvdRange", "NvdResult"]
