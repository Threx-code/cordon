#!/usr/bin/env python3
"""Refresh the shipped allowlist of established package names.

A MAINTENANCE script. It is never imported by the scanner and never runs during
a scan: cordon makes no network calls while scanning, because a tool that asks a
registry about the code in front of it is doing a version of the thing it warns
about. This runs deliberately, by a maintainer or on a schedule, and its output
is a reviewed artefact that ships with the release -- the same arrangement the
advisory database already has.

    python3 scripts/refresh/refresh_package_intel.py            # every ecosystem
    python3 scripts/refresh/refresh_package_intel.py --only pypi npm
    python3 scripts/refresh/refresh_package_intel.py --check     # fail if stale, write nothing

## What goes in the file, and what must not

The allowlist answers one question: is this name an established package. It is
what stops `SUSPECT.DEPENDENCY.TYPOSQUAT.001` accusing a real maintainer, and
growing it can only remove false accusations -- a name known to be established is
never reported as a squat of anything.

That one-directional property is exactly why the contents have to be chosen
carefully, and why this is NOT a dump of every published name. Registries contain
the squats. `lodahs` is very likely a registered npm package; so are thousands of
names registered to catch a slip. An allowlist of everything that exists would
turn the typosquat rule off completely while looking in every way like an
improvement, and nobody would notice until a squat shipped.

So two filters, and the second is the one that makes a list this size safe:

1. A download threshold per ecosystem. A squat registered to catch typos does not
   accumulate millions of installs; an established package does.

2. A name is refused if it is a high-confidence slip of a MORE popular name in
   the same fetch -- a transposition, a doubled character, a separator variant or
   an ASCII homoglyph. Those four are the kinds the detector treats as
   deliberate, and a name of that shape must never be able to allowlist itself
   into silence, whatever its download count says. Adjacent-key and
   insertion-shaped neighbours are kept, because that is where real packages live
   and suppressing them is the entire purpose of this file.

## Sources

Each ecosystem records where its names came from, in the file header, because a
security artefact whose provenance is not written down is not reviewable.

Every supported ecosystem is covered, in one of two ways. A registry that publishes
a popularity signal of its own (downloads, installs, stars, importers) is ranked by
it and written to `<ecosystem>.txt`, an allowlist. A registry that publishes none
-- Maven Central, CocoaPods, conda-forge, opam, vcpkg, Conan Center, the Bazel
Central Registry, nixpkgs, the Swift Package Index -- is never pretended ranked: its
whole index is sampled, every Nth name in the registry's own order, into
`<ecosystem>.index.txt`, which nothing loads as an allowlist.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import datetime as dt
import gzip
import io
import json
import os
import re
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar, cast

ROOT = next(
    (p for p in (Path.cwd(), *Path.cwd().parents) if (p / "src" / "cordon_scanner").is_dir()), None
) or sys.exit("run this from inside the Cordon repository")
DATA = ROOT / "src" / "cordon_scanner" / "intel" / "data"
#: A generic agent on purpose: a registry's access log must not learn who is asking, or about which repository.
USER_AGENT = "Mozilla/5.0"
TIMEOUT = 30

#: Statuses that mean "not now" rather than "not ever", so a request carrying
#: one is worth repeating. 429 is the one that matters here -- pub.dev serves it
#: after roughly twenty requests in quick succession -- and the 5xx entries cover
#: a registry having a bad minute.
RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})

#: What pub.dev answers for a page beyond the last one, instead of an empty
#: result list. Named because a bare 400 in a pagination loop reads like a
#: malformed request rather than like the end of the data.
HTTP_PAST_LAST_PAGE = 400

#: Attempts per request against a rate-limiting host, and the growth of the wait
#: between them. Sized from a measurement rather than a guess: pub.dev sends no
#: `Retry-After` and no rate-limit headers -- a bare Google edge 429 -- and once
#: tripped it went on refusing for 200 seconds. Doubling from two and capped at
#: a minute, nine attempts wait 242 seconds in total, which clears that.
#: A budget in seconds would have given up while the host was merely throttling,
#: which is the failure this is here to prevent.
RETRIES = 9
BACKOFF = 2.0
MAX_BACKOFF = 60.0

#: Seconds between consecutive requests to a host that rate-limits. Unpaced,
#: pub.dev starts refusing at about the twentieth request in a burst, and the
#: refusal outlasts the burst by minutes -- so the cheapest fix is not to trip it.
#: This does not replace the retry; it makes the retry rare.
PACE = 1.5

#: Seconds between searches of GitHub, which allows an unauthenticated client ten a minute.
SEARCH_PACE = 7.0

#: Seconds between files of a static CDN, which does not rate-limit but is still not hammered.
CDN_PACE = 0.05

#: How many names an unranked registry's index file holds: every Nth name, N = ceil(size / this).
INDEX_TARGET = 1_000


class SourceUnavailable(RuntimeError):
    """A source was still refusing to answer after every retry.

    Distinct from an exhausted result set, because `urlopen` reports both as
    `URLError` while they mean opposite things: one is the end of the data, the
    other is the data not being served. A paginating caller that treats them
    alike stops early under load and returns a fraction of the registry, which
    reads downstream as the registry having shrunk.
    """


class SourceShrank(RuntimeError):
    """A refreshed set lost more than `MAX_SHRINK` of the existing file.

    The signal that a source changed shape rather than that the registry lost
    packages. Raised by `write` and handled per ecosystem, so the existing file
    is kept and the other registries are still refreshed -- a shrink in one is
    not a reason to abandon the run.
    """


#: A refresh that loses more than this share of an ecosystem's names is treated
#: as a broken source rather than as news. A registry API that starts returning
#: an error page parses to zero names, and writing that out would empty the
#: allowlist and turn every established package back into a typosquat suspect.
MAX_SHRINK = 0.25


class PackageIntelRefresh:
    """Refreshing the established-package allowlists from the registries."""

    @staticmethod
    def fetch(url: str, *, timeout: int = TIMEOUT) -> bytes:
        """Fetch over https, and refuse anything else.

        Checked rather than assumed even though every URL here is a literal in this
        file. `urlopen` honours `file:`, `ftp:` and whatever else is registered, so a
        function that takes a URL and opens it is one edit away from reading a local
        path into the allowlist -- and the allowlist decides what this scanner stays
        quiet about. The guard costs one comparison and removes the whole class.
        """
        if not url.startswith("https://"):
            raise ValueError(f"refusing a non-https source: {url}")
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return bytes(response.read())

    @staticmethod
    def fetch_json(url: str, *, timeout: int = TIMEOUT) -> object:
        return json.loads(PackageIntelRefresh.fetch(url, timeout=timeout))

    @staticmethod
    def fetch_json_accepting_json(url: str, *, timeout: int = TIMEOUT) -> object:
        """`fetch_json` for a host that refuses the default Accept header.

        pub.dev answers 406 without it, which presents as the whole ecosystem being
        unavailable rather than as one header being wrong.
        """
        if not url.startswith("https://"):
            raise ValueError(f"refusing a non-https source: {url}")
        request = urllib.request.Request(  # noqa: S310
            url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return json.loads(response.read())

    @staticmethod
    def retry_delay(exc: urllib.error.HTTPError) -> float | None:
        """The delay a `Retry-After` header asks for, in seconds.

        Only the delta-seconds form is read. The HTTP-date form returns `None` and
        the caller's backoff covers it, which is the safe direction: waiting the
        computed backoff is never shorter than not waiting at all.
        """
        value = exc.headers.get("Retry-After") if exc.headers else None
        if not value:
            return None
        try:
            return max(0.0, float(value))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def fetch_json_retrying(
        url: str,
        *,
        timeout: int = TIMEOUT,
        fetcher: Callable[..., object] | None = None,
    ) -> object:
        """`fetcher`, against a host that rate-limits.

        Waits out a throttle rather than reporting it, and raises
        `SourceUnavailable` when the host is still refusing after `RETRIES`
        attempts. A status outside `RETRYABLE_STATUS` -- a 400 for a page past the
        end of a result set, say -- is raised immediately, because repeating a
        request the server has answered definitively only delays the answer.
        """
        # Resolved here rather than as a default argument: a default binds the
        # function object once, at import, which would make the choice of fetcher
        # unobservable to anything that replaces the name afterwards.
        fetcher = fetcher or PackageIntelRefresh.fetch_json_accepting_json
        last: Exception | None = None
        for attempt in range(RETRIES):
            try:
                return fetcher(url, timeout=timeout)
            except urllib.error.HTTPError as exc:
                with contextlib.suppress(Exception):  # the error is the response: close it
                    exc.close()
                if exc.code not in RETRYABLE_STATUS:
                    raise
                last = exc
                wait = PackageIntelRefresh.retry_delay(exc) or BACKOFF * (2**attempt)
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last = exc
                wait = BACKOFF * (2**attempt)
            if attempt < RETRIES - 1:
                time.sleep(min(wait, MAX_BACKOFF))
        raise SourceUnavailable(f"{url} still refusing after {RETRIES} attempts: {last}")

    @staticmethod
    def as_object(payload: object, url: str) -> dict[str, object]:
        """A JSON object, or a failure naming the source that did not return one.

        Not `assert`: a registry that starts serving an error page, an HTML redirect
        or a bare array is a broken source, and a broken source has to be reported as
        one. An assertion would read as a bug in this script, and under `-O` would not
        read as anything at all.
        """
        if not isinstance(payload, dict):
            raise ValueError(f"{url} returned {type(payload).__name__}, expected an object")
        return payload

    # ---------------------------------------------------------------------------
    # Per-ecosystem fetchers. Each returns (name, downloads) pairs.
    # ---------------------------------------------------------------------------

    @staticmethod
    def pypi() -> tuple[list[tuple[str, int]], str]:
        """PyPI, from the published top-packages dataset.

        Built from the public BigQuery download statistics PyPI itself exports. Used
        rather than scraped, because the numbers are the registry's own.
        """
        source = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
        payload = PackageIntelRefresh.as_object(PackageIntelRefresh.fetch_json(source), source)
        rows = payload.get("rows") or payload.get("data") or []
        out = [
            (str(row["project"]), int(row["download_count"]))
            for row in cast("list[Any]", rows)
            if isinstance(row, dict) and row.get("project")
        ]
        return out, source

    @staticmethod
    def npm() -> tuple[list[tuple[str, int]], str]:
        """npm, from the npm-high-impact dataset (ranked, maintained).

        npm has no "list everything by downloads" endpoint, and crawling the search
        API for the tens of thousands of established names does not fit a scheduled
        budget: the registry throttles a bulk crawl and the surviving count swings by
        tens of thousands of names between runs, which trips the shrink guard at
        random rather than on real change. So the ranked set is taken from
        `npm-high-impact`, which publishes the most downloaded and most
        depended-upon packages -- the same set a typosquat imitates and the same set
        a real maintainer's package must not be accused against, which is exactly
        what this allowlist is for.

        Rank is the signal; the dataset carries no per-package count, so the score is
        derived from position the way `pub_dev` derives it, which is all the
        threshold and the look-alike filter ask of it. Read from the jsdelivr CDN
        copy of the package's `lib/top.js`, an ESM module whose one export is an
        ordered array of names.
        """
        source = "https://cdn.jsdelivr.net/npm/npm-high-impact/lib/top.js"
        body = PackageIntelRefresh.fetch(source).decode("utf-8", "replace")
        # The module is `export const top = ["a", "b", ...]`. A package name cannot
        # contain a quote, so every quoted run in the file is a name -- extracting
        # them recovers the array without evaluating JavaScript, which is the one
        # thing this tool must never do to data it fetched.
        names = re.findall(r'"([^"\\]{1,214})"', body) + re.findall(r"'([^'\\]{1,214})'", body)
        scored: dict[str, int] = {}
        for rank, name in enumerate(names):
            # A plausible npm name only: scoped (`@scope/name`) or starting with an
            # alphanumeric. This drops the one degenerate real name (`-`) and, more
            # importantly, keeps a stray non-name string from ever entering the
            # allowlist if the module's shape changes -- extracting quoted runs is
            # robust to that only if what it extracts is then checked.
            if _PLAUSIBLE_NPM_NAME.match(name) and name not in scored:
                # Best (first) rank wins, highest-scored, so the look-alike filter --
                # which only compares two names' scores -- ranks the more popular one
                # above the squat.
                scored[name] = 1_000_000 - rank
        return sorted(scored.items()), f"{source} (npm-high-impact; score derived from rank)"

    @staticmethod
    def crates() -> tuple[list[tuple[str, int]], str]:
        """crates.io, downloads-sorted, paged."""
        source = "https://crates.io/api/v1/crates"
        out: list[tuple[str, int]] = []
        for page in range(1, 201):
            query = urllib.parse.urlencode({"page": page, "per_page": 100, "sort": "downloads"})
            payload = PackageIntelRefresh.as_object(
                PackageIntelRefresh.fetch_json(f"{source}?{query}"), source
            )
            items = payload.get("crates") or []
            if not items:
                break
            out.extend(
                (str(c["name"]), int(c.get("downloads") or 0))
                for c in cast("list[Any]", items)
                if c.get("name")
            )
        return out, source

    @staticmethod
    def nuget() -> tuple[list[tuple[str, int]], str]:
        """NuGet, from the search service, sorted by total downloads."""
        source = "https://azuresearch-usnc.nuget.org/query"
        out: list[tuple[str, int]] = []
        for skip in range(0, 6000, 1000):
            query = urllib.parse.urlencode(
                {"q": "", "take": 1000, "skip": skip, "sortBy": "totalDownloads-desc"}
            )
            payload = PackageIntelRefresh.as_object(
                PackageIntelRefresh.fetch_json(f"{source}?{query}", timeout=90), source
            )
            items = payload.get("data") or []
            if not items:
                break
            out.extend(
                (str(p["id"]), int(p.get("totalDownloads") or 0))
                for p in cast("list[Any]", items)
                if p.get("id")
            )
        return out, source

    @staticmethod
    def packagist() -> tuple[list[tuple[str, int]], str]:
        """Packagist, from its popularity listing."""
        source = "https://packagist.org/explore/popular.json"
        out: list[tuple[str, int]] = []
        for page in range(1, 61):
            payload = PackageIntelRefresh.as_object(
                PackageIntelRefresh.fetch_json(f"{source}?page={page}"), source
            )
            items = payload.get("packages") or []
            if not items:
                break
            out.extend(
                (str(p["name"]), int(p.get("downloads") or 0))
                for p in cast("list[Any]", items)
                if p.get("name")
            )
        return out, source

    @staticmethod
    def rubygems() -> tuple[list[tuple[str, int]], str]:
        """RubyGems, from its search API, which reports per-gem download totals.

        RubyGems publishes no ranked endpoint, so the spread of queries does the same
        job as in `npm`: breadth to find candidates, and the registry's own download
        count to decide which are established.

        Paced and retried for the same reason as `pub_dev`: a registry that answers
        one page with a 429 has not told this function that the gem list ended, and
        treating it as though it had quietly narrows what the typosquat rule will
        leave alone.
        """
        source = "https://rubygems.org/api/v1/search.json"
        terms = [
            *"abcdefghijklmnopqrstuvwxyz",
            "rails",
            "rack",
            "active",
            "test",
            "rspec",
            "json",
            "http",
            "aws",
            "api",
            "cli",
            "sql",
            "redis",
            "auth",
            "jwt",
            "mail",
            "log",
            "yaml",
            "parse",
            "config",
            "util",
            "middleware",
            "serializer",
            "migration",
        ]
        seen: dict[str, int] = {}
        for term in terms:
            for page in (1, 2, 3, 4):
                query = urllib.parse.urlencode({"query": term, "page": page})
                payload = PackageIntelRefresh.fetch_json_retrying(
                    f"{source}?{query}", fetcher=PackageIntelRefresh.fetch_json
                )
                time.sleep(PACE)
                if not isinstance(payload, list) or not payload:
                    break
                for gem in payload:
                    name = (gem or {}).get("name")
                    if name:
                        downloads = int((gem or {}).get("downloads") or 0)
                        seen[str(name)] = max(seen.get(str(name), 0), downloads)
        return sorted(seen.items()), source

    @staticmethod
    def cran() -> tuple[list[tuple[str, int]], str]:
        """CRAN: every package the archive serves, with last month's downloads from cranlogs.

        The name list is CRAN's own `PACKAGES` index, so nothing outside the archive enters.
        The counts come from the RStudio CRAN mirror's logs (cranlogs), the figure the R
        community itself quotes, asked for in batches of names.
        """
        index = "https://cran.r-project.org/src/contrib/PACKAGES"
        body = PackageIntelRefresh.fetch(index).decode("utf-8", "replace")
        names = sorted(
            set(re.findall(r"(?m)^Package:[ \t]*([A-Za-z][A-Za-z0-9.]{1,80})[ \t]*$", body))
        )
        counts = "https://cranlogs.r-pkg.org/downloads/total/last-month/"
        out: dict[str, int] = {}
        for start in range(0, len(names), CRAN_BATCH):
            batch = names[start : start + CRAN_BATCH]
            payload = PackageIntelRefresh.fetch_json_retrying(
                counts + ",".join(batch), fetcher=PackageIntelRefresh.fetch_json
            )
            time.sleep(PACE)
            for row in payload if isinstance(payload, list) else []:
                if isinstance(row, dict) and row.get("package") in batch:
                    out[str(row["package"])] = int(row.get("downloads") or 0)
        return sorted(out.items()), f"{index} (names), {counts} (last month's downloads)"

    @staticmethod
    def homebrew() -> tuple[list[tuple[str, int]], str]:
        """Homebrew formulae and casks, from Homebrew's own published install analytics."""
        sources = (
            ("https://formulae.brew.sh/api/analytics/install/365d.json", "formula"),
            ("https://formulae.brew.sh/api/analytics/cask-install/365d.json", "cask"),
        )
        out: dict[str, int] = {}
        for url, key in sources:
            payload = PackageIntelRefresh.as_object(PackageIntelRefresh.fetch_json(url), url)
            for item in cast("list[Any]", payload.get("items") or []):
                if not isinstance(item, dict) or not item.get(key):
                    continue
                # A tap-qualified name (`user/tap/name`) is that tap's, not core's.
                name = str(item[key])
                if "/" in name:
                    continue
                count = int(str(item.get("count") or "0").replace(",", "") or 0)
                out[name] = max(out.get(name, 0), count)
        return sorted(out.items()), ", ".join(url for url, _ in sources)

    @staticmethod
    def openvsx() -> tuple[list[tuple[str, int]], str]:
        """Open VSX, for editor extensions, in download order: `publisher.name` with its download count.

        Every page is required, as for pub.dev: a throttled page is retried, and a page that cannot be read fails
        the ecosystem rather than shortening its list. The Marketplace is not read: its terms allow only
        Microsoft's own products to use it."""
        source = "https://open-vsx.org/api/-/search"
        names: list[tuple[str, int]] = []
        size, pages = 100, 30
        for page in range(pages):
            url = f"{source}?sortBy=downloadCount&sortOrder=desc&size={size}&offset={page * size}"
            payload = PackageIntelRefresh.as_object(
                PackageIntelRefresh.fetch_json_retrying(url), url
            )
            entries = payload.get("extensions")
            if not isinstance(entries, list) or not entries:
                break
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                namespace, name, count = (
                    entry.get("namespace"),
                    entry.get("name"),
                    entry.get("downloadCount"),
                )
                if isinstance(namespace, str) and isinstance(name, str) and isinstance(count, int):
                    names.append((PackageIntelRefresh.spelt(f"{namespace}.{name}"), count))
            if len(entries) < size:
                break
        return names, source

    @staticmethod
    def paged(url: str) -> object:
        """One page of a registry that rate-limits: retried, and paced so the next page is not a burst.

        A page that cannot be read raises `SourceUnavailable`, which fails the ecosystem. It never shortens
        its list: a list cut short by a throttle reads downstream as the registry having shrunk.
        """
        payload = PackageIntelRefresh.fetch_json_retrying(url)
        time.sleep(PACE)
        return payload

    @staticmethod
    def hex_pm() -> tuple[list[tuple[str, int]], str]:
        """Hex, for Elixir and Erlang, in all-time download order, from hex.pm's own package API.

        The signal is `downloads.all`, the registry's own count; `sort=downloads` makes the order the
        registry's too. Pages hold 100 packages and run until one is empty.
        """
        source = "https://hex.pm/api/packages"
        names: list[tuple[str, int]] = []
        for page in range(1, 61):
            payload = PackageIntelRefresh.paged(f"{source}?sort=downloads&page={page}")
            if not isinstance(payload, list) or not payload:
                break
            for entry in payload:
                if not isinstance(entry, dict):
                    continue
                downloads = entry.get("downloads")
                total = downloads.get("all") if isinstance(downloads, dict) else None
                if isinstance(entry.get("name"), str) and isinstance(total, int):
                    names.append((PackageIntelRefresh.spelt(str(entry["name"])), total))
        return names, source

    @staticmethod
    def hackage() -> tuple[list[tuple[str, int]], str]:
        """Hackage, for Haskell, from the download table the registry publishes at `/packages/top`.

        One request holds every package with its download count, so there is no paging to throttle.
        """
        source = "https://hackage.haskell.org/packages/top"
        payload = PackageIntelRefresh.fetch_json_retrying(source)
        if not isinstance(payload, list):
            raise ValueError(f"{source} returned {type(payload).__name__}, expected a list")
        names = [
            (PackageIntelRefresh.spelt(str(entry["packageName"])), int(entry["downloads"]))
            for entry in payload
            if isinstance(entry, dict)
            and isinstance(entry.get("packageName"), str)
            and isinstance(entry.get("downloads"), int)
        ]
        return names, source

    @staticmethod
    def artifact_hub() -> tuple[list[tuple[str, int]], str]:
        """Helm charts, from Artifact Hub, ranked by stars.

        Artifact Hub is the Helm project's own chart index (`helm search hub` reads it), and it publishes no
        install counts, so its star count is the signal. A chart name held by several repositories keeps its
        highest count, because the question asked of the list is whether a name is established anywhere.
        """
        source = "https://artifacthub.io/api/v1/packages/search"
        best: dict[str, int] = {}
        size = 60
        for offset in range(0, 6000, size):
            url = f"{source}?kind=0&sort=stars&limit={size}&offset={offset}"
            payload = PackageIntelRefresh.as_object(PackageIntelRefresh.paged(url), url)
            entries = payload.get("packages")
            if not isinstance(entries, list) or not entries:
                break
            for entry in entries:
                if isinstance(entry, dict) and isinstance(entry.get("name"), str):
                    stars = int(entry.get("stars") or 0)
                    name = PackageIntelRefresh.spelt(str(entry["name"]))
                    best[name] = max(best.get(name, 0), stars)
            if len(entries) < size:
                break
        return sorted(best.items()), source

    @staticmethod
    def terraform_providers() -> tuple[list[tuple[str, int]], str]:
        """Terraform providers, in download order, from the registry's own v2 API.

        Modules are not listed: a module's archive names nothing (see `PublishedMetadata.MODULE_REASON`),
        so only a provider's name is something a release can be compared with.
        """
        source = "https://registry.terraform.io/v2/providers"
        names: list[tuple[str, int]] = []
        for page in range(1, 41):
            url = f"{source}?page%5Bsize%5D=100&page%5Bnumber%5D={page}&sort=-downloads"
            payload = PackageIntelRefresh.as_object(PackageIntelRefresh.paged(url), url)
            data = payload.get("data")
            if not isinstance(data, list) or not data:
                break
            for entry in data:
                attributes = entry.get("attributes") if isinstance(entry, dict) else None
                if (
                    isinstance(attributes, dict)
                    and isinstance(attributes.get("name"), str)
                    and isinstance(attributes.get("downloads"), int)
                ):
                    names.append(
                        (
                            PackageIntelRefresh.spelt(str(attributes["name"])),
                            attributes["downloads"],
                        )
                    )
        return names, source

    @staticmethod
    def julia() -> tuple[list[tuple[str, int]], str]:
        """Julia, from the request counts the Julia project publishes for its package servers.

        `package_requests.csv.gz` counts requests per package UUID; the General registry's `Registry.toml`
        maps each UUID to its name. Both are the Julia project's own files.
        """
        registry = "https://raw.githubusercontent.com/JuliaRegistries/General/master/Registry.toml"
        logs = (
            "https://julialang-logs.s3.amazonaws.com/public_outputs/current/package_requests.csv.gz"
        )
        packages = tomllib.loads(
            PackageIntelRefresh.fetch(registry, timeout=120).decode("utf-8")
        ).get("packages")
        if not isinstance(packages, dict):
            raise ValueError(f"{registry} holds no packages table")
        by_uuid = {
            uuid: str(row["name"])
            for uuid, row in packages.items()
            if isinstance(row, dict) and isinstance(row.get("name"), str)
        }
        totals: dict[str, int] = {}
        text = gzip.decompress(PackageIntelRefresh.fetch(logs, timeout=300)).decode("utf-8")
        for row in csv.DictReader(io.StringIO(text)):
            name = by_uuid.get(row.get("package_uuid", ""))
            if name and row.get("status") in {"200", "302"}:
                totals[PackageIntelRefresh.spelt(name)] = totals.get(
                    PackageIntelRefresh.spelt(name), 0
                ) + int(row.get("request_count") or 0)
        return sorted(totals.items()), f"{registry}, {logs}"

    @staticmethod
    def galaxy() -> tuple[list[tuple[str, int]], str]:
        """Ansible collections, from Galaxy's own index, ranked by the download count each entry carries.

        The index endpoint cannot sort, so every page is read and the sorting is done here. The whole index
        is a few thousand collections.
        """
        source = (
            "https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/index/"
        )
        names: list[tuple[str, int]] = []
        size = 100
        for offset in range(0, 20_000, size):
            url = f"{source}?limit={size}&offset={offset}"
            payload = PackageIntelRefresh.as_object(PackageIntelRefresh.paged(url), url)
            data = payload.get("data")
            if not isinstance(data, list) or not data:
                break
            for entry in data:
                if (
                    isinstance(entry, dict)
                    and isinstance(entry.get("namespace"), str)
                    and isinstance(entry.get("name"), str)
                ):
                    names.append(
                        (
                            PackageIntelRefresh.spelt(f"{entry['namespace']}.{entry['name']}"),
                            int(entry.get("download_count") or 0),
                        )
                    )
            if len(data) < size:
                break
        return sorted(names, key=lambda item: -item[1]), source

    #: Words to search Docker Hub and pkg.go.dev with. Neither lists its whole index, so breadth comes from
    #: many queries and the order comes from each registry's own count (pull count, importer count).
    SEARCH_TERMS: ClassVar[tuple[str, ...]] = (
        "nginx", "redis", "postgres", "mysql", "mongo", "node", "python", "golang", "java", "ruby", "php",
        "alpine", "ubuntu", "debian", "centos", "busybox", "traefik", "grafana", "prometheus", "elastic",
        "kibana", "kafka", "rabbitmq", "memcached", "wordpress", "jenkins", "gitlab", "vault", "consul",
        "envoy", "haproxy", "caddy", "minio", "etcd", "docker", "kubernetes", "terraform", "ansible",
        "runner", "builder", "base", "web", "api", "server", "client", "proxy", "cache", "queue", "db",
        "auth", "log", "metrics", "test", "http", "json", "yaml", "cli", "sql", "crypto", "uuid", "mock",
        "config", "grpc", "cloud", "aws", "gcp", "azure",
    )  # fmt: skip

    @staticmethod
    def docker_hub() -> tuple[list[tuple[str, int]], str]:
        """Container images, from Docker Hub, ranked by pull count.

        The official images come first, from their own listing in pull order. Community images come from
        Hub's search over many queries: Hub lists no whole index, so each query contributes its hits and
        the pull count Hub reports for each decides the order.
        """
        best: dict[str, int] = {}
        official = "https://hub.docker.com/v2/repositories/library/"
        # Hub answers 403 past the first 100 results of this listing: one page, which is its top hundred.
        url = f"{official}?page_size=100&ordering=-pull_count"
        payload = PackageIntelRefresh.as_object(PackageIntelRefresh.paged(url), url)
        for entry in cast("list[Any]", payload.get("results") or []):
            if isinstance(entry, dict) and isinstance(entry.get("name"), str):
                best[PackageIntelRefresh.spelt(str(entry["name"]))] = int(
                    entry.get("pull_count") or 0
                )
        search = "https://hub.docker.com/v2/search/repositories/"
        for term in PackageIntelRefresh.SEARCH_TERMS:
            # Hub answers 403 past the first 200 results of a query, so two pages of 100.
            for page in range(1, 3):
                address = f"{search}?query={term}&page_size=100&page={page}"
                payload = PackageIntelRefresh.as_object(PackageIntelRefresh.paged(address), address)
                results = payload.get("results")
                if not isinstance(results, list) or not results:
                    break
                for entry in results:
                    if isinstance(entry, dict) and isinstance(entry.get("repo_name"), str):
                        name = PackageIntelRefresh.spelt(str(entry["repo_name"]))
                        best[name] = max(best.get(name, 0), int(entry.get("pull_count") or 0))
        return sorted(best.items()), f"{official}, {search}"

    @staticmethod
    def pkg_go_dev() -> tuple[list[tuple[str, int]], str]:
        """Go modules, from pkg.go.dev, ranked by how many other modules import them.

        pkg.go.dev is the Go project's own index and `importedByCounts` its own measure. It lists no whole
        index, so each query in `SEARCH_TERMS` contributes its hits and the count decides the order. The
        standard library (module `std`) is not a published module and is left out.
        """
        source = "https://pkg.go.dev/v1/search"
        best: dict[str, int] = {}
        for term in PackageIntelRefresh.SEARCH_TERMS:
            token = ""
            for _ in range(3):
                url = f"{source}?q={urllib.parse.quote(term)}&limit=100" + (
                    f"&token={token}" if token else ""
                )
                payload = PackageIntelRefresh.as_object(PackageIntelRefresh.paged(url), url)
                items = payload.get("items")
                if not isinstance(items, list) or not items:
                    break
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    module = item.get("modulePath")
                    counts = item.get("importedByCounts")
                    if isinstance(module, str) and module != "std" and isinstance(counts, dict):
                        best[PackageIntelRefresh.spelt(module)] = max(
                            best.get(module.lower(), 0), int(counts.get("modules") or 0)
                        )
                token = str(payload.get("nextPageToken") or "")
                if not token:
                    break
        return sorted(best.items()), source

    @staticmethod
    def github_actions() -> tuple[list[tuple[str, int]], str]:
        """GitHub Actions, from GitHub's own repository search, ranked by stars.

        Actions have no registry of their own: the Marketplace has no API, and an action is the repository
        that holds its `action.yml`. Stars are GitHub's own signal, and the `github-action` topic is the
        repository owner's own statement that the repository is one. The search is unauthenticated and
        returns at most 1,000 results, ten pages, so it is paced to stay inside GitHub's limit of ten
        searches a minute and never carries a token.
        """
        source = "https://api.github.com/search/repositories"
        names: list[tuple[str, int]] = []
        for page in range(1, 11):
            url = f"{source}?q=topic:github-action&sort=stars&order=desc&per_page=100&page={page}"
            payload = PackageIntelRefresh.as_object(
                PackageIntelRefresh.fetch_json_retrying(url), url
            )
            time.sleep(SEARCH_PACE)
            items = payload.get("items")
            if not isinstance(items, list) or not items:
                break
            for item in items:
                if isinstance(item, dict) and isinstance(item.get("full_name"), str):
                    names.append(
                        (
                            PackageIntelRefresh.spelt(str(item["full_name"])),
                            int(item.get("stargazers_count") or 0),
                        )
                    )
        return names, source

    # ---------------------------------------------------------------------------
    # Registries with no popularity signal. They are not allowlists: `RealPackages` reads `<ecosystem>.txt`
    # and never `<ecosystem>.index.txt`, so a squat inside an index is not made safe by being listed.
    # ---------------------------------------------------------------------------

    @staticmethod
    def sampled(names: list[str], source: str) -> tuple[list[str], str, int, int]:
        """Every Nth name of the whole index in the registry's own order, N = ceil(size / INDEX_TARGET).

        A deterministic sample that covers the whole alphabet and the whole age of the registry. The first
        thousand names of an alphabetical index are all names beginning with a digit or an `a`. Returns the
        sample, its source, the whole index's size and N.
        """
        step = max(1, -(-len(names) // INDEX_TARGET))
        return names[::step], source, len(names), step

    @staticmethod
    def fetch_text_retrying(url: str) -> str:
        """A text page from a host that is merely busy sometimes: retried, never shortened."""
        last: Exception | None = None
        for attempt in range(RETRIES):
            try:
                return PackageIntelRefresh.fetch(url).decode("utf-8", "replace")
            except urllib.error.HTTPError as exc:
                with contextlib.suppress(Exception):
                    exc.close()
                if exc.code not in RETRYABLE_STATUS:
                    raise
                last = exc
            except (urllib.error.URLError, TimeoutError) as exc:
                last = exc
            if attempt < RETRIES - 1:
                time.sleep(min(BACKOFF * (2**attempt), MAX_BACKOFF))
        raise SourceUnavailable(f"{url} still refusing after {RETRIES} attempts: {last}")

    @staticmethod
    def github_tree(repository: str, reference: str, *, recursive: bool = False) -> list[str]:
        """The entries of a directory of a public repository, in the order GitHub lists them.

        Unauthenticated and without a token. The directory listing is the registry's own index for the
        registries whose index is a directory of a repository (opam, vcpkg, Conan Center, the Bazel Central
        Registry, nixpkgs).
        """
        url = f"https://api.github.com/repos/{repository}/git/trees/{reference}" + (
            "?recursive=1" if recursive else ""
        )
        payload = PackageIntelRefresh.as_object(PackageIntelRefresh.fetch_json_retrying(url), url)
        if payload.get("truncated"):
            raise ValueError(f"{url} was truncated: the index is not whole")
        tree = payload.get("tree")
        if not isinstance(tree, list):
            raise ValueError(f"{url} holds no tree")
        return [
            str(e["path"]) for e in tree if isinstance(e, dict) and isinstance(e.get("path"), str)
        ]

    @staticmethod
    def opam() -> tuple[list[str], str, int, int]:
        """opam, for OCaml: the directories of `packages/` in the opam repository."""
        names = PackageIntelRefresh.github_tree("ocaml/opam-repository", "master:packages")
        return PackageIntelRefresh.sampled(
            names, "https://github.com/ocaml/opam-repository/tree/master/packages"
        )

    @staticmethod
    def vcpkg() -> tuple[list[str], str, int, int]:
        """vcpkg, for C and C++: the directories of `ports/` in the vcpkg repository."""
        names = PackageIntelRefresh.github_tree("microsoft/vcpkg", "master:ports")
        return PackageIntelRefresh.sampled(
            names, "https://github.com/microsoft/vcpkg/tree/master/ports"
        )

    @staticmethod
    def conan() -> tuple[list[str], str, int, int]:
        """Conan Center: the directories of `recipes/` in the Conan Center Index repository."""
        source = "https://github.com/conan-io/conan-center-index/tree/master/recipes"
        names = PackageIntelRefresh.github_tree("conan-io/conan-center-index", "master:recipes")
        return PackageIntelRefresh.sampled(names, source)

    @staticmethod
    def bazel() -> tuple[list[str], str, int, int]:
        """Bazel modules: the directories of `modules/` in the Bazel Central Registry."""
        source = "https://github.com/bazelbuild/bazel-central-registry/tree/main/modules"
        names = PackageIntelRefresh.github_tree("bazelbuild/bazel-central-registry", "main:modules")
        return PackageIntelRefresh.sampled(names, source)

    @staticmethod
    def nix() -> tuple[list[str], str, int, int]:
        """Nix, from nixpkgs' `pkgs/by-name`: each package is `<shard>/<name>/package.nix`."""
        paths = PackageIntelRefresh.github_tree(
            "NixOS/nixpkgs", "master:pkgs/by-name", recursive=True
        )
        names = sorted(
            {p.split("/")[1] for p in paths if p.count("/") == 2 and p.endswith("/package.nix")}
        )
        return PackageIntelRefresh.sampled(
            names, "https://github.com/NixOS/nixpkgs/tree/master/pkgs/by-name"
        )

    @staticmethod
    def conda() -> tuple[list[str], str, int, int]:
        """conda-forge: the packages named in the channel's own `channeldata.json`, in its order."""
        source = "https://conda.anaconda.org/conda-forge/channeldata.json"
        payload = json.loads(PackageIntelRefresh.fetch(source, timeout=300))
        packages = payload.get("packages") if isinstance(payload, dict) else None
        if not isinstance(packages, dict):
            raise ValueError(f"{source} holds no packages table")
        return PackageIntelRefresh.sampled(list(packages), source)

    @staticmethod
    def swift() -> tuple[list[str], str, int, int]:
        """Swift packages, from the Swift Package Index's `packages.json` (Apache-2.0).

        Swift has no registry: a package is a git repository, and the community-run Swift Package Index is the
        one list of them, so its list is the index. Each entry is a repository URL; the name is the repository's.
        """
        source = (
            "https://raw.githubusercontent.com/SwiftPackageIndex/PackageList/main/packages.json"
        )
        payload = PackageIntelRefresh.fetch_json(source, timeout=120)
        if not isinstance(payload, list):
            raise ValueError(f"{source} returned {type(payload).__name__}, expected a list")
        names = [
            str(url).rstrip("/").removesuffix(".git").rsplit("/", 1)[-1].lower()
            for url in payload
            if isinstance(url, str)
        ]
        return PackageIntelRefresh.sampled(names, source)

    @staticmethod
    def cocoapods() -> tuple[list[str], str, int, int]:
        """CocoaPods: every pod named in the CDN's 4,096 shard files, `all_pods_versions_<a>_<b>_<c>.txt`."""
        source = "https://cdn.cocoapods.org"
        names: set[str] = set()
        digits = "0123456789abcdef"
        for a in digits:
            for b in digits:
                for c in digits:
                    url = f"{source}/all_pods_versions_{a}_{b}_{c}.txt"
                    body = PackageIntelRefresh.fetch_text_retrying(url)
                    names.update(line.split("/", 1)[0] for line in body.splitlines() if "/" in line)
                    time.sleep(CDN_PACE)
        return PackageIntelRefresh.sampled(sorted(names), f"{source}/all_pods_versions_*.txt")

    @staticmethod
    def maven() -> tuple[list[str], str, int, int]:
        """Maven Central: `group:artifact` at every Nth place of the search index, N from its size.

        Central publishes no popularity signal and its index has millions of entries, so the index is
        sampled where it is: one request per sampled place, at `start = i * N`, in the order Central's
        own search returns. The returned list is the sample, and the index size is its `numFound`.
        """
        source = "https://search.maven.org/solrsearch/select"
        first = PackageIntelRefresh.as_object(
            PackageIntelRefresh.fetch_json_retrying(f"{source}?q=*:*&rows=1&start=0&wt=json"),
            source,
        )
        response = first.get("response")
        found = response.get("numFound") if isinstance(response, dict) else None
        if not isinstance(found, int) or found < 1:
            raise ValueError(f"{source} reported no index size")
        step = max(1, -(-found // INDEX_TARGET))
        names: list[str] = []
        for start in range(0, found, step):
            url = f"{source}?q=*:*&rows=1&start={start}&wt=json"
            payload = PackageIntelRefresh.as_object(PackageIntelRefresh.paged(url), url)
            body = payload.get("response")
            docs = body.get("docs") if isinstance(body, dict) else None
            if (
                isinstance(docs, list)
                and docs
                and isinstance(docs[0], dict)
                and isinstance(docs[0].get("id"), str)
            ):
                names.append(PackageIntelRefresh.spelt(str(docs[0]["id"])))
        return names, source, found, step

    @staticmethod
    def pub_dev() -> tuple[list[tuple[str, int]], str]:
        """pub.dev, for Dart and Flutter, in popularity order.

        pub.dev publishes no download counts, so rank is the only signal and the score
        below is derived from it: first result highest, descending by one per place.
        That is enough for both things the score is used for -- the threshold, which
        becomes "inside the top N", and the look-alike filter, which only ever asks
        which of two names is better known.

        It is recorded as a derived score rather than presented as downloads, because a
        rank and a download count are not the same evidence and a reader of the file
        header is entitled to know which one this is.

        Every page is required. pub.dev rate-limits, and a rate-limited page is not
        an empty one: a loop that stops paginating whenever a request fails returns
        however much of the registry it managed to read before being throttled, and
        that lands downstream as an allowlist that appears to have shrunk. So a
        throttled page is retried, and a page that cannot be read after every retry
        fails the ecosystem rather than shortening its list.
        """
        source = "https://pub.dev/api/search"
        # Ten results a page and page 11 is a 400, so one query yields a hundred names
        # and no more. The terms buy breadth the way they do for npm; popularity order
        # within each is what decides the score. A hundred terms at ten pages is a
        # thousand requests, which is why they are paced -- see `PACE`.
        terms = [
            "",
            "flutter",
            "dart",
            "widget",
            "http",
            "json",
            "state",
            "async",
            "util",
            "build",
            "test",
            "mock",
            "lint",
            "firebase",
            "google",
            "aws",
            "api",
            "sql",
            "sqlite",
            "db",
            "storage",
            "cache",
            "auth",
            "oauth",
            "jwt",
            "crypto",
            "hash",
            "uuid",
            "path",
            "file",
            "image",
            "video",
            "audio",
            "pdf",
            "svg",
            "icon",
            "font",
            "theme",
            "color",
            "animation",
            "router",
            "navigation",
            "form",
            "validate",
            "input",
            "picker",
            "calendar",
            "date",
            "time",
            "intl",
            "locale",
            "currency",
            "map",
            "location",
            "camera",
            "permission",
            "notification",
            "share",
            "url",
            "webview",
            "bluetooth",
            "sensor",
            "device",
            "platform",
            "native",
            "ffi",
            "isolate",
            "stream",
            "rx",
            "bloc",
            "provider",
            "riverpod",
            "getx",
            "redux",
            "hive",
            "realm",
            "graphql",
            "grpc",
            "socket",
            "websocket",
            "connectivity",
            "log",
            "logger",
            "analytics",
            "crash",
            "config",
            "env",
            "yaml",
            "xml",
            "csv",
            "markdown",
            "html",
            "css",
            "chart",
            "table",
            "list",
            "grid",
            "scroll",
        ]
        scored: dict[str, int] = {}
        for term in terms:
            for page in range(1, 11):
                query = urllib.parse.urlencode({"q": term, "sort": "popularity", "page": page})
                try:
                    payload = PackageIntelRefresh.as_object(
                        PackageIntelRefresh.fetch_json_retrying(f"{source}?{query}"), source
                    )
                except urllib.error.HTTPError as exc:
                    with contextlib.suppress(Exception):  # the error is the response: close it
                        exc.close()
                    # A page past the end of this term's results, which pub.dev
                    # answers 400 rather than with an empty list. The end of the
                    # term; every other status is a broken source and propagates.
                    if exc.code == HTTP_PAST_LAST_PAGE:
                        break
                    raise
                time.sleep(PACE)
                packages = payload.get("packages") or []
                if not isinstance(packages, list) or not packages:
                    break
                for position, entry in enumerate(packages):
                    name = (entry or {}).get("package")
                    if not name:
                        continue
                    rank = (page - 1) * 10 + position + 1
                    # Best rank across every term that surfaced it, so a package that
                    # is first for a narrow term and four hundredth overall keeps the
                    # ranking that reflects how well known it is.
                    scored[str(name)] = max(scored.get(str(name), 0), 1_000_000 - rank)
        return sorted(scored.items()), f"{source} (sort=popularity; score derived from rank)"

    #: Each name as its registry spells it, keyed by the lowered name the lists hold. Hackage and CRAN names are
    #: case-sensitive (`HTTP`, not `http`): asking a registry about the lowered name asks about nothing.
    SPELLINGS: ClassVar[dict[str, str]] = {}

    @staticmethod
    def spelt(name: str) -> str:
        """The lowered name a list holds, remembering how its registry spells it."""
        lowered = name.lower()
        PackageIntelRefresh.SPELLINGS.setdefault(lowered, name)
        return lowered

    @staticmethod
    def first_published_of(ecosystem: str) -> Callable[[str], str]:
        """When the registry says each name was first published, read from its own release history."""
        sys.path.insert(0, str(ROOT / "src"))
        from cordon_scanner.intel.registries.release_history import ReleaseHistory

        return lambda name: ReleaseHistory.first_published(
            ecosystem, PackageIntelRefresh.SPELLINGS.get(name, name)
        )

    @staticmethod
    def refuse_self_allowlisting(
        ranked: list[tuple[str, int]],
        *,
        ecosystem: str,
        first_published: Callable[[str], str] | None = None,
        today: dt.date | None = None,
    ) -> tuple[list[str], list[str]]:
        """Drop names whose shape and traffic together look like a squat.

        The filter that makes a list of this size safe to ship. Without it a name
        registered to catch a typo could enter the allowlist and switch off the
        detection of itself -- and squats do accumulate installs, because accumulating
        installs is the entire point of registering one.

        Two conditions, and it took real data to find the second. The shape must be
        one of the three kinds a keyboard does not produce on purpose -- a
        transposition, a doubled character, an ASCII homoglyph -- AND the look-alike
        must be at least `MIN_DOWNLOAD_RATIO` times more downloaded. Shape alone threw
        out real packages by the dozen.

        Separator variants were refused in the first version of this filter, on the
        reasoning that registering `node_fetch` beside `node-fetch` is deliberate. The
        first real run disproved it: on crates.io alone it refused `bitvec` against
        `bit-vec`, `sha-1` against `sha1`, `md5` against `md-5`, `sys-info` against
        `sysinfo`, `temp-dir` against `tempdir` and `html-escape` against `htmlescape`
        -- nineteen pairs, both halves of every one a real crate by a different
        author. Rust in particular gets written both ways. So the kind is kept here
        and the detector grades it as weak evidence.

        "More popular" is decided within this fetch, which is the only ranking
        available offline afterwards, and it is the right comparison anyway: the
        question is whether this name looks like a slip of something better known.

        A ratio alone can be bought: a squat whose downloads are inflated past a thousandth of its
        target's clears it. So a name that is ANY slip of a more popular one -- a letter changed,
        added, dropped, a separator moved, as well as the three kinds above under the ratio -- is
        contested, and stays only if a reviewer kept it (`KEEP_DESPITE_SHAPE`), it has at least a tenth of
        its look-alike's downloads (`CONTESTED_MAX_RATIO`), or the registry says it was first published at
        least `CONTESTED_MIN_YEARS` ago. Inflated squats are young; the real
        neighbours that made the ratio necessary (`cchardet`, `pyaml`, `bitvec`) are years old. A
        contested name whose age cannot be read is refused: it stays reportable, which is the safe
        side. Only contested names cost a request.
        """
        sys.path.insert(0, str(ROOT / "src"))
        from cordon_scanner.detect.supply.dependency import DependencyDetector

        refused_kinds = {"transposition", "doubled", "homoglyph"}
        by_downloads = sorted(ranked, key=lambda pair: -pair[1])
        kept: list[str] = []
        refused: list[str] = []
        # Compared against the names already accepted, which are by construction the
        # more popular ones, so the loop is a single pass rather than a square.
        accepted: dict[str, int] = {}
        # Every accepted name under each of its one-letter deletions and its separator-free form: two names one
        # edit apart always share a key, so a name meets only its neighbours, not the whole list.
        neighbours: dict[str, list[str]] = {}
        cutoff = (today or dt.date.today()) - dt.timedelta(days=round(365.25 * CONTESTED_MIN_YEARS))
        for name, downloads in by_downloads:
            reviewed = KEEP_DESPITE_SHAPE.get(ecosystem, {}).get(name)
            long_enough = len(name) >= MIN_NAME_LENGTH
            # The ratio is checked first: it rules out nearly every pair before any shape is read.
            squat = next(
                (
                    other
                    for other, other_downloads in accepted.items()
                    if long_enough
                    and abs(len(other) - len(name)) <= 1
                    and other_downloads >= downloads * MIN_DOWNLOAD_RATIO
                    and DependencyDetector._slip_kind(name, other) in refused_kinds
                ),
                None,
            )
            contested = (
                next(
                    (
                        other
                        for key in PackageIntelRefresh.neighbour_keys(name)
                        for other in neighbours.get(key, ())
                        if PackageIntelRefresh.one_edit(name, other)
                    ),
                    None,
                )
                if long_enough
                else None
            )
            if reviewed or (squat is None and contested is None):
                accepted[name] = downloads
                PackageIntelRefresh.index_neighbour(neighbours, name)
                kept.append(name)
            elif squat is not None:
                refused.append(f"{name} ~ {squat}")
            elif accepted[
                contested
            ] <= downloads * CONTESTED_MAX_RATIO or PackageIntelRefresh._old_enough(
                name, first_published, cutoff
            ):
                accepted[name] = downloads
                PackageIntelRefresh.index_neighbour(neighbours, name)
                kept.append(name)
            else:
                refused.append(
                    f"{name} ~ {contested} (contested; not {CONTESTED_MIN_YEARS} years old)"
                )
        return sorted(kept), refused

    @staticmethod
    def neighbour_keys(name: str) -> set[str]:
        """The keys a name is indexed under: itself, each one-letter deletion of it, and its separator-free form."""
        return {
            name,
            re.sub(r"[-_.]", "", name),
            *(name[:i] + name[i + 1 :] for i in range(len(name))),
        }

    @staticmethod
    def index_neighbour(index: dict[str, list[str]], name: str) -> None:
        for key in PackageIntelRefresh.neighbour_keys(name):
            index.setdefault(key, []).append(name)

    @staticmethod
    def one_edit(name: str, other: str) -> bool:
        """Whether one letter changed, added, dropped or swapped -- or only the separators -- turns one name into the other."""
        if name == other:
            return False
        if re.sub(r"[-_.]", "", name) == re.sub(r"[-_.]", "", other):
            return True
        if len(name) == len(other):
            diff = [i for i, (a, b) in enumerate(zip(name, other, strict=True)) if a != b]
            return len(diff) == 1 or (
                len(diff) == 2
                and diff[1] == diff[0] + 1
                and name[diff[0]] == other[diff[1]]
                and name[diff[1]] == other[diff[0]]
            )
        longer, shorter = (name, other) if len(name) > len(other) else (other, name)
        return len(longer) - len(shorter) == 1 and any(
            longer[:i] + longer[i + 1 :] == shorter for i in range(len(longer))
        )

    @staticmethod
    def _old_enough(
        name: str, first_published: Callable[[str], str] | None, cutoff: dt.date
    ) -> bool:
        """Whether the registry says `name` was first published on or before `cutoff`; False when it cannot say."""
        if first_published is None:
            return False
        try:
            when = first_published(name)
        except Exception:  # noqa: BLE001 - any failure to read the age refuses the name, the safe side
            return False
        try:
            return bool(when) and dt.date.fromisoformat(when[:10]) <= cutoff
        except ValueError:
            return False

    @staticmethod
    def write(
        ecosystem: str, names: list[str], *, source: str, threshold: int, fetched: int
    ) -> None:
        # A name two sources hold (a provider under two namespaces, a package spelled in two cases) is one name.
        names = sorted(set(names))
        DATA.mkdir(parents=True, exist_ok=True)
        path = DATA / f"{ecosystem}.txt"

        if path.exists():
            before = len(
                [
                    line
                    for line in path.read_text(encoding="utf-8").splitlines()
                    if line and not line.startswith("#")
                ]
            )
            if before and len(names) < before * (1 - MAX_SHRINK):
                raise SourceShrank(
                    f"{ecosystem}: refusing to write {len(names)} names over {before}. "
                    f"A shrink this large means the source changed shape, not that the "
                    f"registry lost packages. Investigate before overwriting."
                )

        header = [
            f"# Established {ecosystem} package names. Generated; do not edit by hand.",
            f"# Regenerate with: python3 scripts/refresh/refresh_package_intel.py --only {ecosystem}",
            f"# Source:    {source}",
            f"# Threshold: {threshold:,} downloads",
            f"# Fetched:   {fetched:,} candidates, {len(names):,} kept",
            f"# Refreshed: {dt.date.today().isoformat()}",
            "#",
            "# This is an allowlist of names that must NOT be reported as typosquats.",
            "# It is not a list of every published package: registries contain the squats,",
            "# and allowlisting those would switch the detection off. See the script.",
        ]
        PackageIntelRefresh._write_atomic(path, "\n".join([*header, *names, ""]))
        print(f"  wrote {path.relative_to(ROOT)} ({len(names):,} names)")

    @staticmethod
    def _write_atomic(path: Path, text: str) -> None:
        """Write via a temporary file and one rename.

        `write_text` truncates the target and then writes, so a process killed
        between the two leaves an allowlist that is empty or half there. These files
        are the only bundled data whose contents can REMOVE a detection -- a
        truncated one silently stops `SUSPECT.DEPENDENCY.TYPOSQUAT.001` accusing
        anything -- and the job that writes them was being killed by SIGTERM at the
        runner's six-hour limit. `os.replace` is atomic on every platform this runs
        on, so the file is either the old one or the new one.
        """
        directory = path.parent
        directory.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.", suffix=".tmp")
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as out:
                out.write(text)
                out.flush()
                os.fsync(out.fileno())
            temporary.replace(path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise

    @staticmethod
    def write_refusals(ecosystem: str, refused: list[str]) -> None:
        """Record what the filter excluded, beside what it kept.

        An exclusion nobody can see is the failure mode of every suppression
        mechanism ever shipped. These are the names this scanner will still report as
        typosquats despite their download counts, so the list has to be in the diff
        where a reviewer can disagree with it -- and where the two kinds of entry,
        a real squat like `tdqm` and a real package like `hexx`, can be told apart by
        somebody who knows the ecosystem.
        """
        path = DATA / f"{ecosystem}.refused.txt"
        header = [
            f"# {ecosystem}: established names the look-alike filter refused to allowlist.",
            "# Generated by scripts/refresh/refresh_package_intel.py. Each line is `name ~ what it resembles`.",
            "#",
            "# These remain reportable as typosquats. Review them: a name here is either a",
            "# squat riding on a popular package's typos, or a real package that happens to",
            "# look like one. Move the second kind into KEEP_DESPITE_SHAPE with a reason.",
            f"# Refreshed: {dt.date.today().isoformat()}",
        ]
        PackageIntelRefresh._write_atomic(path, "\n".join([*header, *sorted(refused), ""]))
        print(f"  wrote {path.relative_to(ROOT)} ({len(refused)} refused)")

    @staticmethod
    def write_index(ecosystem: str, names: list[str], *, source: str, size: int, step: int) -> None:
        """An unranked registry's strided index, in `<ecosystem>.index.txt`.

        Not an allowlist, and written to a name that `RealPackages` never reads: a registry with no popularity
        signal cannot tell its established names from its squats, so listing a name here must not make it safe.
        """
        header = [
            f"# {ecosystem} package names, a sample of the registry's whole index. Generated; do not edit by hand.",
            f"# Regenerate with: python3 scripts/refresh/refresh_package_intel.py --only {ecosystem}",
            f"# Source:     {source}",
            f"# Index size: {size:,} names",
            f"# Stride:     every {step:,}th name in the registry's own order (N = ceil({size:,} / {INDEX_TARGET:,}))",
            f"# Kept:       {len(names):,}",
            f"# Refreshed:  {dt.date.today().isoformat()}",
            "#",
            "# NOT an allowlist. This registry publishes no popularity signal, so nothing here is known to be",
            "# established; the file is read by measurements and by look-alike comparison, never by `RealPackages`.",
        ]
        PackageIntelRefresh._write_atomic(
            DATA / f"{ecosystem}.index.txt", "\n".join([*header, *names, ""])
        )
        print(f"  wrote {ecosystem}.index.txt ({len(names):,} names of {size:,}, every {step:,}th)")

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument(
            "--only", nargs="+", choices=sorted([*SOURCES, *INDEXES]), metavar="ECOSYSTEM"
        )
        parser.add_argument(
            "--check",
            action="store_true",
            help="report what a refresh would change and write nothing",
        )
        args = parser.parse_args()

        failed: list[str] = []
        for ecosystem in args.only or sorted([*SOURCES, *INDEXES]):
            print(f"{ecosystem}:")
            if ecosystem in INDEXES:
                try:
                    sample, source, size, step = INDEXES[ecosystem]()
                except Exception as exc:  # a broken source must not abort the rest  # noqa: BLE001
                    print(f"  FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
                    failed.append(ecosystem)
                    continue
                print(f"  {size:,} in the index, every {step:,}th kept: {len(sample):,}")
                if not args.check:
                    PackageIntelRefresh.write_index(
                        ecosystem, sample, source=source, size=size, step=step
                    )
                continue
            fetcher, threshold = SOURCES[ecosystem]
            try:
                ranked, source = fetcher()
            except Exception as exc:  # a broken source must not abort the rest  # noqa: BLE001
                print(f"  FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
                failed.append(ecosystem)
                continue

            established = [(name, count) for name, count in ranked if count >= threshold]
            kept, refused = PackageIntelRefresh.refuse_self_allowlisting(
                established,
                ecosystem=ecosystem,
                first_published=PackageIntelRefresh.first_published_of(ecosystem),
            )
            print(
                f"  {len(ranked):,} fetched, {len(established):,} over {threshold:,} downloads, "
                f"{len(kept):,} kept, {len(refused)} refused as look-alikes"
            )
            for entry in refused[:10]:
                print(f"    refused: {entry}")

            if args.check:
                continue
            try:
                PackageIntelRefresh.write(
                    ecosystem, kept, source=source, threshold=threshold, fetched=len(ranked)
                )
            except SourceShrank as exc:
                # The existing file is kept and the run goes on to the next
                # registry. A shrink in one source is a reason to investigate that
                # source, not to abandon the refresh of the other six.
                print(f"  FAILED: {exc}", file=sys.stderr)
                failed.append(ecosystem)
                continue
            PackageIntelRefresh.write_refusals(ecosystem, refused)

        if failed:
            print(f"\nfailed: {', '.join(failed)}", file=sys.stderr)
            return 1
        return 0


_PLAUSIBLE_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]{0,213}$")
"""What a published npm name can be: optional `@scope/`, then a name that begins
with an alphanumeric. Lowercase because npm lowercases names; the leading-char
rule is what excludes the degenerate `-` and any non-name string the parse might
otherwise pick up."""


#: Ecosystem -> (fetcher, minimum downloads to count as established).
#:
#: The thresholds are not uniform because the units are not comparable: PyPI's
#: figure is all-time from the BigQuery export, npm's is a month, and NuGet's and
#: crates.io's are all-time. Each is set where that ecosystem's long tail stops
#: and established packages start.
SOURCES: dict[str, tuple[Callable[[], tuple[list[tuple[str, int]], str]], int]] = {
    "pypi": (PackageIntelRefresh.pypi, 100_000),
    # A rank-derived score, not downloads: the whole npm-high-impact set.
    "npm": (PackageIntelRefresh.npm, 0),
    "cargo": (PackageIntelRefresh.crates, 50_000),
    "nuget": (PackageIntelRefresh.nuget, 50_000),
    "composer": (PackageIntelRefresh.packagist, 50_000),
    "rubygems": (PackageIntelRefresh.rubygems, 50_000),
    # A rank-derived score, not downloads: everything pub.dev returned.
    "pub": (PackageIntelRefresh.pub_dev, 0),
    # Last month's downloads. CRAN reviews every submission by hand, so its long tail is
    # real packages; the threshold only keeps the list to names people actually install.
    "cran": (PackageIntelRefresh.cran, 1_000),
    # A year of installs, formulae and casks together.
    "homebrew": (PackageIntelRefresh.homebrew, 1_000),
    # Lifetime downloads on Open VSX: the extensions an editor's users actually install.
    "vscode": (PackageIntelRefresh.openvsx, 1_000),
    # All-time downloads, hex.pm's own count.
    "hex": (PackageIntelRefresh.hex_pm, 10_000),
    # Downloads, from Hackage's own table.
    "hackage": (PackageIntelRefresh.hackage, 100),
    # Stars on Artifact Hub, the Helm project's index; it publishes no install counts.
    "helm": (PackageIntelRefresh.artifact_hub, 3),
    # All-time provider downloads, the Terraform registry's own count.
    "terraform": (PackageIntelRefresh.terraform_providers, 10_000),
    # Requests to the Julia package servers, from the Julia project's public logs.
    "julia": (PackageIntelRefresh.julia, 1_000),
    # Download counts Galaxy carries on each collection.
    "ansible": (PackageIntelRefresh.galaxy, 1_000),
    # Pulls, Docker Hub's own count.
    "image": (PackageIntelRefresh.docker_hub, 100_000),
    # Modules that import the module, pkg.go.dev's own count.
    "gomod": (PackageIntelRefresh.pkg_go_dev, 50),
    # Stars on GitHub, where an action lives; GitHub's own signal.
    "actions": (PackageIntelRefresh.github_actions, 5),
}

#: Ecosystem -> fetcher of the registry's whole index, for registries that publish no popularity signal at
#: all. Each returns (names, source, whole index size, N) and the names are every Nth of the index in the
#: registry's own order. They write `<ecosystem>.index.txt`, which is not an allowlist.
#:
#: `gradle` has no entry: it resolves Maven artifacts, so its index is Maven's (`maven.index.txt`), read
#: through `INDEX_SHARED`, not copied.
INDEXES: dict[str, Callable[[], tuple[list[str], str, int, int]]] = {
    "maven": PackageIntelRefresh.maven,
    "cocoapods": PackageIntelRefresh.cocoapods,
    "conda": PackageIntelRefresh.conda,
    "opam": PackageIntelRefresh.opam,
    "vcpkg": PackageIntelRefresh.vcpkg,
    "conan": PackageIntelRefresh.conan,
    "bazel": PackageIntelRefresh.bazel,
    "nix": PackageIntelRefresh.nix,
    "swift": PackageIntelRefresh.swift,
}

#: An ecosystem that shares another's index file, and whose.
INDEX_SHARED = {"gradle": "maven"}

#: Names per cranlogs request: the API takes a comma-separated list in the path.
CRAN_BATCH = 100

#: What each registry's list is, and why, so an ecosystem is never silently absent.
#:
#: Ranked by the registry's own count, written to `<ecosystem>.txt` (an allowlist): the ten registries that
#: publish downloads, plus `hex`, `hackage`, `helm`, `terraform`, `julia`, `ansible`, `image`, `gomod` and
#: `actions` (see `SOURCES` for each one's signal).
#:
#: No ranking at all, written to `<ecosystem>.index.txt` (never an allowlist): `maven`, `cocoapods`,
#: `conda`, `opam`, `vcpkg`, `conan`, `bazel`, `nix` and `swift` (see `INDEXES`). `gradle` reads Maven's file.
#: `index.golang.org` is a chronological feed, which is why `gomod` is ranked from pkg.go.dev instead.
#:
#: `hex` returns after an earlier version of this script wrote a file that nothing read: the ecosystem is
#: registered now, and `RealPackages` reads `hex.txt`.


#: A name is refused only if its look-alike is this many times more downloaded.
#:
#: The number that separates the two things a resemblance can mean. A squat lives
#: on other people's typos, so its traffic is a rounding error beside the package
#: it imitates. A real package that happens to resemble a popular one has its own
#: users, and its share is nothing like a rounding error.
#:
#: Chosen from what the first full refresh actually refused. Without a ratio the
#: filter threw out `cchardet` against `chardet`, `pyaml` against `pyyaml` and
#: `cmap` against `mcap` -- all real, all widely installed, all of them
#: false positives this allowlist exists to prevent. Every one clears a
#: thousandth of its neighbour's traffic comfortably.
MIN_DOWNLOAD_RATIO = 1_000

#: A name that resembles a more popular one stays on the allowlist only if the registry says it is at
#: least this old (or a reviewer kept it): download counts can be inflated, a first-publish date cannot.
CONTESTED_MIN_YEARS = 2

#: ...or has at least a tenth of its look-alike's downloads. Inflating a squat to a tenth of a popular package's
#: real traffic is costly and conspicuous; a project's own new sibling (`nvidia-nccl-cu13` beside `-cu12`, Google's
#: `google-adk` beside `google-ads`) reaches it. Measured on the first refresh with ages: without it, 564 crates and 59
#: PyPI names were refused, most of them real.
CONTESTED_MAX_RATIO = 10

#: Below this, a resemblance carries no information, so refusing on one cannot
#: either. Matches `MIN_NAME_LENGTH` in the detector, which will not compare names
#: this short at all -- so a name below it could not be reported as a typosquat
#: whether it is allowlisted or not, and refusing it only loses a real package.
#: It had refused `oic` against `oci`, `rpm` against `rmp`, `sc` against `scc`,
#: `uid` against `uuid` and `fss` against `fs`.
MIN_NAME_LENGTH = 4

#: Names the shape-and-traffic filter refuses that a human has checked and kept.
#:
#: The filter is deliberately blunt and it is right far more often than not, but it
#: cannot tell a real package that happens to look like a slip from one registered
#: to be one. The number it gets wrong is small enough to review -- four across
#: thirty-two thousand names on the first full run -- so the judgements are written
#: down here rather than absorbed.
#:
#: Each entry needs a reason. A name added without one is a hole in the typosquat
#: detection that looks like housekeeping.
KEEP_DESPITE_SHAPE: dict[str, dict[str, str]] = {
    "cargo": {
        "rustis": "a Redis client, unrelated to rustls; reads as an i/l homoglyph",
        "hexx": "hexagonal grid maths, unrelated to hex; reads as a doubled x",
    },
}


if __name__ == "__main__":
    raise SystemExit(PackageIntelRefresh.main())
