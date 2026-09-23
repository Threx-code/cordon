#!/usr/bin/env python3
"""Refresh the shipped allowlist of established package names.

A MAINTENANCE script. It is never imported by the scanner and never runs during
a scan: cordon makes no network calls while scanning, because a tool that asks a
registry about the code in front of it is doing a version of the thing it warns
about. This runs deliberately, by a maintainer or on a schedule, and its output
is a reviewed artefact that ships with the release -- the same arrangement the
advisory database already has.

    python3 scripts/refresh_package_intel.py            # every ecosystem
    python3 scripts/refresh_package_intel.py --only pypi npm
    python3 scripts/refresh_package_intel.py --check     # fail if stale, write nothing

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

Six ecosystems publish download-ranked data and are refreshed here. Maven Central
and the Go module proxy publish no popularity signal at all -- Maven Central has
no download API, and `index.golang.org` is a chronological feed -- so those two
keep the curated in-code sets in `intel/real.py` and this script leaves them
alone rather than fetching an unranked list and pretending it was ranked.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "src" / "cordon_scanner" / "intel" / "data"
USER_AGENT = "cordon-scanner package-intel refresh (+https://github.com/Threx-code/cordon)"
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


def fetch_json(url: str, *, timeout: int = TIMEOUT) -> object:
    return json.loads(fetch(url, timeout=timeout))


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
    fetcher = fetcher or fetch_json_accepting_json
    last: Exception | None = None
    for attempt in range(RETRIES):
        try:
            return fetcher(url, timeout=timeout)
        except urllib.error.HTTPError as exc:
            if exc.code not in RETRYABLE_STATUS:
                raise
            last = exc
            wait = retry_delay(exc) or BACKOFF * (2**attempt)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last = exc
            wait = BACKOFF * (2**attempt)
        if attempt < RETRIES - 1:
            time.sleep(min(wait, MAX_BACKOFF))
    raise SourceUnavailable(f"{url} still refusing after {RETRIES} attempts: {last}")


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


def pypi() -> tuple[list[tuple[str, int]], str]:
    """PyPI, from the published top-packages dataset.

    Built from the public BigQuery download statistics PyPI itself exports. Used
    rather than scraped, because the numbers are the registry's own.
    """
    source = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
    payload = as_object(fetch_json(source), source)
    rows = payload.get("rows") or payload.get("data") or []
    out = [
        (str(row["project"]), int(row["download_count"]))
        for row in rows
        if isinstance(row, dict) and row.get("project")
    ]
    return out, source


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
    body = fetch(source).decode("utf-8", "replace")
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


_PLAUSIBLE_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]{0,213}$")
"""What a published npm name can be: optional `@scope/`, then a name that begins
with an alphanumeric. Lowercase because npm lowercases names; the leading-char
rule is what excludes the degenerate `-` and any non-name string the parse might
otherwise pick up."""


def crates() -> tuple[list[tuple[str, int]], str]:
    """crates.io, downloads-sorted, paged."""
    source = "https://crates.io/api/v1/crates"
    out: list[tuple[str, int]] = []
    for page in range(1, 201):
        query = urllib.parse.urlencode({"page": page, "per_page": 100, "sort": "downloads"})
        payload = as_object(fetch_json(f"{source}?{query}"), source)
        items = payload.get("crates") or []
        if not items:
            break
        out.extend((str(c["name"]), int(c.get("downloads") or 0)) for c in items if c.get("name"))
    return out, source


def nuget() -> tuple[list[tuple[str, int]], str]:
    """NuGet, from the search service, sorted by total downloads."""
    source = "https://azuresearch-usnc.nuget.org/query"
    out: list[tuple[str, int]] = []
    for skip in range(0, 6000, 1000):
        query = urllib.parse.urlencode(
            {"q": "", "take": 1000, "skip": skip, "sortBy": "totalDownloads-desc"}
        )
        payload = as_object(fetch_json(f"{source}?{query}", timeout=90), source)
        items = payload.get("data") or []
        if not items:
            break
        out.extend((str(p["id"]), int(p.get("totalDownloads") or 0)) for p in items if p.get("id"))
    return out, source


def packagist() -> tuple[list[tuple[str, int]], str]:
    """Packagist, from its popularity listing."""
    source = "https://packagist.org/explore/popular.json"
    out: list[tuple[str, int]] = []
    for page in range(1, 61):
        payload = as_object(fetch_json(f"{source}?page={page}"), source)
        items = payload.get("packages") or []
        if not items:
            break
        out.extend((str(p["name"]), int(p.get("downloads") or 0)) for p in items if p.get("name"))
    return out, source


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
            payload = fetch_json_retrying(f"{source}?{query}", fetcher=fetch_json)
            time.sleep(PACE)
            if not isinstance(payload, list) or not payload:
                break
            for gem in payload:
                name = (gem or {}).get("name")
                if name:
                    downloads = int((gem or {}).get("downloads") or 0)
                    seen[str(name)] = max(seen.get(str(name), 0), downloads)
    return sorted(seen.items()), source


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
                payload = as_object(fetch_json_retrying(f"{source}?{query}"), source)
            except urllib.error.HTTPError as exc:
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


#: Ecosystem -> (fetcher, minimum downloads to count as established).
#:
#: The thresholds are not uniform because the units are not comparable: PyPI's
#: figure is all-time from the BigQuery export, npm's is a month, and NuGet's and
#: crates.io's are all-time. Each is set where that ecosystem's long tail stops
#: and established packages start.
SOURCES: dict[str, tuple[Callable[[], tuple[list[tuple[str, int]], str]], int]] = {
    "pypi": (pypi, 100_000),
    # A rank-derived score, not downloads: the whole npm-high-impact set.
    "npm": (npm, 0),
    "cargo": (crates, 50_000),
    "nuget": (nuget, 50_000),
    "composer": (packagist, 50_000),
    "rubygems": (rubygems, 50_000),
    # A rank-derived score, not downloads: everything pub.dev returned.
    "pub": (pub_dev, 0),
}

#: Supported ecosystems this script does not refresh, and why. Listed rather than
#: omitted, because an ecosystem that is silently absent looks like one that was
#: covered.
#:
#: `maven`, `gradle`: Maven Central publishes no download statistics and no
#: popularity ordering, so there is nothing to rank by. A curated set in
#: `intel/real.py` carries them.
#:
#: `gomod`: `index.golang.org` is a chronological feed of every module version
#: ever published. Fetching it would produce a list in publication order, which is
#: not a popularity signal and would allowlist every squat in it.
#:
#: `cocoapods`: the Specs repository is the whole registry with no ranking.
#:
#: An earlier version of this script also fetched Hex, for Elixir. Cordon has no
#: Hex ecosystem, so the file it wrote was read by nothing -- three thousand names
#: that looked like coverage. It returns when the ecosystem does.
UNRANKED = ("maven", "gradle", "gomod", "cocoapods")


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


def refuse_self_allowlisting(
    ranked: list[tuple[str, int]], *, ecosystem: str
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
    """
    sys.path.insert(0, str(ROOT / "src"))
    from cordon_scanner.detect.dependency import DependencyDetector

    refused_kinds = {"transposition", "doubled", "homoglyph"}
    by_downloads = sorted(ranked, key=lambda pair: -pair[1])
    kept: list[str] = []
    refused: list[str] = []
    # Compared against the names already accepted, which are by construction the
    # more popular ones, so the loop is a single pass rather than a square.
    accepted: dict[str, int] = {}
    for name, downloads in by_downloads:
        slip = next(
            (
                other
                for other, other_downloads in accepted.items()
                if len(name) >= MIN_NAME_LENGTH
                and abs(len(other) - len(name)) <= 1
                and other_downloads >= downloads * MIN_DOWNLOAD_RATIO
                and DependencyDetector._slip_kind(name, other) in refused_kinds
            ),
            None,
        )
        reviewed = KEEP_DESPITE_SHAPE.get(ecosystem, {}).get(name)
        if slip is None or reviewed:
            accepted[name] = downloads
            kept.append(name)
        else:
            refused.append(f"{name} ~ {slip}")
    return sorted(kept), refused


def write(ecosystem: str, names: list[str], *, source: str, threshold: int, fetched: int) -> None:
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
        f"# Regenerate with: python3 scripts/refresh_package_intel.py --only {ecosystem}",
        f"# Source:    {source}",
        f"# Threshold: {threshold:,} downloads",
        f"# Fetched:   {fetched:,} candidates, {len(names):,} kept",
        f"# Refreshed: {dt.date.today().isoformat()}",
        "#",
        "# This is an allowlist of names that must NOT be reported as typosquats.",
        "# It is not a list of every published package: registries contain the squats,",
        "# and allowlisting those would switch the detection off. See the script.",
    ]
    _write_atomic(path, "\n".join([*header, *names, ""]))
    print(f"  wrote {path.relative_to(ROOT)} ({len(names):,} names)")


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
        "# Generated by scripts/refresh_package_intel.py. Each line is `name ~ what it resembles`.",
        "#",
        "# These remain reportable as typosquats. Review them: a name here is either a",
        "# squat riding on a popular package's typos, or a real package that happens to",
        "# look like one. Move the second kind into KEEP_DESPITE_SHAPE with a reason.",
        f"# Refreshed: {dt.date.today().isoformat()}",
    ]
    _write_atomic(path, "\n".join([*header, *sorted(refused), ""]))
    print(f"  wrote {path.relative_to(ROOT)} ({len(refused)} refused)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", nargs="+", choices=sorted(SOURCES), metavar="ECOSYSTEM")
    parser.add_argument(
        "--check",
        action="store_true",
        help="report what a refresh would change and write nothing",
    )
    args = parser.parse_args()

    failed: list[str] = []
    for ecosystem in args.only or sorted(SOURCES):
        fetcher, threshold = SOURCES[ecosystem]
        print(f"{ecosystem}:")
        try:
            ranked, source = fetcher()
        except Exception as exc:  # a broken source must not abort the rest
            print(f"  FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
            failed.append(ecosystem)
            continue

        established = [(name, count) for name, count in ranked if count >= threshold]
        kept, refused = refuse_self_allowlisting(established, ecosystem=ecosystem)
        print(
            f"  {len(ranked):,} fetched, {len(established):,} over {threshold:,} downloads, "
            f"{len(kept):,} kept, {len(refused)} refused as look-alikes"
        )
        for entry in refused[:10]:
            print(f"    refused: {entry}")

        if args.check:
            continue
        try:
            write(ecosystem, kept, source=source, threshold=threshold, fetched=len(ranked))
        except SourceShrank as exc:
            # The existing file is kept and the run goes on to the next
            # registry. A shrink in one source is a reason to investigate that
            # source, not to abandon the refresh of the other six.
            print(f"  FAILED: {exc}", file=sys.stderr)
            failed.append(ecosystem)
            continue
        write_refusals(ecosystem, refused)

    if failed:
        print(f"\nfailed: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
