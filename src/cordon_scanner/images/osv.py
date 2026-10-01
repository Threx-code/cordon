"""Operating-system packages matched against OSV: Debian, Ubuntu, Alpine, Red Hat and its rebuilds,
SUSE, Wolfi and Chainguard advisories, through OSV's batch API.

Network, and it names the image's packages to OSV, so it runs only with `--online`. Distribution
advisories are not bundled: Debian's alone would multiply the wheel's size, and the distributions
revise them daily. OSV compares versions with each distribution's own rules (dpkg, apk, rpm), so
nothing here has to reimplement them.

OSV reports severity as CVSS vectors; the v3 base score is computed here from the specification's
formula. A record with no v3 vector is rated HIGH, the same "unrated is not low" rule the language
advisories follow.
"""

from __future__ import annotations

import json
import math
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Final

from cordon_scanner.version import __version__

API: Final = "https://api.osv.dev/v1"
BATCH: Final = 500
MAX_DETAILS: Final = 3000
WORKERS: Final = 8
TIMEOUT_SECONDS: Final = 30.0
MAX_BYTES: Final = 32 << 20


class OsvError(Exception):
    """OSV could not be asked, or answered unusably. Safe to show."""


@dataclass(frozen=True)
class Query:
    ecosystem: str
    name: str
    version: str


@dataclass(frozen=True)
class Vulnerability:
    id: str
    summary: str
    score: float | None
    cves: frozenset[str]
    fixed: str
    references: tuple[str, ...] = ()
    rating: str = ""
    """The distribution's own severity (`critical`, `high`, `medium`, `low`) when it gives one
    instead of a CVSS vector, as Amazon's advisories do."""


@dataclass
class Matches:
    by_query: dict[Query, list[Vulnerability]] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)


def _post(url: str, body: dict[str, Any]) -> Any:
    request = urllib.request.Request(  # noqa: S310 - fixed https host
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "User-Agent": f"cordon-scanner/{__version__}"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
        return json.loads(response.read(MAX_BYTES))


def _get(url: str) -> Any:
    request = urllib.request.Request(url, headers={"User-Agent": f"cordon-scanner/{__version__}"})  # noqa: S310
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
        return json.loads(response.read(MAX_BYTES))


# -- CVSS v3.x base score (FIRST, CVSS v3.1 specification section 7.1) ---------------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    integer = round(value * 100000)
    return integer / 100000.0 if integer % 10000 == 0 else (math.floor(integer / 10000) + 1) / 10.0


def cvss3_base(vector: str) -> float | None:
    if not vector.startswith("CVSS:3."):
        return None
    metrics = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    try:
        changed = metrics["S"] == "C"
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        privileges = (_PR_CHANGED if changed else _PR_UNCHANGED)[metrics["PR"]]
        exploitability = (
            8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * privileges * _UI[metrics["UI"]]
        )
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return _roundup(min(total, 10.0))


_CVE: Final = re.compile(r"CVE-\d{4}-\d{4,7}")


def _vulnerability(record: dict[str, Any], query: Query) -> Vulnerability:
    scores = [
        cvss3_base(str(s.get("score", "")))
        for s in record.get("severity") or ()
        if isinstance(s, dict)
    ]
    known = [s for s in scores if s is not None]
    cves = {
        c
        for source in (
            record.get("aliases") or [],
            record.get("upstream") or [],
            [record.get("id", "")],
        )
        for text in source
        for c in _CVE.findall(str(text))
    }
    fixed = ""
    for affected in record.get("affected") or ():
        package = affected.get("package") or {}
        if (
            package.get("name") != query.name
            or str(package.get("ecosystem", "")).split(":")[0] != query.ecosystem.split(":")[0]
        ):
            continue
        for rng in affected.get("ranges") or ():
            for event in rng.get("events") or ():
                if "fixed" in event:
                    fixed = str(event["fixed"])
    references = tuple(
        str(r.get("url"))
        for r in (record.get("references") or [])[:3]
        if isinstance(r, dict) and r.get("url")
    )
    return Vulnerability(
        id=str(record.get("id", "")),
        summary=str(record.get("summary") or record.get("details") or "")[:300],
        score=max(known) if known else None,
        cves=frozenset(cves),
        fixed=fixed,
        references=references,
    )


def match(
    queries: list[Query],
    *,
    post: Callable[[str, dict[str, Any]], Any] = _post,
    get: Callable[[str], Any] = _get,
) -> Matches:
    """Ask OSV which of these package versions are affected, then fetch each advisory once."""
    found = Matches()
    ids_by_query: dict[Query, list[str]] = {}
    for start in range(0, len(queries), BATCH):
        chunk = queries[start : start + BATCH]
        body = {
            "queries": [
                {"package": {"ecosystem": q.ecosystem, "name": q.name}, "version": q.version}
                for q in chunk
            ]
        }
        try:
            answer = post(f"{API}/querybatch", body)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise OsvError(f"OSV could not be asked ({type(exc).__name__})") from exc
        for query, result in zip(chunk, answer.get("results") or (), strict=False):
            ids_by_query[query] = [
                str(v.get("id")) for v in (result or {}).get("vulns") or () if v.get("id")
            ]
            if (result or {}).get("next_page_token"):
                found.problems.append(
                    f"OSV paged its answer for {query.name}; only the first page was read"
                )
    unique = sorted({i for ids in ids_by_query.values() for i in ids})
    if len(unique) > MAX_DETAILS:
        found.problems.append(
            f"{len(unique)} advisories matched; details were fetched for the first {MAX_DETAILS}"
        )
        unique = unique[:MAX_DETAILS]

    def detail(identifier: str) -> tuple[str, dict[str, Any] | None]:
        try:
            return identifier, get(f"{API}/vulns/{identifier}")
        except (urllib.error.URLError, OSError, ValueError):
            return identifier, None

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        records = dict(pool.map(detail, unique))
    missing = sum(1 for r in records.values() if r is None)
    if missing:
        found.problems.append(f"{missing} advisory record(s) could not be fetched from OSV")
    for query, ids in ids_by_query.items():
        found.by_query[query] = [
            _vulnerability(record, query) for i in ids if (record := records.get(i)) is not None
        ]
    return found


__all__ = ["Matches", "OsvError", "Query", "Vulnerability", "cvss3_base", "match"]
