"""Amazon Linux advisories (ALAS), matched against an image's RPM packages.

OSV does not carry Amazon Linux. Amazon publishes its advisories in each release's package
repository, as the standard `updateinfo.xml` every RPM distribution uses: per advisory a severity,
the CVEs it fixes, and the fixed version of each package. A package is affected when its installed
version sorts below the fixed one by RPM's own rules (`rpmvercmp`, reimplemented here exactly,
because a version comparison that disagrees with RPM's reports fixed packages as vulnerable or the
reverse).

Network, and it reveals only that someone fetched Amazon's public repository metadata -- not which
packages are installed -- so it runs under `--online` like the OSV path.
"""

from __future__ import annotations

import gzip
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Final

from cordon_scanner.images.packages import OsPackage

HOST: Final = "cdn.amazonlinux.com"
MIRROR_LISTS: Final = {
    "2": "https://cdn.amazonlinux.com/2/core/2.0/{arch}/mirror.list",
    "2023": "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/{arch}/mirror.list",
}
MAX_BYTES: Final = 64 << 20
TIMEOUT_SECONDS: Final = 60.0
SEVERITY: Final = {
    "critical": "critical",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
}


class AlasError(Exception):
    """The advisories could not be fetched or read. Safe to show."""


# -- rpmvercmp ---------------------------------------------------------------------------------


def _alnum(c: str) -> bool:
    return c.isascii() and c.isalnum()


def vercmp(a: str, b: str) -> int:
    """RPM's `rpmvercmp`: -1, 0 or 1. Segments of digits or letters compare in turn; a numeric
    segment is newer than an alphabetic one; `~` sorts before anything, even the end of the string;
    `^` sorts after the end of the string but before anything else."""
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not _alnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < len(b) and not _alnum(b[j]) and b[j] not in "~^":
            j += 1
        a_tilde, b_tilde = i < len(a) and a[i] == "~", j < len(b) and b[j] == "~"
        if a_tilde or b_tilde:
            if not a_tilde:
                return 1
            if not b_tilde:
                return -1
            i, j = i + 1, j + 1
            continue
        a_caret, b_caret = i < len(a) and a[i] == "^", j < len(b) and b[j] == "^"
        if a_caret or b_caret:
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if not a_caret:
                return 1
            if not b_caret:
                return -1
            i, j = i + 1, j + 1
            continue
        if i >= len(a) or j >= len(b):
            break
        start_a, start_b = i, j
        numeric = a[i].isdigit()
        if numeric:
            while i < len(a) and a[i].isdigit():
                i += 1
            while j < len(b) and b[j].isascii() and b[j].isdigit():
                j += 1
        else:
            while i < len(a) and a[i].isascii() and a[i].isalpha():
                i += 1
            while j < len(b) and b[j].isascii() and b[j].isalpha():
                j += 1
        left, right = a[start_a:i], b[start_b:j]
        if not right:
            return 1 if numeric else -1
        if numeric:
            left, right = left.lstrip("0"), right.lstrip("0")
            if len(left) != len(right):
                return 1 if len(left) > len(right) else -1
        if left != right:
            return 1 if left > right else -1
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def evr_compare(a: tuple[str, str, str], b: tuple[str, str, str]) -> int:
    """(epoch, version, release) compared as RPM does; a missing epoch is 0."""
    epoch_a, epoch_b = int(a[0] or 0), int(b[0] or 0)
    if epoch_a != epoch_b:
        return 1 if epoch_a > epoch_b else -1
    return vercmp(a[1], b[1]) or vercmp(a[2], b[2])


# -- the advisories ----------------------------------------------------------------------------


@dataclass(frozen=True)
class Fix:
    name: str
    arch: str
    evr: tuple[str, str, str]


@dataclass(frozen=True)
class Advisory:
    id: str
    severity: str
    cves: tuple[str, ...]
    title: str
    fixes: tuple[Fix, ...] = field(default=())


def parse(xml: bytes) -> list[Advisory]:
    try:
        root = ET.fromstring(xml)  # noqa: S314 - see the import
    except ET.ParseError as exc:
        raise AlasError(f"updateinfo.xml did not parse ({exc})") from exc
    advisories: list[Advisory] = []
    for update in root.iter("update"):
        if update.get("type") != "security":
            continue
        cves = tuple(
            sorted(
                {
                    r.get("id", "")
                    for r in update.iter("reference")
                    if r.get("type") == "cve" and r.get("id")
                }
            )
        )
        fixes = tuple(
            Fix(
                p.get("name", ""),
                p.get("arch", ""),
                (p.get("epoch") or "0", p.get("version", ""), p.get("release", "")),
            )
            for p in update.iter("package")
            if p.get("name") and p.get("arch") != "src"
        )
        advisories.append(
            Advisory(
                id=(update.findtext("id") or "").strip(),
                severity=SEVERITY.get((update.findtext("severity") or "").strip().lower(), "high"),
                cves=cves,
                title=(update.findtext("title") or "").strip()[:200],
                fixes=fixes,
            )
        )
    return advisories


def _get(url: str) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != HOST:
        raise AlasError(f"refusing an Amazon Linux URL off {HOST}: {parsed.hostname}")
    request = urllib.request.Request(url, headers={"User-Agent": "cordon-scanner"})  # noqa: S310 - checked above
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            body = response.read(MAX_BYTES + 1)
    except OSError as exc:
        raise AlasError(f"{HOST} could not be reached ({type(exc).__name__})") from exc
    if len(body) > MAX_BYTES:
        raise AlasError("the Amazon Linux metadata is larger than the reader accepts")
    return bytes(body)


def fetch(release: str, arch: str = "x86_64") -> list[Advisory]:
    """The security advisories for an Amazon Linux release (`2` or `2023`)."""
    if release not in MIRROR_LISTS:
        raise AlasError(f"no advisory source is known for Amazon Linux {release}")
    mirror = _get(MIRROR_LISTS[release].format(arch=arch)).decode("utf-8", "replace").split()
    if not mirror:
        raise AlasError("the Amazon Linux mirror list was empty")
    base = mirror[0].rstrip("/")
    repomd = _get(f"{base}/repodata/repomd.xml").decode("utf-8", "replace")
    match = re.search(r'<data type="updateinfo">.*?<location href="([^"]+)"', repomd, re.S)
    if not match:
        raise AlasError("the Amazon Linux repository lists no updateinfo")
    raw = _get(f"{base}/{match.group(1)}")
    if match.group(1).endswith(".gz"):
        try:
            raw = gzip.decompress(raw)
        except (OSError, EOFError) as exc:
            raise AlasError("updateinfo.xml.gz did not decompress") from exc
    return parse(raw)


@dataclass(frozen=True)
class Match:
    package: OsPackage
    advisory: Advisory
    fixed: str


def affected(packages: list[OsPackage], advisories: list[Advisory]) -> list[Match]:
    """Each installed package below the version an advisory fixes, one match per advisory."""
    by_name: dict[str, list[tuple[Advisory, Fix]]] = {}
    for advisory in advisories:
        for fix in advisory.fixes:
            by_name.setdefault(fix.name, []).append((advisory, fix))
    matches: list[Match] = []
    for package in packages:
        if package.manager != "rpm":
            continue
        version, _, release = (
            package.version.rpartition("-") if "-" in package.version else (package.version, "", "")
        )
        installed = (package.epoch or "0", version, release)
        seen: set[str] = set()
        for advisory, fix in by_name.get(package.name, ()):
            if advisory.id in seen or (package.arch and fix.arch not in (package.arch, "noarch")):
                continue
            if evr_compare(installed, fix.evr) < 0:
                seen.add(advisory.id)
                epoch = f"{fix.evr[0]}:" if fix.evr[0] not in ("", "0") else ""
                matches.append(Match(package, advisory, f"{epoch}{fix.evr[1]}-{fix.evr[2]}"))
    return matches


__all__ = [
    "Advisory",
    "AlasError",
    "Fix",
    "Match",
    "affected",
    "evr_compare",
    "fetch",
    "parse",
    "vercmp",
]
