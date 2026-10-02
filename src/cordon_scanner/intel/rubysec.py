"""The Ruby Advisory Database (rubysec), as a second source for RubyGems beside OSV.

`bundler-audit` and Trivy read rubysec, and it carries advisories OSV's RubyGems export does not:
measured on GitLab's `Gemfile.lock`, eleven of the twenty Trivy reported -- `crass`, `rack-proxy`,
`resolv`, `faraday-http-cache` among them -- were rubysec's alone. Each advisory is one YAML file,
`gems/<gem>/<id>.yml`, stating which versions are *patched* and which were never affected; every
other version is vulnerable. That is turned into OSV-shaped ranges so the rest of Cordon matches
them like any other record.

An advisory OSV already has (the same GHSA or CVE) is dropped, so nothing is reported twice. The
files are read by a reader for exactly their shape -- top-level scalars and lists -- rather than a
YAML library, which keeps the scanner free of runtime dependencies.
"""

from __future__ import annotations

import io
import re
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from cordon_scanner.intel.advisories import Advisory
from cordon_scanner.intel.versions import Versions

HOST: Final = "codeload.github.com"
ARCHIVE_URL: Final = f"https://{HOST}/rubysec/ruby-advisory-db/tar.gz/refs/heads/master"
MAX_DOWNLOAD_BYTES: Final = 64 << 20
MAX_FILE_BYTES: Final = 256 << 10
TIMEOUT_SECONDS: Final = 120.0
USER_AGENT: Final = "cordon-scanner advisory sync"

_KEY: Final = re.compile(r"^(?P<key>[A-Za-z_][\w]{0,40}):[ \t]*(?P<value>.*)$")
_ITEM: Final = re.compile(r"^[ \t]{0,8}-[ \t]+(?P<value>.*)$")
_REQUIREMENT: Final = re.compile(
    r"^(?P<op>~>|>=|<=|!=|=|>|<)?[ \t]*(?P<version>[0-9][0-9A-Za-z.\-]{0,60})$"
)


class RubysecError(RuntimeError):
    """The rubysec source could not be fetched or read. Safe to show."""


class Rubysec:
    "Ruby advisories from the rubysec database that OSV does not carry."

    @staticmethod
    def parse(text: str) -> dict[str, Any]:
        """The top-level scalars and lists of one advisory file. Block scalars are skipped."""
        record: dict[str, Any] = {}
        current: str | None = None
        in_block = False
        for raw in text.splitlines():
            if not raw.strip() or raw.lstrip().startswith("#") or raw.strip() == "---":
                continue
            top = _KEY.match(raw)
            if top and not raw[0].isspace():
                key, value = top.group("key"), top.group("value").strip()
                in_block = value in ("|", ">", "|-", ">-", "|+", ">+")
                if in_block or value == "":
                    record[key] = [] if value == "" else ""
                    current = key if value == "" else None
                else:
                    record[key] = Rubysec._scalar(value)
                    current = None
                continue
            if in_block:
                continue
            item = _ITEM.match(raw)
            if item and current is not None and isinstance(record.get(current), list):
                record[current].append(Rubysec._scalar(item.group("value").strip()))
        return record

    @staticmethod
    def _scalar(value: str) -> str:
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            return value[1:-1]
        return value

    @staticmethod
    def _bump(version: str) -> str:
        """`~> 2.2.5` allows below `2.3`; `~> 2.2` below `3`: drop the last segment, bump the next."""
        parts = [p for p in version.split(".") if p]
        numeric = [p for p in parts if p.isdigit()]
        keep = numeric[:-1] if len(numeric) > 1 else numeric
        keep[-1] = str(int(keep[-1]) + 1)
        return ".".join(keep)

    @staticmethod
    def _interval(requirement: str) -> _Interval | None:
        """One requirement line (`~> 7.2.3, >= 7.2.3.2`) as the interval it allows."""
        low, low_inc, high, high_inc = None, True, None, False
        for clause in requirement.split(","):
            match = _REQUIREMENT.match(clause.strip())
            if match is None:
                return None
            op, version = match.group("op") or "=", match.group("version")
            if op == "~>":
                candidates = [(">=", version), ("<", Rubysec._bump(version))]
            elif op == "!=":
                continue
            else:
                candidates = [(op, version)]
            for each_op, each in candidates:
                if each_op in (">=", ">", "="):
                    inclusive = each_op != ">"
                    if low is None or Versions.compare("rubygems", each, low) > 0:
                        low, low_inc = each, inclusive
                if each_op in ("<=", "<", "="):
                    inclusive = each_op != "<"
                    if high is None or Versions.compare("rubygems", each, high) < 0:
                        high, high_inc = each, inclusive
        return _Interval(low, low_inc, high, high_inc)

    @staticmethod
    def _affected(safe: list[_Interval]) -> list[_Interval]:
        """Every version no safe interval covers, as sorted, non-overlapping intervals.

        A sweep from the bottom: `end` is how far coverage reaches so far (None before any), and
        `end_inclusive` whether `end` itself is covered. A gap opens wherever the next safe interval
        starts above that point.
        """
        gaps: list[_Interval] = []
        started = False
        end: str | None = None
        end_inclusive = False
        for interval in sorted(safe, key=lambda i: _SortKey(i.low)):
            if not started:
                if interval.low is not None:
                    gaps.append(_Interval(None, True, interval.low, not interval.low_inclusive))
            elif interval.low is not None and end is not None:
                order = Versions.compare("rubygems", interval.low, end)
                if order > 0 or (order == 0 and not end_inclusive and not interval.low_inclusive):
                    gaps.append(
                        _Interval(end, not end_inclusive, interval.low, not interval.low_inclusive)
                    )
            if interval.high is None:
                return gaps
            if not started or end is None:
                end, end_inclusive = interval.high, interval.high_inclusive
            else:
                order = Versions.compare("rubygems", interval.high, end)
                if order > 0 or (order == 0 and interval.high_inclusive):
                    end, end_inclusive = interval.high, interval.high_inclusive
            started = True
        gaps.append(
            _Interval(end, not end_inclusive, None, False)
            if started
            else _Interval(None, True, None, False)
        )
        return gaps

    # -- records ----------------------------------------------------------------------------------

    @staticmethod
    def _severity(record: dict[str, Any]) -> str:
        for field in ("cvss_v4", "cvss_v3", "cvss_v2"):
            try:
                score = float(record.get(field) or "")
            except ValueError:
                continue
            return (
                "critical"
                if score >= 9
                else "high"
                if score >= 7
                else "medium"
                if score >= 4
                else "low"
            )
        criticality = str(record.get("criticality") or "").lower()
        return criticality if criticality in ("critical", "high", "medium", "low") else ""

    @staticmethod
    def advisories_from(record: dict[str, Any]) -> tuple[Advisory, ...]:
        """One rubysec file as the OSV-shaped ranges Cordon matches on."""
        gem = str(record.get("gem") or "").strip()
        if not gem:
            return ()
        ghsa = str(record.get("ghsa") or "").strip()
        cve = str(record.get("cve") or "").strip()
        identifier = (
            f"GHSA-{ghsa}" if ghsa else f"CVE-{cve}" if cve else str(record.get("osvdb") or "")
        )
        if not identifier:
            return ()
        aliases = tuple(a for a in (f"CVE-{cve}" if cve else "",) if a and a != identifier)
        safe: list[_Interval] = []
        for field in ("patched_versions", "unaffected_versions"):
            for line in record.get(field) or []:
                interval = Rubysec._interval(str(line))
                if interval is None:
                    return ()
                safe.append(interval)
        summary = str(record.get("title") or "")[:300]
        reference = str(record.get("url") or "")
        severity = Rubysec._severity(record)
        out = []
        # OSV's `introduced` is inclusive. A gap opening just above a safe `<= x` would need an
        # exclusive one; it is written as `x`, which over-reports that single release rather than
        # missing the range above it.
        for gap in Rubysec._affected(safe):
            out.append(
                Advisory(
                    ecosystem="rubygems",
                    name=gem,
                    summary=summary,
                    reference=reference,
                    identifier=identifier,
                    severity=severity,
                    aliases=aliases,
                    introduced=gap.low or "0",
                    fixed=gap.high if gap.high is not None and not gap.high_inclusive else None,
                    last_affected=gap.high if gap.high is not None and gap.high_inclusive else None,
                )
            )
        return tuple(out)

    @staticmethod
    def _download() -> bytes:
        parsed = urllib.parse.urlsplit(ARCHIVE_URL)
        if parsed.scheme != "https" or parsed.hostname != HOST:
            raise RubysecError(f"refusing a rubysec URL off {HOST}")
        request = urllib.request.Request(ARCHIVE_URL, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
                body = response.read(MAX_DOWNLOAD_BYTES + 1)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise RubysecError(f"{HOST} could not be reached ({type(exc).__name__})") from exc
        if len(body) > MAX_DOWNLOAD_BYTES:
            raise RubysecError("the rubysec archive is larger than the reader accepts")
        return bytes(body)

    @staticmethod
    def records_from_archive(data: bytes) -> tuple[Advisory, ...]:
        """Every gem advisory in a rubysec repository tarball."""
        out: list[Advisory] = []
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                for member in archive:
                    parts = member.name.split("/")
                    if not (
                        member.isfile()
                        and len(parts) >= 4
                        and parts[-3] == "gems"
                        and parts[-1].endswith(".yml")
                    ):
                        continue
                    if member.size > MAX_FILE_BYTES:
                        continue
                    handle = archive.extractfile(member)
                    if handle is None:
                        continue
                    out.extend(
                        Rubysec.advisories_from(
                            Rubysec.parse(handle.read().decode("utf-8", "replace"))
                        )
                    )
        except (tarfile.TarError, OSError, EOFError) as exc:
            raise RubysecError(f"the rubysec archive did not read ({type(exc).__name__})") from exc
        return tuple(out)

    @staticmethod
    def new_records(
        existing: tuple[Advisory, ...], *, tmp_dir: Path | None = None
    ) -> tuple[Advisory, ...]:
        """rubysec advisories the OSV records do not already carry, by GHSA or CVE."""
        del tmp_dir  # read in memory; the archive is a few megabytes
        known = {i for a in existing for i in (a.identifier, *a.aliases) if i}
        return tuple(
            a
            for a in Rubysec.records_from_archive(Rubysec._download())
            if not ({a.identifier, *a.aliases} & known)
        )


# -- RubyGems requirements, as intervals ------------------------------------------------------


@dataclass(frozen=True)
class _Interval:
    low: str | None
    low_inclusive: bool
    high: str | None
    high_inclusive: bool


class _SortKey:
    """Orders interval lows by RubyGems rules, with an open low first."""

    def __init__(self, version: str | None) -> None:
        self.version = version

    def __lt__(self, other: _SortKey) -> bool:
        if self.version is None:
            return other.version is not None
        if other.version is None:
            return False
        return Versions.compare("rubygems", self.version, other.version) < 0


__all__ = ["Rubysec", "RubysecError"]
