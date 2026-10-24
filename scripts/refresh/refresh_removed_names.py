#!/usr/bin/env python3
"""Refresh the shipped lists of malicious package names the registry no longer serves.

A MAINTENANCE script, like `refresh_package_intel.py`: never imported by the scanner, never run
during a scan, and its output is a reviewed artefact that ships with the release.

    python3 scripts/refresh/refresh_removed_names.py                 # pypi and cargo
    python3 scripts/refresh/refresh_removed_names.py --only pypi
    python3 scripts/refresh/refresh_removed_names.py --check         # fail if stale, write nothing

## What goes in the file

A name whose EVERY version is recorded as malicious, as the scanner reads the records, and for which
the registry, asked today, serves nothing an install could resolve: PyPI answers 404 or lists no
release with a file; crates.io answers 404. (RubyGems records name exact versions, so none
qualifies.) A project that declares such a name as a range cannot install the malware any more,
only fail, so the advisory detector reports it as a re-registration risk
(`SUSPECT.DEPENDENCY.REMOVED_NAME.001`, medium) instead of a known-malicious dependency (found on
PyPI: 10 legitimate packages blocked for declaring `umap`, `urllib`, `detectron2`,
`importlib-resource` or `azure-sdk-tools`, every one a 404).

The list can only lower a block to a warning, so it is built to fail safe: a name is listed only on
a definite answer that nothing is served. A timeout, a rate limit or any other error leaves it out,
and the block stands. An exact pin of a recorded malicious release is never affected; nor is npm,
where a removed name becomes the security team's placeholder (`POLICY.DEPENDENCY.SECURITY_PLACEHOLDER.001`).

Each file is plain text, one name per line, sorted, after the provenance header every shipped list
carries (Source, Threshold, Fetched, Refreshed), so a reviewer sees every name added or removed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import ClassVar

DATA = Path(__file__).resolve().parents[2] / "src" / "cordon_scanner" / "intel" / "data"
AGENT = "cordon-scanner refresh_removed_names (https://github.com/Threx-code/cordon)"
#: How old a list may be before `--check` fails: a name can be registered again.
STALE_DAYS = 14


class RegistryProbe:
    """One definite answer per name: True (nothing served), False (served), None (not sure)."""

    URLS: ClassVar[dict[str, str]] = {
        "pypi": "https://pypi.org/pypi/{name}/json",
        "cargo": "https://crates.io/api/v1/crates/{name}",
    }

    @staticmethod
    def get(url: str) -> tuple[int, bytes]:
        request = urllib.request.Request(url, headers={"User-Agent": AGENT})  # noqa: S310 - fixed https hosts
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                    return response.status, response.read()
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 500, 502, 503, 504) and attempt < 2:
                    time.sleep(2 + attempt * 3)
                    continue
                return exc.code, b""
            except (urllib.error.URLError, TimeoutError, OSError):
                if attempt < 2:
                    time.sleep(2 + attempt * 3)
                    continue
                return 0, b""
        return 0, b""

    @classmethod
    def removed(cls, ecosystem: str, name: str) -> bool | None:
        status, body = cls.get(cls.URLS[ecosystem].format(name=urllib.parse.quote(name, safe="")))
        if status == 404:
            return True
        if status != 200:
            return None
        if ecosystem != "pypi":
            return False
        try:
            releases = json.loads(body).get("releases") or {}
        except ValueError:
            return None
        # A project page with no release that has a file: nothing an install could resolve.
        return not any(files for files in releases.values())


class RemovedNames:
    @staticmethod
    def candidates(ecosystem: str) -> list[str]:
        """Names the scanner itself treats as malicious in every version: the records as
        `AdvisoryDatabase` materialises them, the same test `AdvisoryDetector._admitted_malware`
        applies. The raw file can hold an all-versions form beside an exact list for one record."""
        sys.path.insert(0, str(DATA.parents[2]))
        from cordon_scanner.intel.advisories.advisories import AdvisoryDatabase

        database = AdvisoryDatabase.bundled()
        raw = json.loads(gzip.decompress((DATA / f"advisories-{ecosystem}.json.gz").read_bytes()))
        names = sorted({str(r["name"]) for r in raw if isinstance(r, dict) and r.get("malicious")})
        return [
            name
            for name in names
            if any(
                a.malicious
                and not a.versions
                and a.affects("0")
                and not (a.fixed or a.last_affected)
                for a in database.for_package(ecosystem, name)
            )
        ]

    @staticmethod
    def path(ecosystem: str) -> Path:
        return DATA / f"{ecosystem}.removed.txt"

    @staticmethod
    def checked(ecosystem: str) -> dt.date | None:
        try:
            lines = RemovedNames.path(ecosystem).read_text(encoding="utf-8").splitlines()
        except OSError:
            return None
        for line in lines:
            if line.startswith("# Refreshed:"):
                try:
                    return dt.date.fromisoformat(line.removeprefix("# Refreshed:").strip())
                except ValueError:
                    return None
        return None

    @staticmethod
    def refresh(ecosystem: str, workers: int) -> dict[str, int]:
        names = RemovedNames.candidates(ecosystem)
        with ThreadPoolExecutor(workers) as pool:
            answers = list(pool.map(lambda n: RegistryProbe.removed(ecosystem, n), names))
        removed = sorted(n for n, a in zip(names, answers, strict=True) if a is True)
        today = dt.datetime.now(dt.UTC).date().isoformat()
        counts = {
            "candidates": len(names),
            "removed": len(removed),
            "served": sum(1 for a in answers if a is False),
            "unsure": sum(1 for a in answers if a is None),
        }
        RemovedNames.path(ecosystem).write_text(
            RemovedNames.header(ecosystem, counts, today) + "".join(f"{n}\n" for n in removed),
            encoding="utf-8",
        )
        return counts

    @staticmethod
    def header(ecosystem: str, counts: dict[str, int], today: str) -> str:
        source = RegistryProbe.URLS[ecosystem].replace("{name}", "<name>")
        return (
            f"# Malicious {ecosystem} package names the registry no longer serves. "
            "Generated; do not edit by hand.\n"
            f"# Regenerate with: python3 scripts/refresh/refresh_removed_names.py --only {ecosystem}\n"
            f"# Source:    {source}, for every name the shipped advisories record as malicious "
            "in every version\n"
            "# Threshold: a definite answer that nothing installable is served (404, or no release "
            "with a file); any error leaves the name out\n"
            f"# Fetched:   {counts['candidates']:,} candidates, {counts['removed']:,} removed, "
            f"{counts['served']:,} still served, {counts['unsure']:,} unsure\n"
            f"# Refreshed: {today}\n"
        )

    @staticmethod
    def main(argv: list[str] | None = None) -> int:
        parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
        parser.add_argument("--only", nargs="*", default=sorted(RegistryProbe.URLS))
        parser.add_argument("--check", action="store_true")
        parser.add_argument("--workers", type=int, default=16)
        args = parser.parse_args(argv)
        if args.check:
            today = dt.datetime.now(dt.UTC).date()
            stale = [
                e
                for e in args.only
                if (c := RemovedNames.checked(e)) is None or (today - c).days > STALE_DAYS
            ]
            if stale:
                print(f"stale or missing: {stale}", file=sys.stderr)
                return 1
            return 0
        for ecosystem in args.only:
            print(ecosystem, json.dumps(RemovedNames.refresh(ecosystem, args.workers)))
        return 0


if __name__ == "__main__":
    sys.exit(RemovedNames.main())
