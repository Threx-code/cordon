#!/usr/bin/env python3
"""Refresh the shipped lists of malicious package names the registry no longer serves.

A MAINTENANCE script, like `refresh_package_intel.py`: never imported by the scanner, never run
during a scan, and its output is a reviewed artefact that ships with the release.

    python3 scripts/refresh/refresh_removed_names.py                 # pypi, rubygems, cargo
    python3 scripts/refresh/refresh_removed_names.py --only pypi
    python3 scripts/refresh/refresh_removed_names.py --check         # fail if stale, write nothing

## What goes in the file

A name whose EVERY version is recorded as malicious, and for which the registry, asked today, serves
nothing an install could resolve: PyPI answers 404 or lists no release with a file; RubyGems and
crates.io answer 404. A project that declares such a name as a range cannot install the malware any
more, only fail, so the advisory detector reports it as a re-registration risk
(`SUSPECT.DEPENDENCY.REMOVED_NAME.001`, medium) instead of a known-malicious dependency
(found on PyPI: 10 legitimate packages blocked for declaring `umap`, `urllib`, `detectron2`,
`importlib-resource` or `azure-sdk-tools`, every one a 404).

The list can only lower a block to a warning, so it is built to fail safe: a name is listed only on
a definite answer that nothing is served. A timeout, a rate limit or any other error leaves it out,
and the block stands. An exact pin of a recorded malicious release is never affected; nor is npm,
where a removed name becomes the security team's placeholder (`POLICY.DEPENDENCY.SECURITY_PLACEHOLDER.001`).

Each file is plain text, one name per line, after a `# checked YYYY-MM-DD` header, so a reviewer
sees every name added or removed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import json
import sys
import time
import urllib.error
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
        "rubygems": "https://rubygems.org/api/v1/versions/{name}.json",
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
        status, body = cls.get(cls.URLS[ecosystem].format(name=urllib.request.quote(name, safe="")))
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
        """Names whose every version is recorded as malicious in the shipped advisories."""
        raw = json.loads(gzip.decompress((DATA / f"advisories-{ecosystem}.json.gz").read_bytes()))
        names = {
            str(r["name"])
            for r in raw
            if isinstance(r, dict)
            and r.get("malicious")
            and not r.get("versions")
            and not r.get("fixed")
            and not r.get("last_affected")
            and r.get("name")
        }
        return sorted(names)

    @staticmethod
    def path(ecosystem: str) -> Path:
        return DATA / f"{ecosystem}.removed.txt"

    @staticmethod
    def checked(ecosystem: str) -> dt.date | None:
        try:
            first = RemovedNames.path(ecosystem).read_text(encoding="utf-8").splitlines()[0]
        except (OSError, IndexError):
            return None
        try:
            return dt.date.fromisoformat(first.removeprefix("# checked ").strip())
        except ValueError:
            return None

    @staticmethod
    def refresh(ecosystem: str, workers: int) -> dict[str, int]:
        names = RemovedNames.candidates(ecosystem)
        with ThreadPoolExecutor(workers) as pool:
            answers = list(pool.map(lambda n: RegistryProbe.removed(ecosystem, n), names))
        removed = sorted(n for n, a in zip(names, answers, strict=True) if a is True)
        today = dt.datetime.now(dt.UTC).date().isoformat()
        RemovedNames.path(ecosystem).write_text(
            f"# checked {today}\n" + "".join(f"{n}\n" for n in removed), encoding="utf-8"
        )
        return {
            "candidates": len(names),
            "removed": len(removed),
            "served": sum(1 for a in answers if a is False),
            "unsure": sum(1 for a in answers if a is None),
        }

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
