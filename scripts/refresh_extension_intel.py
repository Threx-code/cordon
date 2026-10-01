#!/usr/bin/env python3
"""Refresh `intel/data/vscode-extensions.json`: editor extensions removed for cause, and popular ones.

Two public sources, both fetched by an operator or a scheduled job, never at scan time:

* Microsoft's record of extensions removed from the Visual Studio Marketplace
  (`microsoft/vsmarketplace`, `RemovedPackages.md`), with the reason for each: malware,
  impersonation, typosquatting, untrustworthy. A repository that recommends one of these, or vendors
  its `.vsix`, is pointing developers at something the marketplace itself took down.
* The most-downloaded extensions on Open VSX, the registry VS Code forks and Gitpod use. A
  recommended extension one edit away from one of these is the shape an impersonation takes.

The data file is added to the digest manifest, so the scan refuses a copy edited after it was built.

    python3 scripts/refresh_extension_intel.py            # writes the data file
    python3 scripts/refresh_extension_intel.py --check    # fetch and report, write nothing
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "src" / "cordon_scanner" / "intel" / "data"
TARGET = DATA / "vscode-extensions.json"
MANIFEST = DATA / "advisories-digests.json"
REMOVED_URL = "https://raw.githubusercontent.com/microsoft/vsmarketplace/main/RemovedPackages.md"
OPEN_VSX_URL = (
    "https://open-vsx.org/api/-/search?sortBy=downloadCount&sortOrder=desc&size=100&offset={}"
)
POPULAR = 1000
MIN_REMOVED = 1000
"""The removal list held about 2,140 entries in October 2026. A fetch returning far fewer has failed
partway; refuse to shrink the file rather than write the remainder."""

_ROW = re.compile(r"^\|\s*([A-Za-z0-9][\w.-]*\.[\w.-]+)\s*\|\s*([\d/]+)\s*\|\s*([^|]+?)\s*\|")


def _get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "cordon-intel-refresh"})  # noqa: S310 - fixed https URLs
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        return response.read()


def removed() -> dict[str, dict[str, str]]:
    found: dict[str, dict[str, str]] = {}
    for line in _get(REMOVED_URL).decode("utf-8", "replace").splitlines():
        match = _ROW.match(line)
        if not match:
            continue
        identifier, date, reason = match.groups()
        month, day, year = (int(part) for part in date.split("/"))
        found.setdefault(
            identifier.lower(),
            {"reason": reason.strip(), "removed": f"{year:04d}-{month:02d}-{day:02d}"},
        )
    return found


def popular() -> list[str]:
    names: list[str] = []
    for offset in range(0, POPULAR, 100):
        page = json.loads(_get(OPEN_VSX_URL.format(offset)))
        names += [f"{e['namespace']}.{e['name']}".lower() for e in page.get("extensions", [])]
    return sorted(dict.fromkeys(names))[: POPULAR * 2]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    removals = removed()
    if len(removals) < MIN_REMOVED:
        print(
            f"refusing: only {len(removals)} removals parsed, expected over {MIN_REMOVED}",
            file=sys.stderr,
        )
        return 1
    top = popular()
    print(f"{len(removals)} removed extensions, {len(top)} popular")
    if args.check:
        return 0
    document = {
        "generated": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": {"removed": REMOVED_URL, "popular": "https://open-vsx.org (by downloads)"},
        "removed": dict(sorted(removals.items())),
        "popular": top,
    }
    TARGET.write_text(json.dumps(document, indent=0, sort_keys=True) + "\n", encoding="utf-8")
    digests = json.loads(MANIFEST.read_text(encoding="utf-8"))
    digests[TARGET.name] = hashlib.sha256(TARGET.read_bytes()).hexdigest()
    MANIFEST.write_text(json.dumps(digests, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
