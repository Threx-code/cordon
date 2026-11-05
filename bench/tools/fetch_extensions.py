#!/usr/bin/env python3
"""The real-world IDE-extension corpus: the most-installed VS Code extensions, as published.

Lists extensions from the Visual Studio Marketplace's public gallery API by install count, and
downloads each one's `.vsix` as the marketplace serves it -- never installed, never run. The corpus
is the legitimate side of the extension measurement: what a model and the rules must not flag. It
is split by a hash of the extension's identifier, as the other corpora are, so half calibrates and
half is held out.

    python bench/tools/fetch_extensions.py --out corpus-dir --count 2000

Run inside a container with network.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

GALLERY = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
#: IncludeVersions | IncludeFiles | IncludeLatestVersionOnly | IncludeAssetUri | IncludeStatistics
FLAGS = 0x1 | 0x2 | 0x200 | 0x80 | 0x100
SORT_BY_INSTALLS = 4
MAX_VSIX = 64 << 20
_HEADERS = {
    "User-Agent": "cordon-extension-study",
    "Accept": "application/json;api-version=7.2-preview.1",
    "Content-Type": "application/json",
}


class ExtensionCorpus:
    @staticmethod
    def page(number: int, size: int = 100) -> list[dict[str, object]]:
        body = json.dumps(
            {
                "filters": [
                    {
                        # Target: Microsoft.VisualStudio.Code; exclude unpublished.
                        "criteria": [
                            {"filterType": 8, "value": "Microsoft.VisualStudio.Code"},
                            {"filterType": 12, "value": "4096"},
                        ],
                        "pageNumber": number,
                        "pageSize": size,
                        "sortBy": SORT_BY_INSTALLS,
                        "sortOrder": 0,
                    }
                ],
                "flags": FLAGS,
            }
        ).encode()
        for _ in range(5):
            try:
                request = urllib.request.Request(GALLERY, data=body, headers=_HEADERS)
                with urllib.request.urlopen(request, timeout=60) as response:
                    results = json.load(response).get("results") or [{}]
                return list(results[0].get("extensions") or [])
            except (urllib.error.URLError, TimeoutError, OSError):
                time.sleep(5)
        return []

    @staticmethod
    def vsix_url(extension: dict[str, object]) -> tuple[str, str] | None:
        """`(publisher.name, url)` of the latest version's VSIX package."""
        publisher = str((extension.get("publisher") or {}).get("publisherName") or "")  # type: ignore[union-attr]
        name = str(extension.get("extensionName") or "")
        versions = extension.get("versions") or []
        if not publisher or not name or not versions:
            return None
        for item in versions[0].get("files") or []:  # type: ignore[index,union-attr]
            if item.get("assetType") == "Microsoft.VisualStudio.Services.VSIXPackage":
                return f"{publisher}.{name}", str(item.get("source") or "")
        return None

    @staticmethod
    def fetch(out: Path, identifier: str, url: str) -> bool:
        target = out / "vsix" / f"{identifier}.vsix"
        if target.exists():
            return True
        try:
            request = urllib.request.Request(url, headers={"User-Agent": _HEADERS["User-Agent"]})
            with urllib.request.urlopen(request, timeout=120) as response:
                body = response.read(MAX_VSIX + 1)
        except (urllib.error.URLError, TimeoutError, OSError):
            return False
        if len(body) > MAX_VSIX or body[:2] != b"PK":
            return False
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        return True

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--out", type=Path, required=True)
        parser.add_argument("--count", type=int, default=2000)
        args = parser.parse_args()
        chosen: list[tuple[str, str]] = []
        number = 1
        while len(chosen) < args.count:
            extensions = ExtensionCorpus.page(number)
            if not extensions:
                break
            chosen += [x for x in (ExtensionCorpus.vsix_url(e) for e in extensions) if x and x[1]]
            number += 1
            time.sleep(1)
        chosen = chosen[: args.count]
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "extensions.json").write_text(json.dumps(chosen), encoding="utf-8")
        with ThreadPoolExecutor(8) as pool:
            fetched = sum(pool.map(lambda job: ExtensionCorpus.fetch(args.out, *job), chosen))
        print(f"{len(chosen)} extensions listed, {fetched} packages fetched")
        return 0


if __name__ == "__main__":
    sys.exit(ExtensionCorpus.main())
