"""The CVE List (github.com/CVEProject/cvelistV5): every CVE record as its CNA published it, with the
containers ADPs add -- CISA's Vulnrichment among them. Read when the bundled NVD data is built
(`intel/nvd_import`), for the CVEs NVD has not analysed: NVD gives them no CPE configuration, so no
range, while the record itself often names the affected product and versions.

Only what the record states exactly is used:

- the product, from a CPE the record gives (`cpe:2.3:a:...` or the older `cpe:/a:...`) -- never
  from its free-text vendor and product names;
- the versions, from `version`, `lessThan` and `lessThanOrEqual` entries marked `affected`, of a
  version type that is an upstream release's (not `git` commits, `rpm` builds or `patch` ids);
- not an entry whose default status is `affected`, whose exceptions a range cannot express.

The baseline release is a zip of a zip of records, published with a SHA-256 GitHub records for the
asset; the download is checked against it before anything is read.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import urllib.request
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar, Final

LATEST: Final = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
MAX_BASELINE_BYTES: Final = 2 << 30


class CveListError(RuntimeError):
    """The CVE List could not be fetched or did not match its published digest."""


class CveList:
    #: Version types that are not an upstream release's version.
    SKIPPED_TYPES: ClassVar[frozenset[str]] = frozenset(
        {"git", "rpm", "patch", "original_commit_for_fix"}
    )
    #: How a record writes "from the first release".
    NO_START: ClassVar[frozenset[str]] = frozenset({"", "0", "*", "-", "n/a", "unspecified"})

    @staticmethod
    def fetch(directory: Path) -> Path:
        """The latest baseline (`*_all_CVEs_at_midnight.zip.zip`), downloaded into `directory`
        and checked against the SHA-256 GitHub records for the asset."""
        request = urllib.request.Request(
            LATEST,
            headers={"User-Agent": "cordon-scanner", "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            release = json.loads(response.read(1 << 20))
        asset = next(
            (
                a
                for a in release.get("assets") or []
                if str(a.get("name") or "").endswith("_all_CVEs_at_midnight.zip.zip")
            ),
            None,
        )
        digest = str((asset or {}).get("digest") or "")
        url = str((asset or {}).get("browser_download_url") or "")
        if not asset or not digest.startswith("sha256:") or not url.startswith("https://"):
            raise CveListError("the latest CVE List release names no baseline with a digest")
        target = directory / "cve-list-baseline.zip"
        hasher = hashlib.sha256()
        size = 0
        download = urllib.request.Request(url, headers={"User-Agent": "cordon-scanner"})  # noqa: S310
        with urllib.request.urlopen(download, timeout=120) as response, target.open("wb") as out:  # noqa: S310
            while chunk := response.read(1 << 20):
                size += len(chunk)
                if size > MAX_BASELINE_BYTES:
                    raise CveListError("the CVE List baseline is larger than expected")
                hasher.update(chunk)
                out.write(chunk)
        if hasher.hexdigest() != digest.removeprefix("sha256:"):
            target.unlink(missing_ok=True)
            raise CveListError("the CVE List baseline does not match its published SHA-256")
        return target

    @staticmethod
    def records(baseline: Path) -> Iterator[dict[str, Any]]:
        """Every published record in the baseline: an outer zip holding `cves.zip`."""
        with zipfile.ZipFile(baseline) as outer:
            inner_name = next((n for n in outer.namelist() if n.endswith(".zip")), None)
            if inner_name is None:
                raise CveListError("the CVE List baseline holds no record archive")
            with tempfile.TemporaryDirectory() as scratch:
                inner_path = Path(scratch) / "cves.zip"
                with outer.open(inner_name) as source, inner_path.open("wb") as target:
                    shutil.copyfileobj(source, target, 1 << 20)
                with zipfile.ZipFile(inner_path) as inner:
                    for name in inner.namelist():
                        if not name.endswith(".json") or "/CVE-" not in name:
                            continue
                        record = json.loads(inner.read(name))
                        metadata = record.get("cveMetadata") or {}
                        if metadata.get("state") == "PUBLISHED" and metadata.get("cveId"):
                            yield record

    @staticmethod
    def containers(record: dict[str, Any]) -> list[dict[str, Any]]:
        found = record.get("containers") or {}
        cna: dict[str, Any] = found["cna"] if isinstance(found.get("cna"), dict) else {}
        return [cna, *(a for a in found.get("adp") or [] if isinstance(a, dict))]

    @staticmethod
    def severity(record: dict[str, Any]) -> str:
        """The CNA's CVSS rating, else an ADP's (CISA's Vulnrichment); empty when none rates it."""
        for container in CveList.containers(record):
            for metric in container.get("metrics") or []:
                for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                    rating = (metric.get(key) or {}).get("baseSeverity")
                    if rating:
                        return str(rating).lower()
        return ""

    @staticmethod
    def description(record: dict[str, Any]) -> str:
        for container in CveList.containers(record):
            for entry in container.get("descriptions") or []:
                if str(entry.get("lang") or "").startswith("en") and entry.get("value"):
                    return str(entry["value"]).strip().splitlines()[0][:300]
        return ""

    @staticmethod
    def product(cpe: str) -> tuple[str, str] | None:
        """`(vendor:product, version)` of an application CPE, 2.3 or 2.2."""
        if cpe.startswith("cpe:2.3:"):
            parts = cpe.split(":")
            if len(parts) < 6 or parts[2] != "a":
                return None
            return f"{parts[3]}:{parts[4]}", parts[5]
        if cpe.startswith("cpe:/a:"):
            parts = cpe[len("cpe:/a:") :].split(":")
            if len(parts) < 2:
                return None
            return f"{parts[0]}:{parts[1]}", parts[2] if len(parts) > 2 else "*"
        return None

    @staticmethod
    def ranges(record: dict[str, Any]) -> Iterator[tuple[str, dict[str, str]]]:
        """`(vendor:product, bounds)` the record states exactly, in the bounds NVD's ranges use."""
        seen: set[tuple[str, str]] = set()
        for container in CveList.containers(record):
            for affected in container.get("affected") or []:
                if not isinstance(affected, dict) or affected.get("defaultStatus") == "affected":
                    continue
                products = [
                    p for p in (CveList.product(str(c)) for c in affected.get("cpes") or []) if p
                ]
                if not products:
                    continue
                bounds_list: list[dict[str, str]] = []
                for entry in affected.get("versions") or []:
                    if not isinstance(entry, dict) or entry.get("status") != "affected":
                        continue
                    if str(entry.get("versionType") or "") in CveList.SKIPPED_TYPES:
                        continue
                    start = str(entry.get("version") or "").strip()
                    less, upto = entry.get("lessThan"), entry.get("lessThanOrEqual")
                    bounds: dict[str, str] = {}
                    if less or upto:
                        if start.lower() not in CveList.NO_START:
                            bounds["versionStartIncluding"] = start
                        if less and str(less) != "*":
                            bounds["versionEndExcluding"] = str(less)
                        elif upto and str(upto) != "*":
                            bounds["versionEndIncluding"] = str(upto)
                    elif start.lower() not in CveList.NO_START:
                        bounds = {"v": start}
                    else:
                        continue
                    bounds_list.append(bounds)
                # The version list applies to every CPE the entry names; with none, each CPE's own
                # version, where it names one, is its alone.
                pairs = (
                    [(name, bounds) for name, _ in products for bounds in bounds_list]
                    if bounds_list
                    else [
                        (name, {"v": version})
                        for name, version in products
                        if version not in ("*", "-", "")
                    ]
                )
                for name, bounds in pairs:
                    key = (name, json.dumps(bounds, sort_keys=True))
                    if key not in seen:
                        seen.add(key)
                        yield name, bounds

    @staticmethod
    def references(record: dict[str, Any]) -> list[dict[str, Any]]:
        """The record's references, tags as the CVE schema writes them (`vendor-advisory`,
        `patch`, `issue-tracking`, `release-notes`, `product`)."""
        return [
            r
            for container in CveList.containers(record)
            for r in container.get("references") or []
            if isinstance(r, dict)
        ]

    @staticmethod
    def read_bytes(data: bytes) -> Iterator[dict[str, Any]]:
        """Records from an in-memory baseline (tests)."""
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "baseline.zip"
            path.write_bytes(data)
            yield from CveList.records(path)
