"""Building `nvd-cves.json.gz` and `nvd-cpe.json.gz` (read by `intel/nvd`) from NVD's own bulk feeds.

Not run at scan time. Called by `scripts/build_nvd_db.py` on the advisory refresh schedule, and by
`cordon-scanner advisories sync`, the same two callers `intel/osv_import` has.

NVD publishes, per year, every CVE as JSON (`nvdcve-2.0-<year>.json.gz`) beside a `.meta` file
giving the uncompressed feed's SHA-256; and its whole CPE dictionary (`nvdcpe-2.0.tar.gz`) beside
its own. Every feed is checked against its digest before a byte of it is used, and a feed that
fails to download or verify fails the build: nothing is written from a partial set.

From the CVE feeds: for every application CPE a configuration marks vulnerable, the range it
gives -- `versionStart`/`versionEnd`, inclusive or exclusive -- or the exact version (and update)
it names. A criterion whose version is `-` (no version applies) is left out.

From the CPE dictionary: for every application product, the sites its references are on, by the
same `CpeRule.site` the scan applies to a package's homepage -- so the build and the scan cannot
disagree about what "the same site" means.
"""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import io
import json
import os
import re
import tarfile
import urllib.request
from collections import defaultdict
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from cordon_scanner.intel.advisories import DIGESTS_NAME, AdvisoryFiles
from cordon_scanner.intel.nvd import CPE_NAME, CVES_NAME, CpeRule

CVE_FEED: Final = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}"
CPE_FEED: Final = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0"
FIRST_YEAR: Final = 2002
MAX_FEED_BYTES: Final = 512 << 20
AGENT: Final = "cordon-scanner (https://github.com/Threx-code/cordon)"
_SEVERITIES: Final = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
_BOUNDS: Final = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)


class NvdImportError(RuntimeError):
    """A feed could not be downloaded, or did not match its published digest."""


@dataclass
class NvdBuild:
    products: dict[str, list[list[Any]]] = field(default_factory=dict)
    text: dict[str, str] = field(default_factory=dict)
    index: dict[str, list[list[Any]]] = field(default_factory=dict)
    curated: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    cves: int = 0


class NvdImport:
    @staticmethod
    def _fetch(url: str) -> bytes:
        if not url.startswith("https://"):
            raise NvdImportError(f"refusing a non-HTTPS feed: {url}")
        request = urllib.request.Request(url, headers={"User-Agent": AGENT})  # noqa: S310
        try:
            with urllib.request.urlopen(request, timeout=300) as response:  # noqa: S310
                body: bytes = response.read(MAX_FEED_BYTES + 1)
        except OSError as exc:
            raise NvdImportError(f"{url}: {exc}") from exc
        if len(body) > MAX_FEED_BYTES:
            raise NvdImportError(f"{url}: larger than {MAX_FEED_BYTES} bytes")
        return body

    @staticmethod
    def _digest(meta: bytes, url: str) -> str:
        found = re.search(rb"sha256:([0-9A-Fa-f]{64})", meta)
        if not found:
            raise NvdImportError(f"{url}.meta gives no SHA-256")
        return found.group(1).decode().lower()

    @staticmethod
    def verified(base: str, suffix: str) -> bytes:
        """`_verified`, up to three times: a transfer cut short (NVD's CDN does this) fails its
        digest or its decompression, and is fetched again; three failures fail the build."""
        for attempt in range(3):
            try:
                return NvdImport._verified(base, suffix)
            except NvdImportError:
                if attempt == 2:
                    raise
        raise AssertionError("unreachable")

    @staticmethod
    def _verified(base: str, suffix: str) -> bytes:
        """A feed's bytes, uncompressed for a `.json.gz`, after its SHA-256 matches its `.meta`.
        NVD's CVE `.meta` gives the uncompressed JSON's digest; the CPE dictionary's gives its
        archive's."""
        meta = NvdImport._fetch(f"{base}.meta")
        body = NvdImport._fetch(f"{base}{suffix}")
        expected = NvdImport._digest(meta, base)
        if suffix == ".json.gz":
            try:
                body = gzip.decompress(body)
            except (OSError, EOFError) as exc:
                raise NvdImportError(f"{base}{suffix}: {exc}") from exc
            if hashlib.sha256(body).hexdigest() != expected:
                raise NvdImportError(f"{base}{suffix} does not match its published SHA-256")
            return body
        # The CPE dictionary's `.meta` digest is over its chunk files' JSON, concatenated in
        # name order (measured: the archive's own digest and the tar's both differ from it).
        digest = hashlib.sha256()
        try:
            with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tar:
                members = sorted((m for m in tar.getmembers() if m.isfile()), key=lambda m: m.name)
                for member in members:
                    handle = tar.extractfile(member)
                    while handle is not None and (chunk := handle.read(1 << 20)):
                        digest.update(chunk)
        except (tarfile.TarError, OSError, EOFError) as exc:
            raise NvdImportError(f"{base}{suffix}: {exc}") from exc
        if digest.hexdigest() != expected:
            raise NvdImportError(f"{base}{suffix} does not match its published SHA-256")
        return body

    @staticmethod
    def severity(cve: dict[str, Any]) -> str:
        metrics = cve.get("metrics") or {}
        for key in _SEVERITIES:
            entries = metrics.get(key) or []
            if entries:
                first = entries[0]
                rating = (first.get("cvssData") or {}).get("baseSeverity") or first.get(
                    "baseSeverity"
                )
                return str(rating or "").lower()
        return ""

    @staticmethod
    def ranges(cve: dict[str, Any]) -> Iterator[tuple[str, dict[str, str]]]:
        """`(vendor:product, bounds)` for every application criterion marked vulnerable."""
        seen: set[tuple[str, str]] = set()
        for configuration in cve.get("configurations") or []:
            for node in configuration.get("nodes") or []:
                for match in node.get("cpeMatch") or []:
                    if not match.get("vulnerable"):
                        continue
                    parts = str(match.get("criteria") or "").split(":")
                    if len(parts) < 7 or parts[2] != "a":
                        continue
                    version, update = parts[5], parts[6]
                    if version == "-":
                        continue
                    if version != "*":
                        bounds = {"v": version}
                        if update not in ("*", "-"):
                            bounds["u"] = update
                    else:
                        bounds = {k: str(match[k]) for k in _BOUNDS if match.get(k)}
                    product = f"{parts[3]}:{parts[4]}"
                    key = (product, json.dumps(bounds, sort_keys=True))
                    if key not in seen:
                        seen.add(key)
                        yield product, bounds

    @staticmethod
    def cves(year: int) -> Iterator[dict[str, Any]]:
        data = json.loads(NvdImport.verified(CVE_FEED.format(year=year), ".json.gz"))
        for item in data.get("vulnerabilities") or []:
            cve = item.get("cve") or {}
            if cve.get("vulnStatus") != "Rejected" and cve.get("id"):
                yield cve

    @staticmethod
    def build(
        years: range, keep: Callable[[str, str], bool], log: Callable[[str], None] = print
    ) -> NvdBuild:
        """Every year's records, those `keep(id, severity)` accepts, grouped by product."""
        out = NvdBuild()
        products: dict[str, list[list[Any]]] = defaultdict(list)
        # Every product any CVE names, kept or not: a product whose CVEs are all below the bundled
        # cut (open-mpi:hwloc) is still a product NVD knows, to tie a package to.
        named: set[str] = set()
        for year in years:
            count = 0
            for cve in NvdImport.cves(year):
                out.cves += 1
                identifier, rating = str(cve["id"]), NvdImport.severity(cve)
                found = list(NvdImport.ranges(cve))
                named.update(product for product, _ in found)
                if not keep(identifier, rating):
                    continue
                if not found:
                    continue
                for product, bounds in found:
                    products[product].append([identifier, rating, bounds])
                description = next(
                    (
                        str(d.get("value") or "")
                        for d in cve.get("descriptions") or []
                        if d.get("lang") == "en"
                    ),
                    "",
                )
                out.text[identifier] = (
                    description.strip().splitlines()[0][:300] if description else ""
                )
                count += 1
            log(f"  {year}: {count:,} CVEs with application ranges")
        out.products = dict(products)
        out.index = NvdImport.index(named)
        log(f"  CPE dictionary: {len(out.index):,} product names with sites")
        return out

    @staticmethod
    def index(named: set[str] | None = None) -> dict[str, list[list[Any]]]:
        """`normalised name -> [[vendor:product, [sites]]]` from NVD's CPE dictionary, for
        application products that are not deprecated.

        A product's sites are its own references' -- not those NVD types `Advisory`, which are
        third parties' write-ups (a Red Hat or Debian advisory names many products) -- with its
        vendor's `Vendor`-typed sites added (gnu:m4 lists none of its own; GNU's are gnu.org). Its
        names are the product's, and any acronym its title gives in parentheses (nasm:
        netwide_assembler is titled \"Netwide Assembler (NASM)\").

        A product CVEs name but the dictionary lacks (`named`; gnu:m4, open-mpi:hwloc) takes the
        sites of its vendor's other products. A vendor with a single product is that product's
        name too (nasm, whose one product is netwide_assembler)."""
        archive = NvdImport.verified(CPE_FEED, ".tar.gz")
        sites: dict[str, set[str]] = defaultdict(set)
        vendors: dict[str, set[str]] = defaultdict(set)
        names: dict[str, set[str]] = defaultdict(set)
        everything: dict[str, set[str]] = defaultdict(set)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            for member in tar:
                handle = tar.extractfile(member) if member.isfile() else None
                if handle is None:
                    continue
                for item in json.load(handle).get("products") or []:
                    cpe = item.get("cpe") or {}
                    if cpe.get("deprecated"):
                        continue
                    parts = str(cpe.get("cpeName") or "").split(":")
                    if len(parts) < 5 or parts[2] != "a":
                        continue
                    product = f"{parts[3]}:{parts[4]}"
                    names[product].add(CpeRule.name(parts[4]))
                    for title in cpe.get("titles") or []:
                        for acronym in re.findall(
                            r"\(([A-Za-z][\w.+-]{1,40})\)", str(title.get("title") or "")
                        ):
                            names[product].add(CpeRule.name(acronym))
                    for reference in cpe.get("refs") or []:
                        kind = str(reference.get("type") or "")
                        if kind == "Advisory":
                            continue
                        site = CpeRule.site(str(reference.get("ref") or ""))
                        if not site:
                            continue
                        sites[product].add(site)
                        everything[parts[3]].add(site)
                        if kind == "Vendor":
                            vendors[parts[3]].add(site)
        for product in named or ():
            vendor, _, title = product.partition(":")
            if product not in names and everything.get(vendor):
                names[product].add(CpeRule.name(title))
        products_of: dict[str, set[str]] = defaultdict(set)
        for product in names:
            products_of[product.split(":", 1)[0]].add(product)
        for vendor, owned in products_of.items():
            if len(owned) == 1:
                names[next(iter(owned))].add(CpeRule.name(vendor))
        index: dict[str, list[list[Any]]] = defaultdict(list)
        for product in sorted(names):
            vendor = product.split(":", 1)[0]
            found = sites.get(product, set()) | vendors.get(vendor, set())
            if not found and product not in sites:
                found = everything.get(vendor, set())
            if not found:
                continue
            for name in sorted(n for n in names[product] if n):
                index[name].append([product, sorted(found)])
        return dict(index)

    @staticmethod
    def write(output_dir: Path, built: NvdBuild, *, filtered: bool, seal: bool = True) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        NvdImport._write(
            output_dir / CVES_NAME,
            {
                "built_at": stamp,
                "filtered": filtered,
                "products": built.products,
                "text": built.text,
            },
        )
        NvdImport._write(
            output_dir / CPE_NAME,
            {"built_at": stamp, "curated": built.curated, "index": built.index},
        )
        # The digest manifest gains (or refreshes) these two entries; every other entry stays.
        path = output_dir / DIGESTS_NAME
        manifest: dict[str, Any] = {}
        with contextlib.suppress(OSError, ValueError):
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                manifest = {k: v for k, v in loaded.items() if isinstance(v, str)}
        for name in (CVES_NAME, CPE_NAME):
            manifest[name] = AdvisoryFiles.digest_of(output_dir / name)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        if seal:
            AdvisoryFiles.seal_manifest(output_dir)

    @staticmethod
    def _write(path: Path, data: dict[str, Any]) -> None:
        """Gzipped, mode 0600, byte-identical for identical input (`mtime=0`)."""
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with (
            os.fdopen(fd, "wb") as raw,
            gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as compressed,
        ):
            compressed.write(json.dumps(data, separators=(",", ":"), sort_keys=True).encode())

    @staticmethod
    def years(until: int | None = None) -> range:
        return range(FIRST_YEAR, (until or datetime.now(UTC).year) + 1)


__all__ = ["NvdBuild", "NvdImport", "NvdImportError"]
