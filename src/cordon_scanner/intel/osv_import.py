"""Building `intel/data/advisories-*.json` from OSV's own bulk export.

Not run at scan time and not run at package build time -- both would violate
C1/C2 (zero runtime dependencies, no network unless asked). This module is
invoked from two places, both explicit and both operator-initiated:

- `scripts/build_advisory_db.py`, from `.github/workflows/refresh-advisories.yml`
  (a scheduled job, mirroring the existing `refresh-intel.yml` pattern: fetch,
  validate, open a pull request, never push directly).
- `cordon-scanner advisories sync`, for an operator who wants current data
  without waiting for the next release. Writes to a user cache directory, not
  into the installed package -- see `intel/advisories.py`'s `bundled()`.

OSV publishes one zip per ecosystem at a fixed, documented, unauthenticated
URL (https://google.github.io/osv.dev/data/#data-dumps): every vulnerability
that ecosystem's exporter has resolved, as one JSON file per record. That is
the bulk-download route OSV itself recommends over querying its API once per
package, which is what makes this tractable at cordon's scale.

Written against `urllib` and `zipfile` from the standard library only, for the
same reason `intel/registry_client.py` is: C1 forbids a third-party runtime
dependency, and this module lives in `cordon_scanner.intel`, which
`cordon_scanner.cli` imports from.
"""

from __future__ import annotations

import contextlib
import gzip
import json
import os
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cordon_scanner.intel.advisories import (
    DIGESTS_NAME,
    Advisory,
    DatabaseMeta,
    digest_of,
)

OSV_HOST = "osv-vulnerabilities.storage.googleapis.com"
"""The one host this will talk to. Fixed, not derived from any input this
module takes -- the same reasoning as `registry_client.REGISTRY_HOSTS`: naming
the host is a decision an operator makes by invoking this at all, never a
parameter that flows in from anywhere else."""

TIMEOUT_SECONDS = 60.0
"""A bulk export is megabytes, not the few kilobytes `registry_client` bounds
for a single package lookup -- this is a different budget for a different,
explicitly-invoked operation."""

MAX_DOWNLOAD_BYTES = 256 << 20
"""Per-ecosystem ceiling on the compressed export. Real OSV exports run from
under a megabyte (Pub) to tens of megabytes (npm); this is headroom, not an
expectation, and it is enforced incrementally against the stream, not after
the fact -- the H4 lesson (archive/safe.py) applies here as much as it does to
a scan target's archive."""

MAX_UNCOMPRESSED_RECORD_BYTES = 8 << 20
"""One vulnerability record's JSON. A record this large is not a normal OSV
entry and is not read past this bound."""

USER_AGENT = "cordon-scanner (+https://github.com/Threx-code/cordon)"

#: cordon ecosystem id -> OSV's own ecosystem name in its bulk export paths.
#: https://ossf.github.io/osv-schema/#affectedpackage-field lists the set.
ECOSYSTEM_OSV_NAMES: dict[str, str] = {
    "npm": "npm",
    "pypi": "PyPI",
    "cargo": "crates.io",
    "gomod": "Go",
    "maven": "Maven",
    "nuget": "NuGet",
    "composer": "Packagist",
    "rubygems": "RubyGems",
    "pub": "Pub",
}
"""No entry for `gradle` -- it shares Maven's data, the same way
`intel/advisories.py._SHARED_DATA` maps it, so syncing `maven` is sufficient.
No entry for `cocoapods` -- OSV has no CocoaPods feed, the same gap
`intel/real.py` notes for its own per-ecosystem data."""


class OsvImportError(RuntimeError):
    """A sync step that could not complete. Raised rather than degrading to
    an empty result, so a caller invoking this explicitly learns that it
    failed rather than silently shipping nothing."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _download(url: str, dest: Path) -> None:
    """One bounded GET, streamed to `dest`. HTTPS and the fixed host only."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise OsvImportError(f"refusing a non-HTTPS URL: {url}")
    if parsed.netloc != OSV_HOST:
        raise OsvImportError(f"refusing a host outside the fixed allowlist: {parsed.netloc}")

    request = urllib.request.Request(  # noqa: S310  (scheme and host checked above)
        url, headers={"User-Agent": USER_AGENT}, method="GET"
    )
    opener = urllib.request.build_opener(_NoRedirect)

    written = 0
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response, dest.open("wb") as out:
            while True:
                chunk = response.read(1 << 20)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_DOWNLOAD_BYTES:
                    raise OsvImportError(f"{url}: exceeded {MAX_DOWNLOAD_BYTES} bytes, aborted")
                out.write(chunk)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as exc:
        raise OsvImportError(f"{type(exc).__name__} fetching {url}") from exc


def _severity_of(record: dict[str, Any]) -> str:
    database_specific = record.get("database_specific")
    if isinstance(database_specific, dict):
        severity = database_specific.get("severity")
        if isinstance(severity, str) and severity:
            return severity.lower()
    return ""


def _reference_of(record: dict[str, Any]) -> str:
    references = record.get("references")
    if not isinstance(references, list):
        return ""
    for ref in references:
        if isinstance(ref, dict) and ref.get("type") == "ADVISORY":
            url = ref.get("url")
            if isinstance(url, str) and url:
                return url
    for ref in references:
        if isinstance(ref, dict):
            url = ref.get("url")
            if isinstance(url, str) and url:
                return url
    return ""


#: Range types whose bounds are version strings this project can order.
#:
#: `ECOSYSTEM` orders by the registry's own rules and `SEMVER` by semantic
#: versioning, and `intel/versions.compare` already implements whichever of the
#: two an ecosystem uses -- so both are read here and the comparison is chosen
#: by the ecosystem, which is the only thing that knows how its versions sort.
#:
#: `GIT` is not read. Its bounds are commit hashes, and no ordering relates a
#: commit to the version string a lockfile records.
#:
#: Reading only `ECOSYSTEM` is what made this matter. OSV publishes npm,
#: crates.io and Go almost entirely as `SEMVER` -- 215,140 of 229,191 npm
#: records, 2,827 of 2,844 crates.io, 9,260 of 9,305 Go -- so skipping that type
#: left those three ecosystems with only the advisories that happen to carry an
#: exact version list. npm shipped 397 vulnerability records beside 23,550
#: malicious ones, and a lockfile pinning `lodash@4.17.15`, `axios@0.21.0` and
#: `minimist@1.2.0` reported nothing at all.
_ORDERED_RANGE_TYPES = frozenset({"ECOSYSTEM", "SEMVER"})


def _ranges_of(affected: dict[str, Any]) -> tuple[tuple[str | None, str | None, str | None], ...]:
    """Every orderable range's introduced/fixed/last_affected intervals.

    Not just the first. A single `affected` entry commonly carries more than
    one range -- separate fix branches for an old and a new major version is
    the ordinary shape, not an edge case: Django's PYSEC-2011-28 affects
    `[0, 1.1.3)` on its 1.1 branch *and*, separately, `[1.2, 1.2.4)` on its
    1.2 branch, as two entries in the same `ranges` array. An earlier version
    of this function returned only the first and silently dropped the
    second, which meant `django==1.2.1` -- squarely inside the range this
    function was throwing away -- matched nothing. `Advisory` has no way to
    hold more than one range, so the caller turns each of these into its own
    `Advisory` sharing the same identifier.

    Nor just the first interval *within* a range. One range's `events` array may
    describe several disjoint intervals -- `introduced 1.0`, `fixed 1.2`,
    `introduced 2.0`, `fixed 2.2` -- and folding them into a single triple
    produced `[1.0, 2.2)`, which claims every version between the two branches
    is affected when the whole point of the second pair is that 1.2 through 2.0
    are not. An `introduced` opens an interval and the next `fixed` or
    `last_affected` closes it.
    """
    ranges = affected.get("ranges")
    if not isinstance(ranges, list):
        return ()
    found: list[tuple[str | None, str | None, str | None]] = []
    for one_range in ranges:
        if not isinstance(one_range, dict):
            continue
        if one_range.get("type") not in _ORDERED_RANGE_TYPES:
            continue
        events = one_range.get("events")
        if not isinstance(events, list):
            continue

        introduced: str | None = None
        open_interval = False
        for event in events:
            if not isinstance(event, dict):
                continue
            if "introduced" in event:
                if open_interval:
                    # An `introduced` with no close before it: the previous
                    # interval runs to the end of the branch.
                    found.append((introduced, None, None))
                introduced = str(event["introduced"])
                open_interval = True
            elif "fixed" in event:
                found.append((introduced, str(event["fixed"]), None))
                introduced, open_interval = None, False
            elif "last_affected" in event:
                found.append((introduced, None, str(event["last_affected"])))
                introduced, open_interval = None, False
        if open_interval:
            found.append((introduced, None, None))

    return tuple(t for t in found if any(t))


def _same_osv_ecosystem(entry_ecosystem: str, osv_name: str | None) -> bool:
    """Whether an `affected[].package.ecosystem` string names the ecosystem
    this sync is for.

    Not a bare equality check. OSV's own schema allows a `"Ecosystem:suffix"`
    form to name a non-default registry within an ecosystem -- Drupal's
    contrib-module registry shows up as `"Packagist:https://packages.drupal.org/8"`,
    not `"Packagist"`. An equality check against the bare name silently
    dropped every one of those: 574 of 13,443 Packagist-shaped entries in a
    single sync, 4.3%, all Drupal module advisories, all with matching
    entirely -- not a coverage gap this project would have any way to
    notice, since the record still parses, it just names no package this
    sync ever recognised as its own. A package published through
    `packages.drupal.org` is still `drupal/jsonapi` in a `composer.lock`
    that resolved it from there, so it belongs under the same `composer`
    ecosystem cordon's own parser assigns it.
    """
    if osv_name is None:
        return False
    return entry_ecosystem == osv_name or entry_ecosystem.startswith(osv_name + ":")


def advisories_from_osv_record(ecosystem: str, record: dict[str, Any]) -> tuple[Advisory, ...]:
    """One OSV vulnerability record, one `Advisory` per package it affects.

    Usually one; OSV allows a single record (a multi-package security
    incident) to name several. `MAL-`-prefixed identifiers are OpenSSF's own
    malicious-package namespace -- a compromise, not a weakness -- and are
    reported as `malicious=True`; everything else is `malicious=False`.
    """
    identifier = str(record.get("id", ""))
    if not identifier:
        return ()
    malicious = identifier.startswith("MAL-")
    summary = str(record.get("summary") or record.get("details") or "")[:500]
    reference = _reference_of(record)
    severity = _severity_of(record)

    affected = record.get("affected")
    if not isinstance(affected, list):
        return ()

    osv_name = ECOSYSTEM_OSV_NAMES.get(ecosystem)
    results: list[Advisory] = []
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package")
        if not isinstance(package, dict):
            continue
        entry_ecosystem = package.get("ecosystem")
        if not isinstance(entry_ecosystem, str) or not _same_osv_ecosystem(
            entry_ecosystem, osv_name
        ):
            continue
        name = package.get("name")
        if not isinstance(name, str) or not name:
            continue

        versions_raw = entry.get("versions")
        versions = (
            tuple(str(v) for v in versions_raw)
            if isinstance(versions_raw, list) and versions_raw
            else ()
        )

        if versions:
            # An exact list beats a range when the source gives both (see
            # `advisories_from_osv_record`'s own docstring and
            # `TestExactVersionRecords`) -- exactly one `Advisory`, never one
            # per range, since there is no range to enumerate.
            ranges: tuple[tuple[str | None, str | None, str | None], ...] = ((None, None, None),)
        else:
            ranges = _ranges_of(entry)
            if not ranges:
                # Neither an exact list nor a usable range -- nothing this
                # record's `Advisory.affects` could ever match against.
                continue

        for introduced, fixed, last_affected in ranges:
            try:
                results.append(
                    Advisory(
                        ecosystem=ecosystem,
                        name=name,
                        versions=versions,
                        malicious=malicious,
                        summary=summary,
                        reference=reference,
                        identifier=identifier,
                        severity=severity,
                        introduced=introduced,
                        fixed=fixed,
                        last_affected=last_affected,
                    )
                )
            except ValueError:
                # `Advisory.__post_init__` refuses a record with both an
                # exact list and a range; cannot happen given the branch
                # above, but a malformed upstream record is not this sync's
                # crash to have.
                continue
    return tuple(results)


def sync_ecosystem(ecosystem: str, *, tmp_dir: Path) -> tuple[Advisory, ...]:
    """Download and parse one ecosystem's full OSV export."""
    osv_name = ECOSYSTEM_OSV_NAMES.get(ecosystem)
    if osv_name is None:
        raise OsvImportError(f"no OSV ecosystem mapping for {ecosystem!r}")

    archive_path = tmp_dir / f"{ecosystem}.zip"
    url = f"https://{OSV_HOST}/{urllib.parse.quote(osv_name)}/all.zip"
    _download(url, archive_path)

    records: list[Advisory] = []
    try:
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                if info.is_dir() or not info.filename.endswith(".json"):
                    continue
                if info.file_size > MAX_UNCOMPRESSED_RECORD_BYTES:
                    continue
                try:
                    raw = archive.read(info)
                except (zipfile.BadZipFile, OSError):
                    continue
                try:
                    record = json.loads(raw)
                except (json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(record, dict):
                    continue
                records.extend(advisories_from_osv_record(ecosystem, record))
    except zipfile.BadZipFile as exc:
        raise OsvImportError(f"{ecosystem}: not a valid zip export: {exc}") from exc
    finally:
        archive_path.unlink(missing_ok=True)

    return tuple(records)


@dataclass(frozen=True, slots=True)
class SyncResult:
    per_ecosystem: dict[str, tuple[Advisory, ...]]
    meta: DatabaseMeta


def _advisory_to_dict(advisory: Advisory) -> dict[str, Any]:
    data: dict[str, Any] = {
        "ecosystem": advisory.ecosystem,
        "name": advisory.name,
        "malicious": advisory.malicious,
        "summary": advisory.summary,
        "reference": advisory.reference,
        "id": advisory.identifier,
    }
    if advisory.versions:
        data["versions"] = list(advisory.versions)
    if advisory.severity:
        data["severity"] = advisory.severity
    if advisory.introduced:
        data["introduced"] = advisory.introduced
    if advisory.fixed:
        data["fixed"] = advisory.fixed
    if advisory.last_affected:
        data["last_affected"] = advisory.last_affected
    return data


def sync_all(ecosystems: tuple[str, ...], *, tmp_dir: Path) -> SyncResult:
    """Sync every requested ecosystem. Stops at the first failure.

    All-or-nothing on purpose: a partial write would let a later run of
    `AdvisoryDatabase.bundled()` mix an old npm snapshot with a fresh pypi one
    with no way to tell they are from different points in time, which is
    exactly the kind of silent inconsistency `DatabaseMeta.built_at` exists to
    prevent.
    """
    per_ecosystem: dict[str, tuple[Advisory, ...]] = {}
    for ecosystem in ecosystems:
        per_ecosystem[ecosystem] = sync_ecosystem(ecosystem, tmp_dir=tmp_dir)

    total = sum(len(v) for v in per_ecosystem.values())
    meta = DatabaseMeta(
        built_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        sources=tuple(f"osv:{e}" for e in ecosystems),
        record_count=total,
    )
    return SyncResult(per_ecosystem=per_ecosystem, meta=meta)


def _write_text_0600(path: Path, text: str) -> None:
    """Write `text` to `path`, never at a looser mode than `0600`.

    `cordon-scanner advisories sync` writes into the same cache root
    (`ScanCache.default_cache_dir()`) the scan-result cache uses, and that
    cache's own key file is `0600` for a reason worth applying here too: a
    different local user on a shared machine must not be able to plant or
    tamper with a file this project later reads back and trusts. The content
    here is not secret -- it is OSV's own public data -- so this is about
    integrity, not confidentiality, but the fix is the same: create with a
    restrictive mode from the start rather than write, then `chmod`, which
    leaves a window where the file is briefly whatever the process umask
    produced. Not `O_EXCL`: unlike the cache's key, this file is meant to be
    overwritten on every sync.
    """
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)


def _write_gzip_0600(path: Path, text: str) -> None:
    """`_write_text_0600`, compressed, and byte-identical for identical input.

    `mtime=0` because gzip stamps the current time into its header by default,
    which would make two builds of the same advisory set produce two different
    files and two different digests -- and the digest manifest beside them is
    what a later load checks the data against.
    """
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        raw = os.fdopen(fd, "wb")
    except BaseException:
        os.close(fd)
        raise
    with raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as compressed:
        compressed.write(text.encode("utf-8"))


def write_output(result: SyncResult, output_dir: Path) -> None:
    """Write the per-ecosystem JSON files and the metadata sidecar.

    The exact shape `AdvisoryDatabase._shipped`/`_meta` read, and the exact
    shape `AdvisoryDatabase.from_file` already accepts -- one format, not two.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        # Best-effort: `output_dir` is sometimes a CI build directory (from
        # `scripts/build_advisory_db.py`) where this is harmless, and
        # sometimes the user's persistent cache (from `advisories sync`)
        # where it is the point -- see `_write_text_0600`. Never fatal:
        # failing to tighten a permission is not a reason to fail a sync.
        output_dir.chmod(0o700)
    for ecosystem, records in result.per_ecosystem.items():
        path = output_dir / f"advisories-{ecosystem}.json.gz"
        _write_gzip_0600(
            path,
            json.dumps([_advisory_to_dict(a) for a in records], indent=2, sort_keys=True) + "\n",
        )
        # A directory synced before the data was compressed still holds the
        # plain file, and the loader prefers whichever is newer -- so a stale
        # one would win on mtime and quietly serve the previous sync's records.
        (output_dir / f"advisories-{ecosystem}.json").unlink(missing_ok=True)
    meta_path = output_dir / "advisories-meta.json"
    _write_text_0600(
        meta_path,
        json.dumps(
            {
                "built_at": result.meta.built_at,
                "sources": list(result.meta.sources),
                "record_count": result.meta.record_count,
                "filtered": result.meta.filtered,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )

    # Last, and over everything already written including the metadata. The
    # manifest is what lets the load path refuse a file that was edited after
    # it was built -- see `advisories.DIGESTS_NAME` for what that does and does
    # not prove. Written last so it can never record a digest for a file whose
    # write failed afterwards.
    digests = {
        path.name: digest_of(path)
        for path in sorted(
            [*output_dir.glob("advisories-*.json"), *output_dir.glob("advisories-*.json.gz")]
        )
        if path.name != DIGESTS_NAME
    }
    _write_text_0600(
        output_dir / DIGESTS_NAME,
        json.dumps(digests, indent=2, sort_keys=True) + "\n",
    )


__all__ = [
    "ECOSYSTEM_OSV_NAMES",
    "MAX_DOWNLOAD_BYTES",
    "OsvImportError",
    "SyncResult",
    "advisories_from_osv_record",
    "sync_all",
    "sync_ecosystem",
    "write_output",
]
