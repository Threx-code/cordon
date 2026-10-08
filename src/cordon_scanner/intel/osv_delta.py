"""Advisories published since the intel was built, fetched before a scan matches anything.

Bundled intel is as old as its release, and an advisory published an hour after the build
matches nothing until the next one. A Next.js SSRF advisory (GHSA-cjq9-62q9-8jv4) was published
about twenty hours after 0.6.0's intel was built, and `pnpm audit` caught what Cordon could not.
So unless the scan is offline, the changes are fetched first:

    GET <ecosystem>/modified_id.csv     OSV's list of every record, newest change first: read
                                        from the top, a few kilobytes, only down to the last
                                        refresh (an HTTP range at a time, never the whole file)
    GET <ecosystem>/<id>.json           each record changed since, a few kilobytes each

Nothing names a package: the requests are the same for everyone, so they say nothing about
what is scanned, which is the property `intel/feed.py` gives the signed feed. They go to OSV's
public bucket only (`osv_import.OSV_HOST`), over HTTPS, following no redirect. The records are
converted exactly as `advisories sync` converts them and kept as a sealed overlay in the user's
cache, applied on top of the database the way the feed's overlays are (`advisories.py`).
`--offline` and `CORDON_OFFLINE=1` make no attempt at all.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from cordon_scanner.core.local_seal import LocalSeal

SEAL_LABEL: Final = "osv-delta"
CHUNK: Final = 64 << 10
"""How much of a change list one range request reads."""
MAX_LIST_BYTES: Final = 4 << 20
"""The most of one ecosystem's change list read in one refresh: weeks of changes."""
MAX_CHANGES: Final = 3000
"""Past this many changed records in one ecosystem, the refresh says so and points at
`advisories sync`, which takes the whole export at once."""
MAX_RECORD_BYTES: Final = 1 << 20
TIMEOUT: Final = 8.0
RECHECK_SECONDS: Final = 15 * 60
"""A refresh this recent is current enough; the next scan within it makes no request."""
ONLY_IDS: Final[dict[str, str]] = {"GIT": "MAL-"}
"""Ecosystems whose import keeps one kind of record (`osv_import`: GIT's malicious repositories,
not its C and C++ commit ranges), so the rest of their churn is neither fetched nor counted."""
DISABLE_VARIABLE: Final = "CORDON_NO_ADVISORY_REFRESH"
"""Set to 1 to scan with the database as it is, without asking OSV what changed: for a pipeline
that refreshes on a schedule instead (`advisories sync`), or a test suite. `--offline` and
`CORDON_OFFLINE=1` also turn it off, along with every other network use."""
ENABLED: bool = os.environ.get(DISABLE_VARIABLE, "").strip().lower() not in (
    "1",
    "true",
    "yes",
    "on",
)
"""Read once at import. The test suite sets the variable as well as this, so a scanner it runs in
a subprocess does not reach the network either (`tests/conftest.py`)."""


class OsvDeltaError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


@dataclass(frozen=True)
class DeltaResult:
    through: float
    """The newest moment every ecosystem's changes are known through (epoch seconds), or 0."""
    records: int
    error: str = ""


class OsvDelta:
    """The incremental refresh: what changed since, as an overlay on the database."""

    @staticmethod
    def state_dir() -> Path:
        from cordon_scanner.intel.advisories import AdvisoryFiles

        return AdvisoryFiles.user_sync_dir() / "osv-delta"

    @staticmethod
    def overlay_path(ecosystem: str) -> Path:
        return OsvDelta.state_dir() / f"overlay-{ecosystem}.json"

    # -- Reading -------------------------------------------------------------------------

    @staticmethod
    def _load(ecosystem: str) -> dict[str, Any]:
        try:
            raw = json.loads(OsvDelta.overlay_path(ecosystem).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if not LocalSeal.valid(SEAL_LABEL, raw):
            return {}
        assert isinstance(raw, dict)  # noqa: S101 - established by valid()
        return LocalSeal.unsealed(raw)

    @staticmethod
    def read_overlay(ecosystem: str) -> tuple[list[dict[str, Any]], frozenset[str]]:
        """The records changed since the database was built, and the ids OSV withdrew."""
        state = OsvDelta._load(ecosystem)
        upserts = state.get("upsert", {})
        records = [
            r
            for records in (upserts.values() if isinstance(upserts, dict) else ())
            for r in (records if isinstance(records, list) else ())
            if isinstance(r, dict)
        ]
        return records, frozenset(str(i) for i in state.get("withdraw", ()))

    @staticmethod
    def through() -> float:
        """How far every ecosystem's changes are known through, from the last full refresh."""
        state = OsvDelta._load("_status")
        value = state.get("through", 0.0)
        return float(value) if isinstance(value, (int, float)) else 0.0

    @staticmethod
    def checked_at() -> float:
        value = OsvDelta._load("_status").get("checked_at", 0.0)
        return float(value) if isinstance(value, (int, float)) else 0.0

    # -- Fetching ------------------------------------------------------------------------

    @staticmethod
    def _get(path: str, *, byte_range: tuple[int, int] | None = None, limit: int) -> bytes:
        from cordon_scanner.intel.osv_import import OSV_HOST, USER_AGENT

        url = f"https://{OSV_HOST}/{path}"
        headers = {"User-Agent": USER_AGENT}
        if byte_range is not None:
            headers["Range"] = f"bytes={byte_range[0]}-{byte_range[1]}"
        request = urllib.request.Request(url, headers=headers)
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=TIMEOUT) as response:
                body = response.read(limit + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 416:  # a range past the end: the list was shorter than one chunk more
                return b""
            raise OsvDeltaError(f"HTTP {exc.code} from OSV") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise OsvDeltaError(f"OSV could not be reached ({type(exc).__name__})") from exc
        if len(body) > limit:
            raise OsvDeltaError("a response from OSV was larger than expected")
        return bytes(body)

    @staticmethod
    def _parse_time(text: str) -> float:
        return datetime.fromisoformat(text.strip().replace("Z", "+00:00")).timestamp()

    @staticmethod
    def changed_since(osv_name: str, since: float) -> tuple[list[tuple[float, str]], bool]:
        """`(modified, id)` for every record changed after `since`, newest first, and whether the
        list was read all the way down to `since` (False when a limit stopped it first)."""
        changes: list[tuple[float, str]] = []
        start, carry = 0, b""
        quoted = urllib.parse.quote(osv_name)
        while start < MAX_LIST_BYTES:
            chunk = OsvDelta._get(
                f"{quoted}/modified_id.csv", byte_range=(start, start + CHUNK - 1), limit=CHUNK
            )
            if not chunk:
                return changes, True
            start += len(chunk)
            lines = (carry + chunk).split(b"\n")
            carry = lines.pop() if len(chunk) == CHUNK else b""
            for line in lines + ([carry] if len(chunk) < CHUNK and carry else []):
                stamp, _, record = line.decode("utf-8", "replace").partition(",")
                if not record:
                    continue
                try:
                    modified = OsvDelta._parse_time(stamp)
                except ValueError:
                    continue
                if modified <= since:
                    return changes, True
                if not record.strip().startswith(ONLY_IDS.get(osv_name, "")):
                    continue
                changes.append((modified, record.strip()))
                if len(changes) > MAX_CHANGES:
                    return changes[:MAX_CHANGES], False
            if len(chunk) < CHUNK:
                return changes, True
        return changes, False

    @staticmethod
    def _record(osv_name: str, record_id: str) -> dict[str, Any] | None:
        safe = urllib.parse.quote(record_id, safe="-._")
        body = OsvDelta._get(f"{urllib.parse.quote(osv_name)}/{safe}.json", limit=MAX_RECORD_BYTES)
        try:
            value = json.loads(body)
        except ValueError:
            return None
        return value if isinstance(value, dict) else None

    @staticmethod
    def refresh_ecosystem(ecosystem: str, since: float) -> tuple[int, bool]:
        """Fetch one ecosystem's changes since `since` into its overlay: (records, complete)."""
        from cordon_scanner.intel.osv_import import ECOSYSTEM_OSV_NAMES, OsvImport

        osv_name = ECOSYSTEM_OSV_NAMES[ecosystem]
        changes, complete = OsvDelta.changed_since(osv_name, since)
        state = OsvDelta._load(ecosystem)
        upserts: dict[str, list[dict[str, Any]]] = dict(state.get("upsert", {}) or {})
        withdrawn: set[str] = {str(i) for i in state.get("withdraw", ())}
        ids = list(dict.fromkeys(record_id for _, record_id in changes))
        with ThreadPoolExecutor(max_workers=8) as pool:
            records = list(pool.map(lambda i: OsvDelta._record(osv_name, i), ids))
        for record_id, record in zip(ids, records, strict=True):
            if record is None:
                continue
            if record.get("withdrawn"):
                withdrawn.add(record_id)
                upserts.pop(record_id, None)
                continue
            converted = [
                OsvImport._advisory_to_dict(a)
                for a in OsvImport.advisories_from_osv_record(ecosystem, record)
            ]
            withdrawn.discard(record_id)
            if converted:
                upserts[record_id] = converted
            else:
                upserts.pop(record_id, None)
        OsvDelta._write(ecosystem, {"upsert": upserts, "withdraw": sorted(withdrawn)})
        return len(ids), complete

    @staticmethod
    def _write(name: str, document: dict[str, Any]) -> None:
        directory = OsvDelta.state_dir()
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = OsvDelta.overlay_path(name)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(json.dumps(LocalSeal.sealed(SEAL_LABEL, document)), encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(path)

    @staticmethod
    def refresh(since: float, now: float | None = None) -> DeltaResult:
        """Every advisory ecosystem's changes since `since`, or since the last refresh if later.

        Ecosystems are refreshed in parallel and independently: one that cannot be reached is
        named in the error and the others still apply. `through` advances only when every
        ecosystem's list was read down to the starting point."""
        from cordon_scanner.intel.osv_import import ECOSYSTEM_OSV_NAMES

        now = time.time() if now is None else now
        if not ENABLED:
            return DeltaResult(through=0.0, records=0, error="the refresh is disabled")
        start = max(since, OsvDelta.through())
        failures: list[str] = []
        total = 0
        complete = True
        ecosystems = sorted(ECOSYSTEM_OSV_NAMES)

        def one(ecosystem: str) -> tuple[str, int, bool, str]:
            try:
                count, done = OsvDelta.refresh_ecosystem(ecosystem, start)
            except OsvDeltaError as exc:
                return ecosystem, 0, False, str(exc)
            return ecosystem, count, done, ""

        with ThreadPoolExecutor(max_workers=6) as pool:
            for ecosystem, count, done, error in pool.map(one, ecosystems):
                total += count
                complete = complete and done
                if error:
                    failures.append(f"{ecosystem}: {error}")
        through = now if complete and not failures else 0.0
        status = {"checked_at": now, "through": through or OsvDelta.through()}
        OsvDelta._write("_status", status)
        error = ""
        if failures:
            error = f"{len(failures)} ecosystem(s) could not be refreshed ({failures[0]})"
        elif not complete:
            error = f"more than {MAX_CHANGES} changes in an ecosystem; run `cordon-scanner advisories sync`"
        return DeltaResult(through=through, records=total, error=error)


__all__ = ["DeltaResult", "OsvDelta", "OsvDeltaError"]
