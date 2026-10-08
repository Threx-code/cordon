"""Fresh threat intel from Cordon's signed public feed, verified TUF-style.

A scan reads your code and never leaves your machine. The intel it matches against is a
different thing: what is known to be bad, which has to be minutes old rather than as old as the
last release. So by default a scan first pulls the public feed - static, signed files that are
identical for everyone - and then scans locally. Nothing about the code is sent: the feed host
learns only that somebody fetched the feed.

## What is verified, and against what

The feed follows The Update Framework's shape, cut to what this client needs:

    root.json        the keys and thresholds for every role; shipped with the package, pinned
    timestamp.json   short-lived, re-signed often; names the current snapshot by hash
    snapshot.json    names the current targets metadata by hash
    targets.json     the current serial, and every delta and full bundle by length and sha256
    deltas/<n>.json.gz, full/<n>.tar.gz

Every metadata file is signed Ed25519 by its role's keys up to the role's threshold, verified
with the vendored verify-only `_ed25519`. The guarantees and the attack each closes:

* **Rollback.** A version or serial lower than the highest this client has seen is refused, so
  a validly signed OLD feed cannot be replayed to hide newer malware.
* **Freeze.** An expired timestamp is refused, so an attacker who blocks updates cannot keep a
  client on stale data without the client noticing: it reports the intel as stale instead.
* **Mix and match.** Each file is pinned by length and sha256 in the metadata above it, so no
  file can be swapped for another validly signed one.
* **Key rotation.** A new root must be signed by a threshold of the old root's keys and of its
  own, so trust moves forward one signed step at a time.

## Failure is never silent, and never a hang

The first request uses a three-second timeout, so air-gapped CI that forgot `--offline` loses
three seconds, not a job. An unreachable, invalid or expired feed leaves the last verified intel
in place, and the scan reports its age; past `max_intel_age` it says the intel is stale.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from cordon_scanner.core.local_seal import LocalSeal
from cordon_scanner.intel import _ed25519

SPEC: Final = "cordon-feed/1"
DEFAULT_URL: Final = "https://feed.cordon.dev/v1"
URL_VARIABLE: Final = "CORDON_FEED_URL"
"""A mirror. Safe to point anywhere: every byte is still verified against the pinned root."""

OFFLINE_VARIABLE: Final = "CORDON_OFFLINE"

ROOT_FILE: Final = Path(__file__).parent / "data" / "feed-root.json"
"""The root of trust, pinned in the package. Absent until the feed's key ceremony, and while it
is absent the feed is off: no request is made and intel comes from the installed database."""

METADATA_TIMEOUT: Final = 3.0
DATA_TIMEOUT: Final = 30.0
MAX_METADATA_BYTES: Final = 1 << 20
MAX_DATA_BYTES: Final = 256 << 20
MAX_ROOT_STEPS: Final = 32
DEFAULT_MAX_AGE: Final = 24 * 60 * 60
BUNDLED_MAX_AGE: Final = 30 * 24 * 60 * 60
"""How old installed intel may be when there is no feed to refresh it."""
USER_AGENT: Final = "cordon-scanner feed (+https://github.com/Threx-code/cordon)"

Fetch = Callable[[str, float, int], bytes]
"""Returns a URL's body, at most `limit` bytes, or raises `FeedError`. Replaced in tests."""


class FeedError(Exception):
    """The feed could not be used. Carries a message that is safe to show."""


class FeedRoles:
    """The feed's signed roles: canonical bytes, key ids, thresholds and expiry."""

    # -- Canonical form and signatures -------------------------------------------------------

    @staticmethod
    def canonical(value: Any) -> bytes:
        """The bytes a role signs: sorted keys, no insignificant whitespace, UTF-8."""
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

    @staticmethod
    def key_id(key: Mapping[str, Any]) -> str:
        return hashlib.sha256(FeedRoles.canonical(dict(key))).hexdigest()

    @staticmethod
    def verify_role(
        document: Mapping[str, Any], role: str, root: Mapping[str, Any], *, expected_type: str
    ) -> Mapping[str, Any]:
        """The document's `signed` part, once a threshold of `role`'s keys in `root` signed it."""
        signed = document.get("signed")
        signatures = document.get("signatures")
        if not isinstance(signed, dict) or not isinstance(signatures, list):
            raise FeedError(f"{expected_type} metadata is malformed")
        if signed.get("_type") != expected_type or signed.get("spec") != SPEC:
            raise FeedError(f"{expected_type} metadata has the wrong type or spec")
        roles = root.get("roles", {})
        keys = root.get("keys", {})
        spec = roles.get(role) if isinstance(roles, dict) else None
        if not isinstance(spec, dict) or not isinstance(keys, dict):
            raise FeedError(f"the root does not define the {role} role")
        threshold = int(spec.get("threshold", 0))
        if threshold < 1:
            raise FeedError(f"the {role} role has no usable threshold")
        allowed = set(spec.get("keyids", ()))
        message = FeedRoles.canonical(signed)
        good: set[str] = set()
        for entry in signatures:
            if not isinstance(entry, dict):
                continue
            keyid = str(entry.get("keyid", ""))
            if keyid not in allowed or keyid in good:
                continue
            key = keys.get(keyid)
            if not isinstance(key, dict) or key.get("keytype") != "ed25519":
                continue
            try:
                public = bytes.fromhex(str(key.get("public", "")))
                signature = bytes.fromhex(str(entry.get("sig", "")))
            except ValueError:
                continue
            if _ed25519.Ed25519.verify(public, message, signature):
                good.add(keyid)
        if len(good) < threshold:
            raise FeedError(
                f"{expected_type} metadata is signed by {len(good)} of the {threshold} {role} key(s) required"
            )
        return signed

    @staticmethod
    def _expires(signed: Mapping[str, Any]) -> float:
        try:
            return FeedRoles._parse_time(str(signed["expires"]))
        except (KeyError, ValueError) as exc:
            raise FeedError(f"{signed.get('_type', 'metadata')} has no valid expiry") from exc

    @staticmethod
    def _parse_time(value: str) -> float:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC).timestamp()

    @staticmethod
    def _format_time(epoch: float) -> str:
        return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _pinned(body: bytes, meta: Mapping[str, Any], what: str) -> None:
        if len(body) != int(meta.get("length", -1)):
            raise FeedError(f"{what} has the wrong length")
        if hashlib.sha256(body).hexdigest() != meta.get("sha256"):
            raise FeedError(f"{what} does not match its pinned sha256")


# -- Transport ---------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class FeedClient:
    """Refreshing from the feed and reporting how current the intel is."""

    @staticmethod
    def _fetch(url: str, timeout: float, limit: int) -> bytes:
        if urllib.parse.urlsplit(url).scheme != "https":
            raise FeedError("refusing a non-HTTPS feed URL")
        request = urllib.request.Request(  # noqa: S310 - scheme checked above
            url, headers={"User-Agent": USER_AGENT}, method="GET"
        )
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=timeout) as response:
                body = response.read(limit + 1)
        except urllib.error.HTTPError as exc:
            raise FeedError(f"HTTP {exc.code} from the feed") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise FeedError(f"the feed could not be reached ({type(exc).__name__})") from exc
        if len(body) > limit:
            raise FeedError("a feed file exceeded its size limit")
        return bytes(body)

    # -- The scan-time entry point -----------------------------------------------------------

    @staticmethod
    def offline_requested(environ: Mapping[str, str] | None = None) -> bool:
        value = (os.environ if environ is None else environ).get(OFFLINE_VARIABLE, "")
        return value.strip().lower() in ("1", "true", "yes", "on")

    @staticmethod
    def _database_built_at() -> float:
        """When the database in use (synced or shipped, whichever is newer) was built."""
        from cordon_scanner.intel.advisories import DATA_DIR, AdvisoryFiles

        built = [AdvisoryFiles._read_meta(DATA_DIR).built_at]
        if AdvisoryFiles.trusted_user_file("advisories-meta.json") is not None:
            built.append(AdvisoryFiles._read_meta(AdvisoryFiles.user_sync_dir()).built_at)
        times = []
        for value in built:
            try:
                times.append(FeedRoles._parse_time(value) if value else 0.0)
            except ValueError:
                times.append(0.0)
        return max(times)

    @staticmethod
    def status(
        *,
        use_feed: bool,
        max_age: int | None,
        feed: Feed | None = None,
        now: float | None = None,
    ) -> IntelStatus:
        """Refresh from the feed when allowed and available, and report how current the intel is.

        `max_age` is `None` for "the default": 24 hours when the feed is available to this build,
        and no staleness check when it is not, because a build with no feed has no way to become
        fresh and would otherwise fail every scan a day after its release. An explicit value always
        applies, and 0 turns the check off.
        """
        feed = feed if feed is not None else Feed.default()
        now = time.time() if now is None else now
        refreshed = False
        error = ""
        if use_feed and feed.enabled:
            try:
                feed.update()
                refreshed = True
            except FeedError as exc:
                error = str(exc)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                error = f"the feed could not be applied ({type(exc).__name__})"
            if refreshed:
                from cordon_scanner.intel import advisories

                advisories.ShippedAdvisories.reset_caches()

        state = FeedState.load(feed._dir())
        # Advisories OSV published or changed since the database was built (`intel/osv_delta`):
        # without this, bundled intel misses everything after its build until the next release.
        delta_through = 0.0
        from cordon_scanner.intel import osv_delta

        if use_feed and osv_delta.ENABLED:
            delta = osv_delta.OsvDelta
            if now - delta.checked_at() >= osv_delta.RECHECK_SECONDS:
                result = delta.refresh(since=FeedClient._database_built_at(), now=now)
                if result.error and not refreshed:
                    error = f"advisories since the build: {result.error}"
                from cordon_scanner.intel import advisories as _advisories

                _advisories.ShippedAdvisories.reset_caches()
            delta_through = delta.through()
        elif use_feed and not feed.enabled:
            error = "no feed root is pinned in this build"

        if state.serial and state.fresh_at:
            source, fresh_at, serial = "feed", state.fresh_at, state.serial
        else:
            from cordon_scanner.intel.advisories import DATA_DIR, AdvisoryFiles

            synced, shipped = (
                AdvisoryFiles._read_meta(AdvisoryFiles.user_sync_dir())
                if AdvisoryFiles.trusted_user_file("advisories-meta.json") is not None
                else AdvisoryFiles._read_meta(DATA_DIR),
                AdvisoryFiles._read_meta(DATA_DIR),
            )
            chosen, source = (
                (synced, "bundle") if synced.built_at > shipped.built_at else (shipped, "package")
            )
            serial = 0
            try:
                fresh_at = FeedRoles._parse_time(chosen.built_at) if chosen.built_at else 0.0
            except ValueError:
                fresh_at = 0.0
        if delta_through > fresh_at:
            source, fresh_at = "osv", delta_through
        age = int(max(0.0, now - fresh_at)) if fresh_at else None

        # With no feed, intel is as old as the release or the last sync, and that age was never
        # judged: a database a year old read as current. Without a feed the limit is a month.
        effective = (
            max_age
            if max_age is not None
            else (
                DEFAULT_MAX_AGE
                if feed.enabled or (use_feed and osv_delta.ENABLED)
                else BUNDLED_MAX_AGE
            )
        )
        stale = bool(effective) and (age is None or age > int(effective or 0))
        return IntelStatus(
            source=source,
            age_seconds=age,
            serial=serial,
            refreshed=refreshed,
            error=error,
            stale=stale,
            max_age_seconds=effective,
            feed_enabled=feed.enabled,
        )


class FeedStore:
    """What the feed has installed on disk: overlays, deltas and full bundles."""

    # -- Local state -------------------------------------------------------------------------

    @staticmethod
    def state_dir() -> Path:
        """Beside the synced advisory database, which the feed's full bundles replace."""
        from cordon_scanner.intel.advisories import AdvisoryFiles

        return AdvisoryFiles.user_sync_dir() / "feed"

    @staticmethod
    def overlay_path(ecosystem: str) -> Path:
        return FeedStore.state_dir() / f"overlay-{ecosystem}.json"

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_bytes(data)
        temporary.replace(path)

    # -- Deltas and overlays -----------------------------------------------------------------

    MAX_DELTA_BYTES = 64 << 20
    """What one delta may decompress to. A delta is pinned by the signed `targets.json`, so only a
    feed signer could ship a bomb - but `gzip.decompress` had no ceiling at all, and a compromised
    signer should cost a wrong advisory, not every client's memory (`package.md` PK-09)."""

    @staticmethod
    def _read_delta(body: bytes, serial: int) -> Mapping[str, Any]:
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:
                inflated = stream.read(FeedStore.MAX_DELTA_BYTES + 1)
            if len(inflated) > FeedStore.MAX_DELTA_BYTES:
                raise FeedError(f"delta {serial} expands past {FeedStore.MAX_DELTA_BYTES} bytes")
            delta = json.loads(inflated)
        except (OSError, ValueError, EOFError) as exc:
            raise FeedError(f"delta {serial} could not be read") from exc
        if not isinstance(delta, dict) or int(delta.get("serial", -1)) != serial:
            raise FeedError(f"delta {serial} does not carry its own serial")
        return delta

    @staticmethod
    def _load_overlays() -> dict[str, dict[str, Any]]:
        overlays: dict[str, dict[str, Any]] = {}
        directory = FeedStore.state_dir()
        for path in directory.glob("overlay-*.json") if directory.is_dir() else ():
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            # Only an overlay this install wrote: merging an unsealed one and resealing it would
            # launder a planted withdrawal into a trusted one.
            if LocalSeal.valid("feed-overlay", raw):
                overlays[path.stem.removeprefix("overlay-")] = LocalSeal.unsealed(raw)
        return overlays

    @staticmethod
    def _save_overlays(overlays: Mapping[str, Mapping[str, Any]], *, replace: bool = False) -> None:
        directory = FeedStore.state_dir()
        directory.mkdir(parents=True, exist_ok=True)
        if replace:
            for path in directory.glob("overlay-*.json"):
                path.unlink()
        for ecosystem, overlay in overlays.items():
            FeedStore._atomic_write(
                FeedStore.overlay_path(ecosystem),
                FeedRoles.canonical(LocalSeal.sealed("feed-overlay", dict(overlay))),
            )

    @staticmethod
    def _merge_delta(overlays: dict[str, dict[str, Any]], delta: Mapping[str, Any]) -> None:
        """Fold one delta in. A later upsert of an id replaces an earlier one; a withdrawal wins."""
        advisories = delta.get("advisories") or {}
        if not isinstance(advisories, dict):
            raise FeedError("a delta's advisories are malformed")
        for ecosystem, change in advisories.items():
            if not isinstance(change, dict):
                continue
            current = overlays.setdefault(str(ecosystem), {"upsert": {}, "withdraw": []})
            upserts: dict[str, Any] = current.setdefault("upsert", {})
            withdrawn = set(current.get("withdraw", ()))
            for record in change.get("upsert", ()):
                if isinstance(record, dict) and record.get("id") and record.get("name"):
                    upserts[str(record["id"])] = record
                    withdrawn.discard(str(record["id"]))
            for identifier in change.get("withdraw", ()):
                upserts.pop(str(identifier), None)
                withdrawn.add(str(identifier))
            current["withdraw"] = sorted(withdrawn)

    @staticmethod
    def read_overlay(ecosystem: str) -> tuple[list[dict[str, Any]], frozenset[str]]:
        """The feed's additions and withdrawals for one ecosystem, applied on top of its database."""
        try:
            raw = json.loads(FeedStore.overlay_path(ecosystem).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return [], frozenset()
        if not LocalSeal.valid("feed-overlay", raw):
            return [], frozenset()
        assert isinstance(raw, dict)  # noqa: S101 - established by valid()
        upserts = raw.get("upsert", {})
        records = (
            [r for r in upserts.values() if isinstance(r, dict)]
            if isinstance(upserts, dict)
            else []
        )
        return records, frozenset(str(i) for i in raw.get("withdraw", ()))

    @staticmethod
    def _install_full(body: bytes) -> None:
        """Install a full bundle into the synced database directory. Hash-pinned by targets."""
        from cordon_scanner.intel.advisories import AdvisoryFiles

        destination = AdvisoryFiles.user_sync_dir()
        staging = destination.with_name(destination.name + ".staging")
        if staging.exists():
            FeedStore._remove_tree(staging)
        staging.mkdir(parents=True)
        try:
            with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
                for member in archive.getmembers():
                    if not member.isreg() or "/" in member.name or member.name.startswith("."):
                        raise FeedError(
                            f"the full bundle carries an unexpected member: {member.name}"
                        )
                archive.extractall(staging, filter="data")
        except (tarfile.TarError, OSError) as exc:
            FeedStore._remove_tree(staging)
            raise FeedError("the full bundle could not be unpacked") from exc
        bad = AdvisoryFiles.verify_data_dir(staging)
        if bad:
            FeedStore._remove_tree(staging)
            raise FeedError(f"the full bundle does not match its own manifest: {', '.join(bad)}")
        destination.mkdir(parents=True, exist_ok=True)
        installed_at = time.time()
        for path in staging.iterdir():
            # Stamped with the install time. The loader prefers the fresher of the synced and the
            # shipped copy by modification time, and a tar member's own mtime (often the epoch, for
            # a reproducible build) would lose to the package's older file.
            os.utime(path, (installed_at, installed_at))
            path.replace(destination / path.name)
        FeedStore._remove_tree(staging)
        # Verified against the feed's signed targets above; sealed so later scans trust it.
        AdvisoryFiles.seal_manifest(destination)

    @staticmethod
    def _remove_tree(path: Path) -> None:
        for child in sorted(path.rglob("*"), reverse=True):
            if child.is_dir():
                child.rmdir()
            else:
                child.unlink()
        path.rmdir()


@dataclass
class FeedState:
    """What this client has verified so far. Only ever moves forward."""

    root: dict[str, Any] | None = None
    timestamp_version: int = 0
    snapshot_version: int = 0
    targets_version: int = 0
    serial: int = 0
    fresh_at: float = 0.0
    """When the feed last proved its intel current: the verified timestamp's issue time."""
    built_at: str = ""

    @staticmethod
    def load(directory: Path) -> FeedState:
        try:
            raw = json.loads((directory / "state.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return FeedState()
        # Sealed by this install: a state file anyone else wrote could reset the versions
        # rollback protection compares against.
        if not LocalSeal.valid("feed-state", raw):
            return FeedState()
        assert isinstance(raw, dict)  # noqa: S101 - established by valid()
        state = FeedState(
            timestamp_version=int(raw.get("timestamp_version", 0)),
            snapshot_version=int(raw.get("snapshot_version", 0)),
            targets_version=int(raw.get("targets_version", 0)),
            serial=int(raw.get("serial", 0)),
            fresh_at=float(raw.get("fresh_at", 0.0)),
            built_at=str(raw.get("built_at", "")),
        )
        try:
            root = json.loads((directory / "root.json").read_text(encoding="utf-8"))
            # A stored root is a root this install verified through the chain from the pinned
            # one. Self-signed is not enough: anyone can self-sign a root at version 999.
            state.root = LocalSeal.unsealed(root) if LocalSeal.valid("feed-root", root) else None
        except (OSError, ValueError):
            state.root = None
        return state

    def save(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        if self.root is not None:
            FeedStore._atomic_write(
                directory / "root.json",
                FeedRoles.canonical(LocalSeal.sealed("feed-root", self.root)),
            )
        FeedStore._atomic_write(
            directory / "state.json",
            FeedRoles.canonical(
                LocalSeal.sealed(
                    "feed-state",
                    {
                        "timestamp_version": self.timestamp_version,
                        "snapshot_version": self.snapshot_version,
                        "targets_version": self.targets_version,
                        "serial": self.serial,
                        "fresh_at": self.fresh_at,
                        "built_at": self.built_at,
                    },
                )
            ),
        )


# -- Status reported with every scan -----------------------------------------------------


@dataclass(frozen=True)
class IntelStatus:
    """How current the intel behind a scan was. Reported in every result."""

    source: str
    """`feed` (verified this run or earlier), `bundle` (a synced database) or `package`."""
    age_seconds: int | None
    serial: int = 0
    refreshed: bool = False
    """Whether this scan verified the feed itself, rather than using what was already on disk."""
    error: str = ""
    """Why the feed could not be used this run, when it could not. Safe to show."""
    stale: bool = False
    max_age_seconds: int | None = None
    feed_enabled: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "age_seconds": self.age_seconds,
            "serial": self.serial,
            "refreshed": self.refreshed,
            "error": self.error,
            "stale": self.stale,
            "max_age_seconds": self.max_age_seconds,
            "feed_enabled": self.feed_enabled,
        }


# -- The client --------------------------------------------------------------------------


@dataclass
class Feed:
    """One feed endpoint and the root it is verified against."""

    base_url: str = DEFAULT_URL
    root: dict[str, Any] | None = None
    fetch: Fetch = field(default=FeedClient._fetch)
    directory: Path | None = None
    clock: Callable[[], float] = time.time

    @staticmethod
    def pinned_root() -> dict[str, Any] | None:
        try:
            raw = json.loads(ROOT_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return raw if isinstance(raw, dict) else None

    @classmethod
    def default(cls, environ: Mapping[str, str] | None = None) -> Feed:
        environ = os.environ if environ is None else environ
        return cls(base_url=environ.get(URL_VARIABLE, DEFAULT_URL), root=cls.pinned_root())

    @property
    def enabled(self) -> bool:
        return self.root is not None

    def _dir(self) -> Path:
        return self.directory if self.directory is not None else FeedStore.state_dir()

    def _get(self, name: str, *, timeout: float, limit: int) -> bytes:
        return self.fetch(f"{self.base_url.rstrip('/')}/{name}", timeout, limit)

    def _document(self, name: str) -> Mapping[str, Any]:
        body = self._get(name, timeout=METADATA_TIMEOUT, limit=MAX_METADATA_BYTES)
        try:
            document = json.loads(body)
        except ValueError as exc:
            raise FeedError(f"{name} is not valid JSON") from exc
        if not isinstance(document, dict):
            raise FeedError(f"{name} is malformed")
        return document

    def update(self) -> FeedState:
        """Verify the feed and apply anything new. Raises `FeedError`; never half-applies."""
        if self.root is None:
            raise FeedError("no feed root is pinned in this build, so the feed is off")
        directory = self._dir()
        state = FeedState.load(directory)
        now = self.clock()

        root_document = self._rotate_root(self._trusted_root(state), now)
        trusted = root_document["signed"]

        timestamp = FeedRoles.verify_role(
            self._document("timestamp.json"), "timestamp", trusted, expected_type="timestamp"
        )
        version = int(timestamp.get("version", 0))
        if version < state.timestamp_version:
            raise FeedError(
                f"the feed offered timestamp version {version}, older than {state.timestamp_version}: refused as a rollback"
            )
        if FeedRoles._expires(timestamp) <= now:
            raise FeedError("the feed's timestamp has expired: refused as a freeze")
        snapshot_meta = timestamp.get("snapshot")
        if not isinstance(snapshot_meta, dict):
            raise FeedError("the timestamp does not name a snapshot")

        state.root = dict(root_document)
        if (
            int(snapshot_meta.get("version", 0)) != state.snapshot_version
            or not state.targets_version
        ):
            self._apply_snapshot(state, snapshot_meta, trusted, now)

        state.timestamp_version = version
        try:
            state.fresh_at = FeedRoles._parse_time(str(timestamp.get("issued", "")))
        except ValueError:
            state.fresh_at = now
        state.fresh_at = min(state.fresh_at, now)
        state.save(directory)
        return state

    def _trusted_root(self, state: FeedState) -> Mapping[str, Any]:
        """The newest root document this client trusts, verified: pinned, or rotated to since."""
        if self.root is None:
            raise FeedError("no feed root is pinned in this build, so the feed is off")
        pinned = FeedRoles.verify_role(self.root, "root", self.root["signed"], expected_type="root")
        stored = state.root
        if stored is not None:
            try:
                signed = FeedRoles.verify_role(
                    stored, "root", stored["signed"], expected_type="root"
                )
            except (FeedError, KeyError, TypeError):
                signed = None
            # A stored root is used only if it is newer than the pinned one, so an upgraded
            # package brings its own trust with it and a tie resolves to the package.
            if signed is not None and int(signed.get("version", 0)) > int(pinned.get("version", 0)):
                return stored
        return self.root

    def _rotate_root(self, document: Mapping[str, Any], now: float) -> Mapping[str, Any]:
        """Follow `<n+1>.root.json` while the feed publishes one; each step signed by both roots."""
        for _ in range(MAX_ROOT_STEPS):
            trusted = document["signed"]
            following = int(trusted.get("version", 0)) + 1
            try:
                candidate = self._document(f"{following}.root.json")
            except FeedError:
                break
            FeedRoles.verify_role(candidate, "root", trusted, expected_type="root")
            signed = FeedRoles.verify_role(
                candidate, "root", candidate["signed"], expected_type="root"
            )
            if int(signed.get("version", 0)) != following:
                raise FeedError("a rotated root carries the wrong version")
            document = candidate
        if FeedRoles._expires(document["signed"]) <= now:
            raise FeedError("the feed's root metadata has expired")
        return document

    def _apply_snapshot(
        self,
        state: FeedState,
        snapshot_meta: Mapping[str, Any],
        trusted: Mapping[str, Any],
        now: float,
    ) -> None:
        body = self._get("snapshot.json", timeout=METADATA_TIMEOUT, limit=MAX_METADATA_BYTES)
        FeedRoles._pinned(body, snapshot_meta, "snapshot.json")
        snapshot = FeedRoles.verify_role(
            json.loads(body), "snapshot", trusted, expected_type="snapshot"
        )
        if int(snapshot.get("version", 0)) < state.snapshot_version:
            raise FeedError("the feed offered an older snapshot: refused as a rollback")
        if FeedRoles._expires(snapshot) <= now:
            raise FeedError("the feed's snapshot has expired")
        targets_meta = snapshot.get("targets")
        if not isinstance(targets_meta, dict):
            raise FeedError("the snapshot does not name the targets metadata")

        body = self._get("targets.json", timeout=METADATA_TIMEOUT, limit=MAX_METADATA_BYTES)
        FeedRoles._pinned(body, targets_meta, "targets.json")
        targets = FeedRoles.verify_role(
            json.loads(body), "targets", trusted, expected_type="targets"
        )
        if int(targets.get("version", 0)) < state.targets_version:
            raise FeedError("the feed offered older targets: refused as a rollback")
        if FeedRoles._expires(targets) <= now:
            raise FeedError("the feed's targets metadata has expired")
        serial = int(targets.get("serial", 0))
        if serial < state.serial:
            raise FeedError(
                f"the feed is at serial {serial}, behind the {state.serial} already applied: refused as a rollback"
            )

        if serial > state.serial:
            self._apply_targets(state, targets, serial)

        state.snapshot_version = int(snapshot.get("version", 0))
        state.targets_version = int(targets.get("version", 0))
        state.serial = serial
        state.built_at = str(targets.get("built_at", ""))

    def _apply_targets(self, state: FeedState, targets: Mapping[str, Any], serial: int) -> None:
        deltas = targets.get("deltas") or {}
        full = targets.get("full") or {}
        needed = range(state.serial + 1, serial + 1)
        have_all = isinstance(deltas, dict) and all(str(n) in deltas for n in needed)
        # Deltas when the client is close enough to be caught up by them; the full bundle when
        # it is new or has fallen behind the oldest delta the feed still carries.
        if state.serial and have_all:
            overlays = FeedStore._load_overlays()
            for number in needed:
                meta = deltas[str(number)]
                body = self._get(str(meta["path"]), timeout=DATA_TIMEOUT, limit=MAX_DATA_BYTES)
                FeedRoles._pinned(body, meta, f"delta {number}")
                FeedStore._merge_delta(overlays, FeedStore._read_delta(body, number))
            FeedStore._save_overlays(overlays)
            return
        if not isinstance(full, dict) or not full.get("path"):
            raise FeedError("the feed offers no path from this client's serial to the current one")
        body = self._get(str(full["path"]), timeout=DATA_TIMEOUT, limit=MAX_DATA_BYTES)
        FeedRoles._pinned(body, full, "the full bundle")
        FeedStore._install_full(body)
        full_serial = int(full.get("serial", serial))
        fresh: dict[str, dict[str, Any]] = {}
        for number in range(full_serial + 1, serial + 1):
            meta = deltas.get(str(number)) if isinstance(deltas, dict) else None
            if not isinstance(meta, dict):
                raise FeedError(f"the feed is missing delta {number} after its full bundle")
            delta_body = self._get(str(meta["path"]), timeout=DATA_TIMEOUT, limit=MAX_DATA_BYTES)
            FeedRoles._pinned(delta_body, meta, f"delta {number}")
            FeedStore._merge_delta(fresh, FeedStore._read_delta(delta_body, number))
        FeedStore._save_overlays(fresh, replace=True)


__all__ = [
    "DEFAULT_URL",
    "Feed",
    "FeedClient",
    "FeedError",
    "FeedRoles",
    "FeedState",
    "FeedStore",
    "IntelStatus",
]
