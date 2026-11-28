"""A Hackage package, checked against Hackage's signed TUF metadata.

Hackage publishes its repository as TUF metadata (hackage-security): a root (`root.json`) signed by three of six key holders,
a timestamp and a snapshot signed by Hackage's online keys, and the package index `01-index.tar`, in which each release has a
`<package>/<version>/package.json` listing the SHA-256 and length of its source archive. Checked here, link by link:

1. the root is the one pinned in this package (`intel/data/hackage-root.json`, identical to the copy the key holders publish at
   github.com/haskell-infra/hackage-root-keys), or a successor signed by the pinned root's threshold of keys and by its own;
2. the timestamp is signed by the root's timestamp key, is unexpired, and names the snapshot's length and hash;
3. the snapshot is that file, signed by the snapshot key, unexpired, and names the root's and the index's length and hash;
4. the index in the state directory is exactly that length and hash (`hackage_index`: a Range read of the tail, checked whole);
5. the release's entry in the index names the hash and length of the archive that was fetched.

The package targets themselves carry no signatures (Hackage's targets role has no keys): they are covered by the index hash,
which is why the whole index is the thing checked. Freshness is bounded by the timestamp's expiry, a few days.

The answer is `verified`, `invalid` (a link failed, or the archive is not the one the index lists), `absent` (the index has no
entry for this release) or `unverifiable` (the repository or the state directory could not be used)."""

from __future__ import annotations

import datetime as dt
import hashlib
import http.client
import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any, ClassVar, Protocol

from cordon_scanner.foundation.network.downloads import Download
from cordon_scanner.foundation.network.failures import NetworkFailure
from cordon_scanner.foundation.network.pinned import PinnedHTTPS
from cordon_scanner.foundation.network.redirects import NoRedirects
from cordon_scanner.foundation.paths import StatePaths
from cordon_scanner.intel.provenance.bazel_provenance import ModuleCheck
from cordon_scanner.intel.provenance.releases.hackage_index import (
    IndexCache,
    IndexProblem,
    Repository,
    TarIndex,
)
from cordon_scanner.intel.provenance.releases.tuf import Tuf, TufError
from cordon_scanner.intel.provenance.sigstore_bundle import TrustRoot
from cordon_scanner.version import USER_AGENT


class Source(Repository, Protocol):
    def document(self, name: str) -> bytes:
        """The small metadata file `name` (`root.json`, `timestamp.json`, `snapshot.json`)."""


class HackageRepository:
    """hackage.haskell.org, over connections that go only to public addresses."""

    BASE: ClassVar[str] = "https://hackage.haskell.org"
    DOCUMENT_MAX: ClassVar[int] = 1 << 20
    TIMEOUT: ClassVar[float] = 30.0
    CHUNK: ClassVar[int] = 1 << 20
    #: Seconds a whole index read may take: a first fill is a gigabyte, a refresh megabytes.
    INDEX_BUDGET: ClassVar[float] = 3600.0

    def document(self, name: str) -> bytes:
        request = urllib.request.Request(  # noqa: S310 - https, fixed host
            f"{self.BASE}/{name}", headers={"User-Agent": USER_AGENT}
        )
        with self._opener().open(request, timeout=self.TIMEOUT) as response:
            body: bytes = Download.read(response, self.DOCUMENT_MAX + 1)
        if len(body) > self.DOCUMENT_MAX:
            raise ValueError(f"{name} is past the size cap")
        return body

    def index_range(self, start: int, length: int, sink: Callable[[bytes], None]) -> None:
        headers = {"User-Agent": USER_AGENT}
        if start:
            headers["Range"] = f"bytes={start}-{length - 1}"
        request = urllib.request.Request(f"{self.BASE}/01-index.tar", headers=headers)  # noqa: S310 - https, fixed host
        with self._opener().open(request, timeout=self.TIMEOUT) as response:
            if start and response.status != 206:
                raise IndexProblem("the repository ignored the Range request")
            expected = f"bytes {start}-{length - 1}/"
            if start and not str(response.headers.get("Content-Range", "")).startswith(expected):
                raise IndexProblem("the repository answered another range than the one asked")
            sent = 0
            for piece in Download.chunks(response, budget=self.INDEX_BUDGET, size=self.CHUNK):
                sent += len(piece)
                if sent > length - start:
                    raise IndexProblem("more bytes than the snapshot's length")
                sink(piece)

    @staticmethod
    def _opener() -> urllib.request.OpenerDirector:
        return urllib.request.build_opener(NoRedirects, PinnedHTTPS(public_only=True))


class HackageTuf:
    REPO: ClassVar[str] = "<repo>"
    PINNED_ROOT: ClassVar[str] = "hackage-root.json"
    _pinned: ClassVar[bytes | None] = None

    # -- the metadata chain ---------------------------------------------------------------------------------

    @classmethod
    def pinned_root(cls) -> bytes:
        if cls._pinned is None:
            cls._pinned = (TrustRoot.DATA / cls.PINNED_ROOT).read_bytes()
        return cls._pinned

    @classmethod
    def root(cls, source: Source, now: dt.datetime) -> tuple[dict[str, Any], bytes]:
        """The root to trust: the pinned one, or the repository's current one when that is a successor signed by both."""
        pinned = Tuf.parse(cls.pinned_root())
        trusted = pinned["signed"]
        keys = Tuf.keys(trusted)
        if not Tuf.signed_by(
            pinned, trusted["roles"]["root"]["keyids"], trusted["roles"]["root"]["threshold"], keys
        ):
            raise TufError("the pinned root is not signed by its own threshold")
        raw = source.document("root.json")
        current = Tuf.parse(raw)
        if current["signed"] == trusted:
            chosen, chosen_raw = pinned, cls.pinned_root()
        else:
            signed = current["signed"]
            newer = (
                isinstance(signed.get("version"), int) and signed["version"] > trusted["version"]
            )
            by_old = Tuf.signed_by(
                current,
                trusted["roles"]["root"]["keyids"],
                trusted["roles"]["root"]["threshold"],
                keys,
            )
            fresh = Tuf.keys(signed)
            spec = signed["roles"]["root"]
            by_new = Tuf.signed_by(current, spec["keyids"], spec["threshold"], fresh)
            if not (newer and by_old and by_new and signed.get("_type") == "Root"):
                raise TufError(
                    "the repository's root is neither the pinned one nor a successor signed by both"
                )
            chosen, chosen_raw = current, raw
        if Tuf.expired(chosen["signed"], now):
            raise TufError("the root has expired")
        return chosen, chosen_raw

    @classmethod
    def index_meta(cls, source: Source, now: dt.datetime) -> dict[str, Any]:
        """The index's length and SHA-256 as the verified snapshot states them."""
        root, root_raw = cls.root(source, now)
        trusted = root["signed"]
        timestamp = Tuf.role(Tuf.parse(source.document("timestamp.json")), trusted, "timestamp")
        timestamp_doc = timestamp
        if timestamp_doc.get("_type") != "Timestamp" or Tuf.expired(timestamp_doc, now):
            raise TufError("the timestamp has expired, or is not a timestamp")
        wanted = cls._meta(timestamp_doc, "snapshot.json")
        raw = source.document("snapshot.json")
        if len(raw) != wanted["length"] or hashlib.sha256(raw).hexdigest() != wanted["sha256"]:
            raise TufError("the snapshot is not the one the timestamp names")
        snapshot = Tuf.role(Tuf.parse(raw), trusted, "snapshot")
        if snapshot.get("_type") != "Snapshot" or Tuf.expired(snapshot, now):
            raise TufError("the snapshot has expired, or is not a snapshot")
        stated_root = cls._meta(snapshot, "root.json")
        if (
            len(root_raw) != stated_root["length"]
            or hashlib.sha256(root_raw).hexdigest() != stated_root["sha256"]
        ):
            raise TufError("the root is not the one the snapshot names")
        return cls._meta(snapshot, "01-index.tar")

    @classmethod
    def _meta(cls, signed: dict[str, Any], name: str) -> dict[str, Any]:
        entry = signed.get("meta", {}).get(f"{cls.REPO}/{name}")
        sha256 = entry.get("hashes", {}).get("sha256") if isinstance(entry, dict) else None
        length = entry.get("length") if isinstance(entry, dict) else None
        if not isinstance(sha256, str) or not isinstance(length, int) or isinstance(length, bool):
            raise TufError(f"the metadata states no length and SHA-256 for {name}")
        return {"sha256": sha256, "length": length}

    # -- one release ----------------------------------------------------------------------------------------

    @classmethod
    def verify(
        cls,
        archive: bytes,
        name: str,
        version: str,
        source: Source,
        cache: IndexCache,
        now: dt.datetime | None = None,
    ) -> ModuleCheck:
        now = now or dt.datetime.now(dt.UTC)
        try:
            meta = cls.index_meta(source, now)
        except (TufError, KeyError, TypeError) as exc:
            return ModuleCheck("invalid", f"Hackage's signed metadata did not verify: {exc}")
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            return ModuleCheck(
                "unverifiable",
                f"Hackage's metadata could not be read: {NetworkFailure.reason(exc)}",
            )
        try:
            path = cache.ensure(source, meta["length"], meta["sha256"])
            entry = TarIndex.read(path, f"{name}/{version}/package.json")
        except IndexProblem as exc:
            return ModuleCheck(
                "unverifiable", f"the signed index could not be brought up to date: {exc}"
            )
        except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
            return ModuleCheck(
                "unverifiable",
                f"the signed index could not be fetched: {NetworkFailure.reason(exc)}",
            )
        if entry is None:
            return ModuleCheck("absent", f"the signed index lists no {name} {version}")
        return cls._target(entry, archive, name, version)

    @classmethod
    def _target(cls, entry: bytes, archive: bytes, name: str, version: str) -> ModuleCheck:
        try:
            document = json.loads(entry.decode("utf-8"))
            signed = document["signed"]
            target = signed["targets"][f"{cls.REPO}/package/{name}-{version}.tar.gz"]
            sha256, length = target["hashes"]["sha256"], target["length"]
        except (ValueError, KeyError, TypeError, AttributeError):
            return ModuleCheck(
                "invalid", f"the index entry of {name} {version} does not name its archive"
            )
        if signed.get("_type") != "Targets":
            return ModuleCheck(
                "invalid", f"the index entry of {name} {version} is not a targets file"
            )
        if len(archive) != length or hashlib.sha256(archive).hexdigest() != sha256:
            return ModuleCheck(
                "invalid", f"{name} {version} is not the archive Hackage's signed index lists"
            )
        return ModuleCheck(
            "verified", f"{name} {version} is the archive Hackage's signed index lists"
        )

    @classmethod
    def check(cls, name: str, version: str, integrity: str | None) -> ModuleCheck:
        from cordon_scanner.intel.registry import ArchiveSources, RegistryError

        if not name or not version:
            return ModuleCheck("absent", f"{name or 'a package'} names no release")
        try:
            archive = ArchiveSources.package_archive("hackage", name, version)
        except (RegistryError, OSError, ValueError) as exc:
            return ModuleCheck(
                "unverifiable", f"the archive could not be fetched and checked: {exc}"
            )
        cache = IndexCache(StatePaths.default_cache_dir() / "hackage")
        return cls.verify(archive.data, name, version, HackageRepository(), cache)


__all__ = ["HackageRepository", "HackageTuf"]
