"""The execution plane's local store (row BP-2-6): what a point keeps on disk so it can decide, and report, with no network.

One directory holds five things, each in its own folder and each written whole or not at all (a temporary file, then a rename, so
a crash leaves the old file or the new one and never half of either):

* `bundle/`  the signed policy bundles last taken, as the envelopes were received; they are verified again on every load;
* `blobs/`   rule packs and the intel snapshot, each with its digest and the time it was issued, and read back only if the bytes
  still match the digest;
* `decisions/`  decisions kept under their `inputs_digest` (the key `Decider.key` gives before deciding); a decision for the same
  inputs is the same bytes, so a kept one is never stale, and an entry that fails its own checks is a miss and is removed;
* `outbox/`  uploads waiting for the control plane, numbered, oldest first, each with an id (the sha256 of its bytes) the receiver
  can deduplicate on;
* nothing else: a file the store did not write is not read.

A single process writes a store. The cache and the outbox are bounded: the cache drops its oldest entries past `max_cache`; the
outbox refuses a new upload past `max_pending` and counts the refusal (`refused`), because a record dropped without a trace is the
failure an offline queue exists to prevent. The store protects against a crash and a bad disk block; it is not a defence against
someone who can write to the directory, who can already change the policy the point runs under.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Final

from cordon_scanner.contracts.digests import ArtifactDigests

_NAME: Final = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_TEMPORARY: Final = ".tmp"


@dataclass(frozen=True, slots=True)
class Blob:
    """A rule pack or the intel snapshot as stored: its bytes, digest and the time it was issued (ISO 8601, UTC)."""

    kind: str
    name: str
    digest: str
    issued_at: str
    data: bytes


@dataclass(frozen=True, slots=True)
class Pending:
    """An upload waiting to be sent: its order, what it is, its bytes and the id the receiver deduplicates on."""

    sequence: int
    kind: str
    id: str
    body: bytes


@dataclass(frozen=True, slots=True)
class Drained:
    """The result of one `drain`: how many were sent and how many are still waiting."""

    sent: int
    left: int


class StoreFiles:
    """How the store reads and writes its files: whole or not at all, and the names of what it keeps."""

    @staticmethod
    def parse(name: str) -> tuple[int, str, str] | None:
        """`<12 digits>-<kind>-<64 hex>.upload` as (sequence, kind, digest), or None for any other name (a name is cut at
        fixed places, not matched by a pattern with a repeat next to the separator it may contain)."""
        stem = name.removesuffix(".upload")
        if stem == name or len(stem) < 12 + 1 + 1 + 1 + 64:
            return None
        sequence, kind, digest = stem[:12], stem[13:-65], stem[-64:]
        if (
            not (sequence.isascii() and sequence.isdigit())
            or stem[12] != "-"
            or stem[-65] != "-"
            or not _NAME.fullmatch(kind)
            or not set(digest) <= set("0123456789abcdef")
        ):
            return None
        return int(sequence), kind, digest

    @staticmethod
    def part(path: Path, suffix: str) -> Path:
        return path.with_name(path.name + suffix)

    @staticmethod
    def json_bytes(document: Any) -> bytes:
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def read_json(path: Path) -> Any:
        try:
            return json.loads(path.read_bytes())
        except (OSError, ValueError):
            return None

    @staticmethod
    def write(path: Path, data: bytes) -> None:
        """Whole or not at all: write beside, flush to disk, rename over."""
        temporary = path.with_name(path.name + _TEMPORARY)
        with temporary.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)


class LocalStore:
    BLOB_KINDS: ClassVar[tuple[str, ...]] = (
        "rulepack",
        "intel",
        "etag",
        "breaker",
        "feed-serial",
        "pin",
        "rug-pull",
        "decision-delegation",
    )

    def __init__(self, root: Path, *, max_cache: int = 4096, max_pending: int = 10_000) -> None:
        if max_cache < 1 or max_pending < 1:
            raise ValueError("a store holds at least one decision and one pending upload")
        self._root = root
        self._max_cache, self._max_pending = max_cache, max_pending
        self._puts = 0
        self._recent: dict[str, dict[str, None]] = {"decisions": {}, "allowed": {}}
        for folder in ("bundle", "blobs", "decisions", "allowed", "scans", "outbox"):
            (root / folder).mkdir(parents=True, exist_ok=True)

    # -- the policy bundles ----------------------------------------------------------------------

    def save_bundle(self, envelopes: Sequence[object]) -> None:
        """Keep the bundles last taken (oldest first), replacing what was kept."""
        StoreFiles.write(
            self._root / "bundle" / "chain.json", StoreFiles.json_bytes(list(envelopes))
        )

    def load_bundle(self) -> list[object] | None:
        """The envelopes kept, or None when there are none or the file is not what was written."""
        document = StoreFiles.read_json(self._root / "bundle" / "chain.json")
        return document if isinstance(document, list) and document else None

    # -- rule packs and the intel snapshot --------------------------------------------------------

    def put_blob(self, kind: str, name: str, data: bytes, issued_at: str) -> str:
        """Keep `data` as the rule pack or snapshot `name`; returns its digest."""
        path = self._blob_path(kind, name)
        digest = ArtifactDigests.of_bytes(data)
        StoreFiles.write(StoreFiles.part(path, ".bin"), data)
        StoreFiles.write(
            StoreFiles.part(path, ".json"),
            StoreFiles.json_bytes({"digest": digest, "issued_at": issued_at}),
        )
        return digest

    def blob(self, kind: str, name: str) -> Blob | None:
        """The blob, or None when it is absent or its bytes no longer match the digest kept with them."""
        path = self._blob_path(kind, name)
        meta = StoreFiles.read_json(StoreFiles.part(path, ".json"))
        try:
            data = StoreFiles.part(path, ".bin").read_bytes()
        except OSError:
            return None
        if (
            not isinstance(meta, dict)
            or not isinstance(meta.get("issued_at"), str)
            or meta.get("digest") != ArtifactDigests.of_bytes(data)
        ):
            return None
        return Blob(kind, name, str(meta["digest"]), str(meta["issued_at"]), data)

    # -- decisions kept under their key ----------------------------------------------------------

    def cache_put(self, key: str, decision: dict[str, Any]) -> None:
        if decision.get("inputs_digest") != key:
            raise ValueError("a decision is kept under its own inputs_digest")
        path = self._cache_path(key)
        StoreFiles.write(path, StoreFiles.json_bytes({"key": key, "decision": decision}))
        self._note("decisions", path)

    def cache_get(self, key: str) -> dict[str, Any] | None:
        """The decision kept for `key`; an entry that is not exactly what `cache_put` wrote is a miss and is removed."""
        path = self._cache_path(key)
        document = StoreFiles.read_json(path)
        if document is None:
            return None
        decision = document.get("decision") if isinstance(document, dict) else None
        if (
            isinstance(document, dict)
            and document.get("key") == key
            and isinstance(decision, dict)
            and decision.get("inputs_digest") == key
        ):
            return decision
        path.unlink(missing_ok=True)
        return None

    def cache_size(self) -> int:
        return sum(1 for _ in (self._root / "decisions").glob("*.json"))

    # -- the decisions that allowed, kept by what they were about ----------------------------------

    def remember_allow(self, key: str, decision: dict[str, Any], made_at: str) -> None:
        """Keep a decision that allowed under `key` (what it was about, not the moment: see `LocalRuntime`), with when it was made."""
        path = self._allow_path(key)
        StoreFiles.write(
            path, StoreFiles.json_bytes({"key": key, "made_at": made_at, "decision": decision})
        )
        self._note("allowed", path)

    def recall_allow(self, key: str) -> tuple[dict[str, Any], str] | None:
        """The decision kept under `key` and when it was made; an entry that is not exactly what was written is a miss."""
        document = StoreFiles.read_json(self._allow_path(key))
        if (
            isinstance(document, dict)
            and document.get("key") == key
            and isinstance(document.get("decision"), dict)
            and isinstance(document.get("made_at"), str)
        ):
            return document["decision"], document["made_at"]
        return None

    # -- what a scan found, kept by what was scanned ---------------------------------------------

    def keep_scan(self, key: str, evidence: dict[str, Any]) -> None:
        """Keep the evidence a scan produced under `key` (the digest scanned and the rules version, as a digest)."""
        StoreFiles.write(
            self._scan_path(key), StoreFiles.json_bytes({"key": key, "evidence": evidence})
        )

    def recall_scan(self, key: str) -> dict[str, Any] | None:
        document = StoreFiles.read_json(self._scan_path(key))
        if (
            isinstance(document, dict)
            and document.get("key") == key
            and isinstance(document.get("evidence"), dict)
        ):
            evidence: dict[str, Any] = document["evidence"]
            return evidence
        return None

    # -- uploads waiting for the control plane ---------------------------------------------------

    def enqueue(self, kind: str, body: bytes) -> bool:
        """Queue an upload. False (and counted in `refused`) when the outbox is full: the upload is not kept."""
        if not _NAME.fullmatch(kind):
            raise ValueError(f"upload kind {kind!r}: lower case letters, digits, '.', '_' and '-'")
        waiting = self._outbox()
        digest = hashlib.sha256(body).hexdigest()
        if any(item[1] == kind and item[2] == digest for item in waiting):
            return True  # the same upload is already queued: it is stored once
        if len(waiting) >= self._max_pending:
            StoreFiles.write(
                self._root / "outbox" / "refused", str(self.refused() + 1).encode("ascii")
            )
            return False
        sequence = (waiting[-1][0] + 1) if waiting else 1
        name = f"{sequence:012d}-{kind}-{digest}.upload"
        StoreFiles.write(self._root / "outbox" / name, body)
        return True

    def pending(self) -> list[Pending]:
        """The uploads waiting, oldest first."""
        found = []
        for sequence, kind, digest, path in self._outbox():
            try:
                body = path.read_bytes()
            except OSError:
                continue
            if hashlib.sha256(body).hexdigest() != digest:
                continue  # a damaged entry is not sent as something it is not
            found.append(Pending(sequence, kind, digest, body))
        return found

    def drain(self, send: Callable[[Pending], None]) -> Drained:
        """Send the uploads oldest first, removing each once `send` returns. The first `send` that raises stops the drain with
        that upload and the ones after it still queued, so the order is kept and nothing is sent twice by this call."""
        sent = 0
        for item in self.pending():
            try:
                send(item)
            except Exception:  # noqa: BLE001 -- any failure to send leaves the upload queued
                break
            self._path_of(item).unlink(missing_ok=True)
            sent += 1
        return Drained(sent, len(self._outbox()))

    def discard(self, item: Pending) -> None:
        """Remove one waiting upload: a newer one replaces it."""
        self._path_of(item).unlink(missing_ok=True)

    def refused(self) -> int:
        """How many uploads were refused because the outbox was full."""
        try:
            return int((self._root / "outbox" / "refused").read_text(encoding="ascii"))
        except (OSError, ValueError):
            return 0

    # -- the parts --------------------------------------------------------------------------------

    def _outbox(self) -> list[tuple[int, str, str, Path]]:
        found = []
        for path in (self._root / "outbox").glob("*.upload"):
            parsed = StoreFiles.parse(path.name)
            if parsed is not None:
                found.append((*parsed, path))
        return sorted(found, key=lambda item: item[0])

    def _path_of(self, item: Pending) -> Path:
        return self._root / "outbox" / f"{item.sequence:012d}-{item.kind}-{item.id}.upload"

    def _blob_path(self, kind: str, name: str) -> Path:
        if kind not in self.BLOB_KINDS:
            raise ValueError(f"blob kind {kind!r}: one of {', '.join(self.BLOB_KINDS)}")
        if not _NAME.fullmatch(name):
            raise ValueError(f"blob name {name!r}: lower case letters, digits, '.', '_' and '-'")
        return self._root / "blobs" / f"{kind}-{name}"

    def _cache_path(self, key: str) -> Path:
        if not ArtifactDigests.is_digest(key):
            raise ValueError(f"cache key {key!r} is not a digest")
        return self._root / "decisions" / f"{key.partition(':')[2]}.json"

    def _scan_path(self, key: str) -> Path:
        if not ArtifactDigests.is_digest(key):
            raise ValueError(f"scan key {key!r} is not a digest")
        return self._root / "scans" / f"{key.partition(':')[2]}.json"

    def _allow_path(self, key: str) -> Path:
        if not ArtifactDigests.is_digest(key):
            raise ValueError(f"allow key {key!r} is not a digest")
        return self._root / "allowed" / f"{key.partition(':')[2]}.json"

    def _note(self, folder: str, path: Path) -> None:
        """Remember the order a file was put in, and every 64th put drop the oldest past `max_cache`."""
        recent = self._recent[folder]
        recent.pop(path.name, None)
        recent[path.name] = None
        self._puts += 1
        if self._puts % 64 == 0:
            self._trim("decisions")
            self._trim("allowed")

    def _trim(self, folder: str) -> None:
        """Drop the oldest entries past `max_cache`: those of an earlier run by their file time, then this run's in the order
        they were put (file times of entries written within one clock tick do not order them)."""
        recent = self._recent[folder]
        found = {path.name: path for path in (self._root / folder).glob("*.json")}
        earlier = sorted(
            (name for name in found if name not in recent),
            key=lambda name: found[name].stat().st_mtime_ns,
        )
        ordered = earlier + [name for name in recent if name in found]
        excess = max(0, len(ordered) - self._max_cache)
        for name in ordered[:excess]:
            found[name].unlink(missing_ok=True)
        self._recent[folder] = dict.fromkeys(ordered[excess:])


__all__ = ["Blob", "Drained", "LocalStore", "Pending"]
