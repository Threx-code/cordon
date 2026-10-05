"""A signed test feed, built in memory, for exercising the feed client.

Test-only signing. The package verifies and never signs; the real feed is signed in Cordon
Cloud's signing zone. This signer is the RFC 8032 reference built on the package's own curve
arithmetic, and `test_feed.py` checks it against the RFC's test vector before trusting it.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from dataclasses import dataclass, field
from typing import Any

from cordon_scanner.intel import _ed25519 as ed
from cordon_scanner.intel.feed import SPEC, FeedError, FeedRoles

FAR = "2099-01-01T00:00:00Z"
NOW = 1_800_000_000.0
ISSUED = "2027-01-15T08:00:00Z"


class FeedKit:
    """Signed intel feeds built for tests: keys, roles, deltas and bundles."""

    @staticmethod
    def _compress(point: tuple[int, int, int, int]) -> bytes:
        zinv = pow(point[2], ed._P - 2, ed._P)
        x, y = point[0] * zinv % ed._P, point[1] * zinv % ed._P
        return (y | ((x & 1) << 255)).to_bytes(32, "little")

    @staticmethod
    def _expand(seed: bytes) -> tuple[int, bytes]:
        digest = hashlib.sha512(seed).digest()
        scalar = int.from_bytes(digest[:32], "little")
        scalar &= (1 << 254) - 8
        scalar |= 1 << 254
        return scalar, digest[32:]

    @staticmethod
    def public_key(seed: bytes) -> bytes:
        scalar, _ = FeedKit._expand(seed)
        return FeedKit._compress(ed.Ed25519._point_mul(scalar, ed._G))

    @staticmethod
    def sign(seed: bytes, message: bytes) -> bytes:
        scalar, prefix = FeedKit._expand(seed)
        public = FeedKit._compress(ed.Ed25519._point_mul(scalar, ed._G))
        r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % ed._L
        encoded_r = FeedKit._compress(ed.Ed25519._point_mul(r, ed._G))
        k = int.from_bytes(hashlib.sha512(encoded_r + public + message).digest(), "little") % ed._L
        s = (r + k * scalar) % ed._L
        return encoded_r + s.to_bytes(32, "little")

    @staticmethod
    def new_key(label: str) -> Key:
        return Key(hashlib.sha256(label.encode()).digest())

    @staticmethod
    def signed(body: dict[str, Any], *keys: Key) -> dict[str, Any]:
        message = FeedRoles.canonical(body)
        return {
            "signed": body,
            "signatures": [
                {"keyid": k.keyid, "sig": FeedKit.sign(k.seed, message).hex()} for k in keys
            ],
        }

    @staticmethod
    def meta_of(data: bytes, **extra: Any) -> dict[str, Any]:
        return {"length": len(data), "sha256": hashlib.sha256(data).hexdigest(), **extra}

    @staticmethod
    def root_body(
        version: int, roles: dict[str, tuple[list[Key], int]], expires: str = FAR
    ) -> dict[str, Any]:
        keys: dict[str, Any] = {}
        spec: dict[str, Any] = {}
        for role, (members, threshold) in roles.items():
            for key in members:
                keys[key.keyid] = key.public
            spec[role] = {"keyids": [k.keyid for k in members], "threshold": threshold}
        return {
            "_type": "root",
            "spec": SPEC,
            "version": version,
            "expires": expires,
            "keys": keys,
            "roles": spec,
        }

    @staticmethod
    def delta(serial: int, advisories: dict[str, dict[str, list[Any]]]) -> bytes:
        return gzip.compress(
            FeedRoles.canonical({"serial": serial, "advisories": advisories}), mtime=0
        )

    @staticmethod
    def full_bundle(
        records: dict[str, list[dict[str, Any]]], built_at: str = "2027-01-01T00:00:00Z"
    ) -> bytes:
        """A full bundle in the shape the advisory loader reads, with its digest manifest."""
        files: dict[str, bytes] = {}
        for ecosystem, rows in records.items():
            files[f"advisories-{ecosystem}.json.gz"] = gzip.compress(
                json.dumps(rows).encode(), mtime=0
            )
        files["advisories-meta.json"] = json.dumps(
            {"built_at": built_at, "record_count": 1}
        ).encode()
        digests = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
        files["advisories-digests.json"] = json.dumps(digests).encode()
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()


@dataclass
class Key:
    seed: bytes

    @property
    def public(self) -> dict[str, str]:
        return {"keytype": "ed25519", "public": FeedKit.public_key(self.seed).hex()}

    @property
    def keyid(self) -> str:
        return FeedRoles.key_id(self.public)


@dataclass
class SignedFeed:
    """A feed's files and signing keys. `fetch` serves them the way the client asks."""

    root_key: Key = field(default_factory=lambda: FeedKit.new_key("root"))
    timestamp_key: Key = field(default_factory=lambda: FeedKit.new_key("timestamp"))
    snapshot_key: Key = field(default_factory=lambda: FeedKit.new_key("snapshot"))
    targets_key: Key = field(default_factory=lambda: FeedKit.new_key("targets"))
    files: dict[str, bytes] = field(default_factory=dict)
    requests: list[tuple[str, float]] = field(default_factory=list)
    version: int = 0

    def roles(self) -> dict[str, tuple[list[Key], int]]:
        return {
            "root": ([self.root_key], 1),
            "timestamp": ([self.timestamp_key], 1),
            "snapshot": ([self.snapshot_key], 1),
            "targets": ([self.targets_key], 1),
        }

    def root(self) -> dict[str, Any]:
        return FeedKit.signed(FeedKit.root_body(1, self.roles()), self.root_key)

    def publish(
        self,
        serial: int,
        *,
        deltas: dict[int, bytes] | None = None,
        full: tuple[int, bytes] | None = None,
        expires: str = FAR,
        issued: str = ISSUED,
        version: int | None = None,
    ) -> None:
        self.version = version if version is not None else self.version + 1
        entries = {}
        for number, body in (deltas or {}).items():
            path = f"deltas/{number}.json.gz"
            self.files[path] = body
            entries[str(number)] = FeedKit.meta_of(body, path=path)
        targets_body: dict[str, Any] = {
            "_type": "targets",
            "spec": SPEC,
            "version": self.version,
            "expires": expires,
            "serial": serial,
            "built_at": issued,
            "deltas": entries,
        }
        if full is not None:
            path = f"full/{full[0]}.tar.gz"
            self.files[path] = full[1]
            targets_body["full"] = FeedKit.meta_of(full[1], path=path, serial=full[0])
        targets = FeedRoles.canonical(FeedKit.signed(targets_body, self.targets_key))
        snapshot = FeedRoles.canonical(
            FeedKit.signed(
                {
                    "_type": "snapshot",
                    "spec": SPEC,
                    "version": self.version,
                    "expires": expires,
                    "targets": FeedKit.meta_of(targets, version=self.version),
                },
                self.snapshot_key,
            )
        )
        timestamp = FeedRoles.canonical(
            FeedKit.signed(
                {
                    "_type": "timestamp",
                    "spec": SPEC,
                    "version": self.version,
                    "expires": expires,
                    "issued": issued,
                    "snapshot": FeedKit.meta_of(snapshot, version=self.version),
                },
                self.timestamp_key,
            )
        )
        self.files.update(
            {"targets.json": targets, "snapshot.json": snapshot, "timestamp.json": timestamp}
        )

    def fetch(self, url: str, timeout: float, limit: int) -> bytes:
        name = url.split("/v1/", 1)[1]
        self.requests.append((name, timeout))
        if name not in self.files:
            raise FeedError(f"HTTP 404 from the feed ({name})")
        body = self.files[name]
        if len(body) > limit:
            raise FeedError("a feed file exceeded its size limit")
        return body

    def client(self, **overrides: Any):
        from cordon_scanner.intel.feed import Feed

        options = {
            "base_url": "https://feed.test/v1",
            "root": self.root(),
            "fetch": self.fetch,
            "clock": lambda: NOW,
        }
        options.update(overrides)
        return Feed(**options)
