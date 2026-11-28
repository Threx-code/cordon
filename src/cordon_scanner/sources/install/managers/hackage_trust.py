"""Hackage's signed metadata (TUF): the chain root.json -> timestamp.json -> snapshot.json that names the length and SHA-256 of
`01-index.tar`, the one file that holds each release's SHA-256.

Cabal ships six root key ids and a threshold of three. The same is pinned here (`ROOT_KEYS`, from cabal-install's
`Distribution/Client/Config.hs`), so a `root.json` that three of those six did not sign is refused: Cordon follows no key rotation by itself.
Every key id is checked to be the SHA-256 of the key it names; the roles' keys then come from that root.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, ClassVar

from cordon_scanner.intel.provenance._ed25519 import Ed25519
from cordon_scanner.sources.install.plan import InstallRefused


@dataclass(frozen=True, slots=True)
class IndexFacts:
    """What the signed snapshot says of `01-index.tar`."""

    length: int
    sha256: str


class HackageTrust:
    ROOT_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "fe331502606802feac15e514d9b9ea83fee8b6ffef71335479a2e68d84adc6b0",
            "1ea9ba32c526d1cc91ab5e5bd364ec5e9e8cb67179a471872f6e26f0ae773d42",
            "0a5c7ea47cd1b15f01f5f51a33adda7e655bc0f0b0615baa8e271f4c3351e21d",
            "51f0161b906011b52c6613376b1ae937670da69322113a246a09f807c62f6921",
            "d26e46f3b631aae1433b89379a6c68bd417eb5d1c408f0643dcc07757fece522",
            "c7de58fc6a224b92b5b513f26fbb8b370f2d97c7cfe0075a951314a55734be93",
        }
    )
    THRESHOLD: ClassVar[int] = 3
    INDEX: ClassVar[str] = "<repo>/01-index.tar"

    @classmethod
    def canonical(cls, value: Any) -> bytes:
        """The canonical JSON TUF signs: sorted keys, no spaces, only the escapes `"` and `\\`, integers only."""
        if isinstance(value, dict):
            return (
                b"{"
                + b",".join(
                    cls.canonical(str(k)) + b":" + cls.canonical(v)
                    for k, v in sorted(value.items())
                )
                + b"}"
            )
        if isinstance(value, list):
            return b"[" + b",".join(cls.canonical(v) for v in value) + b"]"
        if isinstance(value, str):
            return b'"' + value.replace("\\", "\\\\").replace('"', '\\"').encode() + b'"'
        if value is True:
            return b"true"
        if value is False:
            return b"false"
        if value is None:
            return b"null"
        if isinstance(value, int):
            return str(value).encode()
        raise InstallRefused("Hackage's signed metadata holds a number TUF does not allow")

    @classmethod
    def document(cls, data: bytes, what: str) -> dict[str, Any]:
        try:
            parsed = json.loads(data)
        except ValueError as exc:
            raise InstallRefused(f"Hackage's {what} is not JSON") from exc
        if not isinstance(parsed, dict) or not isinstance(parsed.get("signed"), dict):
            raise InstallRefused(f"Hackage's {what} is not a signed TUF file")
        return parsed

    @classmethod
    def key(cls, entry: Any) -> bytes | None:
        """The Ed25519 public key of a root.json key entry, when it is one."""
        if not isinstance(entry, dict) or entry.get("keytype") != "ed25519":
            return None
        try:
            raw = base64.b64decode(
                str((entry.get("keyval") or {}).get("public", "")), validate=True
            )
        except (binascii.Error, ValueError, AttributeError):
            return None
        return raw if len(raw) == 32 else None

    @classmethod
    def valid(
        cls, doc: dict[str, Any], keys: dict[str, bytes], allowed: set[str] | frozenset[str]
    ) -> int:
        """How many different keys of `allowed` signed `doc["signed"]`."""
        message = cls.canonical(doc["signed"])
        good: set[str] = set()
        for entry in doc.get("signatures") or ():
            if not isinstance(entry, dict):
                continue
            key_id = str(entry.get("keyid", ""))
            public = keys.get(key_id)
            try:
                signature = base64.b64decode(str(entry.get("sig", "")), validate=True)
            except (binascii.Error, ValueError):
                continue
            if (
                key_id in allowed
                and public is not None
                and Ed25519.verify(public, message, signature)
            ):
                good.add(key_id)
        return len(good)

    @classmethod
    def expired(cls, signed: dict[str, Any], now: datetime, what: str) -> None:
        text = str(signed.get("expires") or "")
        try:
            at = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise InstallRefused(f"Hackage's {what} states no expiry") from exc
        if at.tzinfo is None:
            at = at.replace(tzinfo=UTC)
        if at <= now:
            raise InstallRefused(f"Hackage's {what} expired on {text[:30]}")

    @classmethod
    def meta(
        cls, signed: dict[str, Any], name: str, data: bytes | None, what: str
    ) -> dict[str, Any]:
        """The `meta` entry of `name`, held to `data` (its length and SHA-256) when given."""
        entry = (signed.get("meta") or {}).get(name)
        if not isinstance(entry, dict):
            raise InstallRefused(f"Hackage's {what} does not describe {name}")
        if data is not None and (
            entry.get("length") != len(data)
            or (entry.get("hashes") or {}).get("sha256") != hashlib.sha256(data).hexdigest()
        ):
            raise InstallRefused(f"{name} is not the file Hackage's {what} describes")
        return entry

    @classmethod
    def index(
        cls, root: bytes, timestamp: bytes, snapshot: bytes, now: datetime | None = None
    ) -> IndexFacts:
        """The length and SHA-256 of `01-index.tar` the signed chain states, or `InstallRefused`."""
        now = now or datetime.now(UTC)
        root_doc = cls.document(root, "root.json")
        signed = root_doc["signed"]
        keys: dict[str, bytes] = {}
        for key_id, entry in (signed.get("keys") or {}).items():
            public = cls.key(entry)
            if public is not None and hashlib.sha256(cls.canonical(entry)).hexdigest() == key_id:
                keys[str(key_id)] = public
        roles = signed.get("roles") or {}
        if cls.valid(root_doc, keys, cls.ROOT_KEYS) < cls.THRESHOLD:
            raise InstallRefused(
                f"Hackage's root.json is not signed by {cls.THRESHOLD} of the six root keys cabal-install pins; Cordon follows no key "
                "rotation by itself, so update Cordon or run cabal where you trust the index"
            )
        cls.expired(signed, now, "root.json")

        def signer(role: str, doc: dict[str, Any], what: str) -> None:
            entry = roles.get(role) or {}
            ids = {str(i) for i in entry.get("keyids") or ()}
            if cls.valid(doc, keys, ids) < max(int(entry.get("threshold") or 1), 1):
                raise InstallRefused(
                    f"Hackage's {what} is not signed by the {role} key of root.json"
                )

        stamp = cls.document(timestamp, "timestamp.json")
        signer("timestamp", stamp, "timestamp.json")
        cls.expired(stamp["signed"], now, "timestamp.json")
        cls.meta(stamp["signed"], "<repo>/snapshot.json", snapshot, "timestamp.json")
        shot = cls.document(snapshot, "snapshot.json")
        signer("snapshot", shot, "snapshot.json")
        cls.expired(shot["signed"], now, "snapshot.json")
        cls.meta(shot["signed"], "<repo>/root.json", root, "snapshot.json")
        entry = cls.meta(shot["signed"], cls.INDEX, None, "snapshot.json")
        length = entry.get("length")
        digest = str((entry.get("hashes") or {}).get("sha256", ""))
        if not isinstance(length, int) or length <= 0 or len(digest) != 64:
            raise InstallRefused(
                "Hackage's snapshot.json states no usable length and SHA-256 for the index"
            )
        return IndexFacts(length, digest)


__all__ = ["HackageTrust", "IndexFacts"]
