"""The chain of policy bundles, checked offline: from one pinned public key to a bundle this client takes or refuses.

The platform signs each policy bundle of a tenant and scope as a DSSE envelope and chains it to the one before: `prev_sha`
is `sha256:` and the hex sha256 of the previous bundle's canonical payload (sorted keys, no whitespace, UTF-8, no ASCII
escaping), and the first bundle of a tenant and scope is version 1 with an empty `prev_sha`. The client pins ONE thing per
tenant, the root public key, and trusts everything else only through it: the root signs a delegation naming the policy
key and its validity window, and the policy key signs the bundles.

What a client that holds nothing does: it takes any bundle that verifies and has not expired. What a client that holds
bundle N does with an offered bundle:

* the successor (version N+1, `prev_sha` naming the held payload) is `new`;
* the same version with the same payload is `unchanged` (nothing new, not a refusal);
* anything else is refused, with a name of its own: `bundle_rolled_back` (a lower version), `bundle_forked` (the same
  version, another payload), `bundle_chain_broken` (a successor whose `prev_sha` does not match, or another scope),
  `bundle_gap` (a version jump), `bundle_expired`.

The five names are not decision reason codes. A client that missed versions takes the bundles since the held one, oldest
first, all or nothing: every link verifies and chains, only the newest must be unexpired, and every link is verified
with the keys valid at `now`, so a chain that spans a policy key rotation is refused and the client is re-bootstrapped.
A re-issue of a bundle is a new version: the same version signed again with another `issued_at` is another payload.

This is the client half of the platform's `TrustChain.accept_bundle` and `accept_chain`, written over the Ed25519
verification the scanner already carries (the scanner takes no third-party runtime dependency), and checked against the
platform's own fixtures on every case (`tests/unit/cloud/test_bundle_chain.py`).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.cloud import CloudError
from cordon_scanner.intel.provenance import _ed25519

if TYPE_CHECKING:
    from collections.abc import Mapping

DELEGATION_TYPE: Final = "application/vnd.cordon.delegation+json"
BUNDLE_TYPE: Final = "application/vnd.cordon.policy-bundle+json"
DELEGATION_SCHEMA: Final = "cordon.delegation/v1"
POLICY_ROLES: Final = ("policy",)
START_LEEWAY: Final = timedelta(minutes=5)
"""How far BEHIND the issuer a verifier's clock may be and still accept a key that has only just started. Applied to the
start of a key's window only, never to its end: a key that has expired or been retired is not extended by a slow clock."""


class BundleError(CloudError):
    """The envelope is malformed, of another type, too large, or not signed by a key the client trusts."""


class BundleRefused(BundleError):
    """A validly signed bundle that a client holding another one refuses, by name."""

    ROLLED_BACK: ClassVar[str] = "bundle_rolled_back"
    FORKED: ClassVar[str] = "bundle_forked"
    CHAIN_BROKEN: ClassVar[str] = "bundle_chain_broken"
    GAP: ClassVar[str] = "bundle_gap"
    EXPIRED: ClassVar[str] = "bundle_expired"
    NAMES: ClassVar[tuple[str, ...]] = (ROLLED_BACK, FORKED, CHAIN_BROKEN, GAP, EXPIRED)

    def __init__(self, name: str, message: str) -> None:
        super().__init__(message)
        self.name = name


class Dsse:
    """A DSSE envelope: `{payloadType, payload (base64), signatures: [{keyid, sig (base64)}]}`, signed over the
    pre-authentication encoding of the type and the payload."""

    VERSION: ClassVar[bytes] = b"DSSEv1"
    MAX_PAYLOAD_BYTES: ClassVar[int] = 1024 * 1024

    @classmethod
    def pae(cls, payload_type: str, payload: bytes) -> bytes:
        kind = payload_type.encode("utf-8")
        return b" ".join(
            [cls.VERSION, str(len(kind)).encode(), kind, str(len(payload)).encode(), payload]
        )

    @staticmethod
    def keyid(public: bytes) -> str:
        return hashlib.sha256(public).hexdigest()

    @classmethod
    def verify(
        cls,
        envelope: object,
        trusted: Mapping[str, bytes],
        *,
        payload_type: str,
        threshold: int = 1,
    ) -> bytes:
        """The payload, if at least `threshold` DISTINCT trusted keys signed it as `payload_type`; otherwise
        `BundleError`. `trusted` maps key id to the raw 32-byte public key. A signature by a key id not in it, a
        signature that does not verify and a second signature by the same key are not counted."""
        if not isinstance(envelope, dict) or envelope.get("payloadType") != payload_type:
            raise BundleError(f"this is not a {payload_type} envelope")
        body = cls._decode(envelope.get("payload"), "payload", cls.MAX_PAYLOAD_BYTES)
        signatures = envelope.get("signatures")
        if not isinstance(signatures, list) or not signatures:
            raise BundleError("the envelope carries no signature")
        message = cls.pae(payload_type, body)
        good: set[str] = set()
        for entry in signatures:
            if not isinstance(entry, dict) or not isinstance(entry.get("keyid"), str):
                continue
            keyid = entry["keyid"]
            raw = trusted.get(keyid)
            if raw is None or keyid in good:
                continue
            try:
                signature = cls._decode(entry.get("sig"), "signature", 128)
            except BundleError:
                continue
            if _ed25519.Ed25519.verify(raw, message, signature):
                good.add(keyid)
        if len(good) < threshold:
            raise BundleError("no signature by a trusted key verifies")
        return body

    @staticmethod
    def _decode(value: object, what: str, limit: int) -> bytes:
        if not isinstance(value, str) or len(value) > limit * 4 // 3 + 8:
            raise BundleError(f"the {what} is missing or too large")
        try:
            return base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise BundleError(f"the {what} is not base64") from exc


class BundleChain:
    """The offline check of a bundle, and of a chain of bundles, against the pinned root key."""

    @staticmethod
    def canonical(document: dict[str, Any]) -> bytes:
        """The bytes that are signed: sorted keys, no whitespace, UTF-8. Two honest producers write the same bytes."""
        return json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    @classmethod
    def payload_sha(cls, document: dict[str, Any]) -> str:
        """What `prev_sha` holds: `sha256:` and the hex sha256 of a bundle's canonical payload."""
        return "sha256:" + hashlib.sha256(cls.canonical(document)).hexdigest()

    @classmethod
    def delegation(cls, root_public: bytes, envelope: object, *, tenant: str) -> dict[str, Any]:
        """The delegation, if the pinned root signed it and it is for `tenant`; otherwise `BundleError`."""
        body = Dsse.verify(
            envelope, {Dsse.keyid(root_public): root_public}, payload_type=DELEGATION_TYPE
        )
        document = cls._json(body, "the delegation")
        if document.get("_type") != DELEGATION_SCHEMA or document.get("tenant") != tenant:
            raise BundleError("this delegation is not for this tenant")
        if not isinstance(document.get("keys"), list):
            raise BundleError("the delegation lists no keys")
        return document

    @classmethod
    def unverified_payload_document(cls, envelope: object) -> dict[str, Any]:
        """The payload of an envelope WITHOUT checking its signature: for the bundle a client verified and stored
        earlier. A bundle a client is handed goes through `accept_bundle`, which verifies."""
        if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), str):
            raise BundleError("this is not an envelope")
        try:
            body = base64.b64decode(envelope["payload"], validate=True)
        except ValueError as exc:
            raise BundleError("the envelope payload is not base64") from exc
        return cls._json(body, "the payload")

    @classmethod
    def accept_bundle(
        cls,
        *,
        root_public: bytes,
        delegation: object,
        envelope: object,
        tenant: str,
        now: datetime,
        held: dict[str, Any] | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """Whether a client that holds `held` (the verified payload of the bundle it already has, or None) takes
        `envelope`: `("new", bundle)` for the first bundle it takes or the direct successor of the held one,
        `("unchanged", held)` when the offered bundle is the one it holds, and `BundleRefused` by name otherwise. The
        chain is per tenant and scope; a client holding nothing cannot check a chain and takes any bundle that verifies
        and has not expired."""
        offered = cls._verified(root_public, delegation, envelope, tenant, now, check_expiry=True)
        return cls._follows(held, offered)

    @classmethod
    def accept_chain(
        cls,
        *,
        root_public: bytes,
        delegation: object,
        envelopes: list[object],
        tenant: str,
        now: datetime,
        held: dict[str, Any] | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """A client that missed versions takes the bundles since the one it holds, oldest first. Every one must verify
        and chain to the one before; only the newest must be unexpired, because the ones between are old by now. All or
        nothing. Every bundle is verified with the keys valid NOW, so a chain that spans a policy key rotation is
        refused and the client is re-bootstrapped: a retired key is never trusted again to extend a chain."""
        if not envelopes:
            raise BundleRefused(BundleRefused.GAP, "no bundles were offered to catch up with")
        state, current = "unchanged", held
        for index, envelope in enumerate(envelopes):
            offered = cls._verified(
                root_public,
                delegation,
                envelope,
                tenant,
                now,
                check_expiry=index == len(envelopes) - 1,
            )
            verdict, current = cls._follows(current, offered)
            if verdict == "new":
                state = "new"
        if current is None:
            raise BundleRefused(BundleRefused.GAP, "no bundle was taken")
        return state, current

    @classmethod
    def reverify(
        cls, root_public: bytes, delegation: object, envelope: object, tenant: str, now: datetime
    ) -> dict[str, Any]:
        """A bundle kept on disk, checked again when it is loaded: signature, key, tenant, version and scope; its expiry is not
        checked, because an expired bundle is still the last policy the tenant published and the policy's own expiry decides
        what a point does with it (`R202`)."""
        return cls._verified(root_public, delegation, envelope, tenant, now, check_expiry=False)

    @classmethod
    def _verified(
        cls,
        root_public: bytes,
        delegation: object,
        envelope: object,
        tenant: str,
        now: datetime,
        *,
        check_expiry: bool,
    ) -> dict[str, Any]:
        keys = cls.delegation(root_public, delegation, tenant=tenant)["keys"]
        usable: dict[str, bytes] = {}
        for key in keys:
            if (
                isinstance(key, dict)
                and key.get("role") in POLICY_ROLES
                and cls._valid_at(key, now)
            ):
                try:
                    usable[str(key["keyid"])] = bytes.fromhex(str(key["public"]))
                except (KeyError, ValueError):
                    continue
        bundle = cls._json(Dsse.verify(envelope, usable, payload_type=BUNDLE_TYPE), "the payload")
        if bundle.get("tenant") != tenant:
            raise BundleError("this bundle is for another tenant")
        version = bundle.get("version")
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version < 1
            or not bundle.get("scope")
        ):
            raise BundleError("the bundle carries no usable scope and version")
        if check_expiry:
            try:
                cls._not_expired(bundle, now)
            except BundleError as exc:
                raise BundleRefused(BundleRefused.EXPIRED, str(exc)) from exc
        return bundle

    @classmethod
    def _follows(
        cls, held: dict[str, Any] | None, offered: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        if held is None:
            return "new", offered
        if offered["scope"] != held["scope"]:
            raise BundleRefused(
                BundleRefused.CHAIN_BROKEN, "this bundle is for another scope than the one held"
            )
        have, got = int(held["version"]), int(offered["version"])
        if got < have:
            raise BundleRefused(
                BundleRefused.ROLLED_BACK, f"version {got} is older than the version {have} held"
            )
        if got == have:
            if cls.payload_sha(offered) == cls.payload_sha(held):
                return "unchanged", held
            raise BundleRefused(
                BundleRefused.FORKED,
                f"version {got} is not the version {have} held: another payload",
            )
        if got > have + 1:
            raise BundleRefused(BundleRefused.GAP, f"version {got} skips the versions after {have}")
        if offered.get("prev_sha") != cls.payload_sha(held):
            raise BundleRefused(
                BundleRefused.CHAIN_BROKEN, f"version {got} does not follow the version {have} held"
            )
        return "new", offered

    @staticmethod
    def _valid_at(key: dict[str, Any], at: datetime) -> bool:
        try:
            start = datetime.fromisoformat(key["not_before"])
            end = datetime.fromisoformat(key["valid_until"]) if key.get("valid_until") else None
        except (KeyError, ValueError, TypeError):
            return False
        try:
            return start - START_LEEWAY <= at and (end is None or at <= end)
        except TypeError:
            return False

    @staticmethod
    def _not_expired(document: dict[str, Any], now: datetime) -> None:
        try:
            expires = datetime.fromisoformat(document["expires_at"])
            past = now > expires
        except (KeyError, ValueError, TypeError) as exc:
            raise BundleError("the bundle carries no usable expires_at") from exc
        if past:
            raise BundleError("the bundle is past its expiry")

    @staticmethod
    def _json(body: bytes, what: str) -> dict[str, Any]:
        try:
            document = json.loads(body)
        except ValueError as exc:
            raise BundleError(f"{what} is not JSON") from exc
        if not isinstance(document, dict):
            raise BundleError(f"{what} is not an object")
        return document


__all__ = ["BundleChain", "BundleError", "BundleRefused", "Dsse"]
