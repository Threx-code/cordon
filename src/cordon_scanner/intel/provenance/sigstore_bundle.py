"""Verifying a Sigstore bundle with the project's own code, against trust material it pins.

A bundle (`application/vnd.dev.sigstore.bundle+json`, versions 0.1 to 0.3) is evidence that an
identity signed some content and that the signing was logged. Verification checks every link,
and a bundle is VERIFIED only when all of them hold:

1. **The key.** Either a Fulcio certificate -- chained to a certificate authority in the pinned
   trusted root, valid for code signing, logged in certificate transparency (an embedded SCT
   that verifies under a pinned CT log key) -- or, for npm's own publish attestations, a key npm
   publishes for its registry, named by the bundle's key hint.
2. **The log.** Every transparency-log entry is from a pinned log, and proves itself: its
   inclusion proof reaches a root the log signed in a checkpoint, and its signed entry timestamp
   verifies. Its body names the same signature, key and content as the bundle -- an entry about
   other content is not evidence about this content.
3. **The time.** The log's signed time falls inside the certificate's validity, the authority's
   validity and the log key's validity: a short-lived certificate proves nothing outside the
   minutes it was valid.
4. **The signature.** Over the DSSE pre-authentication encoding of the envelope, or over the
   artefact digest for a message signature.

Beyond what sigstore-python checks, this verifier also reads Rekor's `intoto` 0.0.2 entries
(npm's provenance until 2025, which that library declines) and npm's registry-signed publish
attestations; and it refuses ambiguity rather than resolving it: duplicate JSON keys, unknown
media types, more than one signature in an envelope, encodings that are not exact.

What it returns is the cryptographic answer. The identity policy (who must have signed) and the
statement's subject (what was signed) are the caller's (`attest.SigstoreVerification`).
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from cordon_scanner.foundation.paths import PackagePaths
from cordon_scanner.foundation.signatures.der import DerError
from cordon_scanner.foundation.signatures.ecdsa import Ecdsa
from cordon_scanner.intel.provenance._rsa import Rsa
from cordon_scanner.intel.provenance.transparency import (
    Checkpoint,
    EmbeddedTimestamps,
    Merkle,
    SignedEntryTimestamp,
)
from cordon_scanner.intel.provenance.x509 import Certificate, Pem, PublicKey


class BundleError(ValueError):
    """The bundle is not well formed: unverifiable, not rejected."""


class Rejected(ValueError):
    """A check the bundle failed: the bundle is rejected."""


@dataclass(frozen=True)
class Window:
    start: dt.datetime | None
    end: dt.datetime | None

    def holds(self, when: dt.datetime) -> bool:
        return (self.start is None or self.start <= when) and (self.end is None or when <= self.end)

    @staticmethod
    def of(valid_for: dict[str, Any] | None) -> Window:
        valid_for = valid_for or {}
        return Window(Strict.time(valid_for.get("start")), Strict.time(valid_for.get("end")))


@dataclass(frozen=True)
class Authority:
    chain: tuple[Certificate, ...]  # leaf-most first, the root last
    window: Window


@dataclass(frozen=True)
class Log:
    key: PublicKey
    window: Window


class TrustRoot:
    """The pinned Sigstore trusted root (`intel/data/sigstore-trusted-root.json`) and npm's
    registry keys (`intel/data/npm-registry-keys.json`)."""

    DATA: ClassVar[Path] = PackagePaths.data("intel")
    MEDIA_TYPE: ClassVar[str] = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
    _loaded: ClassVar[TrustRoot | None] = None

    def __init__(self, document: dict[str, Any], npm_keys: dict[str, Any]) -> None:
        if document.get("mediaType") != TrustRoot.MEDIA_TYPE:
            raise BundleError("a trusted root of an unknown media type")
        self.authorities = [
            Authority(
                tuple(
                    Certificate.from_der(Strict.b64(c["rawBytes"]))
                    for c in ca["certChain"]["certificates"]
                ),
                Window.of(ca.get("validFor")),
            )
            for ca in document.get("certificateAuthorities", [])
        ]
        #: Logs whose key this does not read: left out, so evidence from them is unverifiable.
        self.unread: list[str] = []
        self.tlogs: dict[bytes, Log] = {}
        for log in document.get("tlogs", []):
            key = self._key(log)
            if key is not None:
                self.tlogs[Strict.b64(log["logId"]["keyId"])] = Log(
                    key, Window.of(log["publicKey"].get("validFor"))
                )
        self.ctlogs: dict[bytes, PublicKey] = {}
        for log in document.get("ctlogs", []):
            key = self._key(log)
            if key is not None:
                self.ctlogs[Strict.b64(log["logId"]["keyId"])] = key
        self.npm: dict[str, tuple[PublicKey, dt.datetime | None]] = {}
        for key in npm_keys.get("keys", []):
            if key.get("keytype") != "ecdsa-sha2-nistp256":
                continue
            self.npm[key["keyid"]] = (
                PublicKey.from_spki(Strict.b64(key["key"])),
                Strict.time(key.get("expires")),
            )

    def _key(self, log: dict[str, Any]) -> PublicKey | None:
        """A log's key in the encoding its `keyDetails` names: PKIX (a SubjectPublicKeyInfo) or
        PKCS #1 (a bare RSA key)."""
        public = log.get("publicKey") or {}
        details = str(public.get("keyDetails", ""))
        try:
            raw = Strict.b64(public["rawBytes"])
            if details.startswith("PKCS1_RSA"):
                return PublicKey("rsa", Rsa.raw_key(raw), raw)
            return PublicKey.from_spki(raw)
        except (KeyError, BundleError, DerError):
            self.unread.append(str(log.get("baseUrl", "a log")))
            return None

    @staticmethod
    def production() -> TrustRoot:
        if TrustRoot._loaded is None:
            root = Strict.loads(
                (TrustRoot.DATA / "sigstore-trusted-root.json").read_text(encoding="utf-8")
            )
            npm = Strict.loads(
                (TrustRoot.DATA / "npm-registry-keys.json").read_text(encoding="utf-8")
            )
            TrustRoot._loaded = TrustRoot(root, npm)
        return TrustRoot._loaded


@dataclass(frozen=True)
class Verified:
    """What a verified bundle proves: the signer, and the content it signed."""

    certificate: Certificate | None  # None for a registry-key signature
    registry_key: str | None
    payload_type: str | None  # a DSSE envelope's, None for a message signature
    payload: bytes | None
    integrated_time: dt.datetime


class BundleVerifier:
    """`verify(bundle_json, digest_hex=..., algorithm=...)` -> `Verified`, or raises `Rejected`
    (the bundle fails a check) or `BundleError` (it cannot be checked)."""

    MEDIA_TYPES: ClassVar[frozenset[str]] = frozenset(
        {
            "application/vnd.dev.sigstore.bundle+json;version=0.1",
            "application/vnd.dev.sigstore.bundle+json;version=0.2",
            "application/vnd.dev.sigstore.bundle.v0.3+json",
            "application/vnd.dev.sigstore.bundle+json;version=0.3",
        }
    )
    CODE_SIGNING: ClassVar[str] = "1.3.6.1.5.5.7.3.3"

    def __init__(self, root: TrustRoot | None = None) -> None:
        self.root = root or TrustRoot.production()

    def verify(
        self,
        bundle_json: str | bytes,
        *,
        digest_hex: str | None = None,
        algorithm: str | None = None,
    ) -> Verified:
        try:
            return self._verify(bundle_json, digest_hex=digest_hex, algorithm=algorithm)
        except DerError as exc:  # an encoding inside the bundle that is not exact
            raise BundleError(f"an encoding in the bundle is malformed: {exc}") from exc

    def _verify(
        self, bundle_json: str | bytes, *, digest_hex: str | None, algorithm: str | None
    ) -> Verified:
        bundle = Strict.loads(bundle_json)
        if (
            not isinstance(bundle, dict)
            or bundle.get("mediaType") not in BundleVerifier.MEDIA_TYPES
        ):
            raise BundleError("not a Sigstore bundle of a known version")
        material = Strict.field(bundle, "verificationMaterial", dict)
        entries = Strict.field(material, "tlogEntries", list)
        if not entries:
            raise Rejected("the bundle carries no transparency-log entry")

        envelope = bundle.get("dsseEnvelope")
        message = bundle.get("messageSignature")
        if (envelope is None) == (message is None):
            raise BundleError(
                "the bundle must carry exactly one of a DSSE envelope and a message signature"
            )

        certificate, chain_ok, registry = self._key_material(material)

        # Bundles from version 0.2 on must prove inclusion; 0.1 may rest on the signed timestamp.
        needs_proof = bundle["mediaType"] != "application/vnd.dev.sigstore.bundle+json;version=0.1"
        times = [
            self._entry(
                entry, certificate, registry, envelope, message, digest_hex, needs_proof=needs_proof
            )
            for entry in entries
        ]
        when = min(times)

        if certificate is not None:
            authority = chain_ok
            assert authority is not None  # noqa: S101 - set with the certificate
            if not certificate.valid_at(when):
                raise Rejected("the log integrated the entry outside the certificate's validity")
            if not authority.window.holds(when):
                raise Rejected("the certificate authority was not valid when the entry was logged")
            key = certificate.public_key()
        else:
            assert registry is not None  # noqa: S101 - one or the other, checked above
            key, expires = self.root.npm[registry]
            if expires is not None and when > expires:
                raise Rejected("npm's registry key had expired when the entry was logged")

        if envelope is not None:
            payload_type, payload, signature = BundleVerifier._envelope(envelope)
            pae = BundleVerifier.pae(payload_type, payload)
            if not key.verify(pae, signature, BundleVerifier._hash_for(key)):
                raise Rejected("the envelope's signature does not verify under the signing key")
            return Verified(certificate, registry, payload_type, payload, when)

        digest, signature = BundleVerifier._message(message, digest_hex, algorithm)
        if key.family != "ec" or BundleVerifier._hash_for(key) != "sha256" or len(digest) != 32:
            raise BundleError(
                "a message signature this verifier cannot check against the pinned digest"
            )
        try:
            r, s = BundleVerifier._ecdsa_rs(signature)
        except DerError as exc:
            raise Rejected("the message signature is not a DER ECDSA signature") from exc
        if not Ecdsa.verify_digest(key.key, digest, r, s):  # type: ignore[arg-type]
            raise Rejected("the message signature does not verify over the pinned digest")
        return Verified(certificate, None, None, None, when)

    # -- the key --------------------------------------------------------------

    def _key_material(
        self, material: dict[str, Any]
    ) -> tuple[Certificate | None, Authority | None, str | None]:
        if "certificate" in material:
            leaf = Certificate.from_der(
                Strict.b64(Strict.field(material["certificate"], "rawBytes", str))
            )
        elif "x509CertificateChain" in material:
            chain = Strict.field(material["x509CertificateChain"], "certificates", list)
            if not chain:
                raise BundleError("an empty certificate chain")
            leaf = Certificate.from_der(Strict.b64(Strict.field(chain[0], "rawBytes", str)))
        elif "publicKey" in material:
            hint = Strict.field(material["publicKey"], "hint", str)
            if hint not in self.root.npm:
                raise BundleError("signed by a key this verifier does not pin")
            return None, None, hint
        else:
            raise BundleError("the bundle names no signing key")
        authority = self._chain(leaf)
        if leaf.is_ca():
            raise Rejected("the signing certificate is a certificate authority")
        if BundleVerifier.CODE_SIGNING not in leaf.extended_key_usages():
            raise Rejected("the signing certificate is not for code signing")
        return leaf, authority, None

    def _chain(self, leaf: Certificate) -> Authority:
        """The pinned authority that issued `leaf`, each link checked up to its self-signed root,
        and its certificate transparency checked: at least one SCT that verifies."""
        for authority in self.root.authorities:
            chain = authority.chain
            issuer = next((c for c in chain if c.subject == leaf.issuer), None)
            if issuer is None or not leaf.signed_by(issuer.public_key()):
                continue
            at = chain.index(issuer)
            for child, parent in zip(chain[at:], chain[at + 1 :], strict=False):
                if (
                    child.issuer != parent.subject
                    or not child.signed_by(parent.public_key())
                    or not parent.is_ca()
                ):
                    raise Rejected("the pinned certificate chain does not hold")
            top = chain[-1]
            if top.subject != top.issuer or not top.signed_by(top.public_key()):
                raise Rejected("the pinned root is not self-signed")
            if not issuer.is_ca():
                raise Rejected("the issuing certificate is not a certificate authority")
            if EmbeddedTimestamps.verify(leaf, issuer.spki, self.root.ctlogs) < 1:
                raise Rejected(
                    "the certificate carries no certificate-transparency timestamp that verifies"
                )
            return authority
        raise Rejected("the signing certificate was not issued by a pinned certificate authority")

    # -- the log --------------------------------------------------------------

    def _entry(
        self,
        entry: dict[str, Any],
        certificate: Certificate | None,
        registry: str | None,
        envelope: dict[str, Any] | None,
        message: dict[str, Any] | None,
        digest_hex: str | None,
        *,
        needs_proof: bool,
    ) -> dt.datetime:
        """One log entry, proved; its signed integration time."""
        log_id = Strict.b64(Strict.field(Strict.field(entry, "logId", dict), "keyId", str))
        log = self.root.tlogs.get(log_id)
        if log is None:
            raise BundleError("an entry in a transparency log this verifier does not pin")
        body_b64 = Strict.field(entry, "canonicalizedBody", str)
        body = Strict.b64(body_b64)
        index = Strict.integer(entry, "logIndex")
        proof, promise = entry.get("inclusionProof"), entry.get("inclusionPromise")
        if proof is None and promise is None:
            raise Rejected(
                "the entry carries neither an inclusion proof nor a signed entry timestamp"
            )
        if proof is None and needs_proof:
            raise Rejected("a bundle of this version must carry an inclusion proof")
        if proof is not None:
            BundleVerifier._proof(proof, body, log.key)
        if promise is None:
            # The proof says the entry is in the log; only the log's signed timestamp says when.
            raise BundleError("the entry has no signed time this verifier can read")
        integrated = Strict.integer(entry, "integratedTime")
        sig = Strict.b64(Strict.field(promise, "signedEntryTimestamp", str))
        if not SignedEntryTimestamp.verify(log.key, sig, body_b64, integrated, log_id.hex(), index):
            raise Rejected("the log's signed entry timestamp does not verify")
        when = dt.datetime.fromtimestamp(integrated, tz=dt.UTC)
        if not log.window.holds(when):
            raise Rejected("the log's key was not valid when the entry was logged")
        kind = Strict.field(entry, "kindVersion", dict)
        Bodies.check(
            Strict.loads(body),
            (kind.get("kind"), kind.get("version")),
            certificate,
            registry,
            self.root,
            envelope,
            message,
            digest_hex,
        )
        return when

    @staticmethod
    def _proof(proof: dict[str, Any], body: bytes, key: PublicKey) -> None:
        index, size = Strict.integer(proof, "logIndex"), Strict.integer(proof, "treeSize")
        hashes = [Strict.b64(h) for h in Strict.field(proof, "hashes", list)]
        root = Strict.b64(Strict.field(proof, "rootHash", str))
        reached = Merkle.root_from_proof(index, size, Merkle.leaf(body), hashes)
        if reached is None or reached != root:
            raise Rejected("the inclusion proof does not reach the stated root")
        checkpoint = Checkpoint.parse(
            Strict.field(Strict.field(proof, "checkpoint", dict), "envelope", str)
        )
        if checkpoint.root != root or checkpoint.size != size:
            raise Rejected("the checkpoint is for another tree than the proof")
        if not checkpoint.signed_by(key):
            raise Rejected("the checkpoint is not signed by the log")

    # -- the content ----------------------------------------------------------

    @staticmethod
    def pae(payload_type: str, payload: bytes) -> bytes:
        """DSSE's pre-authentication encoding: what the signature is over."""
        t = payload_type.encode("utf-8")
        return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)

    @staticmethod
    def _envelope(envelope: dict[str, Any]) -> tuple[str, bytes, bytes]:
        payload_type = Strict.field(envelope, "payloadType", str)
        payload = Strict.b64(Strict.field(envelope, "payload", str))
        signatures = Strict.field(envelope, "signatures", list)
        if len(signatures) != 1:
            raise BundleError("an envelope with other than one signature")
        return payload_type, payload, Strict.b64(Strict.field(signatures[0], "sig", str))

    @staticmethod
    def _message(
        message: dict[str, Any] | None, digest_hex: str | None, algorithm: str | None
    ) -> tuple[bytes, bytes]:
        assert message is not None  # noqa: S101 - the caller checked
        signature = Strict.b64(Strict.field(message, "signature", str))
        if digest_hex is None or (algorithm or "").lower() != "sha256":
            raise BundleError("a message signature needs a pinned sha256 digest to check")
        digest = bytes.fromhex(digest_hex)
        stated = message.get("messageDigest")
        if stated is not None and (
            Strict.field(stated, "algorithm", str) != "SHA2_256"
            or Strict.b64(Strict.field(stated, "digest", str)) != digest
        ):
            raise Rejected("the bundle signs another digest than the pinned one")
        return digest, signature

    @staticmethod
    def _hash_for(key: PublicKey) -> str | None:
        if key.family == "ec":
            return "sha384" if key.key[0].size == 48 else "sha256"  # type: ignore[index]
        if key.family == "ed25519":
            return None
        return "sha256"

    @staticmethod
    def _ecdsa_rs(signature: bytes) -> tuple[int, int]:
        from cordon_scanner.foundation.signatures.der import Der

        parts = Der.parse(signature, Der.SEQUENCE).children()
        if len(parts) != 2:
            raise DerError("an ECDSA signature of the wrong shape")
        return parts[0].integer(), parts[1].integer()


class Bodies:
    """A log entry's body against the bundle: the same signature, key and content."""

    @staticmethod
    def check(
        body: Any,
        kind: tuple[Any, Any],
        certificate: Certificate | None,
        registry: str | None,
        root: TrustRoot,
        envelope: dict[str, Any] | None,
        message: dict[str, Any] | None,
        digest_hex: str | None,
    ) -> None:
        if not isinstance(body, dict) or (body.get("kind"), body.get("apiVersion")) != kind:
            raise Rejected("the entry's body is not the kind it is filed as")
        spec = Strict.field(body, "spec", dict)
        if kind == ("dsse", "0.0.1") and envelope is not None:
            _, payload, signature = BundleVerifier._envelope(envelope)
            Bodies._hash(
                Strict.field(spec, "payloadHash", dict), hashlib.sha256(payload).hexdigest()
            )
            listed = Strict.field(spec, "signatures", list)
            if (
                len(listed) != 1
                or Strict.b64(Strict.field(listed[0], "signature", str)) != signature
            ):
                raise Rejected("the entry records another signature than the envelope's")
            Bodies._same_key(
                Strict.b64(Strict.field(listed[0], "verifier", str)), certificate, registry, root
            )
        elif kind == ("intoto", "0.0.2") and envelope is not None:
            payload_type, payload, signature = BundleVerifier._envelope(envelope)
            content = Strict.field(spec, "content", dict)
            Bodies._hash(
                Strict.field(content, "payloadHash", dict), hashlib.sha256(payload).hexdigest()
            )
            logged = Strict.field(content, "envelope", dict)
            if logged.get("payloadType") != payload_type:
                raise Rejected("the entry records another payload type")
            listed = Strict.field(logged, "signatures", list)
            if len(listed) != 1:
                raise Rejected("the entry records other than one signature")
            # intoto 0.0.2 stores the signature base64-encoded twice.
            inner = Strict.b64(Strict.field(listed[0], "sig", str))
            if Strict.b64(inner.decode("ascii", "strict")) != signature:
                raise Rejected("the entry records another signature than the envelope's")
            Bodies._same_key(
                Strict.b64(Strict.field(listed[0], "publicKey", str)), certificate, registry, root
            )
        elif kind == ("hashedrekord", "0.0.1") and message is not None:
            data = Strict.field(Strict.field(spec, "data", dict), "hash", dict)
            if digest_hex is None:
                raise BundleError("a message signature needs a pinned digest to check")
            Bodies._hash(data, digest_hex.lower())
            sig = Strict.field(spec, "signature", dict)
            if Strict.b64(Strict.field(sig, "content", str)) != Strict.b64(
                Strict.field(message, "signature", str)
            ):
                raise Rejected("the entry records another signature than the bundle's")
            Bodies._same_key(
                Strict.b64(Strict.field(Strict.field(sig, "publicKey", dict), "content", str)),
                certificate,
                registry,
                root,
            )
        else:
            raise BundleError(f"a log entry kind this verifier does not read: {kind}")

    @staticmethod
    def _hash(stated: dict[str, Any], expected_hex: str) -> None:
        if (
            stated.get("algorithm") != "sha256"
            or str(stated.get("value", "")).lower() != expected_hex
        ):
            raise Rejected("the entry records another content hash than the bundle's")

    @staticmethod
    def _same_key(
        pem_bytes: bytes, certificate: Certificate | None, registry: str | None, root: TrustRoot
    ) -> None:
        try:
            text = pem_bytes.decode("ascii", "strict")
            if certificate is not None:
                same = Pem.decode(text, "CERTIFICATE") == certificate.raw
            else:
                same = (
                    registry is not None
                    and Pem.decode(text, "PUBLIC KEY") == root.npm[registry][0].spki
                )
        except (DerError, UnicodeDecodeError):
            same = False
        if not same:
            raise Rejected("the entry was signed with another key than the bundle's")


class Strict:
    """JSON and encodings read exactly: a duplicate key, padding-free or non-canonical base64,
    or a field of the wrong type is a malformed bundle."""

    @staticmethod
    def loads(text: str | bytes) -> Any:
        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            out: dict[str, Any] = {}
            for k, v in items:
                if k in out:
                    raise BundleError(f"a duplicate JSON key: {k}")
                out[k] = v
            return out

        try:
            return json.loads(text, object_pairs_hook=pairs)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise BundleError("not JSON") from exc

    @staticmethod
    def field(container: Any, name: str, kind: type) -> Any:
        if not isinstance(container, dict):
            raise BundleError(f"expected an object holding {name}")
        value = container.get(name)
        if not isinstance(value, kind) or (isinstance(value, bool) and kind is not bool):
            raise BundleError(f"{name} is missing or not a {kind.__name__}")
        return value

    @staticmethod
    def integer(container: Any, name: str) -> int:
        value = container.get(name) if isinstance(container, dict) else None
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        if (
            isinstance(value, str)
            and value.isdigit()
            and (value == "0" or not value.startswith("0"))
        ):
            return int(value)
        raise BundleError(f"{name} is not a non-negative integer")

    @staticmethod
    def b64(text: str) -> bytes:
        try:
            raw = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise BundleError("base64 that does not decode") from exc
        if base64.b64encode(raw).decode("ascii") != text:
            raise BundleError("base64 not in its canonical form")
        return raw

    @staticmethod
    def time(text: Any) -> dt.datetime | None:
        if text is None:
            return None
        if not isinstance(text, str):
            raise BundleError("a time that is not text")
        try:
            return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise BundleError("a time not in ISO 8601") from exc


__all__ = ["BundleError", "BundleVerifier", "Rejected", "TrustRoot", "Verified"]
