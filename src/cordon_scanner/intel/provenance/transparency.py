"""Transparency-log evidence: Merkle inclusion proofs, signed checkpoints, Rekor's signed entry
timestamps, and the certificate-transparency timestamps embedded in a Fulcio certificate.

Each answers one question, and each is checked from first principles against keys this project
pins (`sigstore_root`), never against a key the evidence carries itself:

- **Inclusion proof** (RFC 9162 2.1.3): the entry's leaf hash, folded with the audit path, gives
  the tree's root -- so the entry is in the log the root belongs to.
- **Checkpoint** (the C2SP signed-note format): the log's signature over its size and root, so
  the root the proof reaches is one the log itself published.
- **Signed entry timestamp** (Rekor's `inclusionPromise`): the log's signature over the entry and
  the time it was integrated -- the older form of the same promise.
- **Signed certificate timestamp** (RFC 6962 3.2): a certificate-transparency log's signature
  over the precertificate, so the certificate was logged where anyone can see it was issued.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.intel.provenance._der import Der, DerError

if TYPE_CHECKING:
    from cordon_scanner.intel.provenance.x509 import Certificate, PublicKey


class Merkle:
    """RFC 9162 Merkle tree hashing and inclusion-proof verification."""

    @staticmethod
    def leaf(data: bytes) -> bytes:
        return hashlib.sha256(b"\x00" + data).digest()

    @staticmethod
    def node(left: bytes, right: bytes) -> bytes:
        return hashlib.sha256(b"\x01" + left + right).digest()

    @staticmethod
    def root_from_proof(index: int, size: int, leaf_hash: bytes, path: list[bytes]) -> bytes | None:
        """The root an inclusion proof reaches (RFC 9162 2.1.3.2), or None when the proof is not
        well formed for that index and size."""
        if not 0 <= index < size:
            return None
        fn, sn = index, size - 1
        r = leaf_hash
        for p in path:
            if len(p) != 32 or sn == 0:
                return None
            if fn & 1 or fn == sn:
                r = Merkle.node(p, r)
                if not fn & 1:
                    while fn and not fn & 1:
                        fn >>= 1
                        sn >>= 1
            else:
                r = Merkle.node(r, p)
            fn >>= 1
            sn >>= 1
        return r if sn == 0 else None


class Checkpoint:
    """A C2SP signed note: `origin`, `size`, `root` and a signature by the log's key."""

    EM_DASH: ClassVar[str] = chr(0x2014)

    def __init__(
        self, origin: str, size: int, root: bytes, body: bytes, signatures: list[tuple[str, bytes]]
    ) -> None:
        self.origin, self.size, self.root, self.body, self.signatures = (
            origin,
            size,
            root,
            body,
            signatures,
        )

    @staticmethod
    def parse(envelope: str) -> Checkpoint:
        text, sep, sigs = envelope.partition("\n\n")
        if not sep:
            raise DerError("a checkpoint without signatures")
        lines = text.split("\n")
        if len(lines) < 3:
            raise DerError("a checkpoint body too short")
        origin, size_text, root_text = lines[0], lines[1], lines[2]
        if not size_text.isdigit() or (size_text.startswith("0") and size_text != "0"):
            raise DerError("a checkpoint size that is not a number")
        root = base64.b64decode(root_text, validate=True)
        if len(root) != 32:
            raise DerError("a checkpoint root of the wrong length")
        signatures: list[tuple[str, bytes]] = []
        for line in sigs.split("\n"):
            if not line:
                continue
            if not line.startswith(Checkpoint.EM_DASH + " "):
                raise DerError("a checkpoint signature line not in the note format")
            name, _, blob = line[2:].rpartition(" ")
            raw = base64.b64decode(blob, validate=True)
            if len(raw) < 5:
                raise DerError("a checkpoint signature too short")
            signatures.append((name, raw))
        return Checkpoint(origin, int(size_text), root, (text + "\n").encode("utf-8"), signatures)

    @staticmethod
    def key_hint(name: str, key: PublicKey) -> bytes:
        """The 4-byte key hint a note signature line begins with: for an Ed25519 note key, the
        C2SP note hash of name, type 0x01 and the key; for a log's ECDSA or RSA key, the first four
        bytes of the SHA-256 of its DER key (Rekor's convention)."""
        if key.family == "ed25519":
            return hashlib.sha256(name.encode() + b"\n" + b"\x01" + bytes(key.key)).digest()[:4]  # type: ignore[call-overload]
        return hashlib.sha256(key.spki).digest()[:4]

    def signed_by(self, key: PublicKey) -> bool:
        hash_name = None if key.family == "ed25519" else "sha256"
        for name, raw in self.signatures:
            # The signer is the origin's own name; Rekor v1 writes its origin as `<name> - <tree
            # id>` and signs as `<name>`, which is that one form and no looser match.
            if name not in (self.origin, self.origin.split(" - ", 1)[0]):
                continue
            if raw[:4] != Checkpoint.key_hint(name, key):
                continue
            if key.verify(self.body, raw[4:], hash_name):
                return True
        return False


class SignedEntryTimestamp:
    """Rekor's promise of inclusion: its signature over the canonical entry summary."""

    @staticmethod
    def payload(body_b64: str, integrated_time: int, log_id_hex: str, log_index: int) -> bytes:
        summary = {
            "body": body_b64,
            "integratedTime": integrated_time,
            "logID": log_id_hex,
            "logIndex": log_index,
        }
        return json.dumps(summary, sort_keys=True, separators=(",", ":")).encode()

    @staticmethod
    def verify(
        key: PublicKey,
        signature: bytes,
        body_b64: str,
        integrated_time: int,
        log_id_hex: str,
        log_index: int,
    ) -> bool:
        message = SignedEntryTimestamp.payload(body_b64, integrated_time, log_id_hex, log_index)
        return key.verify(message, signature, "sha256")


class EmbeddedTimestamps:
    """The SCTs a certificate carries, checked against the precertificate they were issued over."""

    @staticmethod
    def parse(cert: Certificate) -> list[dict[str, object]]:
        """Each embedded SCT: `log_id`, `timestamp` (ms), `extensions`, `hash`, `algorithm`,
        `signature`. Raises `DerError` on a list not in its TLS encoding."""
        ext = cert.extensions.get(cert.SCT_LIST)
        if ext is None:
            return []
        data = Der.parse(ext.value, Der.OCTET_STRING).body
        reader = _Tls(data)
        listed = _Tls(reader.vector(2))
        reader.done()
        out: list[dict[str, object]] = []
        while not listed.at_end():
            item = _Tls(listed.vector(2))
            version = item.uint(1)
            if version != 0:
                raise DerError("an SCT version not 1")
            log_id = item.take(32)
            timestamp = item.uint(8)
            extensions = item.vector(2)
            hash_alg, sig_alg = item.uint(1), item.uint(1)
            signature = item.vector(2)
            item.done()
            out.append(
                {
                    "log_id": log_id,
                    "timestamp": timestamp,
                    "extensions": extensions,
                    "hash": hash_alg,
                    "algorithm": sig_alg,
                    "signature": signature,
                }
            )
        return out

    @staticmethod
    def precert_tbs(cert: Certificate) -> bytes:
        """The certificate's TBS with the SCT list extension removed: what the CT log signed."""
        tbs = Der.parse(cert.tbs, Der.SEQUENCE)
        rebuilt: list[bytes] = []
        for child in tbs.children():
            if child.tag != 0xA3:
                rebuilt.append(child.raw)
                continue
            exts = Der.parse(child.body, Der.SEQUENCE).children()
            kept = [e.raw for e in exts if e.children()[0].oid() != cert.SCT_LIST]
            rebuilt.append(DerWriter.tlv(0xA3, DerWriter.tlv(Der.SEQUENCE, b"".join(kept))))
        return DerWriter.tlv(Der.SEQUENCE, b"".join(rebuilt))

    @staticmethod
    def verify(cert: Certificate, issuer_spki: bytes, logs: dict[bytes, PublicKey]) -> int:
        """How many embedded SCTs verify under a pinned CT log key."""
        try:
            scts = EmbeddedTimestamps.parse(cert)
            tbs = EmbeddedTimestamps.precert_tbs(cert)
        except (DerError, IndexError):
            return 0
        issuer_key_hash = hashlib.sha256(issuer_spki).digest()
        good = 0
        for sct in scts:
            key = logs.get(sct["log_id"])  # type: ignore[call-overload]
            if key is None or sct["hash"] != 4:  # SHA-256
                continue
            ext = sct["extensions"]
            assert isinstance(ext, bytes)  # noqa: S101 - built above
            signed = (
                b"\x00\x00"
                + int(sct["timestamp"]).to_bytes(8, "big")  # type: ignore[call-overload]
                + b"\x00\x01"
                + issuer_key_hash
                + len(tbs).to_bytes(3, "big")
                + tbs
                + len(ext).to_bytes(2, "big")
                + ext
            )
            if key.verify(signed, sct["signature"], "sha256"):
                good += 1
        return good


class DerWriter:
    """The one encoding this module writes: a TLV, to rebuild the precertificate it verifies."""

    @staticmethod
    def tlv(tag: int, body: bytes) -> bytes:
        n = len(body)
        if n < 0x80:
            return bytes([tag, n]) + body
        size = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([tag, 0x80 | len(size)]) + size + body


class _Tls:
    """A reader over TLS presentation-language encoding (RFC 8446 3): big-endian integers and
    length-prefixed vectors, every read checked against what remains."""

    def __init__(self, data: bytes) -> None:
        self.data, self.at = data, 0

    def take(self, n: int) -> bytes:
        if self.at + n > len(self.data):
            raise DerError("a TLS structure past its end")
        out = self.data[self.at : self.at + n]
        self.at += n
        return out

    def uint(self, n: int) -> int:
        return int.from_bytes(self.take(n), "big")

    def vector(self, length_bytes: int) -> bytes:
        return self.take(self.uint(length_bytes))

    def at_end(self) -> bool:
        return self.at == len(self.data)

    def done(self) -> None:
        if not self.at_end():
            raise DerError("bytes after a TLS structure")


__all__ = ["Checkpoint", "DerWriter", "EmbeddedTimestamps", "Merkle", "SignedEntryTimestamp"]
