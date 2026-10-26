"""Keyless signing (`cloud/keyless`), end to end against a Sigstore made in the test.

Fulcio and Rekor are out of reach in a unit test, so the test stands up its own: a certificate
authority that issues a certificate for the proof-of-possession key with a certificate-
transparency timestamp, and a log that returns an inclusion proof, a signed checkpoint and a
signed entry timestamp. `Keyless` signs against them, and the bundle it returns must pass the
same verifier that checks real attestations -- with this test's trust root in place of the
pinned one. Every piece the test signs is signed with the project's own `P256Signer`.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
from typing import Any, ClassVar

import pytest

from cordon_scanner.cloud import keyless
from cordon_scanner.cloud._p256 import P256Signer
from cordon_scanner.intel.provenance.sigstore_bundle import BundleVerifier, Rejected, TrustRoot
from cordon_scanner.intel.provenance.transparency import Merkle, SignedEntryTimestamp


class Der:
    """The few DER encodings a test certificate needs."""

    @staticmethod
    def tlv(tag: int, body: bytes) -> bytes:
        n = len(body)
        if n < 0x80:
            return bytes([tag, n]) + body
        size = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([tag, 0x80 | len(size)]) + size + body

    @staticmethod
    def seq(*parts: bytes) -> bytes:
        return Der.tlv(0x30, b"".join(parts))

    @staticmethod
    def integer(v: int) -> bytes:
        return Der.tlv(0x02, v.to_bytes((v.bit_length() + 8) // 8, "big"))

    @staticmethod
    def oid(dotted: str) -> bytes:
        arcs = [int(a) for a in dotted.split(".")]
        out = bytearray([arcs[0] * 40 + arcs[1]])
        for arc in arcs[2:]:
            chunk = [arc & 0x7F]
            arc >>= 7
            while arc:
                chunk.append(0x80 | (arc & 0x7F))
                arc >>= 7
            out += bytes(reversed(chunk))
        return Der.tlv(0x06, bytes(out))

    @staticmethod
    def time(when: dt.datetime) -> bytes:
        return Der.tlv(0x18, when.strftime("%Y%m%d%H%M%SZ").encode())

    @staticmethod
    def name(cn: str) -> bytes:
        return Der.seq(Der.tlv(0x31, Der.seq(Der.oid("2.5.4.3"), Der.tlv(0x0C, cn.encode()))))

    @staticmethod
    def extension(oid: str, value: bytes, *, critical: bool = False) -> bytes:
        flag = Der.tlv(0x01, b"\xff") if critical else b""
        return Der.seq(Der.oid(oid), flag, Der.tlv(0x04, value))


class MiniSigstore:
    """A certificate authority, a CT log and a transparency log, all signing with P256Signer."""

    ECDSA_SHA256: ClassVar[bytes] = Der.seq(Der.oid("1.2.840.10045.4.3.2"))
    REPOSITORY: ClassVar[str] = "acme/app"
    ISSUER: ClassVar[str] = "https://token.actions.githubusercontent.com"

    def __init__(self) -> None:
        self.ca, self.ct, self.log = (P256Signer.ephemeral() for _ in range(3))
        self.now = dt.datetime.now(dt.UTC).replace(microsecond=0)
        self.root = self._certificate(
            "test root",
            self.ca,
            self.ca.public_spki(),
            serial=1,
            extensions=[Der.extension("2.5.29.19", Der.seq(Der.tlv(0x01, b"\xff")), critical=True)],
            days=365,
        )
        self.posted: list[str] = []
        self.tamper: str | None = None

    def _certificate(
        self,
        subject: str,
        signer: P256Signer,
        spki: bytes,
        *,
        serial: int,
        extensions: list[bytes],
        days: float,
    ) -> bytes:
        tbs = Der.seq(
            Der.tlv(0xA0, Der.integer(2)),
            Der.integer(serial),
            MiniSigstore.ECDSA_SHA256,
            Der.name("test root"),
            Der.seq(
                Der.time(self.now - dt.timedelta(minutes=1)),
                Der.time(self.now + dt.timedelta(days=days)),
            ),
            Der.name(subject),
            spki,
            Der.tlv(0xA3, Der.seq(*extensions)),
        )
        return Der.seq(tbs, MiniSigstore.ECDSA_SHA256, Der.tlv(0x03, b"\x00" + signer.sign(tbs)))

    def trust_root(self) -> TrustRoot:
        def log(key: P256Signer) -> dict[str, Any]:
            spki = key.public_spki()
            return {
                "baseUrl": "https://test.invalid",
                "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": base64.b64encode(spki).decode(),
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                },
                "logId": {"keyId": base64.b64encode(hashlib.sha256(spki).digest()).decode()},
            }

        return TrustRoot(
            {
                "mediaType": TrustRoot.MEDIA_TYPE,
                "certificateAuthorities": [
                    {
                        "certChain": {
                            "certificates": [{"rawBytes": base64.b64encode(self.root).decode()}]
                        },
                        "validFor": {"start": "2020-01-01T00:00:00Z"},
                    }
                ],
                "tlogs": [log(self.log)],
                "ctlogs": [log(self.ct)],
            },
            {},
        )

    # -- Fulcio -----------------------------------------------------------------

    def fulcio(self, document: dict[str, Any]) -> dict[str, Any]:
        pem = document["publicKeyRequest"]["publicKey"]["content"]
        spki = base64.b64decode("".join(pem.strip().splitlines()[1:-1]))
        token = document["credentials"]["oidcIdentityToken"]
        proof = base64.b64decode(document["publicKeyRequest"]["proofOfPossession"])
        from cordon_scanner.intel.provenance.x509 import PublicKey

        subject = keyless.OidcToken.subject(token).encode()
        assert PublicKey.from_spki(spki).verify(subject, proof, "sha256"), "no proof of possession"
        identity = [
            Der.extension("2.5.29.37", Der.seq(Der.oid("1.3.6.1.5.5.7.3.3"))),
            Der.extension("1.3.6.1.4.1.57264.1.8", Der.tlv(0x0C, MiniSigstore.ISSUER.encode())),
            Der.extension("1.3.6.1.4.1.57264.1.5", MiniSigstore.REPOSITORY.encode()),
        ]
        precert = self._certificate("", self.ca, spki, serial=7, extensions=identity, days=0.007)
        from cordon_scanner.intel.provenance.x509 import Certificate

        # The CT log signs the certificate as it is without the timestamp list (RFC 6962 3.2).
        precert_tbs = Certificate.from_der(precert).tbs
        stamp = int(self.now.timestamp() * 1000)
        signed = (
            b"\x00\x00"
            + stamp.to_bytes(8, "big")
            + b"\x00\x01"
            + hashlib.sha256(self.ca.public_spki()).digest()
            + len(precert_tbs).to_bytes(3, "big")
            + precert_tbs
            + b"\x00\x00"
        )
        sig = self.ct.sign(signed)
        sct = (
            b"\x00"
            + hashlib.sha256(self.ct.public_spki()).digest()
            + stamp.to_bytes(8, "big")
            + b"\x00\x00"
            + b"\x04\x03"
            + len(sig).to_bytes(2, "big")
            + sig
        )
        listed = len(sct).to_bytes(2, "big") + sct
        sct_list = Der.tlv(0x04, len(listed).to_bytes(2, "big") + listed)
        leaf = self._certificate(
            "",
            self.ca,
            spki,
            serial=7,
            extensions=[*identity, Der.extension("1.3.6.1.4.1.11129.2.4.2", sct_list)],
            days=0.007,
        )
        if self.tamper == "certificate":
            leaf = leaf[:-5] + bytes([leaf[-5] ^ 1]) + leaf[-4:]

        def pem_of(der: bytes) -> str:
            b = base64.b64encode(der).decode()
            return (
                "-----BEGIN CERTIFICATE-----\n"
                + "\n".join(b[i : i + 64] for i in range(0, len(b), 64))
                + "\n-----END CERTIFICATE-----\n"
            )

        return {
            "signedCertificateEmbeddedSct": {
                "chain": {"certificates": [pem_of(leaf), pem_of(self.root)]}
            }
        }

    # -- Rekor ----------------------------------------------------------------

    def rekor(self, document: dict[str, Any]) -> dict[str, Any]:
        content = document["spec"]["proposedContent"]
        envelope = json.loads(content["envelope"])
        payload = base64.b64decode(envelope["payload"])
        body = {
            "apiVersion": "0.0.1",
            "kind": "dsse",
            "spec": {
                "envelopeHash": {
                    "algorithm": "sha256",
                    "value": hashlib.sha256(content["envelope"].encode()).hexdigest(),
                },
                "payloadHash": {
                    "algorithm": "sha256",
                    "value": hashlib.sha256(payload if self.tamper != "body" else b"x").hexdigest(),
                },
                "signatures": [
                    {
                        "signature": envelope["signatures"][0]["sig"],
                        "verifier": content["verifiers"][0],
                    }
                ],
            },
        }
        body_b64 = base64.b64encode(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        root = Merkle.leaf(base64.b64decode(body_b64))
        spki = self.log.public_spki()
        log_id = hashlib.sha256(spki).digest()
        note = f"test.invalid - 1\n1\n{base64.b64encode(root).decode()}\n".encode()
        hint = hashlib.sha256(spki).digest()[:4]
        checkpoint = (
            note.decode()
            + "\n"
            + chr(0x2014)
            + " test.invalid "
            + base64.b64encode(hint + self.log.sign(note)).decode()
            + "\n"
        )
        integrated = int(self.now.timestamp())
        set_signature = self.log.sign(
            SignedEntryTimestamp.payload(body_b64, integrated, log_id.hex(), 0)
        )
        return {
            "uuid": {
                "body": body_b64,
                "integratedTime": integrated,
                "logID": log_id.hex(),
                "logIndex": 0,
                "verification": {
                    "inclusionProof": {
                        "checkpoint": checkpoint,
                        "hashes": [],
                        "logIndex": 0,
                        "rootHash": root.hex(),
                        "treeSize": 1,
                    },
                    "signedEntryTimestamp": base64.b64encode(set_signature).decode(),
                },
            }
        }

    def post(self, url: str, document: dict[str, Any]) -> dict[str, Any]:
        self.posted.append(url)
        return self.fulcio(document) if "fulcio" in url else self.rekor(document)


class Tokens:
    @staticmethod
    def ci(sub: str = "repo:acme/app:ref:refs/heads/main") -> str:
        def part(d: dict[str, Any]) -> str:
            return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

        return ".".join(
            [
                part({"alg": "RS256"}),
                part({"iss": MiniSigstore.ISSUER, "aud": "sigstore", "sub": sub}),
                "sig",
            ]
        )


class TestKeylessSigning:
    PAYLOAD: ClassVar[bytes] = json.dumps(
        {"_type": "https://in-toto.io/Statement/v1", "subject": []}
    ).encode()

    def test_a_signed_bundle_verifies_under_the_independent_verifier(self) -> None:
        sigstore = MiniSigstore()
        signer = keyless.Keyless(sigstore.post, root=sigstore.trust_root())
        bundle = signer.sign_dsse("application/vnd.in-toto+json", self.PAYLOAD, Tokens.ci())
        verified = BundleVerifier(sigstore.trust_root()).verify(json.dumps(bundle))
        assert verified.payload == self.PAYLOAD
        assert verified.certificate is not None
        assert (
            verified.certificate.extension_text("1.3.6.1.4.1.57264.1.5", der_string=False)
            == "acme/app"
        )
        assert sigstore.posted == [signer.fulcio, signer.rekor]

    @pytest.mark.parametrize("tamper", ["certificate", "body"])
    def test_a_bundle_that_does_not_verify_is_never_returned(self, tamper: str) -> None:
        sigstore = MiniSigstore()
        sigstore.tamper = tamper
        with pytest.raises(keyless.KeylessError, match="does not verify"):
            keyless.Keyless(sigstore.post, root=sigstore.trust_root()).sign_dsse(
                "application/vnd.in-toto+json", self.PAYLOAD, Tokens.ci()
            )

    def test_the_bundle_is_for_this_payload_and_no_other(self) -> None:
        sigstore = MiniSigstore()
        bundle = keyless.Keyless(sigstore.post, root=sigstore.trust_root()).sign_dsse(
            "application/vnd.in-toto+json", self.PAYLOAD, Tokens.ci()
        )
        bundle["dsseEnvelope"]["payload"] = base64.b64encode(self.PAYLOAD + b" ").decode()
        with pytest.raises(Rejected):
            BundleVerifier(sigstore.trust_root()).verify(json.dumps(bundle))

    def test_a_token_without_a_subject_is_refused(self) -> None:
        with pytest.raises(keyless.KeylessError):
            keyless.OidcToken.subject("a.b.c")

    def test_only_the_two_sigstore_endpoints_are_posted_to(self) -> None:
        with pytest.raises(keyless.KeylessError, match="not a Sigstore endpoint"):
            keyless.Keyless()._post("https://example.invalid/", {})


class TestTheIdentityToken:
    def test_an_explicit_token_is_used(self, monkeypatch) -> None:
        monkeypatch.setenv("SIGSTORE_ID_TOKEN", " tok ")
        assert keyless.OidcToken.detect() == "tok"

    def test_outside_ci_there_is_none(self, monkeypatch) -> None:
        for name in (
            "SIGSTORE_ID_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        ):
            monkeypatch.delenv(name, raising=False)
        assert keyless.OidcToken.detect() is None

    def test_github_is_asked_over_https_only(self, monkeypatch) -> None:
        monkeypatch.delenv("SIGSTORE_ID_TOKEN", raising=False)
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "http://insecure.invalid/token")
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer")
        assert keyless.OidcToken.detect() is None


class TestTheSigner:
    """RFC 6979 A.2.5: P-256 with SHA-256, the published key, nonces and signatures."""

    KEY: ClassVar[int] = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721

    def test_the_public_key(self) -> None:
        x, y = P256Signer(self.KEY).point
        assert x == 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
        assert y == 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299

    @pytest.mark.parametrize(
        ("message", "r", "s"),
        [
            (
                b"sample",
                0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
                0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8,
            ),
            (
                b"test",
                0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367,
                0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083,
            ),
        ],
    )
    def test_deterministic_signatures(self, message: bytes, r: int, s: int) -> None:
        assert P256Signer(self.KEY).sign_digest(hashlib.sha256(message).digest()) == (r, s)

    def test_two_ephemeral_keys_differ_and_each_verifies(self) -> None:
        from cordon_scanner.intel.provenance.x509 import PublicKey

        a, b = P256Signer.ephemeral(), P256Signer.ephemeral()
        assert a.point != b.point
        for key in (a, b):
            assert PublicKey.from_spki(key.public_spki()).verify(b"m", key.sign(b"m"), "sha256")
