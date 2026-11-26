"""CMS SignedData (RFC 5652) read strictly, and the RFC 3161 time-stamp token carried in one.

A time-stamp is a third party's signed statement that some data existed at a time: the token's content is a `TSTInfo`
(the hash of the data stamped, the time, the authority's serial number), signed by a time-stamping authority whose
certificate chains to a root this project pins. Verified here, each link:

1. the answer is a granted `TimeStampResp` with one token, and the token is SignedData over a `TSTInfo`;
2. the signer is named (issuer and serial, or key id) and is a certificate of a pinned authority, the signer's chain holds up
   to that authority's self-signed root, and the certificate is valid at the stamped time and is for time stamping;
3. the signed attributes bind the content (`messageDigest` is the digest of the `TSTInfo`, `contentType` is `TSTInfo`) and the
   signature over them verifies under the signer's key;
4. the stamped hash is the hash of the data the caller says was stamped.

Nothing here encodes except the one re-tagging CMS requires (the signed attributes are signed as a SET, carried tagged `[0]`)."""

from __future__ import annotations

import datetime as dt
import hashlib
import itertools
from dataclasses import dataclass
from typing import ClassVar

from cordon_scanner.foundation.signatures.der import Der, DerError
from cordon_scanner.intel.provenance.x509 import Certificate


class CmsError(ValueError):
    """The structure is not one this reader accepts, or a check it makes failed."""


@dataclass(frozen=True)
class Signer:
    """One SignerInfo."""

    issuer: bytes | None
    serial: int | None
    key_id: bytes | None
    digest: str
    attributes: dict[str, bytes]
    signed_attributes: bytes
    algorithm: str
    signature: bytes


@dataclass(frozen=True)
class SignedData:
    content_type: str
    content: bytes
    certificates: tuple[Certificate, ...]
    signers: tuple[Signer, ...]


@dataclass(frozen=True)
class Authority:
    """A pinned authority: its certificates, signer first and the self-signed root last, and the time it is trusted for."""

    chain: tuple[Certificate, ...]
    start: dt.datetime | None
    end: dt.datetime | None

    def holds(self, when: dt.datetime) -> bool:
        return (self.start is None or self.start <= when) and (self.end is None or when <= self.end)


class Cms:
    SIGNED_DATA: ClassVar[str] = "1.2.840.113549.1.7.2"
    CONTENT_TYPE: ClassVar[str] = "1.2.840.113549.1.9.3"
    MESSAGE_DIGEST: ClassVar[str] = "1.2.840.113549.1.9.4"
    HASHES: ClassVar[dict[str, str]] = {
        "1.3.14.3.2.26": "sha1",
        "2.16.840.1.101.3.4.2.1": "sha256",
        "2.16.840.1.101.3.4.2.2": "sha384",
        "2.16.840.1.101.3.4.2.3": "sha512",
    }
    #: Signature algorithms that name the key family only; the hash then is the signer's digest algorithm.
    BARE: ClassVar[dict[str, str]] = {"1.2.840.10045.2.1": "ec", "1.2.840.113549.1.1.1": "rsa"}
    MAX_CERTIFICATES: ClassVar[int] = 16
    MAX_ATTRIBUTES: ClassVar[int] = 32

    @classmethod
    def parse(cls, content_info: Der) -> SignedData:
        parts = content_info.expect(Der.SEQUENCE).children()
        if len(parts) != 2 or parts[0].oid() != cls.SIGNED_DATA or parts[1].tag != 0xA0:
            raise CmsError("not CMS SignedData")
        signed = Der.parse(parts[1].body, Der.SEQUENCE).children()
        if len(signed) < 4:
            raise CmsError("a SignedData of the wrong shape")
        encapsulated = signed[2].expect(Der.SEQUENCE).children()
        if len(encapsulated) != 2 or encapsulated[1].tag != 0xA0:
            raise CmsError("a SignedData with no content")
        content = Der.parse(encapsulated[1].body, Der.OCTET_STRING).body
        certificates: list[Certificate] = []
        signer_set: Der | None = None
        for part in signed[3:]:
            if part.tag == 0xA0:
                held = part.children()
                if len(held) > cls.MAX_CERTIFICATES:
                    raise CmsError("more certificates than any real token carries")
                certificates = [Certificate.from_der(c.raw) for c in held]
            elif part.tag == Der.SET:
                signer_set = part
        if signer_set is None:
            raise CmsError("a SignedData with no signers")
        signers = tuple(cls._signer(child) for child in signer_set.children())
        return SignedData(encapsulated[0].oid(), content, tuple(certificates), signers)

    @classmethod
    def _signer(cls, node: Der) -> Signer:
        fields = node.expect(Der.SEQUENCE).children()
        if len(fields) < 5:
            raise CmsError("a SignerInfo of the wrong shape")
        sid = fields[1]
        issuer = serial = key_id = None
        if sid.tag == Der.SEQUENCE:
            pair = sid.children()
            if len(pair) != 2:
                raise CmsError("a signer identifier of the wrong shape")
            issuer, serial = pair[0].expect(Der.SEQUENCE).raw, pair[1].integer(unsigned=False)
        elif sid.tag == 0x80:
            key_id = sid.body
        else:
            raise CmsError("a signer identifier that is neither issuer and serial nor a key id")
        digest = cls.HASHES.get(fields[2].expect(Der.SEQUENCE).children()[0].oid())
        if digest is None:
            raise CmsError("a digest algorithm not accepted")
        at = 3
        attributes: dict[str, bytes] = {}
        signed_attributes = b""
        if fields[at].tag == 0xA0:
            body = fields[at].body
            # What is signed is the SET OF attributes: the same bytes under a SET tag, not the [0] they are carried in.
            signed_attributes = b"\x31" + fields[at].raw[1:]
            attrs = Der.parse(signed_attributes, Der.SET).children()
            if not attrs or len(attrs) > cls.MAX_ATTRIBUTES:
                raise CmsError("signed attributes of an unreasonable size")
            for attribute in attrs:
                pair = attribute.expect(Der.SEQUENCE).children()
                values = pair[1].expect(Der.SET).children()
                oid = pair[0].oid()
                if oid in attributes or len(values) != 1:
                    raise CmsError("a repeated attribute, or one with several values")
                attributes[oid] = values[0].raw
            del body
            at += 1
        algorithm = fields[at].expect(Der.SEQUENCE).children()[0].oid()
        signature = fields[at + 1].expect(Der.OCTET_STRING).body
        return Signer(
            issuer, serial, key_id, digest, attributes, signed_attributes, algorithm, signature
        )

    @classmethod
    def signature_ok(
        cls, signer: Signer, certificate: Certificate, content: bytes, content_type: str
    ) -> bool:
        """The attributes bind this content and the signature over them verifies under the certificate's key."""
        if not signer.signed_attributes:
            return False
        try:
            stated = (
                Der.parse(signer.attributes.get(cls.MESSAGE_DIGEST, b""))
                .expect(Der.OCTET_STRING)
                .body
            )
            kind = Der.parse(signer.attributes.get(cls.CONTENT_TYPE, b"")).oid()
        except DerError:
            return False
        if kind != content_type or stated != hashlib.new(signer.digest, content).digest():
            return False
        key = certificate.public_key()
        if signer.algorithm in cls.BARE:
            return key.family == cls.BARE[signer.algorithm] and key.verify(
                signer.signed_attributes, signer.signature, signer.digest
            )
        return key.verify_algorithm(signer.algorithm, signer.signed_attributes, signer.signature)


@dataclass(frozen=True)
class Stamp:
    """What a verified time-stamp says."""

    time: dt.datetime
    hash_algorithm: str
    imprint: bytes
    serial: int


class TimestampToken:
    TST_INFO: ClassVar[str] = "1.2.840.113549.1.9.16.1.4"
    TIME_STAMPING: ClassVar[str] = "1.3.6.1.5.5.7.3.8"

    @classmethod
    def info(cls, content: bytes) -> Stamp:
        fields = Der.parse(content, Der.SEQUENCE).children()
        if len(fields) < 5 or fields[0].integer() != 1:
            raise CmsError("a TSTInfo of the wrong shape")
        imprint = fields[2].expect(Der.SEQUENCE).children()
        algorithm = Cms.HASHES.get(imprint[0].expect(Der.SEQUENCE).children()[0].oid())
        if algorithm is None:
            raise CmsError("a stamped-hash algorithm not accepted")
        generated = fields[4]
        if generated.tag != Der.GENERALIZED_TIME:
            raise CmsError("a TSTInfo with no generation time")
        return Stamp(
            Certificate._time(generated),
            algorithm,
            imprint[1].expect(Der.OCTET_STRING).body,
            fields[3].integer(),
        )

    @classmethod
    def verify(cls, answer: bytes, data: bytes, authorities: list[Authority]) -> Stamp:
        """The stamp in a DER `TimeStampResp` over `data` (the bytes that were stamped), when every link holds; `CmsError` otherwise."""
        try:
            response = Der.parse(answer, Der.SEQUENCE).children()
            if len(response) != 2:
                raise CmsError("a time-stamp response with no token")
            status = response[0].expect(Der.SEQUENCE).children()
            if not status or status[0].integer() not in (0, 1):
                raise CmsError("a time-stamp response that does not grant a stamp")
            signed = Cms.parse(response[1])
            if signed.content_type != cls.TST_INFO or len(signed.signers) != 1:
                raise CmsError("a token that is not one TSTInfo with one signer")
            stamp = cls.info(signed.content)
            if hashlib.new(stamp.hash_algorithm, data).digest() != stamp.imprint:
                raise CmsError("the stamp is over other data")
            cls._trusted(signed, stamp, authorities)
            return stamp
        except DerError as exc:
            raise CmsError(f"the time-stamp is not well formed: {exc}") from exc

    @classmethod
    def _trusted(cls, signed: SignedData, stamp: Stamp, authorities: list[Authority]) -> None:
        signer = signed.signers[0]
        candidates = [
            (a, c)
            for a in authorities
            if a.holds(stamp.time)
            for c in (*a.chain, *signed.certificates)
        ]
        for authority, certificate in candidates:
            named = (
                signer.issuer == certificate.issuer and signer.serial == certificate.serial
                if signer.issuer is not None
                else False
            )
            if not named or not certificate.valid_at(stamp.time):
                continue
            if cls.TIME_STAMPING not in certificate.extended_key_usages():
                continue
            if not cls._chain_holds(certificate, authority, stamp.time):
                continue
            if Cms.signature_ok(signer, certificate, signed.content, cls.TST_INFO):
                return
            raise CmsError("the signature over the stamp does not verify")
        raise CmsError("the stamp was not signed by a pinned time-stamping authority")

    @staticmethod
    def _chain_holds(certificate: Certificate, authority: Authority, when: dt.datetime) -> bool:
        """`certificate` is one of the authority's or signed by one that is, up to the self-signed root, each link valid at `when`."""
        chain = authority.chain
        if certificate in chain or any(c.raw == certificate.raw for c in chain):
            position = next(i for i, c in enumerate(chain) if c.raw == certificate.raw)
            below = chain[position:]
        else:
            issuer = next((c for c in chain if c.subject == certificate.issuer), None)
            if issuer is None or not certificate.signed_by(issuer.public_key()):
                return False
            below = chain[chain.index(issuer) :]
        for child, parent in itertools.pairwise(below):
            if (
                child.issuer != parent.subject
                or not child.signed_by(parent.public_key())
                or not parent.is_ca()
            ):
                return False
        top = below[-1]
        return (
            all(c.valid_at(when) for c in below)
            and top.subject == top.issuer
            and top.signed_by(top.public_key())
        )
