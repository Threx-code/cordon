"""``pe.signatures``: a file's Authenticode signatures, read on Cordon's own primitives.

Each signature holds its signer, the certificates in the PKCS #7 SignedData, the timestamp
countersignatures (PKCS #9 and Microsoft's), each certificate as OpenSSL formats it, the chain built
from the signer with no trust anchors, and whether the signature signs the file's bytes. The ASN.1
layer is here; RSA is modular exponentiation, ECDSA and DSA come from ``intel.provenance`` -- there is
no OpenSSL and no third-party code, only the behaviour matched to it.

It is as lenient as OpenSSL and no more: BER indefinite and long-form lengths and constructed strings
are read; a non-minimal integer, a misplaced field, a name value of a type no string allows are refused
exactly where OpenSSL's templates refuse them, with the same effect on what a rule sees. ``verified``
means the signature signs the file's bytes; it is not trust, and no root is consulted. The reference
engine's recorded output is what the tests hold this to.

Named difference from the reference's reading: a timestamp countersignature whose signature, message
imprint and content digest all check is reported verified even when an element of its certificate set
that CMS declares opaque (a CertificateChoices other than a certificate) is damaged inside; the
reference empties that countersignature. On the 14,292-file malformed set this is the only difference
left: 43 values, all on one file; on 1,964 real PEs every value is the reference's
(`TestCountersignCertSetOpacity`).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.der import BadDer, Clock, Encode, Hash, Tlv
from cordon_scanner.detect.binary.modules.layout import ABSENT, Cursor
from cordon_scanner.detect.binary.modules.oids import ObjectIds
from cordon_scanner.detect.binary.modules.values import Call, Record, Scalar, Seq, Sig
from cordon_scanner.detect.binary.modules.x509 import X500, Certificate, ChainWalk, PublicKey


@dataclass(slots=True)
class Signer:
    """One PKCS #7 (or CMS) SignerInfo."""

    node: Tlv
    issuer: X500 | None
    serial: int | None
    key_id: bytes | None
    digest_oid: str
    signed_attrs: list[Tlv] | None
    signature: bytes
    unsigned_attrs: list[Tlv] | None

    @staticmethod
    def parse(node: Tlv, *, cms: bool) -> Signer:
        parts = node.row((5, 7))
        parts[0].whole_number()
        sid = parts[1]
        issuer: X500 | None = None
        serial: int | None = None
        key_id: bytes | None = None
        if sid.is_tag(16):
            name, number = sid.row(2)
            issuer, serial = X500.parse(name), number.whole_number()
        elif cms and sid.is_context(0) and not sid.constructed:
            key_id = sid.body
        else:
            raise BadDer("a signer identified by neither issuer and serial nor key")
        digest_oid = Tlv._alg_oid(parts[2])
        at = 3
        signed_attrs: list[Tlv] | None = None
        if parts[at].is_context(0):
            signed_attrs = parts[at].tagged_bag(0)
            at += 1
        if at + 2 > len(parts):
            raise BadDer("a signer info missing a field")
        Tlv._alg_oid(parts[at])
        signature = parts[at + 1].bytes_of()
        unsigned_attrs: list[Tlv] | None = None
        if at + 2 < len(parts):
            unsigned_attrs = parts[at + 2].tagged_bag(1)
            if at + 3 < len(parts):
                raise BadDer("a signer info with fields out of place")
        for attr in (signed_attrs or []) + (unsigned_attrs or []):
            pair = attr.row(2)
            pair[0].object_id()
            pair[1].bag()
        return Signer(
            node, issuer, serial, key_id, digest_oid, signed_attrs, signature, unsigned_attrs
        )

    @staticmethod
    def values_of(attrs: list[Tlv] | None, oid: str) -> list[Tlv] | None:
        """The values of the first attribute of this type (``X509at_get_attr_by_NID``)."""
        for attr in attrs or []:
            kind, values = attr.unpack()
            if kind.object_id() == oid:
                return values.unpack()
        return None

    def first(self, oid: str, *, signed: bool) -> Tlv | None:
        values = Signer.values_of(self.signed_attrs if signed else self.unsigned_attrs, oid)
        return values[0] if values else None

    def locate(self, certs: list[Certificate]) -> Certificate | None:
        """The certificate this signer names: by subject key id when it gives one, else by the issuer
        name and serial number."""

        def names(cert: Certificate) -> bool:
            if self.key_id is not None:
                return cert.subject_key_id is not None and cert.subject_key_id == self.key_id
            return (
                self.issuer is not None
                and cert.serial == self.serial
                and cert.issuer.key == self.issuer.key
            )

        return next((cert for cert in certs if names(cert)), None)


@dataclass(slots=True)
class Pkcs7:
    """PKCS #7 (or, for a timestamp, CMS) SignedData."""

    version: int
    digest_oids: list[str]
    content_type: str
    content: Tlv | None
    certs: list[Certificate]
    signers: list[Signer]

    SIGNED: ClassVar[str] = "1.2.840.113549.1.7.2"

    @staticmethod
    def parse(data: bytes, *, cms: bool = False) -> tuple[str, Pkcs7 | None]:
        """The ContentInfo's type and, when it is SignedData, the SignedData. The parse itself is the
        template: each declared SEQUENCE/SET is read and validated as it is walked (a malformation in
        declared structure raises), while the fields OpenSSL's d2i leaves opaque are read as raw bytes and
        never descended -- OCTET STRING and BIT STRING, the ANY of an AlgorithmIdentifier's parameters or an
        attribute's value, and the non-certificate CertificateChoices alternatives (extendedCertificate [0],
        v1AttrCert [1], v2AttrCert [2], other [3]), which CMS types as a plain SEQUENCE and keeps whole. So a
        scatter inside one of those does not fail the structure, exactly as it does not for the reference."""
        outer = Tlv.decode(data).row((1, 2))
        kind = outer[0].object_id()
        if kind != Pkcs7.SIGNED:
            if cms:
                raise BadDer("not SignedData")
            if len(outer) == 2 and not (outer[1].is_context(0) and outer[1].constructed):
                raise BadDer("a content that is not [0]")
            return kind, None
        if len(outer) == 1:
            if cms:
                raise BadDer("SignedData without content")
            return kind, None
        if not (outer[1].is_context(0) and outer[1].constructed):
            raise BadDer("a content that is not [0]")
        (body,) = outer[1].unpack()
        parts = body.row((4, 6))
        version = parts[0].whole_number()
        digest_oids = [Tlv._alg_oid(a) for a in parts[1].bag()]
        inner = parts[2].row((1, 2))
        content_type = inner[0].object_id()
        content: Tlv | None = None
        if len(inner) == 2:
            if not (inner[1].is_context(0) and inner[1].constructed):
                raise BadDer("an inner content that is not [0]")
            (content,) = inner[1].unpack()
            if cms and not content.is_tag(4):
                raise BadDer("encapsulated content that is not an OCTET STRING")
        at = 3
        certs: list[Certificate] = []
        if parts[at].is_context(0):
            for choice in parts[at].unpack():
                if choice.is_tag(16):
                    certs.append(Certificate.parse(choice))
                elif not cms:
                    raise BadDer("a certificate choice PKCS #7 does not have")
            at += 1
        if at < len(parts) and parts[at].is_context(1):
            at += 1
        if at != len(parts) - 1:
            raise BadDer("SignedData with fields out of place")
        signers = [Signer.parse(s, cms=cms) for s in parts[at].bag()]
        return kind, Pkcs7(version, digest_oids, content_type, content, certs, signers)

    def digest_bases(self) -> list[str] | None:
        """The digests the data is hashed with; None when OpenSSL does not know one."""
        names = []
        for oid in self.digest_oids:
            base = Hash.base(Hash.oid_long_name(oid))
            if base is None:
                return None
            names.append(base)
        return names

    def verifies_content(self, si: Signer, cert: Certificate, content: bytes) -> bool:
        """``PKCS7_signatureVerify``: the signed attributes' digest of the content, then the
        signature over those attributes (or, with none, over the content)."""
        names = self.digest_bases()
        name = Hash.base(Hash.oid_long_name(si.digest_oid))
        if names is None or name is None or name not in names:
            return False
        digest = Hash.compute(name, content)
        if digest is None:
            return False
        if si.signed_attrs:
            claimed = si.first("1.2.840.113549.1.9.4", signed=True)
            if claimed is None or claimed.joined() != digest:
                return False
            over_attrs = Hash.compute(name, Encode.signed_attributes(si.signed_attrs))
            if over_attrs is None:
                return False
            digest = over_attrs
        return PublicKey.verifies(cert.spki, name, digest, si.signature)


@dataclass(slots=True)
class Countersign:
    """A timestamp countersignature: PKCS #9 (a SignerInfo) or Microsoft's (a nested SignedData)."""

    verified: bool = False
    sign_time: int = 0
    digest_alg: str | None = None
    digest: bytes | None = None
    chain: list[Certificate] | None = None
    certs: list[Certificate] | None = None

    MSG_DIGEST: ClassVar[str] = "1.2.840.113549.1.9.4"
    SIGN_TIME_OID: ClassVar[str] = "1.2.840.113549.1.9.5"

    @staticmethod
    def from_pkcs9(
        value: Tlv, certs: list[Certificate], parent_signature: bytes, when: int
    ) -> Countersign:
        out = Countersign()
        try:
            si = Signer.parse(value, cms=False)
        except (BadDer, ValueError, IndexError):
            return out
        out.digest_alg = Hash.oid_long_name(si.digest_oid)
        stamped = si.first(Countersign.SIGN_TIME_OID, signed=True)
        if stamped is None:
            return out
        out.sign_time = Clock.at_or_fallback(stamped)
        cert = si.locate(certs)
        if cert is None:
            return out
        out.chain = ChainWalk.build(cert, certs, when)
        claimed = si.first(Countersign.MSG_DIGEST, signed=True)
        claimed_digest = claimed.joined() if claimed is not None else b""
        if not claimed_digest:
            return out
        name = Hash.base(out.digest_alg)
        if name is None:
            return out
        out.digest = claimed_digest
        over_attrs = Hash.compute(name, Encode.signed_attributes(si.signed_attrs or []))
        recovered = PublicKey.rsa_recover(cert.spki, si.signature, exact=False)
        if over_attrs is None or recovered is None:
            return out
        size = ObjectIds.DIGEST_SIZES[name]
        if len(recovered) == size:
            good = recovered == over_attrs
        else:
            try:
                good = Tlv.decode(recovered).row(2)[1].bytes_of()[:size] == over_attrs
            except (BadDer, ValueError, IndexError):
                good = False
        if not good:
            return out
        expected = Hash.compute(name, parent_signature)
        out.verified = (
            expected is not None and len(claimed_digest) == size and claimed_digest == expected
        )
        return out

    @staticmethod
    def from_microsoft(value: Tlv, parent_signature: bytes, when: int) -> Countersign:
        out = Countersign()
        cms = False
        try:
            signed = Pkcs7.parse(value.span)[1]
            if signed is None:
                return out
        except (BadDer, ValueError, IndexError):
            try:
                _, signed = Pkcs7.parse(value.span, cms=True)
                cms = True
            except (BadDer, ValueError, IndexError):
                return out
        if signed is None:
            return out
        stamp = Countersign._timestamp_info(signed)
        if stamp is None:
            return out
        version, gen_time, imprint_oid, imprint = stamp
        out.sign_time = Clock.at_or_fallback(gen_time)
        cert = Countersign._find_signer(signed, cms=cms)
        if cert is None:
            return out
        out.certs = list(signed.certs)
        out.chain = ChainWalk.build(cert, signed.certs, when)
        out.digest_alg = Hash.oid_long_name(imprint_oid)
        out.digest = imprint or None
        if not imprint:
            return out
        name = Hash.base(out.digest_alg)
        if name is None:
            return out
        expected = Hash.compute(name, parent_signature)
        if expected is None or imprint != expected or version != 1:
            return out
        content = (
            signed.content.joined()
            if signed.content is not None and signed.content.is_tag(4)
            else b""
        )
        si = signed.signers[0]
        if cms:
            out.verified = Countersign._cms_verify(signed, si, content)
        else:
            out.verified = signed.verifies_content(si, cert, content)
        return out

    @staticmethod
    def _timestamp_info(signed: Pkcs7) -> tuple[int, Tlv | None, str, bytes] | None:
        if signed.content_type != "1.2.840.113549.1.9.16.1.4" or signed.content is None:
            return None
        if not signed.content.is_tag(4):
            return None
        try:
            parts = Tlv.decode(signed.content.joined()).row((5, 10))
            version = parts[0].whole_number()
            parts[1].object_id()
            imprint_alg, imprint = parts[2].row(2)
            oid = Tlv._alg_oid(imprint_alg)
            digest = imprint.bytes_of()
            parts[3].whole_number()
            gen_time = parts[4]
            if not gen_time.is_tag(24):
                return None
        except (BadDer, ValueError, IndexError):
            return None
        return version, gen_time, oid, digest

    @staticmethod
    def _find_signer(signed: Pkcs7, *, cms: bool) -> Certificate | None:
        # each signer resolves to its own certificate by the same rule as the main signature; a CMS
        # timestamp takes the first signer that resolves, a PKCS #7 one needs every signer to resolve
        if not signed.signers:
            return None
        resolved = [si.locate(signed.certs) for si in signed.signers]
        if cms:
            return next((cert for cert in resolved if cert is not None), None)
        return None if any(cert is None for cert in resolved) else resolved[0]

    @staticmethod
    def _cms_verify(signed: Pkcs7, si: Signer, content: bytes) -> bool:
        """``CMS_SignerInfo_verify_content``: the content's digest against the signed one."""
        names = signed.digest_bases()
        name = Hash.base(Hash.oid_long_name(si.digest_oid))
        if names is None or name is None or name not in names or si.signed_attrs is None:
            return False
        claimed = [
            v
            for a in si.signed_attrs
            for k, v in [a.unpack()]
            if k.object_id() == Countersign.MSG_DIGEST
        ]
        if (
            len(claimed) != 1
            or len(claimed[0].unpack()) != 1
            or not claimed[0].unpack()[0].is_tag(4)
        ):
            return False
        digest = Hash.compute(name, content)
        return digest is not None and claimed[0].unpack()[0].joined() == digest


@dataclass(slots=True)
class Signed:
    """One Authenticode signature (the parser's ``Authenticode`` struct)."""

    flags: int = 0
    digest_alg: str | None = None
    digest: bytes | None = None
    authenticode_digest: bytes | None = None
    certs: list[Certificate] | None = None
    has_signer: bool = False
    chain: list[Certificate] | None = None
    signer_digest_alg: str | None = None
    signer_digest: bytes | None = None
    program_name: bytes | None = None
    countersigs: list[Countersign] | None = None

    CLEAN: ClassVar[int] = 0
    UNREADABLE: ClassVar[int] = 1
    SIGNER_ABSENT: ClassVar[int] = 2
    DIGEST_ABSENT: ClassVar[int] = 3
    DIGEST_ERROR: ClassVar[int] = 4
    SIGNER_INFO_ABSENT: ClassVar[int] = 5
    NOT_SIGNED_DATA: ClassVar[int] = 6
    CONTENT_BAD: ClassVar[int] = 7
    UNVERIFIED: ClassVar[int] = 8
    FILE_DIGEST_WRONG: ClassVar[int] = 9
    ALGORITHM_UNKNOWN: ClassVar[int] = 10
    #: outcomes the reference reports no signature for
    SUPPRESSED: ClassVar[frozenset[int]] = frozenset({1, 2, 4, 5, 6})
    MAX_NESTED: ClassVar[int] = 16
    MAX_DEPTH: ClassVar[int] = 32


INT, TEXT = Scalar.INT, Scalar.TEXT

CERTIFICATE :Record =Record ({
"thumbprint":TEXT ,"issuer":TEXT ,"subject":TEXT ,"version":INT ,"algorithm":TEXT ,
"algorithm_oid":TEXT ,"serial":TEXT ,"not_before":INT ,"not_after":INT ,
})  # fmt: skip

SIGNATURE :Record =Record ({
"thumbprint":TEXT ,"issuer":TEXT ,"subject":TEXT ,"version":INT ,"algorithm":TEXT ,
"algorithm_oid":TEXT ,"serial":TEXT ,"not_before":INT ,"not_after":INT ,
"verified":INT ,"digest_alg":TEXT ,"digest":TEXT ,"file_digest":TEXT ,
"number_of_certificates":INT ,"certificates":Seq (CERTIFICATE ),
"signer_info":Record ({
"program_name":TEXT ,"digest":TEXT ,"digest_alg":TEXT ,
"length_of_chain":INT ,"chain":Seq (CERTIFICATE ),
}),
"number_of_countersignatures":INT ,
"countersignatures":Seq (Record ({
"verified":INT ,"sign_time":INT ,"digest_alg":TEXT ,"digest":TEXT ,
"length_of_chain":INT ,"chain":Seq (CERTIFICATE ),
})),
"valid_on":Call (Sig (("int",),INT )),
})  # fmt: skip


class Signatures:
    """``pe.signatures``: the Authenticode signatures of a file (``parse_authenticode``)."""

    SPC_INDIRECT: ClassVar[str] = "1.3.6.1.4.1.311.2.1.4"
    SPC_OPUS: ClassVar[str] = "1.3.6.1.4.1.311.2.1.12"
    SPC_NESTED: ClassVar[str] = "1.3.6.1.4.1.311.2.4.1"
    MS_TIMESTAMP: ClassVar[str] = "1.3.6.1.4.1.311.3.3.1"
    PKCS9_COUNTERSIG: ClassVar[str] = "1.2.840.113549.1.9.6"
    MSG_DIGEST: ClassVar[str] = "1.2.840.113549.1.9.4"

    @staticmethod
    def parse(blob: bytes, now: int, depth: int = 0, *, bundled: bool = False) -> list[Signed]:
        """``authenticode_new``: this signature, then the ones nested in it. With `bundled`, a
        Microsoft timestamp's chain is built from its own certificates and the signature's together
        (YARA-X's reading, which the installer module follows); without, from its own (YARA's)."""
        if not blob:
            return []
        sig = Signed()
        out = [sig]
        try:
            _, signed = Pkcs7.parse(blob)
        except (BadDer, ValueError, IndexError):
            sig.flags = Signed.UNREADABLE
            return out
        if signed is None:
            sig.flags = Signed.NOT_SIGNED_DATA
            return out
        sig.certs = list(signed.certs)
        content = Signatures._spc_indirect(signed)
        if content is None:
            sig.flags = Signed.CONTENT_BAD
            return out
        sig.digest_alg, sig.digest = Hash.oid_long_name(content[0]), content[1]
        sig.has_signer = True
        if not signed.signers:
            sig.flags = Signed.SIGNER_INFO_ABSENT
            return out
        si = signed.signers[0]
        sig.countersigs = []
        nested = Signer.values_of(si.unsigned_attrs, Signatures.SPC_NESTED) or []
        if depth < Signed.MAX_DEPTH:
            for value in nested[: Signed.MAX_NESTED]:
                out.extend(Signatures.parse(value.span, now, depth + 1, bundled=bundled))
        for value in (Signer.values_of(si.unsigned_attrs, Signatures.PKCS9_COUNTERSIG) or [])[
            : Signed.MAX_NESTED
        ]:
            sig.countersigs.append(Countersign.from_pkcs9(value, signed.certs, si.signature, now))
        for value in (Signer.values_of(si.unsigned_attrs, Signatures.MS_TIMESTAMP) or [])[
            : Signed.MAX_NESTED
        ]:
            counter = Countersign.from_microsoft(value, si.signature, now)
            if bundled and counter.chain:
                pool = [*(counter.certs or []), *signed.certs]
                counter.chain = ChainWalk.build(counter.chain[0], pool, now)
            sig.countersigs.append(counter)
            sig.certs.extend(counter.certs or [])
        resolved = [s.locate(signed.certs) for s in signed.signers]
        cert = None if any(c is None for c in resolved) else resolved[0]
        if cert is None:
            sig.flags = Signed.SIGNER_ABSENT
            return out
        sig.chain = ChainWalk.build(cert, signed.certs, now)
        claimed = si.first(Signatures.MSG_DIGEST, signed=True)
        if claimed is None:
            sig.flags = Signed.DIGEST_ABSENT
            return out
        sig.signer_digest_alg = Hash.oid_long_name(si.digest_oid)
        sig.signer_digest = claimed.joined() or None
        opus = si.first(Signatures.SPC_OPUS, signed=True)
        if opus is not None:
            sig.program_name = Signatures._opus_program(opus)
        inner = signed.content.span if signed.content is not None else b""
        if signed.version == 1 and signed.content is not None:
            inner = b"" if signed.content.indefinite else signed.content.body
        if not signed.verifies_content(si, cert, inner):
            sig.flags = Signed.UNVERIFIED
        return out

    @staticmethod
    def _spc_indirect(signed: Pkcs7) -> tuple[str, bytes] | None:
        """SpcIndirectDataContent's digest algorithm and digest."""
        if signed.content_type != Signatures.SPC_INDIRECT or signed.content is None:
            return None
        try:
            data, pkcs1_wrap = Tlv.decode(signed.content.span).row(2)
            data.row((1, 2))[0].object_id()
            algorithm, digest = pkcs1_wrap.row(2)
            return Tlv._alg_oid(algorithm), digest.bytes_of()
        except (BadDer, ValueError, IndexError):
            return None

    @staticmethod
    def _opus_program(opus: Tlv) -> bytes | None:
        if not opus.is_tag(16):
            return None
        try:
            for part in opus.row((0, 2)):
                if part.is_context(0) and part.constructed:
                    (choice,) = part.unpack()
                    raw = choice.joined()
                    if choice.is_context(0):
                        if len(raw) % 2:
                            return None
                        name = raw.decode("utf-16-be", "surrogatepass").encode(
                            "utf-8", "surrogatepass"
                        )
                    elif choice.is_context(1):
                        name = raw.decode("latin-1").encode("utf-8")
                    else:
                        return None
                    return name if len(name) < len(opus.span) else None
        except (BadDer, ValueError, IndexError, UnicodeDecodeError):
            return None
        return None

    @staticmethod
    def authenticode_digest(
        data: bytes, name: str, pe_offset: int, is64: bool, cert_addr: int
    ) -> bytes | None:
        """The Authenticode digest: everything before the certificate table, less the checksum and
        the table's own directory entry."""
        checksum_at = pe_offset + 0x58
        directory_at = checksum_at + 4 + 0x3C + (16 if is64 else 0)
        if cert_addr < directory_at + 8:
            return None
            # the digest covers the file with two windows removed: the 4-byte checksum, and the 8-byte
            # security directory entry; everything from there to the certificate table is included
        kept = bytearray(data[:checksum_at])
        kept += data[checksum_at + 4 : directory_at]
        kept += data[directory_at + 8 : cert_addr]
        return Hash.compute(name, bytes(kept))

    @staticmethod
    def read(data: bytes, now: int) -> list[Signed]:
        """``parse_authenticode``: every signature in the first certificate, with file digests."""
        cur = Cursor(data)
        if len(data) < 0x40 or data[:2] != b"MZ":
            return []
        pe_offset = cur.uint(0x3C, 4, "little")
        if pe_offset is ABSENT or len(data) < pe_offset + 0x18 + 2:
            return []
        is64 = cur.uint(pe_offset + 0x18, 2, "little") == 0x20B
        table = pe_offset + (16 if is64 else 0) + 0x98
        if len(data) < table + 8:
            return []
        cert_addr = cur.uint(table, 4, "little")
        cert_len = cur.uint(table + 4, 4, "little")
        # the security directory (a file offset and a size) must lie within the file, as the reference requires
        # before it reads the table at all; without this a corrupted directory yields a phantom signature
        if (
            cert_addr == 0
            or cert_addr > len(data)
            or cert_len > len(data)
            or cert_addr + cert_len > len(data)
        ):
            return []
        if cert_len < 8 or len(data) < cert_addr + 8:
            return []
        length = cur.uint(cert_addr, 4, "little")
        if len(data) < cert_addr + length or length <= 8:
            return []
        found = Signatures.parse(data[cert_addr + 8 : cert_addr + length], now)
        Signatures.check_digests(
            found,
            lambda name: Signatures.authenticode_digest(data, name, pe_offset, is64, cert_addr),
        )
        return found

    @staticmethod
    def check_digests(found: list[Signed], digest_of: Callable[[str], bytes | None]) -> None:
        """Each signature's file digest computed by `digest_of` (the hash name's digest of the
        signed content; None where it cannot be) and held against the signed one: the flags say
        where it is wrong, the algorithm unknown, or the content unreadable."""
        for sig in found:
            name = Hash.base(sig.digest_alg)
            if name is None or not sig.digest:
                if sig.flags == Signed.CLEAN:
                    sig.flags = Signed.ALGORITHM_UNKNOWN
                continue
            digest = digest_of(name)
            if digest is None:
                if sig.flags == Signed.CLEAN:
                    sig.flags = Signed.DIGEST_ERROR
                break
            sig.authenticode_digest = digest
            if digest != sig.digest[: len(digest)] or len(sig.digest) < len(digest):
                sig.flags = Signed.FILE_DIGEST_WRONG

    @staticmethod
    def _present(fields: dict[str, Any]) -> dict[str, Any]:
        """A cert's fields with the absent ones (None) dropped, as the reference omits an undefined value."""
        return {k: v for k, v in fields.items() if v is not None}

    @staticmethod
    def _cert_seq(certs: list[Certificate]) -> dict[int, Any]:
        return {i: Signatures._present(cert.fields()) for i, cert in enumerate(certs)}

    @staticmethod
    def _validity_call(not_before: int | None, not_after: int | None) -> Any:
        def valid_on(when: int) -> int | None:
            if not_before is None or not_after is None:
                return None
            return int(not_before <= when <= not_after)

        return valid_on

    @staticmethod
    def signature_values(data: bytes) -> tuple[dict[int, Any], int]:
        """``pe.signatures`` as schema-first data (a Seq of SIGNATURE), and ``pe.is_signed``: every
        reported signature, each with the signer certificate's fields flattened in, as the reference reports it."""
        return Signatures.records(Signatures.read(data, int(time.time())))

    @staticmethod
    def records(found: list[Signed]) -> tuple[dict[int, Any], int]:
        """The SIGNATURE records of parsed and checked signatures, and whether any is valid."""
        out: dict[int, Any] = {}
        any_valid = 0
        for sig in found:
            if sig.flags in Signed.SUPPRESSED:
                continue
            verified = sig.flags == Signed.CLEAN
            any_valid |= int(verified)
            rec: dict[str, Any] = {"verified": int(verified)}
            if sig.digest_alg is not None:
                rec["digest_alg"] = sig.digest_alg.encode()
            if sig.digest:
                rec["digest"] = sig.digest.hex().encode()
            if sig.authenticode_digest:
                rec["file_digest"] = sig.authenticode_digest.hex().encode()
            certs = sig.certs or []
            rec["number_of_certificates"] = len(certs)
            rec["certificates"] = Signatures._cert_seq(certs)
            signer: dict[str, Any] = {}
            if sig.has_signer:
                if sig.chain:
                    rec.update(Signatures._present(sig.chain[0].fields()))
                if sig.program_name is not None:
                    signer["program_name"] = sig.program_name
                if sig.signer_digest_alg is not None:
                    signer["digest_alg"] = sig.signer_digest_alg.encode()
                if sig.signer_digest:
                    signer["digest"] = sig.signer_digest.hex().encode()
                signer["length_of_chain"] = len(sig.chain or [])
                signer["chain"] = Signatures._cert_seq(sig.chain or [])
            rec["signer_info"] = signer
            counters = sig.countersigs or []
            rec["number_of_countersignatures"] = len(counters)
            block: dict[int, Any] = {}
            for j, counter in enumerate(counters):
                one: dict[str, Any] = {
                    "verified": int(counter.verified),
                    "sign_time": counter.sign_time,
                    "length_of_chain": len(counter.chain or []),
                    "chain": Signatures._cert_seq(counter.chain or []),
                }
                if counter.digest_alg is not None:
                    one["digest_alg"] = counter.digest_alg.encode()
                if counter.digest:
                    one["digest"] = counter.digest.hex().encode()
                block[j] = one
            rec["countersignatures"] = block
            rec["valid_on"] = (
                Signatures._validity_call(rec.get("not_before"), rec.get("not_after")),
            )
            out[len(out)] = rec
        return out, any_valid


__all__ = [
    "CERTIFICATE",
    "INT",
    "SIGNATURE",
    "TEXT",
    "Countersign",
    "Pkcs7",
    "Signatures",
    "Signed",
    "Signer",
]
