"""A NuGet package's repository signature, verified against DigiCert's roots without a signing service in the way.

nuget.org signs every package it hosts: the package carries `.signature.p7s`, a CMS SignedData whose content is the hash of the
rest of the archive (a hash defined over the zip structure with the signature entry cut out, so the signature can live inside
the archive it covers). An author may sign first; nuget.org then counter-signs the author's signature. Checked here, each link,
against two pinned DigiCert roots (`intel/data/nuget-trust-roots.json`) and nothing the package carries:

1. the package hash the signature states is the hash of this archive (the archive itself is first checked by the verified-archive
   layer against the SHA-512 nuget.org's catalog states);
2. the repository's signature (the package's own, or the counter-signature on an author's) verifies under a certificate issued
   to `NuGet.org Repository by Microsoft` that is for code signing and chains, through the intermediates the signature carries,
   to a pinned root;
3. the certificate was valid when the signature was time-stamped: nuget.org's certificates are renewed and the old ones expire
   while the packages stay, so what dates a signature is the RFC 3161 token inside it (`cms`), signed by a time-stamping
   authority that chains to a pinned root, over this signature's bytes.

Not consulted: certificate revocation (CRL, OCSP). The signature's value is that the archive is what nuget.org published; a
certificate revoked after the stamp was still the repository's at that time.

The answer is `verified`, `invalid`, `absent` (the archive carries no signature) or `unverifiable` (the archive could not be
fetched, or the package is signed only by its author, with no repository counter-signature to check)."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import struct
from typing import ClassVar

from cordon_scanner.foundation.signatures.der import Der, DerError
from cordon_scanner.intel.provenance.bazel_provenance import ModuleCheck
from cordon_scanner.intel.provenance.releases.cms import (
    Authority,
    CertificatePath,
    Cms,
    CmsError,
    SignedData,
    Signer,
    TimestampToken,
)
from cordon_scanner.intel.provenance.sigstore_bundle import Strict, TrustRoot
from cordon_scanner.intel.provenance.x509 import Certificate


class ZipLayout:
    """The central directory of a signed package, read as strictly as the signature's hash needs."""

    EOCD: ClassVar[bytes] = b"PK\x05\x06"
    CENTRAL: ClassVar[bytes] = b"PK\x01\x02"
    LOCAL: ClassVar[bytes] = b"PK\x03\x04"
    SIGNATURE: ClassVar[bytes] = b".signature.p7s"
    MAX_ENTRIES: ClassVar[int] = 65534

    def __init__(self, data: bytes) -> None:
        self.data = data
        end = data.rfind(self.EOCD, max(0, len(data) - 22 - 0xFFFF))
        if end < 0 or end + 22 > len(data):
            raise ValueError("no end of central directory")
        disk, cd_disk, here, total, size, offset, comment = struct.unpack(
            "<HHHHIIH", data[end + 4 : end + 22]
        )
        if (
            disk
            or cd_disk
            or here != total
            or total in (0, 0xFFFF)
            or 0xFFFFFFFF in (size, offset)
            or end + 22 + comment != len(data)
            or offset + size != end
        ):
            raise ValueError(
                "an archive this layout does not cover (split, Zip64, or a directory that does not end at its record)"
            )
        self.end, self.total, self.size, self.offset = end, total, size, offset
        self.records: list[
            tuple[int, int, int, bytes, int, int]
        ] = []  # position, length, local offset, name, method, csize
        at = offset
        for _ in range(total):
            if data[at : at + 4] != self.CENTRAL or at + 46 > end:
                raise ValueError("a central directory record out of place")
            method, csize = (
                struct.unpack("<H", data[at + 10 : at + 12])[0],
                struct.unpack("<I", data[at + 20 : at + 24])[0],
            )
            name_len, extra_len, comment_len = struct.unpack("<HHH", data[at + 28 : at + 34])
            local = struct.unpack("<I", data[at + 42 : at + 46])[0]
            length = 46 + name_len + extra_len + comment_len
            if at + length > end:
                raise ValueError("a central directory record past its end")
            self.records.append(
                (at, length, local, data[at + 46 : at + 46 + name_len], method, csize)
            )
            at += length
        if at != end:
            raise ValueError("bytes between the last record and the end record")
        signatures = [r for r in self.records if r[3] == self.SIGNATURE]
        if len(signatures) != 1:
            raise LookupError(
                "no signature entry" if not signatures else "more than one signature entry"
            )
        self.signature = signatures[0]
        self.starts = sorted(r[2] for r in self.records)
        if len(set(self.starts)) != len(self.starts) or self.starts[-1] >= offset:
            raise ValueError("local entries that overlap or lie past the directory")

    def entry_end(self, local: int) -> int:
        index = self.starts.index(local)
        return self.starts[index + 1] if index + 1 < len(self.starts) else self.offset

    def signature_bytes(self) -> bytes:
        _, _, local, _, method, csize = self.signature
        if method != 0:
            raise ValueError("a signature entry that is compressed")
        head = self.data[local : local + 30]
        if len(head) < 30 or head[:4] != self.LOCAL:
            raise ValueError("a signature entry with no local header")
        name_len, extra_len = struct.unpack("<HH", head[26:30])
        if self.data[local + 30 : local + 30 + name_len] != self.SIGNATURE:
            raise ValueError("a local header that names another entry")
        start = local + 30 + name_len + extra_len
        if start + csize > self.entry_end(local):
            raise ValueError("a signature entry larger than its place")
        return self.data[start : start + csize]

    def package_hash(self, algorithm: str) -> bytes:
        """What the signature signs: the archive with the signature entry cut out and the directory counts, size and
        offsets written as they would be without it (NuGet's signed-package integrity definition)."""
        data, sig = self.data, self.signature
        sig_span = self.entry_end(sig[2]) - sig[2]
        digest = hashlib.new(algorithm)
        digest.update(data[: self.starts[0]])
        others = [r for r in self.records if r is not sig]
        for record in sorted(others, key=lambda r: r[2]):
            digest.update(data[record[2] : self.entry_end(record[2])])
        for position, length, local, *_ in sorted(others, key=lambda r: r[0]):
            moved = local - sig_span if local > sig[2] else local
            digest.update(
                data[position : position + 42]
                + struct.pack("<I", moved)
                + data[position + 46 : position + length]
            )
        eocd = self.end
        digest.update(
            data[eocd : eocd + 8]
            + struct.pack("<HH", self.total - 1, self.total - 1)
            + struct.pack("<II", self.size - sig[1], self.offset - sig_span)
            + data[eocd + 20 :]
        )
        return digest.digest()


class NuGetSignature:
    DATA_TYPE: ClassVar[str] = "1.2.840.113549.1.7.1"
    COUNTERSIGNATURE: ClassVar[str] = "1.2.840.113549.1.9.6"
    TIMESTAMP_TOKEN: ClassVar[str] = "1.2.840.113549.1.9.16.2.14"  # noqa: S105 - an object identifier
    SUBJECT_KEY_ID: ClassVar[str] = "2.5.29.14"
    ORGANIZATION: ClassVar[str] = "2.5.4.10"
    COMMON_NAME: ClassVar[str] = "2.5.4.3"
    REPOSITORY: ClassVar[str] = "NuGet.org Repository by Microsoft"
    HASH_OIDS: ClassVar[dict[str, str]] = {
        "2.16.840.1.101.3.4.2.1": "sha256",
        "2.16.840.1.101.3.4.2.2": "sha384",
        "2.16.840.1.101.3.4.2.3": "sha512",
    }
    _roots: ClassVar[tuple[Certificate, ...] | None] = None

    @classmethod
    def roots(cls) -> tuple[Certificate, ...]:
        if cls._roots is None:
            document = Strict.loads(
                (TrustRoot.DATA / "nuget-trust-roots.json").read_text(encoding="utf-8")
            )
            found: list[Certificate] = []
            for entry in document["roots"]:
                raw = base64.b64decode(entry["rawBytes"])
                if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
                    raise ValueError("a pinned root that is not the one recorded")
                found.append(Certificate.from_der(raw))
            cls._roots = tuple(found)
        return cls._roots

    # -- the checks (no network) ---------------------------------------------------------------------------

    @classmethod
    def verify(cls, package: bytes, now: dt.datetime | None = None) -> ModuleCheck:
        try:
            layout = ZipLayout(package)
        except LookupError:
            return ModuleCheck("absent", "the package carries no signature")
        except (ValueError, struct.error) as exc:
            return ModuleCheck(
                "invalid", f"the package is not a layout a signature can cover: {exc}"
            )
        try:
            signed = Cms.parse(Der.parse(layout.signature_bytes()))
            cls._check(layout, signed, now or dt.datetime.now(dt.UTC))
        except _AuthorOnly as exc:
            return ModuleCheck("unverifiable", str(exc))
        except (CmsError, DerError, ValueError, KeyError, IndexError, struct.error) as exc:
            return ModuleCheck("invalid", f"the package signature did not verify: {exc}")
        return ModuleCheck("verified", "the package is as NuGet.org signed it")

    @classmethod
    def _check(cls, layout: ZipLayout, signed: SignedData, now: dt.datetime) -> None:
        if signed.content_type != cls.DATA_TYPE or len(signed.signers) != 1:
            raise CmsError("not one signature over data")
        primary = signed.signers[0]
        cls._hash(layout, signed.content)
        # The repository's signature: the package's own, or a counter-signature on the author's.
        candidates: list[tuple[Signer, bytes | None]] = [(primary, signed.content)]
        for oid, value in primary.unsigned:
            if oid == cls.COUNTERSIGNATURE:
                candidates.append((Cms._signer(value), None))
        for signer, content in candidates:
            certificate = cls._certificate(signer, signed.certificates)
            if certificate is None or not cls._repository(certificate):
                continue
            over = content if content is not None else primary.signature
            # A counter-signature may state the content type or leave it out; a signature over the package's content states it.
            kinds = (cls.DATA_TYPE,) if content is not None else (None, cls.DATA_TYPE)
            when = cls._time(signer, now)
            if Certificate.CODE_SIGNING not in certificate.extended_key_usages():
                raise CmsError("the repository certificate is not for code signing")
            if not cls._chains(certificate, signed.certificates, when):
                raise CmsError(
                    "the repository certificate does not chain to a pinned DigiCert root, valid when it signed"
                )
            if not any(Cms.signature_ok(signer, certificate, over, kind) for kind in kinds):
                raise CmsError("the repository's signature does not verify")
            return
        raise _AuthorOnly(
            "the package carries no signature of NuGet.org's: its author's alone, or another signer's"
        )

    @classmethod
    def _chains(
        cls, certificate: Certificate, pool: tuple[Certificate, ...], when: dt.datetime
    ) -> bool:
        return any(CertificatePath.holds(certificate, (root,), when, pool) for root in cls.roots())

    @classmethod
    def _hash(cls, layout: ZipLayout, content: bytes) -> None:
        lines = content.decode("utf-8").split("\n")
        if lines[:2] != ["Version:1", ""]:
            raise CmsError("signature content of a version not read")
        stated = [line.partition("-Hash:") for line in lines[2:] if line]
        if len(stated) != 1 or not stated[0][1] or stated[0][0] not in cls.HASH_OIDS:
            raise CmsError("signature content that states no accepted package hash")
        algorithm = cls.HASH_OIDS[stated[0][0]]
        if layout.package_hash(algorithm) != base64.b64decode(stated[0][2], validate=True):
            raise CmsError("the package is not the one signed: its hash differs")

    @classmethod
    def _time(cls, signer: Signer, now: dt.datetime) -> dt.datetime:
        """When the signature existed: the token's stamp over its bytes, or now when it is not stamped."""
        tokens = [value for oid, value in signer.unsigned if oid == cls.TIMESTAMP_TOKEN]
        if not tokens:
            return now
        if len(tokens) != 1:
            raise CmsError("more than one time-stamp on a signature")
        authorities = [Authority((root,), None, None) for root in cls.roots()]
        return TimestampToken.verify_token(tokens[0], signer.signature, authorities).time

    @classmethod
    def _certificate(cls, signer: Signer, pool: tuple[Certificate, ...]) -> Certificate | None:
        for certificate in pool:
            if signer.key_id is not None:
                held = certificate.extensions.get(cls.SUBJECT_KEY_ID)
                if (
                    held is not None
                    and Der.parse(held.value, Der.OCTET_STRING).body == signer.key_id
                ):
                    return certificate
            elif signer.issuer == certificate.issuer and signer.serial == certificate.serial:
                return certificate
        return None

    @classmethod
    def _repository(cls, certificate: Certificate) -> bool:
        names: dict[str, set[str]] = {}
        for rdn in Der.parse(certificate.subject, Der.SEQUENCE).children():
            for pair in rdn.expect(Der.SET).children():
                oid, value = pair.expect(Der.SEQUENCE).children()
                names.setdefault(oid.oid(), set()).add(value.body.decode("utf-8", "replace"))
        return names.get(cls.COMMON_NAME) == {cls.REPOSITORY} and names.get(cls.ORGANIZATION) == {
            cls.REPOSITORY
        }

    # -- the package ---------------------------------------------------------------------------------------

    @classmethod
    def check(cls, name: str, version: str, integrity: str | None) -> ModuleCheck:
        """The signature of `name` at `version`, on the archive nuget.org serves (itself checked against the catalog's SHA-512)."""
        from cordon_scanner.intel.registry import ArchiveSources, RegistryError

        if not name or not version:
            return ModuleCheck("absent", f"{name or 'a package'} names no release")
        try:
            archive = ArchiveSources.package_archive("nuget", name, version)
        except (RegistryError, OSError, ValueError) as exc:
            return ModuleCheck(
                "unverifiable", f"the archive could not be fetched and checked: {exc}"
            )
        return cls.verify(archive.data)


class _AuthorOnly(Exception):
    """The signature is real but is not nuget.org's."""
