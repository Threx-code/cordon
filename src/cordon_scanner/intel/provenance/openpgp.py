"""OpenPGP signatures, verified against the keys the operator trusts.

Two ecosystems sign with OpenPGP rather than sigstore: a Helm chart's provenance file (`.prov`, a
cleartext-signed copy of the chart's metadata and its archive's SHA-256) and an Ansible
collection's signatures (detached, over its MANIFEST.json). Neither has a public trust root: who
may sign is whatever keyring the person installing decides -- `helm verify --keyring`,
`ansible-galaxy --keyring`. So the keyring is the operator's, given with `--keyring`, and never read
from the scanned repository's configuration: a repository that chose the keys it is verified
against would bring its own.

**Verified by the project's own code** (`pgp`): packets, keys, self-signatures and data
signatures read and checked from RFC 4880 and RFC 9580, with no third-party verifier, and read as
Helm and GnuPG read them -- a signature value stated with more bits than it has is the value it
is, and a key is judged as it stands now -- where Sequoia, which this replaced, refused both.

Three answers, kept apart because they mean different things: the signature verifies under a key
in the keyring (`VERIFIED`, with the signed bytes, which the caller still has to tie to the
artefact); it does not verify although a trusted key made it -- altered content, or a forged
signature -- or it was made by a key the keyring does not hold, which is what a release re-signed by
whoever replaced it looks like (`INVALID`, the signer named so a legitimate publisher's key can be
added); or it could not be checked (`UNVERIFIABLE`).
"""

from __future__ import annotations

import base64
import binascii
import enum
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from cordon_scanner.intel.base import KeyInfo, Keyring
from cordon_scanner.intel.provenance.pgp import (
    Algorithms,
    Cert,
    Certs,
    Cleartext,
    Packets,
    PgpError,
    Signature,
)

#: A keyring larger than this is not a keyring.
MAX_KEYRING_BYTES = 16 << 20

_SIGNATURE: Final = b"SIGNATURE"
_PUBLIC_KEY: Final = b"PUBLIC KEY BLOCK"


class Canonical:
    """ASCII armor (RFC 4880 section 6)."""

    @staticmethod
    def crc24(data: bytes) -> int:
        """RFC 4880 §6.1."""
        crc = 0xB704CE
        for octet in data:
            crc ^= octet << 16
            for _ in range(8):
                crc <<= 1
                if crc & 0x1000000:
                    crc ^= 0x1864CFB
        return crc & 0xFFFFFF

    @staticmethod
    def _markers(kind: bytes) -> tuple[bytes, bytes]:
        return b"-----BEGIN PGP " + kind + b"-----", b"-----END PGP " + kind + b"-----"

    @staticmethod
    def dearmor(block: bytes, kind: bytes = _SIGNATURE) -> bytes | None:
        """The packets of one armored block of `kind` (RFC 4880 §6.2), or None where the block is
        not one or its checksum does not match."""
        begin, end = Canonical._markers(kind)
        lines = block.replace(b"\r\n", b"\n").split(b"\n")
        if not lines or lines[0].strip() != begin:
            return None
        index = 1
        while index < len(lines) and lines[index].strip():
            if b": " not in lines[index]:
                return None  # an armor header line is `Key: Value`, and a blank line ends them
            index += 1
        body: list[bytes] = []
        checksum: bytes | None = None
        for line in lines[index + 1 :]:
            line = line.strip()
            if line == end:
                break
            if line.startswith(b"=") and len(line) == 5:
                checksum = line[1:]
            elif line:
                body.append(line)
        else:
            return None
        try:
            data = base64.b64decode(b"".join(body), validate=True)
            if checksum is not None and int.from_bytes(base64.b64decode(checksum), "big") != (
                Canonical.crc24(data)
            ):
                return None
        except (binascii.Error, ValueError):
            return None
        return data

    @staticmethod
    def armor(data: bytes, kind: bytes = _SIGNATURE) -> bytes:
        """RFC 4880 §6.2: no headers, 64-character lines, the CRC-24 checksum."""
        begin, end = Canonical._markers(kind)
        encoded = base64.b64encode(data)
        lines = [encoded[i : i + 64] for i in range(0, len(encoded), 64)]
        checksum = base64.b64encode(Canonical.crc24(data).to_bytes(3, "big"))
        return b"\n".join([begin, b"", *lines, b"=" + checksum, end]) + b"\n"

    @staticmethod
    def blocks(data: bytes, kind: bytes) -> list[bytes] | None:
        """The packets of every armored block of `kind` in `data`, or None when one is malformed;
        an empty list where `data` holds none (it may be binary)."""
        begin, end = Canonical._markers(kind)
        out: list[bytes] = []
        at = 0
        while (start := data.find(begin, at)) >= 0:
            stop = data.find(end, start)
            if stop < 0:
                return None
            stop += len(end)
            packets = Canonical.dearmor(data[start:stop], kind)
            if packets is None:
                return None
            out.append(packets)
            at = stop
        return out


class Outcome(enum.StrEnum):
    VERIFIED = "verified"
    INVALID = "invalid"
    UNVERIFIABLE = "unverifiable"


@dataclass(frozen=True)
class Result:
    outcome: Outcome
    detail: str
    signed: bytes = b""
    """The bytes the signature covers: for a cleartext signature, the text inside it."""
    signer: str = ""
    expires: datetime | None = None
    """When the signing key expires (it has, if this is past), read from its current
    self-signature: a caller verifying as Helm does refuses a key expired now."""


class Keybox:
    """GnuPG 2.1's keybox (pubring.kbx), read as Helm 4.3 reads it (`pkg/provenance/keybox.go`,
    after GnuPG's kbx/keybox-blob.c): a sequence of blobs, each `u32 length` (big endian,
    including itself), `u8 type` (1 header, 2 OpenPGP), `u8 version`; the first, a header, holds
    `KBXf` at offset 8. An OpenPGP blob holds `u16 flags` at 6, and its keyblock's offset and length
    (`u32` each) at 8 and 12. A blob flagged ephemeral (0x0002) is skipped, as GnuPG skips it."""

    @staticmethod
    def detect(data: bytes) -> bool:
        return len(data) >= 12 and data[4] == 1 and data[8:12] == b"KBXf"

    @staticmethod
    def keyblocks(data: bytes) -> bytes:
        """The OpenPGP keyblocks, concatenated. ValueError for a malformed keybox."""
        out = bytearray()
        offset = 0
        while offset < len(data):
            rest = data[offset:]
            if len(rest) < 5:
                raise ValueError(f"truncated blob header at offset {offset}")
            length = int.from_bytes(rest[:4], "big")
            if length < 5:
                raise ValueError(f"invalid blob length {length} at offset {offset}")
            if length > len(rest):
                raise ValueError(f"blob at offset {offset} runs past the end")
            blob = rest[:length]
            if blob[4] == 2:
                if len(blob) < 16:
                    raise ValueError(f"OpenPGP blob at offset {offset} is too short")
                flags = int.from_bytes(blob[6:8], "big")
                start = int.from_bytes(blob[8:12], "big")
                size = int.from_bytes(blob[12:16], "big")
                if start + size > len(blob):
                    raise ValueError(
                        f"OpenPGP blob at offset {offset} has an out-of-range keyblock"
                    )
                if not flags & 0x0002:
                    out += blob[start : start + size]
            offset += length
        if not out:
            raise ValueError("the keybox holds no OpenPGP keys")
        return bytes(out)


class OpenPgp:
    @staticmethod
    def available() -> bool:
        """Always: OpenPGP verification is built in."""
        return True

    @staticmethod
    def load(paths: tuple[str, ...]) -> Keyring:
        """Every certificate in the files given, in the forms Helm 4.3 reads a keyring in: armored
        (one or several concatenated exports), binary (an export, or GnuPG's legacy pubring.gpg),
        or a GnuPG 2.1 keybox (pubring.kbx). A version 4 key with no user ID is left out, as Helm's
        OpenPGP library leaves it out (go-crypto `ReadEntity`: "entity without any identities")."""
        if not paths:
            return Keyring(paths=paths)
        keys: list[KeyInfo] = []
        problems: list[str] = []
        for path in paths:
            try:
                data = Path(path).expanduser().read_bytes()
            except OSError as exc:
                problems.append(f"{path}: {exc.strerror or type(exc).__name__}")
                continue
            if len(data) > MAX_KEYRING_BYTES:
                problems.append(f"{path}: larger than a keyring")
                continue
            try:
                if Keybox.detect(data):
                    data = Keybox.keyblocks(data)
            except ValueError as exc:
                problems.append(f"{path}: not a keybox this reads ({exc})")
                continue
            armored = Canonical.blocks(data, _PUBLIC_KEY)
            if armored is None:
                problems.append(f"{path}: not an OpenPGP keyring (a malformed armored block)")
                continue
            try:
                found = [c for block in (armored or [data]) for c in Certs.split(block)]
            except PgpError as exc:
                problems.append(f"{path}: not an OpenPGP keyring ({exc})")
                continue
            for cert in found:
                if cert.primary.version == 4 and not cert.user_ids:
                    problems.append(
                        f"{path}: key {cert.fingerprint} has no user ID, so it is left out, as Helm "
                        "leaves it out"
                    )
                    continue
                problems.extend(f"{path}: key {cert.fingerprint}: {p}" for p in cert.problems)
                keys.append(
                    KeyInfo(
                        cert,
                        cert.fingerprint,
                        frozenset(cert.key_ids()),
                        tuple(cert.certified),
                        {k: tuple(sorted(v)) for k, v in cert.bindings().items()},
                    )
                )
        return Keyring(tuple(keys), paths, tuple(problems))

    @staticmethod
    def _signature(data: bytes, signature: bytes | None) -> tuple[Signature, bytes] | None:
        """The first signature packet, and the bytes it covers as its type defines them."""
        if signature is None:
            try:
                text, block = Cleartext.split(data)
            except PgpError:
                return None
            packets = Canonical.dearmor(block.strip(), _SIGNATURE)
            covered = Cleartext.canonical(text)
        else:
            armored = Canonical.blocks(signature, _SIGNATURE)
            packets = armored[0] if armored else (signature if armored == [] else None)
            covered = data
        if packets is None:
            return None
        try:
            sig = next(Signature.parse(body) for tag, body in Packets.read(packets) if tag == 2)
        except (PgpError, StopIteration):
            return None
        if signature is not None and sig.type == 0x01:
            covered = b"\r\n".join(data.replace(b"\r\n", b"\n").split(b"\n"))
        elif signature is not None and sig.type != 0x00:
            return None
        if signature is None and sig.type != 0x01:
            return None
        return sig, covered

    @staticmethod
    def verify(data: bytes, keyring: Keyring, *, signature: bytes | None = None) -> Result:
        """A cleartext-signed message (`signature` None), or `data` against a detached signature."""
        if not keyring:
            return Result(
                Outcome.UNVERIFIABLE,
                "the configured keyring holds no usable key: " + "; ".join(keyring.problems)
                if keyring.paths
                else "no keyring is configured (--keyring) to verify its OpenPGP signature against",
            )
        read = OpenPgp._signature(data, signature)
        if read is None:
            return Result(Outcome.UNVERIFIABLE, "the signature could not be read")
        sig, covered = read
        issuers = sorted(f.hex().upper() for f in sig.issuer_fingerprints) or sorted(
            i.hex().upper() for i in sig.issuer_ids
        )
        issuer = issuers[0] if issuers else ""
        key = next((k for i in issuers if (k := keyring.holding(i)) is not None), None)
        if key is None:
            return Result(
                Outcome.INVALID,
                f"signed by key {issuer or 'unnamed'}, which the configured keyring does not hold",
                signer=issuer,
            )
        cert: Cert = key.cert
        expires = cert.expiration()
        if sig.hash_algorithm in Algorithms.WEAK:
            return Result(
                Outcome.UNVERIFIABLE,
                f"the signature by key {key.fingerprint} uses "
                f"{Algorithms.HASHES.get(sig.hash_algorithm, 'a broken hash')}, which no longer "
                "proves who signed",
                signer=issuer,
                expires=expires,
            )
        if cert.current is None:
            return Result(
                Outcome.UNVERIFIABLE,
                f"key {key.fingerprint} has no valid self-signature binding it, so no OpenPGP "
                "implementation can use it as given",
                signer=issuer,
            )
        signers = [k for k in cert.signing_keys() if sig.issued_by(k)]
        if not any(sig.verified_by(k, covered) for k in signers):
            return Result(
                Outcome.INVALID,
                f"the signature by trusted key {key.fingerprint} does not verify: the signed "
                "content was altered, or the signature forged",
                signer=issuer,
            )
        if cert.revoked:
            return Result(Outcome.INVALID, f"key {key.fingerprint} is revoked", signer=issuer)
        made = sig.created
        if made is not None and expires is not None and expires <= made:
            return Result(
                Outcome.INVALID,
                f"key {key.fingerprint} expired on {expires:%Y-%m-%d}, before it made this "
                f"signature on {made:%Y-%m-%d}",
                signer=issuer,
                expires=expires,
            )
        if made is not None and not sig.valid_at(datetime.now(UTC)):
            return Result(
                Outcome.INVALID,
                f"the signature by key {key.fingerprint} has expired",
                signer=issuer,
                expires=expires,
            )
        return Result(
            Outcome.VERIFIED,
            f"signed by {key.fingerprint}",
            signed=Cleartext.split(data)[0] + b"\n" if signature is None else data,
            signer=key.fingerprint,
            expires=expires,
        )


__all__ = ["Canonical", "KeyInfo", "Keybox", "Keyring", "OpenPgp", "Outcome", "Result"]
