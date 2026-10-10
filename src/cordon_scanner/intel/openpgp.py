"""OpenPGP signatures, verified against the keys the operator trusts.

Two ecosystems sign with OpenPGP rather than sigstore: a Helm chart's provenance file (`.prov`, a
cleartext-signed copy of the chart's metadata and its archive's SHA-256) and an Ansible
collection's signatures (detached, over its MANIFEST.json). Neither has a public trust root: who
may sign is whatever keyring the person installing decides -- `helm verify --keyring`,
`ansible-galaxy --keyring`. So the keyring is the operator's, given with `--keyring`, and never read
from the scanned repository's configuration: a repository that chose the keys it is verified
against would bring its own.

**Why an extra, and why Sequoia.** As with sigstore, an OpenPGP verifier is not a thing to
reimplement; this delegates to `pysequoia`, Sequoia-PGP's Python binding, behind the `[attest]`
extra. Without it every answer is `UNVERIFIABLE`, never a pass.

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
from datetime import datetime
from pathlib import Path
from typing import Any, Final

#: A keyring larger than this is not a keyring.
MAX_KEYRING_BYTES = 16 << 20

_SIGNATURE: Final = b"SIGNATURE"
_PUBLIC_KEY: Final = b"PUBLIC KEY BLOCK"
#: The signature material of each public-key algorithm whose signature is a sequence of MPIs: RSA
#: (1, 3: m^d mod n; RFC 4880 §5.2.2), DSA (17: r, s; ibid.), ECDSA (19: r, s; RFC 6637 §5) and
#: the legacy EdDSA (22: r, s; RFC 9580 §5.2.3.3).
_SIGNATURE_MPIS: Final = {1: 1, 3: 1, 17: 2, 19: 2, 22: 2}


class Canonical:
    """Signature values re-encoded with their exact bit count, as RFC 4880 §3.2 requires.

    Some signers write a signature value's MPI with the key's size as its bit count (4096 for an
    RSA key, 256 for a DSA `s`) even when the value is shorter, which it is whenever it starts with
    a zero bit. GnuPG and Helm's Go OpenPGP library read such a signature; Sequoia refuses it --
    the packet as "Not a signature", or, in a key's own self-signatures, the binding, so the key
    is unusable. Measured on real charts in October 2026, every one verifying under GnuPG with the
    publisher's key and none under Sequoia: the provenance files of prometheus-community's
    alertmanager 2.1.0 (RSA, declared 4096, actual 4095 bits), cert-manager v1.21.2 (4094),
    opentelemetry-collector 0.175.1 (4091) and LeoColomb's cisco-nso 7.6.1 (DSA `s`, 256 for 252),
    and flowable's signing key (both user ID certifications 4096 for 4095).

    The bit count is not what is signed (§5.2.4: the hash covers the signed data and the packet's
    fields up to the hashed subpackets) and the value's bytes are kept, so re-encoding changes
    nothing a signature check depends on: an invalid signature stays invalid. Anything other than
    an overstated value in a version 4 signature packet is returned unchanged, byte for byte, for
    Sequoia to judge.
    """

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
    def _length(octets: int) -> bytes:
        """A new-format packet length (RFC 4880 §4.2.2)."""
        if octets < 192:
            return bytes([octets])
        if octets < 8384:
            octets -= 192
            return bytes([(octets >> 8) + 192, octets & 0xFF])
        return b"\xff" + octets.to_bytes(4, "big")

    @staticmethod
    def _packets(data: bytes) -> list[tuple[int, bytes]] | None:
        """`(tag, body)` of each packet (RFC 4880 §4.2), or None for a length this does not read
        (an indeterminate or partial body length, which neither keys nor signatures use)."""
        packets: list[tuple[int, bytes]] = []
        index = 0
        while index < len(data):
            ctb = data[index]
            if not ctb & 0x80:
                return None
            if ctb & 0x40:  # new format
                tag = ctb & 0x3F
                if index + 1 >= len(data):
                    return None
                first = data[index + 1]
                if first < 192:
                    header, length = 2, first
                elif first < 224:
                    if index + 2 >= len(data):
                        return None
                    header, length = 3, ((first - 192) << 8) + data[index + 2] + 192
                elif first == 255:
                    header, length = 6, int.from_bytes(data[index + 2 : index + 6], "big")
                else:
                    return None
            else:  # old format
                tag = (ctb >> 2) & 0x0F
                kind = ctb & 0x03
                if kind == 3:
                    return None
                size = (1, 2, 4)[kind]
                header, length = 1 + size, int.from_bytes(data[index + 1 : index + 1 + size], "big")
            body = data[index + header : index + header + length]
            if len(body) != length:
                return None
            packets.append((tag, body))
            index += header + length
        return packets

    @staticmethod
    def _signature(body: bytes) -> bytes | None:
        """A version 4 signature packet's body with every overstated MPI made exact, or None to
        keep it as it is."""
        if len(body) < 6 or body[0] != 4 or body[2] not in _SIGNATURE_MPIS:
            return None
        hashed = int.from_bytes(body[4:6], "big")
        unhashed_at = 6 + hashed
        if unhashed_at + 2 > len(body):
            return None
        unhashed = int.from_bytes(body[unhashed_at : unhashed_at + 2], "big")
        at = unhashed_at + 2 + unhashed + 2  # after the hash's left 16 bits
        values: list[bytes] = []
        changed = False
        for _ in range(_SIGNATURE_MPIS[body[2]]):
            if at + 2 > len(body):
                return None
            declared = int.from_bytes(body[at : at + 2], "big")
            value = body[at + 2 : at + 2 + (declared + 7) // 8]
            if len(value) != (declared + 7) // 8:
                return None
            actual = int.from_bytes(value, "big").bit_length()
            if actual > declared:
                return None
            if actual < declared:
                changed = True
                value = value[len(value) - (actual + 7) // 8 :]
            values.append(actual.to_bytes(2, "big") + value)
            at += 2 + (declared + 7) // 8
        if at != len(body) or not changed:
            return None  # not exactly the algorithm's MPIs to the end of the packet, or exact
        return body[: unhashed_at + 2 + unhashed + 2] + b"".join(values)

    @staticmethod
    def packets(data: bytes) -> bytes:
        """Binary packets -- signatures, or keys with their self-signatures -- with every
        overstated signature value made exact; unchanged, the same bytes, where none is."""
        parsed = Canonical._packets(data)
        if parsed is None:
            return data
        changed = False
        out: list[bytes] = []
        for tag, body in parsed:
            fixed = Canonical._signature(body) if tag == 2 else None
            if fixed is not None:
                changed = True
                body = fixed
            out.append(bytes([0xC0 | tag]) + Canonical._length(len(body)) + body)
        return b"".join(out) if changed else data

    @staticmethod
    def _armored(data: bytes, kind: bytes) -> bytes:
        """Every armored block of `kind` in `data` made canonical, the text around them kept."""
        begin, end = Canonical._markers(kind)
        out = bytearray()
        index = 0
        while True:
            start = data.find(begin, index)
            stop = data.find(end, start) if start >= 0 else -1
            if start < 0 or stop < 0:
                out += data[index:]
                return bytes(out)
            stop += len(end)
            packets = Canonical.dearmor(data[start:stop], kind)
            fixed = Canonical.packets(packets) if packets is not None else None
            out += data[index:start]
            if packets is None or fixed is None or fixed == packets:
                out += data[start:stop]
            else:
                out += Canonical.armor(fixed, kind).rstrip(b"\n")
            index = stop

    @staticmethod
    def signature(data: bytes) -> bytes:
        """A detached signature, armored or binary, canonical; unchanged where nothing needs it."""
        begin, _ = Canonical._markers(_SIGNATURE)
        return Canonical._armored(data, _SIGNATURE) if begin in data else Canonical.packets(data)

    @staticmethod
    def signed(data: bytes) -> bytes:
        """A cleartext-signed message with its signature block made canonical; the signed text
        before it is not touched."""
        return Canonical._armored(data, _SIGNATURE)

    @staticmethod
    def keyring(data: bytes) -> bytes:
        """Keys -- armored blocks, one or several, or binary packets -- with their self-signatures
        made canonical."""
        begin, _ = Canonical._markers(_PUBLIC_KEY)
        return Canonical._armored(data, _PUBLIC_KEY) if begin in data else Canonical.packets(data)


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


@dataclass(frozen=True)
class KeyInfo:
    """One certificate of the keyring, as its own packets describe it."""

    cert: Any
    fingerprint: str
    key_ids: frozenset[str]
    """The primary key's and every subkey's fingerprint and key ID, upper case."""
    certified: tuple[datetime, ...]
    """When each self-signature over the primary key (a user ID certification, or a direct-key
    signature) was made."""
    bound: dict[str, tuple[datetime, ...]]
    """For each subkey ID (and fingerprint), when each binding signature over it was made."""


@dataclass(frozen=True)
class Keyring:
    """The certificates in the operator's keyring files, and every key and subkey ID they hold."""

    keys: tuple[KeyInfo, ...] = ()
    paths: tuple[str, ...] = ()
    problems: tuple[str, ...] = ()

    @property
    def certs(self) -> tuple[Any, ...]:
        return tuple(k.cert for k in self.keys)

    @property
    def key_ids(self) -> frozenset[str]:
        return frozenset(i for k in self.keys for i in k.key_ids)

    def holding(self, key_id: str) -> KeyInfo | None:
        return next((k for k in self.keys if key_id.upper() in k.key_ids), None)

    def __bool__(self) -> bool:
        return bool(self.keys)


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
    def _certifications() -> tuple[Any, ...]:
        """RFC 4880 §5.2.1: the signature types by which a key certifies itself (0x10-0x13 over a
        user ID, 0x1F directly over the key)."""
        import pysequoia

        kind = pysequoia.packet.SignatureType
        # A tuple: pysequoia's SignatureType compares equal but is not hashable.
        return (
            kind.GenericCertification,
            kind.PersonaCertification,
            kind.CasualCertification,
            kind.PositiveCertification,
            kind.DirectKey,
        )

    @staticmethod
    def available() -> bool:
        """Whether the `[attest]` extra's OpenPGP verifier is installed."""
        from importlib.util import find_spec

        try:
            return find_spec("pysequoia") is not None
        except (ImportError, ValueError):  # pragma: no cover - find_spec internals
            return False

    @staticmethod
    def load(paths: tuple[str, ...]) -> Keyring:
        """Every certificate in the files given, in the forms Helm 4.3 reads a keyring in: armored
        (one or several concatenated exports), binary (an export, or GnuPG's legacy pubring.gpg),
        or a GnuPG 2.1 keybox (pubring.kbx). A version 4 key with no user ID is left out, as Helm's
        OpenPGP library leaves it out (go-crypto `ReadEntity`: "entity without any identities")."""
        if not paths or not OpenPgp.available():
            return Keyring(paths=paths)
        import pysequoia

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
                data = Canonical.keyring(data)
                found = pysequoia.Cert.split_bytes(data)
            except ValueError as exc:
                problems.append(f"{path}: not a keybox this reads ({exc})")
                continue
            except Exception as exc:  # pysequoia raises RuntimeError for what it cannot parse
                problems.append(f"{path}: not an OpenPGP keyring ({exc})")
                continue
            for cert in found:
                info = OpenPgp._describe(cert)
                if info is None:
                    problems.append(
                        f"{path}: key {str(cert.fingerprint).upper()} has no user ID, so it is left "
                        "out, as Helm leaves it out"
                    )
                    continue
                keys.append(info)
        return Keyring(tuple(keys), paths, tuple(problems))

    @staticmethod
    def _describe(cert: Any) -> KeyInfo | None:
        """The certificate's key IDs and self-signature times, from its own packets; None for a
        version 4 key with no user ID."""
        import pysequoia

        tag = pysequoia.packet.Tag
        certifications = OpenPgp._certifications()
        primary = ""
        ids: set[str] = set()
        certified: list[datetime] = []
        bound: dict[str, list[datetime]] = {}
        user_ids = 0
        subkey: tuple[str, ...] = ()
        for packet in pysequoia.packet.PacketPile.from_bytes(bytes(cert)):
            if packet.tag == tag.PublicKey:
                primary = str(packet.key_id).upper()
                ids.update(str(v).upper() for v in (packet.fingerprint, packet.key_id) if v)
            elif packet.tag == tag.PublicSubkey:
                subkey = tuple(str(v).upper() for v in (packet.fingerprint, packet.key_id) if v)
                ids.update(subkey)
            elif packet.tag == tag.UserID:
                user_ids += 1
            elif packet.tag == tag.Signature and packet.signature_created is not None:
                issuer = str(packet.issuer_key_id or "").upper()
                if issuer != primary:
                    continue
                kind = packet.signature_type
                if not subkey and kind in certifications:
                    certified.append(packet.signature_created)
                elif subkey and kind == pysequoia.packet.SignatureType.SubkeyBinding:
                    for key_id in subkey:
                        bound.setdefault(key_id, []).append(packet.signature_created)
        # RFC 9580 §5.5.4: a version 4 fingerprint is 20 octets, a version 6 one 32; only version 4
        # keys need a user ID to be usable.
        if len(str(cert.fingerprint)) == 40 and not user_ids:
            return None
        return KeyInfo(
            cert,
            str(cert.fingerprint).upper(),
            frozenset(ids),
            tuple(sorted(certified)),
            {k: tuple(sorted(v)) for k, v in bound.items()},
        )

    @staticmethod
    def _signature_packet(data: bytes, signature: bytes | None) -> Any:
        """The (first) signature packet of a cleartext message or a detached signature, made
        canonical, or None where it cannot be read."""
        import pysequoia

        source = Canonical.signature(signature) if signature is not None else Canonical.signed(data)
        start = source.find(b"-----BEGIN PGP SIGNATURE-----")
        try:
            return pysequoia.Sig.from_bytes(source[start:] if start >= 0 else source)
        except Exception:  # RuntimeError "Not a signature"
            return None

    @staticmethod
    def _why(key: KeyInfo, issuer: str, made: datetime | None) -> Result | None:
        """What about the signing key, rather than the content, a refused signature comes down
        to: None where nothing in the key explains it."""
        try:
            expires = key.cert.expiration
        except Exception:  # RuntimeError "No binding signature at time ..."
            return Result(
                Outcome.UNVERIFIABLE,
                f"key {key.fingerprint} has no valid self-signature binding it, so no OpenPGP "
                "implementation can use it as given",
                signer=issuer,
            )
        if key.cert.is_revoked:
            return Result(Outcome.INVALID, f"key {key.fingerprint} is revoked", signer=issuer)
        if made is not None and expires is not None and expires <= made:
            return Result(
                Outcome.INVALID,
                f"key {key.fingerprint} expired on {expires:%Y-%m-%d}, before it made this "
                f"signature on {made:%Y-%m-%d}",
                signer=issuer,
                expires=expires,
            )
        subkey = issuer if issuer in key.bound else None
        bindings = key.bound.get(subkey, ()) if subkey else key.certified
        if made is not None and bindings and min(bindings) > made:
            return Result(
                Outcome.UNVERIFIABLE,
                f"the keyring's copy of key {key.fingerprint} was certified on "
                f"{min(bindings):%Y-%m-%d}, after this signature was made on {made:%Y-%m-%d}; "
                "Sequoia judges a key as it stood when it signed, so this copy cannot vouch for "
                "it. Helm and GnuPG, which judge the key as it stands now, accept it: export the "
                "key again with its older self-signatures",
                signer=issuer,
                expires=expires,
            )
        return None

    @staticmethod
    def verify(data: bytes, keyring: Keyring, *, signature: bytes | None = None) -> Result:
        """A cleartext-signed message (`signature` None), or `data` against a detached signature."""
        if not OpenPgp.available():
            return Result(Outcome.UNVERIFIABLE, "the [attest] extra is not installed")
        if not keyring:
            return Result(
                Outcome.UNVERIFIABLE,
                "the configured keyring holds no usable key: " + "; ".join(keyring.problems)
                if keyring.paths
                else "no keyring is configured (--keyring) to verify its OpenPGP signature against",
            )
        import pysequoia

        packet = OpenPgp._signature_packet(data, signature)
        if packet is None:
            return Result(Outcome.UNVERIFIABLE, "the signature could not be read")
        issuer = str(packet.issuer_fingerprint or packet.issuer_key_id or "").upper()
        made = packet.created
        key = keyring.holding(issuer) if issuer else None

        def store(ids: list[str]) -> list[Any]:
            return list(keyring.certs)

        try:
            if signature is None:
                verified = pysequoia.verify(bytes=Canonical.signed(data), store=store)
            else:
                verified = pysequoia.verify(
                    bytes=data,
                    store=store,
                    signature=pysequoia.Sig.from_bytes(Canonical.signature(signature)),
                )
        except RuntimeError:  # "Signature verification failed: no valid signatures found."
            if key is None:
                return Result(
                    Outcome.INVALID,
                    f"signed by key {issuer or 'unnamed'}, which the configured keyring does not "
                    "hold",
                    signer=issuer,
                )
            explained = OpenPgp._why(key, issuer, made)
            if explained is not None:
                return explained
            return Result(
                Outcome.INVALID,
                f"the signature by trusted key {key.fingerprint} does not verify: the signed "
                "content was altered, or the signature forged",
                signer=issuer,
            )
        except Exception as exc:  # anything else pysequoia raises: not an answer either way
            return Result(Outcome.UNVERIFIABLE, f"the signature could not be checked ({exc})")
        signer = next((str(s.certificate).upper() for s in verified.valid_sigs), "")
        held = keyring.holding(signer)
        try:
            expires = held.cert.expiration if held else None
        except RuntimeError:
            expires = None
        return Result(
            Outcome.VERIFIED,
            f"signed by {signer}",
            signed=bytes(verified.bytes or b"") if signature is None else data,
            signer=signer,
            expires=expires,
        )


__all__ = ["Canonical", "KeyInfo", "Keybox", "Keyring", "OpenPgp", "Outcome", "Result"]
