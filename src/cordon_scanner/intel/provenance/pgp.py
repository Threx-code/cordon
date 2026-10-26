"""OpenPGP keys and signatures, read and verified by the project's own code (RFC 4880, RFC 9580).

What a Helm chart's provenance and an Ansible collection's signatures need, read strictly:

- **Packets** (RFC 9580 section 4): old and new framing; definite lengths only -- keys and
  signatures never use partial or indeterminate ones, so a packet that does is refused.
- **Keys**, version 4 and 6: RSA, DSA, ECDSA (P-256, P-384, P-521), EdDSA (legacy, and the
  version 6 Ed25519), each fingerprinted as the standard says, so a key ID is never trusted on
  its own: a signature names its issuer, and the issuer's key must verify it.
- **Signatures**, version 4 and 6: the hashed subpackets (creation time, issuer, issuer
  fingerprint, key and signature expiry, key flags, embedded back-signatures), hashed with the
  data, the packet's trailer and -- for version 6 -- the salt.
- **Certificates**: a primary key, its user IDs, its subkeys, each with self-signatures that are
  themselves verified before anything about the key is believed: when it expires, whether it is
  revoked, which subkeys it has bound and which may sign. A signing subkey must carry a valid
  back-signature (RFC 9580 5.2.3.31), or anyone could bind someone else's signing key.

Read where other implementations disagree, as Helm and GnuPG read it, because Helm is what the
person installing a chart runs: a signature value whose MPI states more bits than it has (real
charts carry them: cert-manager, alertmanager, opentelemetry-collector) is the same value, since
the bit count is not hashed; and a key is judged as it stands now. What weakens a signature is
refused outright: MD5, SHA-1 and RIPEMD-160 over data, and SHA-1 self-signatures made after
2023 (the policy Sequoia also applies).
"""

from __future__ import annotations

import datetime as dt
import hashlib
from dataclasses import dataclass, field
from typing import ClassVar

from cordon_scanner.intel.provenance._dsa import Dsa
from cordon_scanner.intel.provenance._ecdsa import Ecdsa
from cordon_scanner.intel.provenance._ed25519 import Ed25519
from cordon_scanner.intel.provenance._rsa import Rsa


class PgpError(ValueError):
    """The bytes are not OpenPGP this reads."""


class Packets:
    """`(tag, body)` of each packet."""

    MAX_PACKETS: ClassVar[int] = 100_000

    @staticmethod
    def read(data: bytes) -> list[tuple[int, bytes]]:
        out: list[tuple[int, bytes]] = []
        at, n = 0, len(data)
        while at < n:
            if len(out) >= Packets.MAX_PACKETS:
                raise PgpError("more packets than a keyring holds")
            ctb = data[at]
            if not ctb & 0x80:
                raise PgpError("not a packet header")
            if ctb & 0x40:  # new format
                tag = ctb & 0x3F
                if at + 1 >= n:
                    raise PgpError("a truncated packet header")
                first = data[at + 1]
                if first < 192:
                    header, length = 2, first
                elif first < 224:
                    if at + 2 >= n:
                        raise PgpError("a truncated packet length")
                    header, length = 3, ((first - 192) << 8) + data[at + 2] + 192
                elif first == 255:
                    if at + 6 > n:
                        raise PgpError("a truncated packet length")
                    header, length = 6, int.from_bytes(data[at + 2 : at + 6], "big")
                else:
                    raise PgpError("a partial body length, which keys and signatures never use")
            else:  # old format
                tag = (ctb >> 2) & 0x0F
                kind = ctb & 0x03
                if kind == 3:
                    raise PgpError("an indeterminate length")
                size = (1, 2, 4)[kind]
                if at + 1 + size > n:
                    raise PgpError("a truncated packet length")
                header, length = 1 + size, int.from_bytes(data[at + 1 : at + 1 + size], "big")
            body = data[at + header : at + header + length]
            if len(body) != length:
                raise PgpError("a packet past the end")
            out.append((tag, bytes(body)))
            at += header + length
        return out


class _Reader:
    """Big-endian fields and MPIs out of one packet body, every read bounds-checked."""

    def __init__(self, data: bytes, at: int = 0) -> None:
        self.data, self.at = data, at

    def take(self, n: int) -> bytes:
        if n < 0 or self.at + n > len(self.data):
            raise PgpError("a field past the end of its packet")
        out = self.data[self.at : self.at + n]
        self.at += n
        return out

    def uint(self, n: int) -> int:
        return int.from_bytes(self.take(n), "big")

    def mpi(self) -> int:
        """An MPI. Its stated bit count fixes how many bytes it spans; a value shorter than it
        states (a leading zero bit or byte) is the same value -- the count is not signed -- and
        one longer than it states is malformed."""
        bits = self.uint(2)
        raw = self.take((bits + 7) // 8)
        value = int.from_bytes(raw, "big")
        if value.bit_length() > bits:
            raise PgpError("an MPI longer than it states")
        return value

    def mpi_bytes(self) -> bytes:
        bits = self.uint(2)
        return self.take((bits + 7) // 8)

    def rest(self) -> bytes:
        return self.take(len(self.data) - self.at)

    def done(self) -> bool:
        return self.at == len(self.data)


class Algorithms:
    RSA: ClassVar[frozenset[int]] = frozenset({1, 3})
    DSA: ClassVar[int] = 17
    ECDSA: ClassVar[int] = 19
    EDDSA_LEGACY: ClassVar[int] = 22
    ED25519: ClassVar[int] = 27
    #: Encryption-only key algorithms (ElGamal, ECDH, X25519, X448): read for their fingerprint,
    #: never able to sign.
    ENCRYPTION_ONLY: ClassVar[frozenset[int]] = frozenset({16, 18, 25, 26})
    #: Hash algorithm IDs (RFC 9580 9.5) -> hashlib names.
    HASHES: ClassVar[dict[int, str]] = {
        1: "md5",
        2: "sha1",
        3: "ripemd160",
        8: "sha256",
        9: "sha384",
        10: "sha512",
        11: "sha224",
        12: "sha3_256",
        14: "sha3_512",
    }
    WEAK: ClassVar[frozenset[int]] = frozenset({1, 2, 3})
    #: Curve OIDs as they are written in a key packet (the DER value bytes).
    CURVES: ClassVar[dict[bytes, str]] = {
        bytes.fromhex("2a8648ce3d030107"): "1.2.840.10045.3.1.7",
        bytes.fromhex("2b81040022"): "1.3.132.0.34",
        bytes.fromhex("2b81040023"): "1.3.132.0.35",
    }
    ED25519_LEGACY_OID: ClassVar[bytes] = bytes.fromhex("2b06010401da470f01")
    SHA1_SELF_SIGNATURES_UNTIL: ClassVar[dt.datetime] = dt.datetime(2023, 2, 1, tzinfo=dt.UTC)


@dataclass
class Key:
    """A public key or subkey packet."""

    version: int
    created: dt.datetime
    algorithm: int
    material: object
    body: bytes
    fingerprint: bytes

    @property
    def key_id(self) -> bytes:
        return self.fingerprint[-8:] if self.version == 4 else self.fingerprint[:8]

    @staticmethod
    def parse(body: bytes) -> Key:
        r = _Reader(body)
        version = r.uint(1)
        if version not in (4, 6):
            raise PgpError(f"a version {version} key, which this does not read")
        created = dt.datetime.fromtimestamp(r.uint(4), tz=dt.UTC)
        algorithm = r.uint(1)
        if version == 6:
            r = _Reader(r.take(r.uint(4)))
        material = Key._material(algorithm, r, version)
        if not r.done():
            raise PgpError("bytes after a key's material")
        if version == 4:
            fingerprint = hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).digest()  # noqa: S324 - the v4 fingerprint is defined as SHA-1
        else:
            fingerprint = hashlib.sha256(b"\x9b" + len(body).to_bytes(4, "big") + body).digest()
        return Key(version, created, algorithm, material, body, fingerprint)

    @staticmethod
    def _material(algorithm: int, r: _Reader, version: int) -> object:
        if algorithm in Algorithms.ENCRYPTION_ONLY:
            r.rest()  # an encryption subkey: its material is never used to verify anything
            return None
        try:
            if algorithm in Algorithms.RSA:
                return Rsa.checked(r.mpi(), r.mpi(), min_bits=1024)
            if algorithm == Algorithms.DSA:
                return Dsa.checked(r.mpi(), r.mpi(), r.mpi(), r.mpi())
            if algorithm == Algorithms.ECDSA:
                oid = r.take(r.uint(1))
                curve = Ecdsa.CURVES.get(Algorithms.CURVES.get(oid, ""))
                if curve is None:
                    raise PgpError("an ECDSA curve this does not read")
                return (curve, Ecdsa.point(curve, r.mpi_bytes()))
            if algorithm == Algorithms.EDDSA_LEGACY:
                oid = r.take(r.uint(1))
                point = r.mpi_bytes()
                if oid != Algorithms.ED25519_LEGACY_OID or len(point) != 33 or point[0] != 0x40:
                    raise PgpError("an EdDSA key that is not Ed25519")
                return point[1:]
            if algorithm == Algorithms.ED25519:
                return r.take(32)
        except ValueError as exc:  # DerError and the parameter checks are ValueErrors
            if isinstance(exc, PgpError):
                raise
            raise PgpError(f"a key whose parameters are not valid: {exc}") from exc
        raise PgpError(f"a public-key algorithm this does not read: {algorithm}")

    def framed(self) -> bytes:
        """The key as it is hashed into a signature over it."""
        if self.version == 4:
            return b"\x99" + len(self.body).to_bytes(2, "big") + self.body
        return b"\x9b" + len(self.body).to_bytes(4, "big") + self.body

    def verifies(self, digest: bytes, values: list[int] | bytes, hash_name: str) -> bool:
        a = self.algorithm
        if a in Algorithms.RSA and isinstance(values, list) and len(values) == 1:
            rsa: tuple[int, int] = self.material  # type: ignore[assignment]
            k = (rsa[0].bit_length() + 7) // 8
            if values[0].bit_length() > k * 8:
                return False
            return Rsa.verify_pkcs1_digest(rsa, digest, values[0].to_bytes(k, "big"), hash_name)
        if a == Algorithms.DSA and isinstance(values, list) and len(values) == 2:
            return Dsa.verify_digest(self.material, digest, values[0], values[1])  # type: ignore[arg-type]
        if a == Algorithms.ECDSA and isinstance(values, list) and len(values) == 2:
            return Ecdsa.verify_digest(self.material, digest, values[0], values[1])  # type: ignore[arg-type]
        if a == Algorithms.EDDSA_LEGACY and isinstance(values, list) and len(values) == 2:
            if values[0].bit_length() > 256 or values[1].bit_length() > 256:
                return False
            # R and S, each the 32-octet native string written as a big-endian MPI.
            signature = values[0].to_bytes(32, "big") + values[1].to_bytes(32, "big")
            return Ed25519.verify(self.material, digest, signature)  # type: ignore[arg-type]
        if a == Algorithms.ED25519 and isinstance(values, bytes) and len(values) == 64:
            return Ed25519.verify(self.material, digest, values)  # type: ignore[arg-type]
        return False


@dataclass
class Signature:
    """A signature packet."""

    version: int
    type: int
    algorithm: int
    hash_algorithm: int
    hashed: bytes  # the packet from its version through the hashed subpackets: what is hashed
    left16: bytes
    values: list[int] | bytes
    salt: bytes
    created: dt.datetime | None
    expires_after: int | None  # signature expiry, seconds after creation
    key_expires_after: int | None  # key expiry, seconds after the key's creation
    issuer_ids: set[bytes] = field(default_factory=set)
    issuer_fingerprints: set[bytes] = field(default_factory=set)
    key_flags: int | None = None
    embedded: list[bytes] = field(default_factory=list)
    critical_unknown: bool = False

    #: Subpacket types this reads (RFC 9580 5.2.3.7).
    CREATED: ClassVar[int] = 2
    EXPIRES: ClassVar[int] = 3
    KEY_EXPIRES: ClassVar[int] = 9
    ISSUER: ClassVar[int] = 16
    KEY_FLAGS: ClassVar[int] = 27
    EMBEDDED: ClassVar[int] = 32
    ISSUER_FINGERPRINT: ClassVar[int] = 33
    #: Subpackets that, critical, change nothing this decides: safe to accept unread.
    HARMLESS: ClassVar[frozenset[int]] = frozenset(
        {4, 5, 7, 11, 20, 21, 22, 23, 24, 25, 26, 28, 30, 31, 34, 35, 39}
    )

    @staticmethod
    def parse(body: bytes) -> Signature:
        r = _Reader(body)
        version = r.uint(1)
        if version not in (4, 6):
            raise PgpError(f"a version {version} signature, which this does not read")
        kind, algorithm, hash_algorithm = r.uint(1), r.uint(1), r.uint(1)
        hashed_len = r.uint(4 if version == 6 else 2)
        hashed_area = r.take(hashed_len)
        hashed = body[: r.at]
        unhashed_area = r.take(r.uint(4 if version == 6 else 2))
        left16 = r.take(2)
        salt = b""
        if version == 6:
            salt = r.take(r.uint(1))
        if algorithm in Algorithms.RSA:
            values: list[int] | bytes = [r.mpi()]
        elif algorithm in (Algorithms.DSA, Algorithms.ECDSA, Algorithms.EDDSA_LEGACY):
            values = [r.mpi(), r.mpi()]
        elif algorithm == Algorithms.ED25519:
            values = r.take(64)
        else:
            raise PgpError(f"a signature algorithm this does not read: {algorithm}")
        if not r.done():
            raise PgpError("bytes after a signature's values")
        sig = Signature(
            version, kind, algorithm, hash_algorithm, hashed, left16, values, salt, None, None, None
        )
        sig._subpackets(hashed_area, hashed=True)
        sig._subpackets(unhashed_area, hashed=False)
        return sig

    def _subpackets(self, area: bytes, *, hashed: bool) -> None:
        r = _Reader(area)
        while not r.done():
            first = r.uint(1)
            if first < 192:
                length = first
            elif first < 255:
                length = ((first - 192) << 8) + r.uint(1) + 192
            else:
                length = r.uint(4)
            if length == 0:
                raise PgpError("an empty subpacket")
            content = r.take(length)
            kind, value = content[0] & 0x7F, content[1:]
            critical = bool(content[0] & 0x80)
            if not hashed:
                # Only the issuer may be read from the unhashed area, and only as a hint: the key
                # it names must still verify the signature.
                if kind == Signature.ISSUER and len(value) == 8:
                    self.issuer_ids.add(value)
                elif kind == Signature.ISSUER_FINGERPRINT and len(value) in (21, 33):
                    self.issuer_fingerprints.add(value[1:])
                elif kind == Signature.EMBEDDED:
                    self.embedded.append(value)
                continue
            if kind == Signature.CREATED and len(value) == 4:
                self.created = dt.datetime.fromtimestamp(int.from_bytes(value, "big"), tz=dt.UTC)
            elif kind == Signature.EXPIRES and len(value) == 4:
                self.expires_after = int.from_bytes(value, "big") or None
            elif kind == Signature.KEY_EXPIRES and len(value) == 4:
                self.key_expires_after = int.from_bytes(value, "big") or None
            elif kind == Signature.ISSUER and len(value) == 8:
                self.issuer_ids.add(value)
            elif kind == Signature.ISSUER_FINGERPRINT and len(value) in (21, 33):
                self.issuer_fingerprints.add(value[1:])
            elif kind == Signature.KEY_FLAGS and value:
                self.key_flags = value[0]
            elif kind == Signature.EMBEDDED:
                self.embedded.append(value)
            elif critical and kind not in Signature.HARMLESS:
                self.critical_unknown = True

    # -- hashing --------------------------------------------------------------

    def digest(self, signed: bytes) -> bytes | None:
        """The digest over `signed` (the data, or the key material a self-signature covers) and
        this packet's trailer; None for a hash this does not compute."""
        name = Algorithms.HASHES.get(self.hash_algorithm)
        if name is None:
            return None
        h = hashlib.new(name)
        if self.version == 6:
            h.update(self.salt)
        h.update(signed)
        h.update(self.hashed)
        h.update(bytes([self.version, 0xFF]) + len(self.hashed).to_bytes(4, "big"))
        return h.digest()

    def verified_by(self, key: Key, signed: bytes) -> bool:
        if self.critical_unknown or (
            key.algorithm != self.algorithm
            and not (key.algorithm in Algorithms.RSA and self.algorithm in Algorithms.RSA)
        ):
            return False
        if self.version == 6 and key.version != 6:
            return False
        digest = self.digest(signed)
        if digest is None or digest[:2] != self.left16:
            return False
        return key.verifies(digest, self.values, Algorithms.HASHES[self.hash_algorithm])

    def issued_by(self, key: Key) -> bool:
        """Whether this signature names `key` as its issuer (fingerprint, or key ID)."""
        return (
            key.fingerprint in self.issuer_fingerprints
            or key.key_id in self.issuer_ids
            or (not self.issuer_fingerprints and not self.issuer_ids)
        )

    def valid_at(self, when: dt.datetime) -> bool:
        if self.created is None or self.created > when + dt.timedelta(minutes=5):
            return False
        return self.expires_after is None or when < self.created + dt.timedelta(
            seconds=self.expires_after
        )


@dataclass
class Bound:
    """A subkey, its binding, and what the binding says."""

    key: Key
    binding: Signature | None
    revoked: bool = False


@dataclass
class Cert:
    """A certificate: a primary key, with what its own valid self-signatures say about it."""

    primary: Key
    user_ids: list[bytes]
    subkeys: list[Bound]
    packets: bytes
    certified: list[dt.datetime]  # when each valid self-certification was made
    current: Signature | None  # the newest valid self-signature over the primary key
    revoked: bool
    problems: list[str]

    @property
    def fingerprint(self) -> str:
        return self.primary.fingerprint.hex().upper()

    def expiration(self) -> dt.datetime | None:
        if self.current is None or self.current.key_expires_after is None:
            return None
        return self.primary.created + dt.timedelta(seconds=self.current.key_expires_after)

    def signing_keys(self) -> list[Key]:
        """The keys of this certificate that may sign data: the primary key (unless its flags say
        it may not) and each subkey bound with the signing flag and a valid back-signature."""
        keys: list[Key] = []
        flags = self.current.key_flags if self.current is not None else None
        if flags is None or flags & 0x02:
            keys.append(self.primary)
        for bound in self.subkeys:
            if (
                bound.binding is not None
                and not bound.revoked
                and (bound.binding.key_flags or 0) & 0x02
            ):
                keys.append(bound.key)
        return keys

    def key_ids(self) -> set[str]:
        out: set[str] = set()
        for key in [self.primary, *(b.key for b in self.subkeys)]:
            out.update({key.fingerprint.hex().upper(), key.key_id.hex().upper()})
        return out

    def bindings(self) -> dict[str, list[dt.datetime]]:
        out: dict[str, list[dt.datetime]] = {}
        for bound in self.subkeys:
            if bound.binding is not None and bound.binding.created is not None:
                for ident in (bound.key.fingerprint.hex().upper(), bound.key.key_id.hex().upper()):
                    out.setdefault(ident, []).append(bound.binding.created)
        return out


class Certs:
    """Certificates out of a keyring's packets, each self-signature verified."""

    CERTIFICATION: ClassVar[frozenset[int]] = frozenset({0x10, 0x11, 0x12, 0x13})
    DIRECT: ClassVar[int] = 0x1F
    SUBKEY_BINDING: ClassVar[int] = 0x18
    PRIMARY_BINDING: ClassVar[int] = 0x19
    KEY_REVOCATION: ClassVar[int] = 0x20
    SUBKEY_REVOCATION: ClassVar[int] = 0x28

    @staticmethod
    def split(data: bytes, *, now: dt.datetime | None = None) -> list[Cert]:
        now = now or dt.datetime.now(dt.UTC)
        packets = Packets.read(data)
        groups: list[list[tuple[int, bytes]]] = []
        for tag, body in packets:
            if tag == 6:
                groups.append([(tag, body)])
            elif (
                tag in (2, 13, 14, 17, 12) and groups
            ):  # signature, user ID, subkey, attribute, trust
                groups[-1].append((tag, body))
            elif tag in (2, 13, 14, 17, 12):
                raise PgpError("a key's packets before any primary key")
            else:
                raise PgpError(f"a packet of type {tag} in a keyring")
        return [Certs._one(g, now) for g in groups]

    @staticmethod
    def _self_ok(sig: Signature, now: dt.datetime) -> bool:
        if sig.hash_algorithm in (1, 3):
            return False
        if sig.hash_algorithm == 2 and (
            sig.created is None or sig.created >= Algorithms.SHA1_SELF_SIGNATURES_UNTIL
        ):
            return False
        return sig.valid_at(now)

    @staticmethod
    def _one(group: list[tuple[int, bytes]], now: dt.datetime) -> Cert:
        primary = Key.parse(group[0][1])
        frame = primary.framed()
        user_ids: list[bytes] = []
        subkeys: list[Bound] = []
        certified: list[dt.datetime] = []
        selfsigs: list[Signature] = []
        revoked = False
        problems: list[str] = []
        user: bytes | None = None
        sub: Key | None = None
        for tag, body in group[1:]:
            if tag == 13:
                user, sub = body, None
                user_ids.append(body)
                continue
            if tag == 17:
                user, sub = None, None
                continue
            if tag == 14:
                try:
                    sub = Key.parse(body)
                except PgpError as exc:
                    problems.append(f"a subkey is not readable ({exc})")
                    sub = None
                    continue
                subkeys.append(Bound(sub, None))
                user = None
                continue
            if tag == 12:
                continue
            try:
                sig = Signature.parse(body)
            except PgpError as exc:
                problems.append(f"a self-signature is not readable ({exc})")
                continue
            if not sig.issued_by(primary) or not Certs._self_ok(sig, now):
                continue
            if sub is not None and sig.type in (Certs.SUBKEY_BINDING, Certs.SUBKEY_REVOCATION):
                if not sig.verified_by(primary, frame + sub.framed()):
                    continue
                bound = subkeys[-1]
                if sig.type == Certs.SUBKEY_REVOCATION:
                    bound.revoked = True
                elif Certs._back_signed(sig, primary, sub) and (
                    bound.binding is None or (sig.created or now) > (bound.binding.created or now)
                ):
                    bound.binding = sig
            elif user is not None and sig.type in Certs.CERTIFICATION:
                uid = b"\xb4" + len(user).to_bytes(4, "big") + user
                if sig.verified_by(primary, frame + uid):
                    selfsigs.append(sig)
                    if sig.created is not None:
                        certified.append(sig.created)
            elif sig.type == Certs.DIRECT and sub is None and user is None:
                if sig.verified_by(primary, frame):
                    selfsigs.append(sig)
                    if sig.created is not None:
                        certified.append(sig.created)
            elif (
                sig.type == Certs.KEY_REVOCATION
                and sub is None
                and user is None
                and sig.verified_by(primary, frame)
            ):
                revoked = True
        current = max(
            selfsigs,
            key=lambda s: s.created or dt.datetime.min.replace(tzinfo=dt.UTC),
            default=None,
        )
        return Cert(
            primary,
            user_ids,
            subkeys,
            Certs._packets(group),
            sorted(certified),
            current,
            revoked,
            problems,
        )

    @staticmethod
    def _back_signed(binding: Signature, primary: Key, sub: Key) -> bool:
        """A signing subkey must sign the primary key back (a primary key binding, 0x19, embedded
        in the binding): otherwise anyone could bind another person's signing key as their own."""
        if not (binding.key_flags or 0) & 0x02:
            return True  # not a signing subkey: no back-signature is required
        for raw in binding.embedded:
            try:
                back = Signature.parse(raw)
            except PgpError:
                continue
            if back.type == Certs.PRIMARY_BINDING and back.verified_by(
                sub, primary.framed() + sub.framed()
            ):
                return True
        return False

    @staticmethod
    def _packets(group: list[tuple[int, bytes]]) -> bytes:
        out = bytearray()
        for tag, body in group:
            n = len(body)
            if n < 192:
                length = bytes([n])
            elif n < 8384:
                m = n - 192
                length = bytes([(m >> 8) + 192, m & 0xFF])
            else:
                length = b"\xff" + n.to_bytes(4, "big")
            out += bytes([0xC0 | tag]) + length + body
        return bytes(out)


class Cleartext:
    """The cleartext signature framework (RFC 9580 section 7)."""

    BEGIN: ClassVar[bytes] = b"-----BEGIN PGP SIGNED MESSAGE-----"
    SIGNATURE: ClassVar[bytes] = b"-----BEGIN PGP SIGNATURE-----"

    @staticmethod
    def split(message: bytes) -> tuple[bytes, bytes]:
        """The signed text (dash-escaping undone, as written, without the line break before the
        signature) and the armored signature block."""
        lines = message.replace(b"\r\n", b"\n").split(b"\n")
        try:
            begin = next(i for i, line in enumerate(lines) if line.rstrip() == Cleartext.BEGIN)
        except StopIteration as exc:
            raise PgpError("not a cleartext-signed message") from exc
        at = begin + 1
        while at < len(lines) and lines[at].strip():
            if not lines[at].startswith(b"Hash: "):
                raise PgpError("an armor header that is not Hash in a signed message")
            at += 1
        at += 1
        text: list[bytes] = []
        while at < len(lines):
            line = lines[at]
            if line.rstrip() == Cleartext.SIGNATURE:
                break
            if line.startswith(b"- "):
                line = line[2:]
            elif line.startswith(b"-"):
                raise PgpError("a line beginning with a dash that is not dash-escaped")
            text.append(line)
            at += 1
        else:
            raise PgpError("a signed message without its signature")
        return b"\n".join(text), b"\n".join(lines[at:])

    @staticmethod
    def canonical(text: bytes) -> bytes:
        """What a text signature covers: each line without trailing spaces or tabs, CRLF between."""
        return b"\r\n".join(line.rstrip(b" \t\r") for line in text.split(b"\n"))


__all__ = ["Cert", "Certs", "Cleartext", "Key", "Packets", "PgpError", "Signature"]
