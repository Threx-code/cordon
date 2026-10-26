"""ECDSA signature verification over P-256, P-384 and P-521, verify-only, in pure Python.

Why: Sigstore's certificate authority, its certificate transparency log and its transparency log
(Rekor) sign with ECDSA on these curves, and a signed build attestation is checked through all
three. The core takes no third-party code (`_ed25519.py` says why), and the standard library
has no elliptic curves, so the one operation needed -- verification -- is written here from
FIPS 186-5 and SEC 1.

Only verification: no key generation, no signing, no secret ever held, so the timing side
channels that make elliptic-curve code hard to write do not arise -- every input is public.

What a verifier must refuse, it refuses (each is a Wycheproof test family, run in
`tests/unit/intel/provenance/test_ecdsa.py`):

- a public key that is not a point on the curve, or the point at infinity (invalid-curve
  attacks);
- `r` or `s` outside `[1, n-1]`;
- a signature not in strict DER (`_der.Der`), or with bytes after it;
- a hash longer than the order is truncated to its leftmost bits, as FIPS 186 says.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import ClassVar

from cordon_scanner.intel.provenance._der import Der, DerError


@dataclass(frozen=True)
class Curve:
    """A short Weierstrass curve y^2 = x^3 + ax + b over GF(p), with a = -3."""

    name: str
    oid: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int
    size: int  # bytes in a coordinate


_Jacobian = tuple[int, int, int]


class Ecdsa:
    """`Ecdsa.verify(key, message, signature, hash_name)`, and the key and curve readers."""

    P256: ClassVar[Curve] = Curve(
        "P-256",
        "1.2.840.10045.3.1.7",
        p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        size=32,
    )
    P384: ClassVar[Curve] = Curve(
        "P-384",
        "1.3.132.0.34",
        p=int(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
            16,
        ),
        a=int(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
            16,
        ),
        b=int(
            "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
            16,
        ),
        gx=int(
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            16,
        ),
        gy=int(
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            16,
        ),
        n=int(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
            16,
        ),
        size=48,
    )
    P521: ClassVar[Curve] = Curve(
        "P-521",
        "1.3.132.0.35",
        p=2**521 - 1,
        a=2**521 - 4,
        b=int(
            "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B"
            "1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
            16,
        ),
        gx=int(
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928"
            "FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            16,
        ),
        gy=int(
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640"
            "C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            16,
        ),
        n=int(
            "01FF"
            + "FFFFFFFF" * 7
            + "FFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
            16,
        ),
        size=66,
    )
    CURVES: ClassVar[dict[str, Curve]] = {}
    EC_PUBLIC_KEY: ClassVar[str] = "1.2.840.10045.2.1"

    # -- keys ---------------------------------------------------------------

    @staticmethod
    def public_key(spki_der: bytes) -> tuple[Curve, tuple[int, int]]:
        """The curve and point of a DER SubjectPublicKeyInfo holding an EC key."""
        spki = Der.parse(spki_der, Der.SEQUENCE).children()
        if len(spki) != 2:
            raise DerError("a key info of the wrong shape")
        algorithm = spki[0].expect(Der.SEQUENCE).children()
        if len(algorithm) != 2 or algorithm[0].oid() != Ecdsa.EC_PUBLIC_KEY:
            raise DerError("not an elliptic-curve key")
        curve = Ecdsa.CURVES.get(algorithm[1].oid())
        if curve is None:
            raise DerError("a curve not supported")
        return curve, Ecdsa.point(curve, spki[1].bit_string())

    @staticmethod
    def point(curve: Curve, encoded: bytes) -> tuple[int, int]:
        """An uncompressed (04) or compressed (02/03) SEC 1 point, checked to be on the curve."""
        size = curve.size
        if len(encoded) == 1 + 2 * size and encoded[0] == 4:
            x = int.from_bytes(encoded[1 : 1 + size], "big")
            y = int.from_bytes(encoded[1 + size :], "big")
        elif len(encoded) == 1 + size and encoded[0] in (2, 3):
            x = int.from_bytes(encoded[1:], "big")
            if x >= curve.p:
                raise DerError("a coordinate out of range")
            rhs = (pow(x, 3, curve.p) + curve.a * x + curve.b) % curve.p
            y = pow(rhs, (curve.p + 1) // 4, curve.p)  # p = 3 mod 4 for each of these curves
            if y * y % curve.p != rhs:
                raise DerError("not a point on the curve")
            if y & 1 != encoded[0] & 1:
                y = curve.p - y
        else:
            raise DerError("a point in an unknown encoding")
        if not Ecdsa.on_curve(curve, x, y):
            raise DerError("not a point on the curve")
        return x, y

    @staticmethod
    def on_curve(curve: Curve, x: int, y: int) -> bool:
        p = curve.p
        if not (0 <= x < p and 0 <= y < p):
            return False
        return (y * y - (x * x * x + curve.a * x + curve.b)) % p == 0

    # -- verification -------------------------------------------------------

    @staticmethod
    def verify(
        key: tuple[Curve, tuple[int, int]], message: bytes, signature: bytes, hash_name: str
    ) -> bool:
        """Whether `signature` (DER `SEQUENCE { r, s }`) signs `message` hashed with `hash_name`
        under `key`. False for anything malformed: one outcome, whatever the reason."""
        try:
            parts = Der.parse(signature, Der.SEQUENCE).children()
            if len(parts) != 2:
                return False
            r, s = parts[0].integer(), parts[1].integer()
        except DerError:
            return False
        return Ecdsa.verify_digest(key, hashlib.new(hash_name, message).digest(), r, s)

    @staticmethod
    def verify_digest(key: tuple[Curve, tuple[int, int]], digest: bytes, r: int, s: int) -> bool:
        curve, (qx, qy) = key
        n = curve.n
        if not (1 <= r < n and 1 <= s < n):
            return False
        if not Ecdsa.on_curve(curve, qx, qy):
            return False
        e = int.from_bytes(digest, "big")
        excess = len(digest) * 8 - n.bit_length()
        if excess > 0:
            e >>= excess
        w = pow(s, -1, n)
        u1, u2 = e * w % n, r * w % n
        point = Ecdsa._shamir(curve, u1, u2, (qx, qy))
        if point is None:
            return False
        return point[0] % n == r

    # -- arithmetic (Jacobian coordinates, a = -3) ---------------------------

    @staticmethod
    def _double(curve: Curve, pt: _Jacobian) -> _Jacobian:
        x, y, z = pt
        p = curve.p
        if y == 0 or z == 0:
            return (0, 1, 0)
        zz = z * z % p
        m = 3 * (x - zz) * (x + zz) % p
        yy = y * y % p
        s = 4 * x * yy % p
        x3 = (m * m - 2 * s) % p
        y3 = (m * (s - x3) - 8 * yy * yy) % p
        z3 = 2 * y * z % p
        return (x3, y3, z3)

    @staticmethod
    def _add(curve: Curve, a: _Jacobian, b: _Jacobian) -> _Jacobian:
        p = curve.p
        x1, y1, z1 = a
        x2, y2, z2 = b
        if z1 == 0:
            return b
        if z2 == 0:
            return a
        z1z1, z2z2 = z1 * z1 % p, z2 * z2 % p
        u1, u2 = x1 * z2z2 % p, x2 * z1z1 % p
        s1, s2 = y1 * z2 * z2z2 % p, y2 * z1 * z1z1 % p
        if u1 == u2:
            if s1 != s2:
                return (0, 1, 0)
            return Ecdsa._double(curve, a)
        h, r = (u2 - u1) % p, (s2 - s1) % p
        hh = h * h % p
        hhh = h * hh % p
        v = u1 * hh % p
        x3 = (r * r - hhh - 2 * v) % p
        y3 = (r * (v - x3) - s1 * hhh) % p
        z3 = h * z1 * z2 % p
        return (x3, y3, z3)

    @staticmethod
    def _shamir(curve: Curve, u1: int, u2: int, q: tuple[int, int]) -> tuple[int, int] | None:
        """u1*G + u2*Q in one pass over the bits, in affine form, or None at infinity."""
        g: _Jacobian = (curve.gx, curve.gy, 1)
        qj: _Jacobian = (q[0], q[1], 1)
        gq = Ecdsa._add(curve, g, qj)
        table = {(1, 0): g, (0, 1): qj, (1, 1): gq}
        acc: _Jacobian = (0, 1, 0)
        for i in range(max(u1.bit_length(), u2.bit_length()) - 1, -1, -1):
            acc = Ecdsa._double(curve, acc)
            bits = ((u1 >> i) & 1, (u2 >> i) & 1)
            if bits != (0, 0):
                acc = Ecdsa._add(curve, acc, table[bits])
        x, y, z = acc
        if z == 0:
            return None
        zi = pow(z, -1, curve.p)
        zi2 = zi * zi % curve.p
        return (x * zi2 % curve.p, y * zi2 * zi % curve.p)


Ecdsa.CURVES.update({c.oid: c for c in (Ecdsa.P256, Ecdsa.P384, Ecdsa.P521)})


__all__ = ["Curve", "Ecdsa"]
