"""Ed25519 signature verification, vendored, verify-only.

Why this is here at all. The advisory database can be refreshed from a signed
artefact (see `intel/dbsync.py`), and verifying that signature needs Ed25519.
The core takes no third-party runtime dependency -- that is a governing
constraint, not a preference -- and the standard library has no Ed25519, so the
one operation that is needed is vendored rather than pulled in as `cryptography`.

Only verification is here. There is no key generation and no signing: this code
never holds a private key, and the release pipeline that *signs* the artefact
uses a real, audited library. Verification is not on any hot path -- it runs once
when an operator syncs a new database -- so a pure-Python implementation is fast
enough, and its cost buys keeping the core dependency-free.

The algorithm is the reference from RFC 8032 (Edwards-curve Digital Signature
Algorithm), which is published for exactly this purpose. It is validated against
the RFC's own test vectors in `tests/unit/test_ed25519.py`, including that a
tampered signature, message or key is rejected -- because a verifier that
accepts a forgery is worse than no verifier at all.
"""

from __future__ import annotations

import hashlib

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _modp_inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = -121665 * _modp_inv(121666) % _P
_MODP_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * _modp_inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _MODP_SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


# Extended homogeneous coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, xy = T/Z.
_Point = tuple[int, int, int, int]

_G_Y = 4 * _modp_inv(5) % _P
_G_X = _recover_x(_G_Y, 0)
assert _G_X is not None  # noqa: S101 - the base point is fixed; a failure here is a broken constant
_G: _Point = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)
_NEUTRAL: _Point = (0, 1, 1, 0)


def _point_add(p: _Point, q: _Point) -> _Point:
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    dd = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mul(s: int, p: _Point) -> _Point:
    q = _NEUTRAL
    while s > 0:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _point_equal(p: _Point, q: _Point) -> bool:
    if (p[0] * q[2] - q[0] * p[2]) % _P != 0:
        return False
    return (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _point_decompress(data: bytes) -> _Point | None:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Whether `signature` is a valid Ed25519 signature of `message` by `public_key`.

    `public_key` is 32 bytes, `signature` is 64. Returns False for anything
    malformed rather than raising, so a caller can treat "did not verify" as one
    outcome regardless of why.
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a = _point_decompress(public_key)
    if a is None:
        return False
    r_bytes = signature[:32]
    r = _point_decompress(r_bytes)
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(_sha512(r_bytes + public_key + message), "little") % _L
    return _point_equal(_point_mul(s, _G), _point_add(r, _point_mul(h, a)))


__all__ = ["verify"]
