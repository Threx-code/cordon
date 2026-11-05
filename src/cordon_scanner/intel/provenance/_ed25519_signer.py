"""Ed25519 signing (RFC 8032), for the release ceremony that signs Cordon's own feed and bundles.

Verification lives apart (`_ed25519`), and nothing a scan runs signs anything. This is what the
release scripts (`scripts/release/key_ceremony.py`, `sign_advisory_bundle.py`) and the tests that
exercise them use, in place of a third-party library:

- **Deterministic.** Ed25519's nonce is derived from the key and the message (RFC 8032 5.1.6):
  there is no randomness at signing time to fail, the weakness that has leaked ECDSA keys.
- **Checked.** It reproduces RFC 8032's own test vectors (7.1), and every signature is verified
  with the independent verifier before it is returned.
- **Seeds** come from the operating system's CSPRNG (`secrets`).
- **Timing.** Python's integers are not constant-time; the scalar multiplication runs a fixed
  ladder over all 253 bits, which removes the branch on the key, not every timing difference. The
  release ceremony runs offline on a machine no one else can run code on, where that is the
  threat model; nothing here signs on a shared host.
"""

from __future__ import annotations

import hashlib
import secrets

from cordon_scanner.intel.provenance import _ed25519 as verify_side
from cordon_scanner.intel.provenance._ed25519 import _G, _L, _NEUTRAL, _P, Ed25519


class Ed25519Signer:
    """A signing key from its 32-byte seed; `generate()` makes one."""

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("an Ed25519 seed is 32 bytes")
        h = hashlib.sha512(seed).digest()
        a = int.from_bytes(h[:32], "little")
        a &= (1 << 254) - 8
        a |= 1 << 254
        self._a, self._prefix = a, h[32:]
        self.public = Ed25519Signer._compress(Ed25519Signer._ladder(a))
        self.seed = seed

    @staticmethod
    def generate() -> Ed25519Signer:
        return Ed25519Signer(secrets.token_bytes(32))

    def sign(self, message: bytes) -> bytes:
        r = int.from_bytes(hashlib.sha512(self._prefix + message).digest(), "little") % _L
        big_r = Ed25519Signer._compress(Ed25519Signer._ladder(r))
        k = int.from_bytes(hashlib.sha512(big_r + self.public + message).digest(), "little") % _L
        s = (r + k * self._a) % _L
        signature = big_r + s.to_bytes(32, "little")
        if not Ed25519.verify(self.public, message, signature):
            raise RuntimeError("a signature that does not verify: refusing to use it")
        return signature

    @staticmethod
    def _ladder(scalar: int) -> verify_side._Point:
        r0, r1 = _NEUTRAL, _G
        for i in range(254, -1, -1):
            if (scalar >> i) & 1:
                r0, r1 = Ed25519._point_add(r0, r1), Ed25519._point_add(r1, r1)
            else:
                r0, r1 = Ed25519._point_add(r0, r0), Ed25519._point_add(r0, r1)
        return r0

    @staticmethod
    def _compress(point: verify_side._Point) -> bytes:
        x, y, z, _ = point
        zi = pow(z, _P - 2, _P)
        x, y = x * zi % _P, y * zi % _P
        return (y | ((x & 1) << 255)).to_bytes(32, "little")


__all__ = ["Ed25519Signer"]
