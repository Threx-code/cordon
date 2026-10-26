"""ECDSA P-256 signing with a one-use key: the one private-key operation Cordon performs.

Keyless signing (`keyless`) needs it: a key made for one signature, certified by Fulcio for the CI
job's identity, used once, and dropped. Everything else this project does with signatures is
verification (`intel/provenance/_ecdsa`).

How the risks of hand-written signing are met:

- **The nonce.** A repeated or biased nonce gives the private key away, and a broken random
  source is how that has happened in practice. Nonces here are deterministic (RFC 6979): an
  HMAC-DRBG over the key and the digest, so there is no randomness at signing time to fail. It
  is checked against RFC 6979's own vectors (A.2.5).
- **Timing.** The scalar multiplications run a Montgomery ladder: the same sequence of point
  operations whatever the scalar's bits. Python's integers are not constant-time, so this is a
  mitigation, not a guarantee -- which is why the key is ephemeral: it signs one statement in a
  CI job, and nothing it could leak outlives that job.
- **The key.** Drawn from `secrets` (the operating system's CSPRNG), uniformly in [1, n-1].
- **Self-check.** Every signature is verified with the independent verifier before it is used.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from cordon_scanner.intel.provenance._ecdsa import Curve, Ecdsa


class P256Signer:
    """An ECDSA P-256 key that signs; `ephemeral()` makes one, `public_spki()` names it."""

    CURVE: Curve = Ecdsa.P256
    SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")

    def __init__(self, private: int) -> None:
        n = P256Signer.CURVE.n
        if not 1 <= private < n:
            raise ValueError("a private key out of range")
        self._d = private
        self.point = P256Signer._multiply(private)

    @staticmethod
    def ephemeral() -> P256Signer:
        return P256Signer(secrets.randbelow(P256Signer.CURVE.n - 1) + 1)

    def public_spki(self) -> bytes:
        x, y = self.point
        return P256Signer.SPKI_PREFIX + b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")

    def public_pem(self) -> str:
        import base64

        body = base64.b64encode(self.public_spki()).decode()
        lines = [body[i : i + 64] for i in range(0, len(body), 64)]
        return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"

    def sign(self, message: bytes) -> bytes:
        """A DER `SEQUENCE { r, s }` over SHA-256(message), checked before it is returned."""
        digest = hashlib.sha256(message).digest()
        r, s = self.sign_digest(digest)
        if not Ecdsa.verify_digest((P256Signer.CURVE, self.point), digest, r, s):
            raise RuntimeError("a signature that does not verify: refusing to use it")
        return P256Signer.der(r, s)

    def sign_digest(self, digest: bytes) -> tuple[int, int]:
        n = P256Signer.CURVE.n
        z = int.from_bytes(digest, "big") % n
        for k in P256Signer._nonces(self._d, digest):
            x, _ = P256Signer._multiply(k)
            r = x % n
            if r == 0:
                continue
            s = pow(k, -1, n) * (z + r * self._d) % n
            if s != 0:
                return r, s
        raise RuntimeError("unreachable: the nonce generator does not end")  # pragma: no cover

    # -- RFC 6979 3.2 --------------------------------------------------------

    @staticmethod
    def _nonces(d: int, digest: bytes):  # type: ignore[no-untyped-def]
        n = P256Signer.CURVE.n
        size = 32
        x = d.to_bytes(size, "big")
        h = (int.from_bytes(digest, "big") % n).to_bytes(size, "big")
        v, k = b"\x01" * 32, b"\x00" * 32
        k = hmac.new(k, v + b"\x00" + x + h, hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()
        k = hmac.new(k, v + b"\x01" + x + h, hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()
        while True:
            v = hmac.new(k, v, hashlib.sha256).digest()
            candidate = int.from_bytes(v, "big")
            if 1 <= candidate < n:
                yield candidate
            k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
            v = hmac.new(k, v, hashlib.sha256).digest()

    # -- arithmetic ----------------------------------------------------------

    @staticmethod
    def _multiply(scalar: int) -> tuple[int, int]:
        """scalar * G by a Montgomery ladder over all 256 bits."""
        curve = P256Signer.CURVE
        r0: tuple[int, int, int] = (0, 1, 0)
        r1: tuple[int, int, int] = (curve.gx, curve.gy, 1)
        for i in range(255, -1, -1):
            if (scalar >> i) & 1:
                r0, r1 = Ecdsa._add(curve, r0, r1), Ecdsa._double(curve, r1)
            else:
                r0, r1 = Ecdsa._double(curve, r0), Ecdsa._add(curve, r0, r1)
        x, y, z = r0
        if z == 0:
            raise ValueError("the point at infinity")
        zi = pow(z, -1, curve.p)
        zi2 = zi * zi % curve.p
        return x * zi2 % curve.p, y * zi2 * zi % curve.p

    @staticmethod
    def der(r: int, s: int) -> bytes:
        def integer(v: int) -> bytes:
            raw = v.to_bytes((v.bit_length() + 8) // 8, "big")  # a leading zero keeps it positive
            return bytes([0x02, len(raw)]) + raw

        body = integer(r) + integer(s)
        return bytes([0x30, len(body)]) + body


__all__ = ["P256Signer"]
