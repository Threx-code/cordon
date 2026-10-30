"""DSA signature verification, verify-only, in pure Python (FIPS 186-4 section 4.7).

Why: OpenPGP keys of a certain age are DSA -- a Helm chart publisher's signing key among them
(cisco-nso's) -- and verifying what they signed needs it. Only verification: every input is
public. The key is the operator's own choice in their keyring; its parameters are still checked
to be a DSA group at all, so a malformed key cannot make every signature verify.
"""

from __future__ import annotations


class Dsa:
    """`Dsa.verify_digest((p, q, g, y), digest, r, s)`."""

    MIN_P_BITS = 1024

    @staticmethod
    def checked(p: int, q: int, g: int, y: int) -> tuple[int, int, int, int]:
        """The key, when it is a DSA group: `q` divides `p - 1`, `g` and `y` lie in the order-`q`
        subgroup and neither is trivial."""
        if p.bit_length() < Dsa.MIN_P_BITS or q.bit_length() not in (160, 224, 256):
            raise ValueError("DSA parameters out of range")
        if (p - 1) % q or not 1 < g < p or not 1 < y < p:
            raise ValueError("not a DSA group")
        if pow(g, q, p) != 1 or pow(y, q, p) != 1:
            raise ValueError("a DSA generator or key outside the subgroup")
        return p, q, g, y

    @staticmethod
    def verify_digest(key: tuple[int, int, int, int], digest: bytes, r: int, s: int) -> bool:
        p, q, g, y = key
        if not (0 < r < q and 0 < s < q):
            return False
        z = int.from_bytes(digest[: (q.bit_length() + 7) // 8], "big")
        excess = min(len(digest) * 8, ((q.bit_length() + 7) // 8) * 8) - q.bit_length()
        if excess > 0:
            z >>= excess
        w = pow(s, -1, q)
        u1, u2 = z * w % q, r * w % q
        v = pow(g, u1, p) * pow(y, u2, p) % p % q
        return v == r


__all__ = ["Dsa"]
