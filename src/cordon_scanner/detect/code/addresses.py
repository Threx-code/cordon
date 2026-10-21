"""Whether an IPv4 address is publicly routable (`PublicAddress.is_public`).

Moved verbatim from `detect/code/capability.py`: a pure predicate over an octet list, with no class
state, used to tell a beacon's destination from a private or reserved one. The ranges are the usual
private, loopback, link-local, carrier-grade-NAT, documentation and benchmarking blocks, hand-listed
rather than `ipaddress.is_global`, whose ranges differ.
"""

from __future__ import annotations


class PublicAddress:
    """A publicly routable IPv4 address, by its octets."""

    @staticmethod
    def is_public(octets: list[int]) -> bool:
        a, b, c = octets[0], octets[1], octets[2]
        return not (
            a in (0, 10, 127)
            or a >= 224
            or (a == 169 and b == 254)
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or (a == 100 and 64 <= b <= 127)
            or (a, b, c) in ((192, 0, 2), (198, 51, 100), (203, 0, 113))
            or (a == 198 and b in (18, 19))
        )
