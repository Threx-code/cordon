"""A test double for the tenant key hierarchy (`cordon_scanner.contracts.private_names.TenantKeys`).

Keys are derived from the tenant name and the purpose with a fixed test secret: stable across runs,
different per tenant and purpose, and nothing a real tenant's key could be mistaken for.
"""

from __future__ import annotations

import hashlib


class StaticTenantKeys:
    def __init__(self, secret: bytes = b"test-only-root-secret-not-a-key") -> None:
        self._secret = secret

    def key(self, tenant: str, purpose: str) -> bytes:
        return hashlib.sha256(
            self._secret + b"\0" + tenant.encode() + b"\0" + purpose.encode()
        ).digest()


class ShortKeys:
    def key(self, tenant: str, purpose: str) -> bytes:
        return b"short"
