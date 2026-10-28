"""Fetching what an upstream look-up reads, bounded in size, and remembering what this process has
already resolved.
"""

from __future__ import annotations

from typing import ClassVar

from cordon_scanner.intel.advisories.upstream.base import (
    Unnamed,
    Upstream,
)


class Fetch:
    """Fetches for the upstream look-ups, and the upstreams already resolved."""

    @staticmethod
    def get(url: str, limit: int = 4 << 20) -> bytes:
        from cordon_scanner.intel.registries.registry_http import RegistryHttp

        body = RegistryHttp.get(url)
        if len(body) > limit:
            raise ValueError("response too large")
        return body

    resolved: ClassVar[dict[tuple[str, str, str | None, str | None], Upstream | Unnamed]] = {}


__all__ = ["Fetch"]
