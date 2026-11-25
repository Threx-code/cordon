"""The API domains a social platform's signed app requests go to (the abuse-tooling label).

Kept apart from the signature names (`platform_signing.py`): `POLICY.ABUSE_TOOLING.PLATFORM_FORGERY.001`
is a file that writes down several of those names beside one of these hosts, and a module holding
both tables would be that shape itself. Apart, Cordon's own detector does not report itself.
"""

from __future__ import annotations

from typing import Final

PLATFORM_API_HOSTS: Final = frozenset(
    {"tiktokv.com", "tiktokcdn.com", "snssdk.com", "byteoversea.com", "musical.ly", "tiktok.com"}
)
"""Domains the signed requests go to."""

__all__ = ["PLATFORM_API_HOSTS"]
