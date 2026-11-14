"""What a client has to forge to pass as a platform's own app (the abuse-tooling label).

A social platform's mobile API refuses requests that do not carry the app's request signature:
a handful of headers and query parameters computed from the request, the device and the time.
A program that computes those, for a platform whose API host it also names, is not a client of
the platform's public API; it is passing as the platform's app. That is a tool somebody runs on
purpose against the platform, not something done to the machine that installs it, and it is
labelled as policy, never as malware.

Names are compared with case and separators removed (`X-Gorgon`, `x_gorgon`, `xgorgon`).
"""

from __future__ import annotations

from typing import Final

SIGNING_PARAMETERS: Final = frozenset(
    {
        "xgorgon",
        "xkhronos",
        "xargus",
        "xladon",
        "xbogus",
        "mstoken",
        "xssstub",
        "xtttoken",
        "xtttokensign",
    }
)
"""Request-signature headers and parameters of the platform's app API."""

PLATFORM_API_HOSTS: Final = frozenset(
    {"tiktokv.com", "tiktokcdn.com", "snssdk.com", "byteoversea.com", "musical.ly", "tiktok.com"}
)
"""Domains the signed requests go to."""

MINIMUM_PARAMETERS: Final = 2
"""One of these names in a file is a coincidence of vocabulary (a scraper reads a cookie called
`msToken`); the signature is several of them computed together."""


class PlatformSigning:
    @staticmethod
    def normalise(name: str) -> str:
        return "".join(ch for ch in name.lower() if ch.isalnum())

    @staticmethod
    def parameter(text: str) -> str | None:
        """The signing parameter this string is, whole, or None."""
        if len(text) > 40:
            return None
        key = PlatformSigning.normalise(text)
        return key if key in SIGNING_PARAMETERS else None

    @staticmethod
    def names_platform(text: str) -> bool:
        """The string is, or holds, a URL on one of the platform's API domains."""
        lowered = text.lower()
        return any(host in lowered for host in PLATFORM_API_HOSTS)


__all__ = ["MINIMUM_PARAMETERS", "PLATFORM_API_HOSTS", "SIGNING_PARAMETERS", "PlatformSigning"]
