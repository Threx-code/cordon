"""The client for Cordon Cloud: sign-in, signed result upload, and the organisation's policy bundle.

Everything here is opt-in and changes nothing about what a scan finds. A scan with no cloud flags
makes no request to the cloud, and one with them still finds the same things -- the cloud receives
results and supplies an organisation's policy, and never decides a finding.

The contracts are in `schemas/`: K2 (signed results), K3 (policy bundle), K7 (auth). The core
needs only the standard library; keyless signing uses `sigstore` from the `[attest]` extra when it
is installed, and without it an upload is authenticated by the sign-in token alone and says so.
"""

from __future__ import annotations

import os
from typing import Final

DEFAULT_URL: Final = "https://api.cordon.dev"


class CloudError(Exception):
    """A cloud operation failed. The message is safe to show and never contains a token."""


class CloudEndpoint:
    """Where the cloud API is: explicit, then CORDON_CLOUD_URL, then the default."""

    @staticmethod
    def base_url(explicit: str | None = None) -> str:
        """The API base: explicit, then `CORDON_CLOUD_URL`, then the default. HTTPS only, except a
        loopback address, which is what a local development server listens on."""
        import urllib.parse

        url = (explicit or os.environ.get("CORDON_CLOUD_URL") or DEFAULT_URL).rstrip("/")
        parsed = urllib.parse.urlsplit(url)
        loopback = parsed.hostname in ("localhost", "127.0.0.1", "::1")
        if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
            raise CloudError(f"the cloud URL must be https: {parsed.scheme}://{parsed.hostname}")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise CloudError("the cloud URL must not carry credentials, a query or a fragment")
        return url


__all__ = ["DEFAULT_URL", "CloudEndpoint", "CloudError"]
