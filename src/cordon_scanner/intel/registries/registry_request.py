"""What one registry request may be: how long it waits, how much it reads, how often it asks
again, who it says it is, and how it fails. Below the registry clients, so each of them and
the HTTP and host helpers read it without importing one another (architecture audit F3)."""

from __future__ import annotations

import http.client
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable

from cordon_scanner.foundation.network.downloads import Download
from cordon_scanner.foundation.network.failures import NetworkFailure
from cordon_scanner.foundation.network.pinned import PinnedHTTPS
from cordon_scanner.foundation.network.redirects import NoRedirects

TIMEOUT_SECONDS = 5.0

"""Per-request ceiling. A scan waiting on a slow registry is a scan somebody
kills, and a killed scan reports nothing at all."""

MAX_RESPONSE_BYTES = 48 << 20
"""How much of a response to read, after decompression.

Four megabytes was here, on the reasoning that metadata for a large package runs to a few. It
runs to thirty: the npm documents for `react` (6.8 MB), `aws-sdk` (10 MB), `@types/node` (11 MB),
`typescript` (15 MB) and `next` (30 MB) all exceeded it, so the most-installed packages on npm
were the ones `--online` always reported as unanswerable. Bodies are requested gzip-compressed
(a tenth of the size on the wire) and this bounds what they may expand to."""

RETRY_ATTEMPTS = 3
"""How many times one question is asked before it is given up on.

Three, not more. The budget this spends is bounded by the scan's own deadline,
and a registry that has refused three times in a row is down rather than busy."""

RETRY_BACKOFF_SECONDS = 0.25
"""Base for an exponential backoff: 0.25s, then 0.5s. Short, because a scan is
interactive and a retry that costs more than the answer is worth is not one."""

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
"""Statuses that mean "ask again". Everything else is a decision: a 404 is the
registry saying it does not have the package, and asking twice does not help."""

USER_AGENT = "cordon-scanner (+https://github.com/Threx-code/cordon)"


class RegistryError(RuntimeError):
    """A question that could not be answered.

    Raised rather than returning a default, so a caller cannot mistake "the
    registry was unreachable" for "the registry said no". The two have opposite
    meanings and the same shape if this returns `False`.
    """


class PackageNotFound(RegistryError):
    """The registry answered, and it has no package by that name.

    Not an outage: a definite answer about the name. A dependency the public registry does not
    have is either private -- and a public package registered under the name would win, which is
    dependency confusion -- or invented, which is what an AI assistant does when it suggests a
    package that sounds right, and what slopsquatting registers.
    """


MAX_ARCHIVE_BYTES = 64 << 20


class RegistryRequest:
    """The download every registry client shares: a package archive from the registry's own file
    hosts, over https, without redirects, bounded in size."""

    @staticmethod
    def headers(url: str, allow: Callable[[str], bool], *, public: bool = False) -> dict[str, str]:
        """The response headers of `HEAD url` (names lower-cased), from a host `allow` admits, https, no redirect."""
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or not allow(parsed.hostname or ""):
            raise RegistryError(f"refusing an archive URL off the allowlist: {parsed.hostname!r}")
        request = urllib.request.Request(  # noqa: S310 - scheme and host checked above
            url, headers={"User-Agent": USER_AGENT}, method="HEAD"
        )
        try:
            with urllib.request.build_opener(NoRedirects, PinnedHTTPS(public_only=public)).open(
                request, timeout=TIMEOUT_SECONDS * 2
            ) as response:
                return {k.lower(): str(v) for k, v in response.headers.items()}
        except urllib.error.HTTPError as exc:
            NetworkFailure.release(exc)
            raise RegistryError(f"HTTP {exc.code} from {parsed.netloc}") from exc
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            raise RegistryError(
                f"{NetworkFailure.reason(exc)} fetching from {parsed.netloc}"
            ) from exc

    @staticmethod
    def fetch_bytes(
        url: str, allow: Callable[[str], bool], *, redirects: int = 0, public: bool = False
    ) -> bytes:
        """The bytes at `url`, from a host `allow` admits. `redirects` is how many redirects may be followed, each only to an https
        address on a host `allow` admits (a registry that signs a storage URL answers with one); none by default. With `public`,
        the name is resolved once and every address it gives must be a public one (the connection goes to the address checked)."""
        for hop in range(redirects + 1):
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme != "https" or not allow(parsed.hostname or ""):
                raise RegistryError(
                    f"refusing an archive URL off the allowlist: {parsed.hostname!r}"
                )
            request = urllib.request.Request(  # noqa: S310 - scheme and host checked above
                url, headers={"User-Agent": USER_AGENT}, method="GET"
            )
            opener = urllib.request.build_opener(NoRedirects, PinnedHTTPS(public_only=public))
            try:
                with opener.open(request, timeout=TIMEOUT_SECONDS * 6) as response:
                    body = Download.read(response, MAX_ARCHIVE_BYTES + 1)
            except urllib.error.HTTPError as exc:
                NetworkFailure.release(exc)
                where = str(exc.headers.get("Location", "")) if exc.headers else ""
                if exc.code in (301, 302, 303, 307, 308) and where and hop < redirects:
                    url = urllib.parse.urljoin(url, where)
                    continue
                raise RegistryError(f"HTTP {exc.code} from {parsed.netloc}") from exc
            except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
                raise RegistryError(
                    f"{NetworkFailure.reason(exc)} fetching from {parsed.netloc}"
                ) from exc
            if len(body) > MAX_ARCHIVE_BYTES:
                raise RegistryError(
                    f"archive from {parsed.netloc} exceeded {MAX_ARCHIVE_BYTES} bytes"
                )
            return bytes(body)
        raise RegistryError(f"too many redirects fetching from {parsed.netloc}")


__all__ = [
    "MAX_ARCHIVE_BYTES",
    "MAX_RESPONSE_BYTES",
    "RETRY_ATTEMPTS",
    "RETRY_BACKOFF_SECONDS",
    "RETRY_STATUSES",
    "TIMEOUT_SECONDS",
    "USER_AGENT",
    "PackageNotFound",
    "RegistryError",
    "RegistryRequest",
]
