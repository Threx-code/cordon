"""Reading a registry over HTTPS: a bounded GET, JSON and text bodies, the shapes a response may
take checked as they are read, a redirect followed once and only to the same kind of host, and OCI
registry requests with their token handshake.
"""

from __future__ import annotations

import gzip
import http.client
import io
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Final

from cordon_scanner.foundation.network.downloads import Download
from cordon_scanner.foundation.network.redirects import NoRedirects
from cordon_scanner.intel.registries import registry_request as base
from cordon_scanner.intel.registries.challenge import Challenge
from cordon_scanner.intel.registries.registry_hosts import (
    _MAX_GZIP_BYTES,
    Redirected,
)
from cordon_scanner.intel.registries.registry_request import PackageNotFound, RegistryError


class RegistryHttp:
    """HTTP and OCI requests to package registries, bounded and checked."""

    @staticmethod
    def get(url: str, *, accept: str = "application/json") -> bytes:
        """One bounded, redirect-free, credential-free answer, decompressed when the server sent
        gzip (NuGet's registration pages always are), with the decompressed size bounded too."""
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https":
            raise RegistryError(f"refusing a non-HTTPS registry URL: {parsed.scheme}")
        request = urllib.request.Request(  # noqa: S310 (scheme checked above)
            url,
            headers={"User-Agent": base.USER_AGENT, "Accept": accept, "Accept-Encoding": "gzip"},
            method="GET",
        )
        opener = urllib.request.build_opener(NoRedirects)
        body, encoding = b"", ""
        for attempt in range(base.RETRY_ATTEMPTS):
            try:
                with opener.open(request, timeout=base.TIMEOUT_SECONDS) as response:
                    body = Download.read(response, base.MAX_RESPONSE_BYTES + 1)
                    encoding = str(response.headers.get("Content-Encoding", "")).lower()
                break
            except urllib.error.HTTPError as exc:
                if exc.code in (404, 410):
                    # The Go proxy answers 410 Gone for a module it will not serve.
                    raise PackageNotFound(f"{parsed.netloc} has no package by that name") from exc
                location = str(exc.headers.get("Location", "")) if exc.headers else ""
                if exc.code in (301, 302, 303, 307, 308) and location.startswith("https://"):
                    # Not followed here: the caller decides whether this destination is one it
                    # trusts (`_cocoapods_spec`), and every other reader refuses it.
                    raise Redirected(f"HTTP {exc.code} from {parsed.netloc}", location) from exc
                if exc.code not in base.RETRY_STATUSES or attempt == base.RETRY_ATTEMPTS - 1:
                    raise RegistryError(f"HTTP {exc.code} from {parsed.netloc}") from exc
                time.sleep(base.RETRY_BACKOFF_SECONDS * (2**attempt))
            except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
                if attempt == base.RETRY_ATTEMPTS - 1:
                    raise RegistryError(f"{type(exc).__name__} asking {parsed.netloc}") from exc
                time.sleep(base.RETRY_BACKOFF_SECONDS * (2**attempt))
        if len(body) > base.MAX_RESPONSE_BYTES:
            raise RegistryError(
                f"response from {parsed.netloc} exceeded {base.MAX_RESPONSE_BYTES} bytes"
            )
        if encoding == "gzip" or body[:2] == b"\x1f\x8b":
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:
                    body = stream.read(_MAX_GZIP_BYTES + 1)
            except (OSError, EOFError) as exc:
                raise RegistryError(f"unreadable compressed response from {parsed.netloc}") from exc
            if len(body) > _MAX_GZIP_BYTES:
                raise RegistryError(
                    f"response from {parsed.netloc} expands past {_MAX_GZIP_BYTES} bytes"
                )
        return body

    @staticmethod
    def json(url: str) -> Any:
        body = RegistryHttp.get(url)
        try:
            return json.loads(body)
        except (json.JSONDecodeError, ValueError) as exc:
            raise RegistryError(
                f"unreadable response from {urllib.parse.urlsplit(url).netloc}"
            ) from exc

    @staticmethod
    def text(url: str) -> str:
        return RegistryHttp.get(url, accept="text/plain").decode("utf-8", "replace")

    @staticmethod
    def mapping(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def entries(value: Any) -> list[dict[str, Any]]:
        return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []

    @staticmethod
    def string(value: Any) -> str | None:
        return value if isinstance(value, str) and value else None

    @staticmethod
    def redirected(exc: urllib.error.HTTPError) -> bytes:
        """A registry's blob, where it sends it: a storage URL, fetched over HTTPS without the
        registry's token, whose bytes the caller checks against the blob's digest."""
        location = str(exc.headers.get("Location", ""))
        if not location.startswith("https://"):
            raise RegistryError("an OCI registry redirected a blob somewhere other than HTTPS")
        return RegistryHttp.get(location, accept="*/*")

    @staticmethod
    def oci(url: str, accept: str) -> Any:
        """An OCI distribution request's JSON body."""
        try:
            return json.loads(RegistryHttp.oci_bytes(url, accept))
        except ValueError as exc:
            raise RegistryError("an OCI registry answered with something other than JSON") from exc

    @staticmethod
    def oci_bytes(url: str, accept: str, *, follow: bool = False) -> bytes:
        """An OCI distribution request, with the anonymous bearer token a public registry hands
        out when it answers 401 with `WWW-Authenticate: Bearer realm=...`. The body as served:
        a manifest's digest is the hash of exactly these bytes."""
        # https is checked by the caller.
        headers = {"User-Agent": base.USER_AGENT, "Accept": accept}
        request = urllib.request.Request(url, headers=headers)  # noqa: S310
        opener = urllib.request.build_opener(NoRedirects)
        try:
            with opener.open(request, timeout=base.TIMEOUT_SECONDS) as response:
                return bytes(Download.read(response, base.MAX_RESPONSE_BYTES))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise PackageNotFound("the registry has no such artefact") from exc
            if follow and exc.code in (301, 302, 303, 307, 308):
                return RegistryHttp.redirected(exc)
            challenge = str(exc.headers.get("WWW-Authenticate", "")) if exc.code == 401 else ""
            if not challenge.startswith("Bearer "):
                raise RegistryError(f"HTTP {exc.code} from an OCI registry") from exc
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            raise RegistryError(f"{type(exc).__name__} asking an OCI registry") from exc
        fields = Challenge.fields(challenge)
        realm = fields.get("realm", "")
        if not realm.startswith("https://"):
            raise RegistryError("an OCI registry asked for credentials somewhere other than HTTPS")
        query = urllib.parse.urlencode(
            {k: v for k, v in fields.items() if k in ("service", "scope")}
        )
        token = RegistryHttp.mapping(RegistryHttp.json(f"{realm}?{query}")).get("token")
        if not isinstance(token, str):
            raise RegistryError("an OCI registry gave no token")
        bearer = {**headers, "Authorization": f"Bearer {token}"}
        authorised = urllib.request.Request(url, headers=bearer)  # noqa: S310
        try:
            with opener.open(authorised, timeout=base.TIMEOUT_SECONDS) as response:
                return bytes(Download.read(response, base.MAX_RESPONSE_BYTES))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise PackageNotFound("the registry has no such artefact") from exc
            if follow and exc.code in (301, 302, 303, 307, 308):
                return RegistryHttp.redirected(exc)
            raise RegistryError(f"HTTP {exc.code} from an OCI registry") from exc
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            raise RegistryError(f"{type(exc).__name__} asking an OCI registry") from exc

    MAX_PLATFORMS: Final = 32

    @staticmethod
    def latest(versions: list[str]) -> str | None:
        def order(v: str) -> tuple[Any, ...]:
            core, _, pre = v.removeprefix("v").partition("-")
            # A fixed width, so `1` and `1.2.3` compare number by number and never a number
            # against the prerelease that follows a shorter one.
            numbers = [int(p) if p.isdigit() else 0 for p in core.split(".")][:8]
            return (*numbers, *([0] * (8 - len(numbers))), pre == "", pre)

        return max(versions, key=order) if versions else None


__all__ = ["RegistryHttp"]
