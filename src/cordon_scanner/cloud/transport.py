"""JSON over HTTPS to the cloud: no redirects, bounded responses, tokens never in errors."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Final, Protocol

from cordon_scanner.cloud import CloudError
from cordon_scanner.version import __version__

TIMEOUT_SECONDS: Final = 15.0
MAX_RESPONSE_BYTES: Final = 8 << 20
USER_AGENT: Final = f"cordon-scanner/{__version__}"


@dataclass(frozen=True)
class Response:
    status: int
    body: dict[str, Any]


class Transport(Protocol):
    def __call__(
        self, method: str, url: str, *, body: bytes | None, headers: dict[str, str]
    ) -> tuple[int, bytes]: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class CloudTransport:
    """JSON over HTTPS to the cloud: no redirects, bounded responses, tokens never in errors."""

    @staticmethod
    def _urllib(
        method: str, url: str, *, body: bytes | None, headers: dict[str, str]
    ) -> tuple[int, bytes]:
        request = urllib.request.Request(url, data=body, headers=headers, method=method)  # noqa: S310 - base_url() checked the scheme
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                return int(response.status), response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            return int(exc.code), exc.read(MAX_RESPONSE_BYTES + 1)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            host = urllib.parse.urlsplit(url).hostname
            raise CloudError(f"could not reach {host} ({type(exc).__name__})") from exc

    @staticmethod
    def request(
        method: str,
        url: str,
        *,
        json_body: Any = None,
        form: dict[str, str] | None = None,
        token: str | None = None,
        transport: Transport | None = None,
    ) -> Response:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        body: bytes | None = None
        if json_body is not None:
            body = json.dumps(json_body, sort_keys=True, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        elif form is not None:
            body = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        status, raw = (transport or CloudTransport._urllib)(method, url, body=body, headers=headers)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise CloudError(
                f"the response from {urllib.parse.urlsplit(url).hostname} was too large"
            )
        if 300 <= status < 400:
            raise CloudError(
                f"the cloud answered with a redirect ({status}), which is not followed"
            )
        try:
            parsed = json.loads(raw) if raw else {}
        except ValueError as exc:
            raise CloudError(f"the cloud answered {status} with a body that is not JSON") from exc
        return Response(status, parsed if isinstance(parsed, dict) else {"value": parsed})

    @staticmethod
    def error_text(response: Response) -> str:
        """The cloud's error code and description, never anything that could hold a secret."""
        code = str(response.body.get("error", "") or response.status)
        description = str(
            response.body.get("error_description", "") or response.body.get("detail", "")
        )[:300]
        return f"{code}: {description}" if description else code


__all__ = ["CloudTransport", "Response", "Transport"]
