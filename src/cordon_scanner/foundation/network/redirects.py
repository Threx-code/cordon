"""Refusing redirects: a request reaches the address it names, or fails.

Every request this package makes names its server on purpose: an advisory source, a registry, the
feed, a notification endpoint. A redirect would let that server, or anyone on the path who can
answer for it, send the request elsewhere, with its headers. So none is followed; a 3xx answer is
the response, and its caller treats it as the failure it is.

The one exception, an extension download that may move between HTTPS addresses, keeps its own
handler in mcp/extensions.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any, NoReturn

from cordon_scanner.foundation.network.failures import NetworkFailure


class ClosedErrors(urllib.request.HTTPDefaultErrorHandler):
    """Raises each 4xx and 5xx with its response already closed.

    An `HTTPError` is the server's open response. Caught as itself, `NetworkFailure.release` closed
    it; caught as `URLError` or `OSError`, or never caught, it held a socket until the collector
    found it, which Python 3.14 reports ("Implicitly cleaning up <HTTPError 404>"). Closing it
    where it is raised covers every caller at once. Its code, reason and headers stay readable; no
    caller reads an error's body."""

    def http_error_default(self, req: Any, fp: Any, code: int, msg: str, hdrs: Any) -> NoReturn:
        error = urllib.error.HTTPError(req.full_url, code, msg, hdrs, fp)
        NetworkFailure.release(error)
        raise error


class NoRedirects(urllib.request.HTTPRedirectHandler, ClosedErrors):
    """Answers every redirect with no follow-up request, so urllib returns the 3xx as it is. Also
    the opener's error handler (`ClosedErrors`): `build_opener(NoRedirects)` installs both."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None

    @staticmethod
    def opener(*handlers: Any) -> urllib.request.OpenerDirector:
        """An opener that follows no redirect, with any other `handlers` it needs."""
        return urllib.request.build_opener(NoRedirects, *handlers)


__all__ = ["ClosedErrors", "NoRedirects"]
