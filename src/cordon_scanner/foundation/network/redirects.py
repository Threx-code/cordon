"""Refusing redirects: a request reaches the address it names, or fails.

Every request this package makes names its server on purpose: an advisory source, a registry, the
feed, a notification endpoint. A redirect would let that server, or anyone on the path who can
answer for it, send the request elsewhere, with its headers. So none is followed; a 3xx answer is
the response, and its caller treats it as the failure it is.

The one exception, an extension download that may move between HTTPS addresses, keeps its own
handler in mcp/extensions.
"""

from __future__ import annotations

import urllib.request
from typing import Any


class NoRedirects(urllib.request.HTTPRedirectHandler):
    """Answers every redirect with no follow-up request, so urllib returns the 3xx as it is."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None

    @staticmethod
    def opener(*handlers: Any) -> urllib.request.OpenerDirector:
        """An opener that follows no redirect, with any other `handlers` it needs."""
        return urllib.request.build_opener(NoRedirects, *handlers)


__all__ = ["NoRedirects"]
