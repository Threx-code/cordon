"""A 4xx or 5xx is raised with its response already closed, however the caller catches it.

Python 3.14's CI job failed on "Implicitly cleaning up <HTTPError 404>": an `HTTPError` is the
server's open response, and a caller that caught it as `URLError` or `OSError` (or not at all) held
the socket until the collector ran. `ClosedErrors`, the error handler `NoRedirects` carries, closes
it where it is raised (4 Nov).
"""

from __future__ import annotations

import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from cordon_scanner.foundation.network.redirects import ClosedErrors, NoRedirects


class MissingKit:
    """A loopback server that answers every request 404, with headers and a body."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = b"not here"
            self.send_response(404)
            self.send_header("X-Reason", "gone")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: Any) -> None:
            return None

    def __init__(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), MissingKit.Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/x"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def error(self, opener: urllib.request.OpenerDirector) -> urllib.error.HTTPError:
        try:
            opener.open(self.url, timeout=10)
        except OSError as exc:  # caught as broadly as the callers that leaked did
            assert isinstance(exc, urllib.error.HTTPError)
            return exc
        raise AssertionError("a 404 did not raise")

    @staticmethod
    def is_closed(error: urllib.error.HTTPError) -> bool:
        return error.fp is None or bool(getattr(error.fp, "closed", False))


class TestClosedErrors:
    @pytest.fixture
    def missing(self):
        kit = MissingKit()
        yield kit
        kit.close()

    def test_an_opener_without_it_leaves_the_error_open(self, missing: MissingKit) -> None:
        error = missing.error(urllib.request.build_opener())
        try:
            assert not MissingKit.is_closed(error)
        finally:
            error.close()

    def test_no_redirects_raises_it_closed(self, missing: MissingKit) -> None:
        error = missing.error(urllib.request.build_opener(NoRedirects))
        assert MissingKit.is_closed(error)

    def test_it_closes_beside_another_redirect_handler(self, missing: MissingKit) -> None:
        error = missing.error(
            urllib.request.build_opener(urllib.request.HTTPRedirectHandler, ClosedErrors)
        )
        assert MissingKit.is_closed(error)

    def test_the_code_and_headers_stay_readable(self, missing: MissingKit) -> None:
        error = missing.error(urllib.request.build_opener(NoRedirects))
        assert error.code == 404
        assert error.headers["X-Reason"] == "gone"
        assert error.url.endswith("/x")
