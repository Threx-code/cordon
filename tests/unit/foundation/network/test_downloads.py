"""A response body is read within a budget for the whole body, not one read at a time.

Against a real local server: a socket timeout bounds each read, and a server that sends a byte now
and then never trips it, so `response.read` of a 200-byte body sent a byte every 0.1 s took 20 s
under a 3 s timeout.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import time
import urllib.request

import pytest

from cordon_scanner.foundation.network.downloads import Download


class Server:
    """A local HTTP server sending `size` bytes, one every `gap` seconds, or all at once."""

    def __init__(self, size: int, gap: float = 0.0) -> None:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.send_header("Content-Length", str(size))
                self.end_headers()
                if not gap:
                    self.wfile.write(b"x" * size)
                    return
                for _ in range(size):
                    try:
                        self.wfile.write(b"x")
                        self.wfile.flush()
                    except OSError:
                        return
                    time.sleep(gap)

            def log_message(self, *args: object) -> None:
                pass

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class TestDownload:
    @staticmethod
    def local(url: str, timeout: float):
        """Open a URL on the test's own local server."""
        return urllib.request.urlopen(url, timeout=timeout)  # noqa: S310 - http://127.0.0.1 only

    @pytest.fixture
    def serve(self):
        servers: list[Server] = []

        def start(size: int, gap: float = 0.0) -> str:
            servers.append(Server(size, gap))
            return servers[-1].url

        yield start
        for server in servers:
            server.close()

    def test_a_trickled_body_ends_at_its_budget(self, serve) -> None:
        url = serve(200, gap=0.1)
        started = time.monotonic()
        with self.local(url, timeout=3) as response, pytest.raises(TimeoutError):
            Download.read(response, 1 << 20, budget=1.0)
        assert time.monotonic() - started < 5, "the budget bounds the whole body, not each read"

    def test_a_whole_body_is_read(self, serve) -> None:
        with self.local(serve(300_000), timeout=3) as response:
            assert Download.read(response, 1 << 20) == b"x" * 300_000

    def test_a_body_past_its_limit_is_cut_at_the_limit(self, serve) -> None:
        """So a caller asking for `limit + 1` can tell an oversized body."""
        with self.local(serve(300_000), timeout=3) as response:
            assert len(Download.read(response, 100_001)) == 100_001

    def test_chunks_stream_the_body_within_the_budget(self, serve) -> None:
        with self.local(serve(200_000), timeout=3) as response:
            assert sum(len(c) for c in Download.chunks(response, size=16_384)) == 200_000
        with self.local(serve(200, gap=0.1), timeout=3) as response, pytest.raises(TimeoutError):
            for _ in Download.chunks(response, budget=1.0):
                pass

    def test_the_timeout_is_an_os_error_so_callers_treat_it_as_unreachable(self) -> None:
        assert issubclass(TimeoutError, OSError)
