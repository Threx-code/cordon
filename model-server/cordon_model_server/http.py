"""The model server's HTTP interface.

    GET  /healthz            liveness: 200 when a bundle is loaded; no authentication, no details
    GET  /v1/model           the model's identity and published measurements
    POST /v1/model/score     cordon.model/v1: score packages' features

Authentication is a bearer token, checked against SHA-256 hashes the operator lists (the server
never holds the tokens themselves), compared in constant time. TLS is served directly
(--tls-cert/--tls-key) or by a proxy in front; plain HTTP is refused on any address but loopback
unless the operator says a TLS proxy terminates in front (--behind-tls-proxy). Bodies are capped,
requests run under a concurrency bound and socket timeouts, and the access log records method,
path, status, size and time -- never a body, a header value or a token.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar, Final

from cordon_model_server.judge import Judge
from cordon_model_server.scoring import RequestError, Scorer
from cordon_model_server.text import TextModel

MAX_BODY: Final = 16 << 20
SOCKET_TIMEOUT: Final = 30


class Service:
    """Shared state for request handlers."""

    def __init__(self, scorer: Scorer, token_hashes: frozenset[str], concurrency: int) -> None:
        self.scorer = scorer
        self.token_hashes = token_hashes
        self.slots = threading.BoundedSemaphore(concurrency)
        text = scorer.bundle.text
        self.judge = (
            Judge(
                TextModel.load(scorer.bundle.root, text["categories"]),
                text["malicious"],
                text["suspicious"],
            )
            if text
            else None
        )

    def authorised(self, header: str | None) -> bool:
        if not header or not header.startswith("Bearer "):
            return False
        offered = hashlib.sha256(header[7:].strip().encode()).hexdigest()
        # Every stored hash is compared, so the time taken says nothing about which one matched.
        matched = False
        for stored in self.token_hashes:
            matched |= hmac.compare_digest(offered, stored)
        return matched


class Handler(BaseHTTPRequestHandler):
    service: ClassVar[Service]
    server_version = "cordon-model-server"
    sys_version = ""
    timeout = SOCKET_TIMEOUT

    def setup(self) -> None:
        # The TLS handshake runs here, in this connection's thread and under its timeout -- never
        # in the accept loop, where one client that never finishes it would stall every other.
        self.request.settimeout(SOCKET_TIMEOUT)
        if isinstance(self.request, ssl.SSLSocket):
            self.request.do_handshake()
        super().setup()

    def log_message(self, format: str, *args: Any) -> None:
        """Access log: no bodies, headers or tokens."""

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)
        print(
            json.dumps(
                {
                    "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "method": self.command,
                    "path": self.path.split("?", 1)[0][:100],
                    "status": status,
                    "bytes": len(body),
                }
            ),
            file=sys.stderr,
            flush=True,
        )

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._send(200, {"status": "ok"})
        elif path == "/v1/model":
            if not self.service.authorised(self.headers.get("Authorization")):
                self._send(401, {"error": "a valid bearer token is required"})
                return
            self._send(200, self.service.scorer.bundle.describe())
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        route = self.path.split("?", 1)[0]
        if route not in ("/v1/model/score", "/v1/judge") or (
            route == "/v1/judge" and self.service.judge is None
        ):
            self._send(404, {"error": "not found"})
            return
        if not self.service.authorised(self.headers.get("Authorization")):
            self._send(401, {"error": "a valid bearer token is required"})
            return
        if (self.headers.get("Content-Type") or "").split(";", 1)[0].strip() != "application/json":
            self._send(415, {"error": "Content-Type must be application/json"})
            return
        try:
            length = int(self.headers.get("Content-Length") or "-1")
        except ValueError:
            length = -1
        if not 0 < length <= MAX_BODY:
            self._send(
                413 if length > MAX_BODY else 411,
                {"error": f"a JSON body of at most {MAX_BODY} bytes is required"},
            )
            return
        if not self.service.slots.acquire(timeout=5):
            self._send(503, {"error": "busy: retry shortly"})
            return
        try:
            body = json.loads(self.rfile.read(length))
            if route == "/v1/judge":
                assert self.service.judge is not None  # noqa: S101 - checked with the route
                _, text = Judge.parse(body)
                with self.service.scorer.lock:
                    verdict = self.service.judge.verdict(text)
                self._send(200, {"verdict": verdict})
                return
            packages = Scorer.parse(body)
            results = self.service.scorer.score(packages)
        except (ValueError, RecursionError) as exc:
            message = str(exc) if isinstance(exc, RequestError) else "the body is not valid JSON"
            self._send(400, {"error": message})
            return
        finally:
            self.service.slots.release()
        self._send(
            200,
            {
                "schema": "cordon.model/v1",
                "model": {
                    "name": self.service.scorer.bundle.name,
                    "version": self.service.scorer.bundle.version,
                },
                "results": results,
            },
        )


class BoundedServer(ThreadingHTTPServer):
    """At most `connections` connections at once; one past that is closed at once, so slow
    clients cannot exhaust the server's threads."""

    daemon_threads = True
    connections = 128

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.open_slots = threading.BoundedSemaphore(self.connections)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self.open_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.open_slots.release()

    def handle_error(self, request: Any, client_address: Any) -> None:
        """A client that times out or breaks the handshake is not an error worth a traceback."""


class HttpServer:
    @staticmethod
    def loopback(host: str) -> bool:
        if host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    @staticmethod
    def build(
        service: Service,
        host: str,
        port: int,
        *,
        tls_cert: str | None,
        tls_key: str | None,
        behind_tls_proxy: bool,
    ) -> BoundedServer:
        if not (tls_cert and tls_key) and not behind_tls_proxy and not HttpServer.loopback(host):
            raise ValueError(
                f"refusing plain HTTP on {host}: give --tls-cert and --tls-key, or --behind-tls-proxy "
                "when a TLS-terminating proxy is in front"
            )
        if not service.token_hashes:
            raise ValueError("no token hashes: every request would be refused (--tokens-file)")
        handler = type("BoundHandler", (Handler,), {"service": service})
        server = BoundedServer((host, port), handler)
        if tls_cert and tls_key:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(tls_cert, tls_key)
            server.socket = context.wrap_socket(
                server.socket, server_side=True, do_handshake_on_connect=False
            )
        return server
