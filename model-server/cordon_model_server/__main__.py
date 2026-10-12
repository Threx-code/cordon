"""`cordon-model-server`: serve a signed Cordon model bundle.

    cordon-model-server serve --bundle DIR --public-key KEY.pub --tokens-file HASHES \\
        [--host 0.0.0.0 --port 8443 --tls-cert C --tls-key K | --behind-tls-proxy] [--concurrency 4]
    cordon-model-server hash-token          reads a token on stdin, prints the hash to list

The public key is the raw 32-byte Ed25519 key (or its 64-character hex) the bundle was signed with;
a bundle that does not verify is never served. The tokens file lists SHA-256 hex hashes, one per
line; the tokens themselves stay with the clients.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from cordon_model_server.bundle import Bundle, BundleError
from cordon_model_server.http import HttpServer, Service
from cordon_model_server.scoring import Scorer


class Main:
    @staticmethod
    def public_key(path: Path) -> bytes:
        raw = path.read_bytes().strip()
        if len(raw) == 64:
            try:
                return bytes.fromhex(raw.decode())
            except ValueError:
                pass
        return raw

    @staticmethod
    def hashes(path: Path) -> frozenset[str]:
        lines = [x.strip().lower() for x in path.read_text(encoding="utf-8").splitlines()]
        hashes = frozenset(x for x in lines if x and not x.startswith("#"))
        for value in hashes:
            if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("the tokens file must list SHA-256 hex hashes, one per line")
        return hashes

    @staticmethod
    def run(argv: list[str] | None = None) -> int:
        parser = argparse.ArgumentParser(
            prog="cordon-model-server", description=__doc__.split("\n", 1)[0]
        )
        sub = parser.add_subparsers(dest="command", required=True)
        serve = sub.add_parser("serve")
        serve.add_argument("--bundle", type=Path, required=True)
        serve.add_argument("--public-key", type=Path, required=True)
        serve.add_argument("--tokens-file", type=Path, required=True)
        serve.add_argument("--host", default="127.0.0.1")
        serve.add_argument("--port", type=int, default=8443)
        serve.add_argument("--tls-cert")
        serve.add_argument("--tls-key")
        serve.add_argument("--behind-tls-proxy", action="store_true")
        serve.add_argument(
            "--plaintext-internal",
            action="store_true",
            help="accept plain HTTP: only on a private container network no client outside the deployment "
            "reaches (Cordon Cloud's API calling its own model service). Tokens are still required",
        )
        serve.add_argument("--concurrency", type=int, default=4)
        sub.add_parser("hash-token")
        args = parser.parse_args(argv)
        if args.command == "hash-token":
            token = sys.stdin.readline().strip()
            if len(token) < 32:
                print("a token must be at least 32 characters of randomness", file=sys.stderr)
                return 3
            print(hashlib.sha256(token.encode()).hexdigest())
            return 0
        try:
            bundle = Bundle.load(args.bundle, Main.public_key(args.public_key))
            service = Service(
                Scorer(bundle), Main.hashes(args.tokens_file), max(1, min(args.concurrency, 64))
            )
            server = HttpServer.build(
                service,
                args.host,
                args.port,
                tls_cert=args.tls_cert,
                tls_key=args.tls_key,
                behind_tls_proxy=args.behind_tls_proxy,
                plaintext_internal=args.plaintext_internal,
            )
        except (BundleError, OSError, ValueError) as exc:
            print(f"cordon-model-server: {exc}", file=sys.stderr)
            return 3
        print(
            f"cordon-model-server: serving {bundle.name} {bundle.version} on {args.host}:{args.port}",
            file=sys.stderr,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0


if __name__ == "__main__":
    sys.exit(Main.run())
