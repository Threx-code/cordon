#!/usr/bin/env python3
"""Build and sign the advisory bundle for a release.

A RELEASE-side maintenance script, never imported by the scanner and never run
during a scan. It is the counterpart to `intel/dbsync.py`, which verifies and
installs what this produces.

Signing uses `cryptography` -- an audited library the release environment
installs -- rather than the vendored verifier in the package: the scanner ships
only the ability to *check* a signature (`intel/_ed25519`, verify-only), and the
private key never comes near it. The signature is the raw 64-byte Ed25519 form
that `_ed25519.verify` expects.

The private key is read from `CORDON_DB_SIGNING_KEY` -- a 32-byte Ed25519 seed,
hex or base64, from the release workflow's secrets. It is never written to disk
and never printed.

    CORDON_DB_SIGNING_KEY=<hex-or-base64 seed> \\
        python3 scripts/sign_advisory_bundle.py --data-dir src/cordon_scanner/intel/data --out dist

Produces `dist/cordon-advisories.tar.gz` and `dist/cordon-advisories.tar.gz.sig`.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cordon_scanner.intel.dbsync import BUNDLE_NAME, SIGNATURE_NAME, build_bundle  # noqa: E402


def _load_seed() -> bytes:
    raw = os.environ.get("CORDON_DB_SIGNING_KEY", "").strip()
    if not raw:
        print("CORDON_DB_SIGNING_KEY is not set", file=sys.stderr)
        raise SystemExit(2)
    for decode in (bytes.fromhex, base64.b64decode):
        try:
            seed = decode(raw)
        except ValueError:
            continue
        if len(seed) == 32:
            return seed
    print("CORDON_DB_SIGNING_KEY must be a 32-byte Ed25519 seed (hex or base64)", file=sys.stderr)
    raise SystemExit(2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--print-public-key",
        action="store_true",
        help="also print the hex public key, so the maintainer can pin it in dbsync.PUBLIC_KEY_HEX",
    )
    args = parser.parse_args()

    # Imported here, not at module scope: this is the one release-only third-party
    # dependency, and it must not be a requirement of the repository's own tests.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = _load_seed()
    key = Ed25519PrivateKey.from_private_bytes(seed)

    archive = build_bundle(args.data_dir)
    signature = key.sign(archive)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / BUNDLE_NAME).write_bytes(archive)
    (args.out / SIGNATURE_NAME).write_bytes(signature)
    print(f"wrote {args.out / BUNDLE_NAME} ({len(archive):,} bytes) and its signature")

    if args.print_public_key:
        from cryptography.hazmat.primitives import serialization

        public_raw = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        print(f"public key (pin in dbsync.PUBLIC_KEY_HEX): {public_raw.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
