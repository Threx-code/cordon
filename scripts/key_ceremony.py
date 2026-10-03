#!/usr/bin/env python3
"""Generate Cordon's signing keys: the feed's root and online roles, and the advisory-bundle key.

A RELEASE-side script, run once by the maintainer and again only to rotate. Never imported by the
scanner, never run during a scan. Run it on a machine with no network, ideally in a container:

    printf 'FROM python:3.13-slim\\nRUN pip install cryptography\\n' | docker build -t cordon-ceremony -
    docker run --rm --network none -v "$PWD:/src:ro" -v "$HOME/cordon-keys:/out" cordon-ceremony \\
      python /src/scripts/key_ceremony.py --out /out

The image is built with `cryptography` first, so the ceremony itself runs with the network off.
What it writes:

    <out>/private/root-1.seed ... root-N.seed    OFFLINE. Each on separate storage, never online.
    <out>/private/timestamp.seed, snapshot.seed, targets.seed
                                                 ONLINE. The cloud's FEED_*_KEYS secrets.
    <out>/private/advisories.seed                The release workflow's CORDON_DB_SIGNING_KEY.
    <out>/public/feed-root.json                  Commit to src/cordon_scanner/intel/data/.
    <out>/public/advisory-signing-key.json       Commit to src/cordon_scanner/intel/data/.
    <out>/public/fingerprints.txt                What `docs/12-SIGNING-KEYS.md` will publish.

The output directory must not be inside a git working tree: a private seed one `git add -A` away
from a public repository is how signing keys leak. Private files are created mode 0600 and the
seeds are never printed. Every public file is verified against the package's own verifier before
the script reports success, so what is committed is what a client will accept.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROLE_LIFETIME_DAYS = 365


class KeyCeremony:
    """One run of the ceremony: fresh keys, a self-signed root, verified output."""

    ONLINE_ROLES = ("timestamp", "snapshot", "targets")

    def __init__(
        self, out: Path, *, root_keys: int = 3, threshold: int = 2, now: float | None = None
    ) -> None:
        if not 1 <= threshold <= root_keys:
            raise ValueError("the root threshold must be between 1 and the number of root keys")
        self.out = out
        self.root_keys = root_keys
        self.threshold = threshold
        self.now = time.time() if now is None else now

    @staticmethod
    def inside_git_tree(path: Path) -> bool:
        current = path.resolve()
        return any((candidate / ".git").exists() for candidate in (current, *current.parents))

    def _prepare(self) -> tuple[Path, Path]:
        if self.inside_git_tree(self.out):
            raise SystemExit(f"refusing to write keys inside a git working tree: {self.out}")
        private, public = self.out / "private", self.out / "public"
        for directory in (private, public):
            if directory.exists() and any(directory.iterdir()):
                raise SystemExit(f"{directory} is not empty; a ceremony never overwrites keys")
        private.mkdir(parents=True, exist_ok=True)
        public.mkdir(parents=True, exist_ok=True)
        private.chmod(0o700)
        return private, public

    @staticmethod
    def _key() -> tuple[bytes, dict[str, str]]:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private = Ed25519PrivateKey.generate()
        seed = private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return seed, {"keytype": "ed25519", "public": public.hex()}

    @staticmethod
    def _sign(seed: bytes, message: bytes) -> str:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        return Ed25519PrivateKey.from_private_bytes(seed).sign(message).hex()

    @staticmethod
    def _write_private(path: Path, seed: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as handle:
            handle.write(seed.hex() + "\n")

    def run(self) -> dict[str, object]:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
        from cordon_scanner.intel.feed import SPEC, FeedRoles

        private, public = self._prepare()
        keys: dict[str, dict[str, str]] = {}
        roles: dict[str, dict[str, object]] = {}
        root_seeds: list[tuple[str, bytes]] = []
        for index in range(1, self.root_keys + 1):
            seed, key = self._key()
            keyid = FeedRoles.key_id(key)
            keys[keyid] = key
            root_seeds.append((keyid, seed))
            self._write_private(private / f"root-{index}.seed", seed)
        roles["root"] = {"keyids": [k for k, _ in root_seeds], "threshold": self.threshold}
        for role in self.ONLINE_ROLES:
            seed, key = self._key()
            keyid = FeedRoles.key_id(key)
            keys[keyid] = key
            roles[role] = {"keyids": [keyid], "threshold": 1}
            self._write_private(private / f"{role}.seed", seed)

        signed = {
            "_type": "root",
            "spec": SPEC,
            "version": 1,
            "expires": FeedRoles._format_time(self.now + ROLE_LIFETIME_DAYS * 86400),
            "keys": keys,
            "roles": roles,
        }
        message = FeedRoles.canonical(signed)
        # Every root key signs, not just a threshold: the next rotation needs a threshold of THESE
        # keys, and a root signed by all of them proves each was present and working today.
        signatures = [
            {"keyid": keyid, "sig": self._sign(seed, message)} for keyid, seed in root_seeds
        ]
        root_document = {"signed": signed, "signatures": signatures}

        seed, advisory_key = self._key()
        self._write_private(private / "advisories.seed", seed)

        self.verify(root_document, advisory_key, seed)
        (public / "feed-root.json").write_text(
            json.dumps(root_document, indent=2, sort_keys=True) + "\n"
        )
        (public / "advisory-signing-key.json").write_text(
            json.dumps(advisory_key, indent=2, sort_keys=True) + "\n"
        )
        fingerprints = self.fingerprints(root_document, advisory_key)
        (public / "fingerprints.txt").write_text("\n".join(fingerprints) + "\n")
        return {"root": root_document, "advisory_key": advisory_key, "fingerprints": fingerprints}

    @staticmethod
    def verify(
        root_document: dict[str, object], advisory_key: dict[str, str], advisory_seed: bytes
    ) -> None:
        """Check the output with the package's own verify-only code before anything is reported."""
        from cordon_scanner.intel import _ed25519
        from cordon_scanner.intel.feed import FeedRoles

        signed = root_document["signed"]
        if not isinstance(signed, dict):
            raise SystemExit("the root document has no signed part")
        FeedRoles.verify_role(root_document, "root", signed, expected_type="root")
        probe = b"cordon key ceremony self-check"
        signature = bytes.fromhex(KeyCeremony._sign(advisory_seed, probe))
        if not _ed25519.Ed25519.verify(bytes.fromhex(advisory_key["public"]), probe, signature):
            raise SystemExit("the advisory key failed its own verification; nothing is valid")

    @staticmethod
    def fingerprints(root_document: dict[str, object], advisory_key: dict[str, str]) -> list[str]:
        from cordon_scanner.intel.feed import FeedRoles

        signed = root_document["signed"]
        if not isinstance(signed, dict):
            raise SystemExit("the root document has no signed part")
        lines = []
        for role, spec in sorted(signed["roles"].items()):
            for keyid in spec["keyids"]:
                lines.append(f"feed {role:<9} {keyid}")
        lines.append(f"advisories     {FeedRoles.key_id(advisory_key)}")
        return lines


class Main:
    @staticmethod
    def run(argv: list[str] | None = None) -> int:
        parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
        parser.add_argument(
            "--out", required=True, type=Path, help="directory outside any git working tree"
        )
        parser.add_argument("--root-keys", type=int, default=3)
        parser.add_argument("--threshold", type=int, default=2)
        args = parser.parse_args(argv)
        result = KeyCeremony(args.out, root_keys=args.root_keys, threshold=args.threshold).run()
        print("Keys generated and verified. Fingerprints (public; publish these):\n")
        for line in result["fingerprints"]:  # type: ignore[union-attr]
            print(f"  {line}")
        print(
            f"\nNext:\n  1. Move {args.out / 'private'}/root-*.seed to separate offline storage.\n"
            "  2. Set the cloud's FEED_TIMESTAMP_KEYS, FEED_SNAPSHOT_KEYS, FEED_TARGETS_KEYS from the\n"
            "     matching seeds, and the release workflow's CORDON_DB_SIGNING_KEY from advisories.seed.\n"
            f"  3. Copy {args.out / 'public'}/feed-root.json and advisory-signing-key.json to\n"
            "     src/cordon_scanner/intel/data/, then run: python tests/signing_keys.py > docs/12-SIGNING-KEYS.md"
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(Main.run())
