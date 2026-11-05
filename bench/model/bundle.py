#!/usr/bin/env python3
"""Build and sign a model bundle (cordon.model-bundle/v1) for `cordon-model-server`.

The shipped models are the time-split ones: trained only on what was published before the cut-off
and measured on what came after, so the numbers in the manifest describe exactly the artefact that
ships. The thresholds are the joint ones `combine.py` chose on training data alone. The judge model
is `train_text.py`'s, its threshold set on calibrate-half real skills.

The manifest carries every file's SHA-256, the feature layout the models were trained on, the
thresholds and the measured results; `manifest.sig` is a raw Ed25519 signature over its exact
bytes. The server refuses a bundle whose signature, layout or any file digest does not match.

The signing key is a 32-byte Ed25519 seed in `--key` (mode 0600), kept in a Docker volume for
development; a release is signed with the release key, which never enters a bench container.

    docker run --rm --network none -v cordon-model-work:/work -v cordon-model-keys:/keys \\
      -v "$PWD/bench:/bench:ro" -v "$PWD/src:/src:ro" -e PYTHONPATH=/src cordon-model:next \\
      python /bench/model/bundle.py --version 2026.10.12 --out /work/bundle --key /keys/dev.key
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

import joblib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cordon_scanner.model.features import FILE_DENSE, PACKAGE_DENSE, TOKEN_DIM

SCHEMA = "cordon.model-bundle/v1"
TEXT_FILES = (
    "text_idf.npy",
    "text_weights.npy",
    "text_bias.npy",
    "text_category_weights.npy",
    "text_category_bias.npy",
)


class BundleBuilder:
    @staticmethod
    def key(path: Path, generate: bool) -> Ed25519PrivateKey:
        if not path.exists():
            if not generate:
                raise SystemExit(
                    f"no signing key at {path}: pass --generate-dev-key for a development key"
                )
            seed = os.urandom(32)
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(seed)
        seed = path.read_bytes()
        if len(seed) != 32:
            raise SystemExit(f"{path} is not a 32-byte Ed25519 seed")
        return Ed25519PrivateKey.from_private_bytes(seed)

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--work", type=Path, default=Path("/work"))
        parser.add_argument("--split", default="time")
        parser.add_argument("--file-threshold", type=float, required=True)
        parser.add_argument("--version", required=True)
        parser.add_argument("--out", type=Path, required=True)
        parser.add_argument("--key", type=Path, required=True)
        parser.add_argument("--generate-dev-key", action="store_true")
        parser.add_argument(
            "--metrics", type=Path, help="a JSON file of measured results to record"
        )
        args = parser.parse_args()
        meta = joblib.load(args.work / f"model-{args.split}" / "meta.joblib")
        text_meta = json.loads((args.work / "text-model" / "meta.json").read_text(encoding="utf-8"))
        if args.out.exists():
            shutil.rmtree(args.out)
        args.out.mkdir(parents=True)
        shutil.copyfile(args.work / f"model-{args.split}" / "model.txt", args.out / "package.txt")
        shutil.copyfile(args.work / f"files-{args.split}" / "model.txt", args.out / "file.txt")
        for name in TEXT_FILES:
            shutil.copyfile(args.work / "text-model" / name, args.out / name)
        names = ("package.txt", "file.txt", *TEXT_FILES)
        manifest = {
            "schema": SCHEMA,
            "name": "cordon-model",
            "version": args.version,
            "features": {
                "package_dense": list(PACKAGE_DENSE),
                "file_dense": list(FILE_DENSE),
                "token_dim": TOKEN_DIM,
            },
            "columns": [int(c) for c in meta["columns"]],
            "thresholds": {"package": float(meta["threshold"]), "file": args.file_threshold},
            "text": {
                "categories": list(text_meta["categories"]),
                # One threshold for both: no separate suspicious band was calibrated, so none is claimed.
                "thresholds": {
                    "malicious": float(text_meta["threshold"]),
                    "suspicious": float(text_meta["threshold"]),
                },
            },
            "training": {"split": args.split, "fpr_budget": float(meta["fpr"])},
            "metrics": json.loads(args.metrics.read_text(encoding="utf-8")) if args.metrics else {},
            "files": {n: hashlib.sha256((args.out / n).read_bytes()).hexdigest() for n in names},
        }
        raw = json.dumps(manifest, indent=1, sort_keys=True).encode()
        key = BundleBuilder.key(args.key, args.generate_dev_key)
        (args.out / "manifest.json").write_bytes(raw)
        (args.out / "manifest.sig").write_bytes(key.sign(raw))
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        (args.out / "model.pub").write_bytes(public)
        print(f"{args.out}: {len(names)} files, manifest sha256 {hashlib.sha256(raw).hexdigest()}")
        print(f"public key (raw, hex): {public.hex()}")
        return 0


if __name__ == "__main__":
    sys.exit(BundleBuilder.main())
