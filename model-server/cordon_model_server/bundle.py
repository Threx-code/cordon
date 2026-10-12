"""A model bundle: the trained models, their thresholds and the evidence for them, signed.

    manifest.json   name, version, the feature layout it was trained on, thresholds, the
                    held-out measurements, and the SHA-256 of every model file
    manifest.sig    Ed25519 signature over manifest.json's exact bytes
    package.txt     LightGBM model over package features (dense + selected token columns)
    file.txt        LightGBM model over per-file features (optional)

A server loads a bundle only when the signature verifies against a public key the operator pinned
and every file matches its digest, and only when the bundle's feature layout is the one this
installation's extractor produces: a model scoring features computed differently from the ones it
was trained on would answer confidently and wrongly.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from cordon_scanner.intel._ed25519 import Ed25519
from cordon_scanner.model.features import FILE_DENSE, PACKAGE_DENSE, TOKEN_DIM

SCHEMA: Final = "cordon.model-bundle/v1"
MAX_MANIFEST: Final = 4 << 20


class BundleError(Exception):
    """A bundle that must not be served, with the reason."""


@dataclass(frozen=True, slots=True)
class Bundle:
    name: str
    version: str
    root: Path
    manifest: dict[str, Any]
    columns: tuple[int, ...]
    """Indices into [dense features..., token buckets...] the package model reads, in order."""
    package_threshold: float
    file_threshold: float | None

    @staticmethod
    def load(root: Path, public_key: bytes) -> Bundle:
        manifest_path, signature_path = root / "manifest.json", root / "manifest.sig"
        try:
            raw = manifest_path.read_bytes()
            signature = signature_path.read_bytes()
        except OSError as exc:
            raise BundleError(f"cannot read the bundle: {exc}") from exc
        if len(raw) > MAX_MANIFEST:
            raise BundleError("manifest.json is larger than 4 MB")
        if len(public_key) != 32 or len(signature) != 64:
            raise BundleError("the public key must be 32 bytes and the signature 64 (raw Ed25519)")
        if not Ed25519.verify(public_key, raw, signature):
            raise BundleError("manifest.sig does not verify against the pinned public key: refused")
        try:
            manifest = json.loads(raw)
        except ValueError as exc:
            raise BundleError("manifest.json is not JSON") from exc
        if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
            raise BundleError(f"not a {SCHEMA} manifest")
        features = manifest.get("features") or {}
        if (
            features.get("package_dense") != list(PACKAGE_DENSE)
            or features.get("file_dense") != list(FILE_DENSE)
            or features.get("token_dim") != TOKEN_DIM
        ):
            raise BundleError(
                "the bundle was trained on a feature layout this installation does not produce: "
                "install the cordon-scanner version the bundle names"
            )
        files = manifest.get("files") or {}
        if "package.txt" not in files:
            raise BundleError("the bundle has no package model")
        for name, digest in files.items():
            if name not in ("package.txt", "file.txt") or not isinstance(digest, str):
                raise BundleError(f"unexpected file entry {name!r}")
            try:
                actual = hashlib.sha256((root / name).read_bytes()).hexdigest()
            except OSError as exc:
                raise BundleError(f"cannot read {name}: {exc}") from exc
            if actual != digest:
                raise BundleError(
                    f"{name} does not match its digest in the signed manifest: refused"
                )
        columns = manifest.get("columns")
        width = len(PACKAGE_DENSE) + TOKEN_DIM
        if not isinstance(columns, list) or not all(
            isinstance(c, int) and 0 <= c < width for c in columns
        ):
            raise BundleError("columns must be indices into the package feature vector")
        thresholds = manifest.get("thresholds") or {}
        package_threshold = thresholds.get("package")
        file_threshold = thresholds.get("file") if "file.txt" in files else None
        if not isinstance(package_threshold, int | float) or (
            file_threshold is not None and not isinstance(file_threshold, int | float)
        ):
            raise BundleError("thresholds must be numbers")
        return Bundle(
            name=str(manifest.get("name") or "cordon-model"),
            version=str(manifest.get("version") or "0"),
            root=root,
            manifest=manifest,
            columns=tuple(columns),
            package_threshold=float(package_threshold),
            file_threshold=None if file_threshold is None else float(file_threshold),
        )

    def describe(self) -> dict[str, Any]:
        """What a client may know about the model: identity and its published measurements."""
        return {
            "name": self.name,
            "version": self.version,
            "created": self.manifest.get("created"),
            "trained_on": self.manifest.get("trained_on"),
            "measured": self.manifest.get("measured"),
            "thresholds": {"package": self.package_threshold, "file": self.file_threshold},
        }
