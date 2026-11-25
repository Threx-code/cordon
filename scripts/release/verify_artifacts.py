#!/usr/bin/env python3
"""Verify the shipped artifacts of a release, independently of the scanner (BP-15-14).

Stdlib only and importing nothing from `cordon_scanner`, so a checker that shares no code with the release builds nothing
the release could hide a defect in. For a directory holding the wheels, the sdist and the vsix it checks that:

- `SHA256SUMS` lists every artifact and nothing else, and each digest is that file's;
- each artifact has an in-toto statement (`<artifact>.intoto.json`) whose subject names the artifact with its digest;
- each artifact opens as what its name says (a wheel and a vsix as a zip, the sdist as a gzip tar).

It refuses a modified artifact, a missing or extra one and a statement about different bytes. It does not check the
signature on a statement: that needs the signer's identity and the transparency log, and is done by `gh attestation verify`
or `cosign verify-blob` against the published bundle.

    python3 scripts/release/verify_artifacts.py dist
"""

from __future__ import annotations

import hashlib
import json
import sys
import tarfile
import zipfile
from pathlib import Path


class ArtifactVerifier:
    """`problems(directory)`: why a release directory is not acceptable; empty when it is."""

    KINDS = (".whl", ".tar.gz", ".vsix")
    SUMS = "SHA256SUMS"
    STATEMENT = ".intoto.json"

    @classmethod
    def problems(cls, directory: Path) -> list[str]:
        artifacts = sorted(p for p in directory.iterdir() if p.name.endswith(cls.KINDS))
        if not artifacts:
            return ["no artifact to verify"]
        digests = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts}
        found = cls._sums(directory / cls.SUMS)
        found_problems = [f"{name}: not in {cls.SUMS}" for name in digests if name not in found]
        found_problems += [
            f"{name}: listed in {cls.SUMS} but not shipped" for name in found if name not in digests
        ]
        found_problems += [
            f"{n}: digest differs from {cls.SUMS}"
            for n, d in digests.items()
            if n in found and found[n] != d
        ]
        for path in artifacts:
            found_problems += cls._statement(directory, path.name, digests[path.name])
            found_problems += cls._opens(path)
        return found_problems

    @classmethod
    def _sums(cls, path: Path) -> dict[str, str]:
        if not path.is_file():
            return {}
        out: dict[str, str] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            digest, _, name = line.partition("  ")
            if len(digest) == 64 and name:
                out[name] = digest
        return out

    @classmethod
    def _statement(cls, directory: Path, name: str, digest: str) -> list[str]:
        path = directory / (name + cls.STATEMENT)
        if not path.is_file():
            return [f"{name}: no statement"]
        try:
            statement = json.loads(path.read_text(encoding="utf-8"))
            subjects = statement["subject"]
            matched = any(s["name"] == name and s["digest"]["sha256"] == digest for s in subjects)
        except (ValueError, KeyError, TypeError):
            return [f"{name}: the statement is not an in-toto statement"]
        return [] if matched else [f"{name}: the statement is about different bytes"]

    @classmethod
    def _opens(cls, path: Path) -> list[str]:
        try:
            if path.name.endswith(".tar.gz"):
                with tarfile.open(path, "r:gz") as archive:
                    archive.getmembers()
            else:
                with zipfile.ZipFile(path) as archive:
                    if archive.testzip() is not None:
                        return [f"{path.name}: a member fails its checksum"]
        except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError):
            return [
                f"{path.name}: does not open as {'a gzip tar' if path.name.endswith('.tar.gz') else 'a zip'}"
            ]
        return []


if __name__ == "__main__":
    found = ArtifactVerifier.problems(Path(sys.argv[1] if len(sys.argv) > 1 else "dist"))
    print("\n".join(found) if found else "every artifact verifies")
    sys.exit(1 if found else 0)
