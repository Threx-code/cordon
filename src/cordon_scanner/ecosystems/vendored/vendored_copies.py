"""A copy of a package bundled inside another package, told apart from the original by its bytes.

A directory of the scanned tree that holds a `package.json` naming a package and a version (and is not an install under
`node_modules`) is a vendored copy of that package. Its digest is the sha256 over its files, each entered by the length and
the text of its path from the directory and the sha256 of its bytes, in path order, so no file name can pass for another
entry. The caller says what digest the original has for a package url: equal is `identical` (the copy is an occurrence of
the original), different is `modified` (the copy derives from it), and a package url the caller has no digest for is
`unknown`, never taken as identical. A copy some of whose files were not read is `partial` and is never compared.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar


@dataclass(frozen=True, slots=True)
class VendoredCopy:
    """One vendored copy: where it sits, which package it claims to be, its digest and how that compares with the original."""

    path: str
    purl: str
    digest: str
    state: str

    def to_dict(self) -> dict[str, Any]:
        """What the upload carries: the place, the package url and the digest, and `partial` when the digest covers part of the copy."""
        document: dict[str, Any] = {"path": self.path, "purl": self.purl, "digest": self.digest}
        if self.state == "partial":
            document["partial"] = True
        return document


class VendoredCopies:
    """Finds the vendored copies in a scan's tree."""

    STATES: ClassVar[tuple[str, ...]] = ("identical", "modified", "unknown", "partial")
    MAX_FILES: ClassVar[int] = 5000
    MAX_BYTES: ClassVar[int] = 2 << 20
    MAX_NAME: ClassVar[int] = 214
    MAX_VERSION: ClassVar[int] = 64

    @classmethod
    def of(
        cls,
        files: Mapping[str, bytes],
        known: Mapping[str, str] | None = None,
        partial: frozenset[str] = frozenset(),
    ) -> tuple[VendoredCopy, ...]:
        """The copies of the tree `files` (path to bytes), nearest the root first, each compared with `known` (purl to digest)."""
        shas = {path: hashlib.sha256(data).hexdigest() for path, data in files.items()}
        manifests = {
            path.rpartition("/")[0]: data
            for path, data in files.items()
            if path.rpartition("/")[2] == "package.json"
        }
        return cls._copies(shas, manifests, known or {}, partial)

    @classmethod
    def of_directory(
        cls, root: Path, known: Mapping[str, str] | None = None
    ) -> tuple[VendoredCopy, ...]:
        """The copies in a directory tree: each file under a vendored package read once and kept as its digest, bounded in count and size."""
        candidates: list[str] = []
        for here, dirs, names in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in ("node_modules", ".git"))
            if "package.json" in names and Path(here) != root:
                candidates.append(Path(here).relative_to(root).as_posix())
        shas: dict[str, str] = {}
        manifests: dict[str, bytes] = {}
        unread: set[str] = set()
        for base in candidates:
            manifest = root / base / "package.json"
            if not manifest.is_symlink() and manifest.stat().st_size <= cls.MAX_BYTES:
                data = manifest.read_bytes()
                manifests[base] = data
                shas[f"{base}/package.json"] = hashlib.sha256(data).hexdigest()
        for base in candidates:
            for here, dirs, names in os.walk(root / base):
                dirs[:] = sorted(d for d in dirs if d != "node_modules")
                for name in sorted(names):
                    path = Path(here, name)
                    key = path.relative_to(root).as_posix()
                    if key in shas:
                        continue
                    if (
                        len(shas) >= cls.MAX_FILES
                        or path.is_symlink()
                        or path.stat().st_size > cls.MAX_BYTES
                    ):
                        unread.add(key)
                        continue
                    shas[key] = hashlib.sha256(path.read_bytes()).hexdigest()
        partial = cls._owners(unread, set(manifests))
        return cls._copies(shas, manifests, known or {}, partial)

    @classmethod
    def _copies(
        cls,
        shas: Mapping[str, str],
        manifests: Mapping[str, bytes],
        known: Mapping[str, str],
        partial: frozenset[str],
    ) -> tuple[VendoredCopy, ...]:
        """Each manifest that names a package, with the digest of the files under its directory (every file indexed once)."""
        named = {
            root: purl
            for root, data in manifests.items()
            if cls._vendored(root) and (purl := cls._purl(data)) is not None
        }
        entries: dict[str, list[bytes]] = {root: [] for root in named}
        for path in sorted(shas):
            for root in cls._directories(path):
                if root in entries:
                    relative = path[len(root) + 1 :].encode()
                    entries[root].append(
                        f"{len(relative)}:".encode() + relative + b":" + shas[path].encode()
                    )
        found = []
        for root, purl in named.items():
            digest = "sha256:" + hashlib.sha256(b"\n".join(entries[root])).hexdigest()
            original = known.get(purl)
            state = (
                "partial"
                if root in partial
                else "unknown"
                if original is None
                else "identical"
                if original == digest
                else "modified"
            )
            found.append(VendoredCopy(root, purl, digest, state))
        return tuple(sorted(found, key=lambda copy: (copy.path.count("/"), copy.path)))

    @staticmethod
    def _directories(path: str) -> list[str]:
        """Every directory a path sits in, from its own up to the first level."""
        parts = path.split("/")[:-1]
        return ["/".join(parts[: i + 1]) for i in range(len(parts))]

    @classmethod
    def _owners(cls, keys: set[str], roots: set[str]) -> frozenset[str]:
        return frozenset(root for key in keys for root in cls._directories(key) if root in roots)

    @classmethod
    def tree_digest(cls, files: Mapping[str, bytes]) -> str:
        """The digest of a package's own files, keyed by their path from the package root: equal to `digest` of a copy of the same
        files at any depth, so a vendored copy of a release is told identical to the release."""
        return cls.digest({f"root/{path}": data for path, data in files.items()}, "root")

    @classmethod
    def digest(cls, files: Mapping[str, bytes], root: str) -> str:
        """The digest of the files under `root`, as `of` computes it."""
        shas = {path: hashlib.sha256(data).hexdigest() for path, data in files.items()}
        relative = [
            (path[len(root) + 1 :].encode(), sha)
            for path, sha in sorted(shas.items())
            if path.startswith(root + "/")
        ]
        lines = [f"{len(name)}:".encode() + name + b":" + sha.encode() for name, sha in relative]
        return "sha256:" + hashlib.sha256(b"\n".join(lines)).hexdigest()

    @staticmethod
    def _vendored(root: str) -> bool:
        """A directory below the root of the tree that is not an install."""
        return bool(root) and "node_modules" not in root.split("/")

    @classmethod
    def _purl(cls, data: bytes) -> str | None:
        try:
            manifest = json.loads(data)
        except ValueError:
            return None  # S2: a manifest that is not JSON names no package
        name = manifest.get("name") if isinstance(manifest, dict) else None
        version = manifest.get("version") if isinstance(manifest, dict) else None
        if not isinstance(name, str) or not isinstance(version, str):
            return None
        if not name or not version or len(name) > cls.MAX_NAME or len(version) > cls.MAX_VERSION:
            return None
        return f"pkg:npm/{urllib.parse.quote(name, safe='')}@{urllib.parse.quote(version, safe='')}"
