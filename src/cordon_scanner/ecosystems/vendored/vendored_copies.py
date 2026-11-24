"""A copy of a package bundled inside another package, told apart from the original by its bytes.

A directory of the scanned tree that holds a `package.json` naming a package and a version (and is not an install under
`node_modules`) is a vendored copy of that package. Its digest is the sha256 over its files, each taken by its path from the
directory and the sha256 of its bytes, in path order. The caller says what digest the original has for a package url:
equal is `identical` (the copy is an occurrence of the original), different is `modified` (the copy derives from it), and a
package url the caller has no digest for is `unknown`, never taken as identical.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar


@dataclass(frozen=True, slots=True)
class VendoredCopy:
    """One vendored copy: where it sits, which package it claims to be, its digest and how that compares with the original."""

    path: str
    purl: str
    digest: str
    state: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "purl": self.purl, "digest": self.digest, "state": self.state}


class VendoredCopies:
    """Finds the vendored copies in the files of a scan."""

    STATES: ClassVar[tuple[str, ...]] = ("identical", "modified", "unknown")

    @classmethod
    def of(
        cls, files: Mapping[str, bytes], known: Mapping[str, str] | None = None
    ) -> tuple[VendoredCopy, ...]:
        """The copies of the tree `files` (path to bytes), nearest the root first, each compared with `known` (purl to digest)."""
        wanted = known or {}
        found: list[VendoredCopy] = []
        for path in sorted(files):
            root, _, leaf = path.rpartition("/")
            purl = (
                cls._purl(files[path]) if leaf == "package.json" and cls._vendored(root) else None
            )
            if purl is None:
                continue
            digest = cls.digest(files, root)
            original = wanted.get(purl)
            state = (
                "unknown" if original is None else "identical" if original == digest else "modified"
            )
            found.append(VendoredCopy(root, purl, digest, state))
        return tuple(sorted(found, key=lambda copy: (copy.path.count("/"), copy.path)))

    @classmethod
    def of_directory(
        cls, root: Path, known: Mapping[str, str] | None = None
    ) -> tuple[VendoredCopy, ...]:
        """The copies in a directory tree, reading only what they need: the files under each vendored package, bounded in count and size."""
        candidates: list[str] = []
        for here, dirs, names in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in ("node_modules", ".git"))
            if "package.json" in names and Path(here) != root:
                candidates.append(Path(here).relative_to(root).as_posix())
        files: dict[str, bytes] = {}
        for base in candidates:
            for here, dirs, names in os.walk(root / base):
                dirs[:] = sorted(d for d in dirs if d != "node_modules")
                for name in sorted(names):
                    path = Path(here, name)
                    key = path.relative_to(root).as_posix()
                    if len(files) >= cls.MAX_FILES or path.is_symlink() or key in files:
                        continue
                    if path.stat().st_size <= cls.MAX_BYTES:
                        files[key] = path.read_bytes()
        return cls.of(files, known)

    MAX_FILES: ClassVar[int] = 5000
    MAX_BYTES: ClassVar[int] = 2 << 20

    @staticmethod
    def digest(files: Mapping[str, bytes], root: str) -> str:
        """The digest of the files under `root`: path from `root` and content digest, in path order."""
        lines = [
            f"{path[len(root) + 1 :]}\0{hashlib.sha256(data).hexdigest()}"
            for path, data in sorted(files.items())
            if path.startswith(root + "/")
        ]
        return "sha256:" + hashlib.sha256("\n".join(lines).encode()).hexdigest()

    @staticmethod
    def _vendored(root: str) -> bool:
        """A directory below the root of the tree that is not an install."""
        return bool(root) and "node_modules" not in root.split("/")

    @staticmethod
    def _purl(data: bytes) -> str | None:
        try:
            manifest = json.loads(data)
        except ValueError:
            return None  # S2: a manifest that is not JSON names no package
        name = manifest.get("name") if isinstance(manifest, dict) else None
        version = manifest.get("version") if isinstance(manifest, dict) else None
        if not isinstance(name, str) or not isinstance(version, str) or not name or not version:
            return None
        return f"pkg:npm/{urllib.parse.quote(name, safe='')}@{version}"
