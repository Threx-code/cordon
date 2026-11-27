"""An installed editor extension against the package Open VSX signed for the same release.

An extension folder holds the files of its `.vsix`: everything under the package's `extension/` directory sits at the folder's
root, and `extension.vsixmanifest` is the folder's `.vsixmanifest`. For an editor whose extensions come from Open VSX, each
installed release is looked up there (online: the extension's id and version are asked of a public registry, so this is opt-in
and never part of an offline inventory) and its files are compared by SHA-256 with the signed package's.

Only a file that is in the signed package and differs is reported. A folder holds more than the package did (a runtime download,
a cache, a language server fetched on first use), so a file the package never had is not evidence of change; a modified file
the package did have is. Editors that install from Microsoft's Marketplace are not asked: its packages are signed by Microsoft
and are not guaranteed byte-identical to Open VSX's."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import Any, ClassVar

from cordon_scanner.foundation.evidence_key import EvidenceKey


class InstalledExtensions:
    #: The editors that install from Open VSX.
    OPEN_VSX_EDITORS: ClassVar[frozenset[str]] = frozenset(
        {"vscodium", "cursor", "windsurf", "cursor-server", "windsurf-server"}
    )
    MAX_FILES: ClassVar[int] = 20_000
    MAX_BYTES: ClassVar[int] = 512 << 20
    PACKAGE_ROOT: ClassVar[str] = "extension/"
    MANIFEST: ClassVar[tuple[str, str]] = (".vsixmanifest", "extension.vsixmanifest")

    @classmethod
    def members(cls, folder: Path) -> dict[str, str] | None:
        """The folder's files by the name they have in the package, with SHA-256s; None when the folder is too large to hash."""
        found: dict[str, str] = {}
        total = 0
        stack = [folder]
        while stack:
            directory = stack.pop()
            try:
                entries = sorted(directory.iterdir())
            except OSError:
                continue
            for entry in entries:
                if entry.is_symlink():
                    continue
                if entry.is_dir():
                    stack.append(entry)
                    continue
                if not entry.is_file():
                    continue
                total += entry.stat().st_size
                if len(found) >= cls.MAX_FILES or total > cls.MAX_BYTES:
                    return None
                relative = entry.relative_to(folder).as_posix()
                name = (
                    cls.MANIFEST[1]
                    if relative == cls.MANIFEST[0]
                    else f"{cls.PACKAGE_ROOT}{relative}"
                )
                try:
                    found[name] = hashlib.sha256(entry.read_bytes()).hexdigest()
                except OSError:
                    continue
        return found

    @classmethod
    def findings(cls, installed: list[tuple[dict[str, str], Path]]) -> list[dict[str, Any]]:
        """One finding for each installed extension whose files differ from the package Open VSX signed for its release."""
        from cordon_scanner.foundation.dependencies import PROVENANCE_INVALID_RULE
        from cordon_scanner.intel.registry import OpenVsxSignature

        out: list[dict[str, Any]] = []
        for entry, folder in installed:
            editor, identifier, version = entry["editor"], entry["id"], entry["version"]
            if editor not in cls.OPEN_VSX_EDITORS or not version:
                continue
            files = cls.members(folder)
            if files is None:
                continue
            found = OpenVsxSignature.compare(identifier, version, files, added=False)
            if found.outcome != "invalid":
                continue
            where = f"{editor}:{identifier}@{version}"
            out.append(
                {
                    "rule_id": PROVENANCE_INVALID_RULE,
                    "severity": "critical",
                    "category": "vulnerable",
                    "path": f"extensions/{where}",
                    "line": None,
                    "message": (
                        f"{editor} has {identifier}@{version} installed, and its files are not the package Open VSX "
                        f"signed for that release: {found.detail}."
                    ),
                    "fingerprint": hmac.new(
                        EvidenceKey.key(), f"{PROVENANCE_INVALID_RULE}\0{where}".encode(), "sha256"
                    ).hexdigest()[:16],
                }
            )
        return out
