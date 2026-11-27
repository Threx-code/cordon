"""An installed editor extension against the package Open VSX signed for the same release.

An extension folder holds the files of its `.vsix`: everything under the package's `extension/` directory sits at the folder's
root, and `extension.vsixmanifest` is the folder's `.vsixmanifest`. For an editor whose extensions come from Open VSX, each
installed release is looked up there (online: the extension's id and version are asked of a public registry, so this is opt-in
and never part of an offline inventory) and its files are compared by SHA-256 with the signed package's.

Two things are reported. A file that is in the signed package and differs. And a file the package never had, when it is of a
code kind (`CODE_KINDS`: a script, a native library, a program): tampering with an extension most often adds one, a `.js` the entry
point requires or a dropped binary. An added file that the signed entry point or any signed file names is the same finding as a
changed file (critical, VULNERABLE.PROVENANCE.INVALID.001); one nothing signed names is SUSPECT.EXTENSION.ADDED_CODE.001 (high).
An added data or cache file is not reported: a folder holds more than the package did (a runtime download, a language server
fetched on first use). Editors that install from Microsoft's Marketplace are not asked (its packages are signed by Microsoft and are
not guaranteed byte-identical to Open VSX's, and its terms stop us asking it); `not_verified` names them."""

from __future__ import annotations

import hashlib
import hmac
import io
import re
import zipfile
from pathlib import Path, PurePosixPath
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
    #: The file kinds that run code when an extension is used: suffix -> what it is. An added file of any other kind is data.
    CODE_KINDS: ClassVar[dict[str, str]] = {
        ".js": "script",
        ".mjs": "script",
        ".cjs": "script",
        ".node": "native module",
        ".wasm": "WebAssembly module",
        ".exe": "program",
        ".dll": "native library",
        ".so": "native library",
        ".dylib": "native library",
        ".sh": "shell script",
        ".ps1": "PowerShell script",
        ".py": "script",
    }
    #: The signed files read for a mention of an added file's name, and how much of them.
    MENTIONING: ClassVar[frozenset[str]] = frozenset(
        {".js", ".mjs", ".cjs", ".json", ".html", ".sh", ".ps1", ".py", ".cmd", ".bat"}
    )
    MENTION_FILE_BYTES: ClassVar[int] = 4 << 20
    MENTION_TOTAL_BYTES: ClassVar[int] = 64 << 20
    MAX_ADDED_CHECKED: ClassVar[int] = 200
    NOT_VERIFIED_MARKETPLACE: ClassVar[str] = (
        "not verified: installed from the Visual Studio Marketplace"
    )
    ADDED_CODE_RULE: ClassVar[str] = "SUSPECT.EXTENSION.ADDED_CODE.001"

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
    def added_code(cls, files: dict[str, str], known: dict[str, str]) -> dict[str, str]:
        """The files in the folder the signed package never had that are of a code kind: name in the package -> kind."""
        out: dict[str, str] = {}
        for name in sorted(n for n in files if n not in known):
            kind = cls.CODE_KINDS.get(PurePosixPath(name).suffix.lower())
            if kind:
                out[name] = kind
        return out

    @classmethod
    def mentioned(cls, added: list[str], package: bytes) -> set[str]:
        """Which of the added files a signed file of the package names (as `"./helper"`, `'lib/helper.js'` and the like)."""
        spellings: dict[bytes, str] = {}
        for name in added:
            path = PurePosixPath(name)
            for text in (path.name, path.stem):
                spellings.setdefault(text.encode(), name)
        if not spellings:
            return set()
        pattern = re.compile(
            rb"""[/'"`]("""
            + b"|".join(re.escape(t) for t in sorted(spellings, key=len, reverse=True))
            + rb""")['"`]"""
        )
        found: set[str] = set()
        total = 0
        try:
            with zipfile.ZipFile(io.BytesIO(package)) as archive:
                for info in archive.infolist():
                    if (
                        info.is_dir()
                        or PurePosixPath(info.filename).suffix.lower() not in cls.MENTIONING
                    ):
                        continue
                    if info.file_size > cls.MENTION_FILE_BYTES:
                        continue
                    total += info.file_size
                    if total > cls.MENTION_TOTAL_BYTES:
                        break
                    for match in pattern.finditer(archive.read(info)):
                        found.add(spellings[match.group(1)])
        except (zipfile.BadZipFile, OSError, ValueError):
            return found
        return found

    @classmethod
    def not_verified(cls, installed: list[dict[str, str]]) -> list[dict[str, str]]:
        """The installed extensions this check does not ask about, with why (`NOT_VERIFIED_MARKETPLACE`)."""
        return [
            {**entry, "reason": cls.NOT_VERIFIED_MARKETPLACE}
            for entry in installed
            if entry["editor"] not in cls.OPEN_VSX_EDITORS
        ]

    @classmethod
    def findings(cls, installed: list[tuple[dict[str, str], Path]]) -> list[dict[str, Any]]:
        """One finding for each installed extension whose files differ from the package Open VSX signed for its release, or that
        holds code the package never had."""
        from cordon_scanner.foundation.dependencies import PROVENANCE_INVALID_RULE
        from cordon_scanner.intel.provenance.bazel_provenance import ModuleCheck
        from cordon_scanner.intel.registry import OpenVsxSignature

        out: list[dict[str, Any]] = []
        for entry, folder in installed:
            editor, identifier, version = entry["editor"], entry["id"], entry["version"]
            if editor not in cls.OPEN_VSX_EDITORS or not version:
                continue
            files = cls.members(folder)
            if files is None:
                continue
            signed = OpenVsxSignature.signed_package(identifier, version)
            if isinstance(signed, ModuleCheck):
                continue
            package, known = signed
            changed = sorted(n for n, digest in files.items() if n in known and known[n] != digest)
            added = cls.added_code(files, known)
            checked = list(added)[: cls.MAX_ADDED_CHECKED]
            named = cls.mentioned(checked, package) if checked else set()
            unnamed = [n for n in added if n not in named]
            what = [f"{n} (changed)" for n in changed] + [
                f"{n} ({added[n]} not in the signed package, named by a signed file)"
                for n in added
                if n in named
            ]
            if what:
                rule_id, severity, category = PROVENANCE_INVALID_RULE, "critical", "vulnerable"
                shown = what
                message = (
                    f"{editor} has {identifier}@{version} installed, and its files are not the package Open VSX "
                    f"signed for that release: {', '.join(shown[:5])}"
                    f"{f' and {len(shown) - 5} more' if len(shown) > 5 else ''}."
                )
            elif unnamed:
                rule_id, severity, category = cls.ADDED_CODE_RULE, "high", "suspicious"
                shown = [f"{n} ({added[n]})" for n in unnamed]
                message = (
                    f"{editor} has {identifier}@{version} installed, and its folder holds code the package Open VSX signed "
                    f"for that release does not have: {', '.join(shown[:5])}"
                    f"{f' and {len(shown) - 5} more' if len(shown) > 5 else ''}."
                )
            else:
                continue
            where = f"{editor}:{identifier}@{version}"
            out.append(
                {
                    "rule_id": rule_id,
                    "severity": severity,
                    "category": category,
                    "path": f"extensions/{where}",
                    "line": None,
                    "message": message,
                    "fingerprint": hmac.new(
                        EvidenceKey.key(), f"{rule_id}\0{where}".encode(), "sha256"
                    ).hexdigest()[:16],
                }
            )
        return out
