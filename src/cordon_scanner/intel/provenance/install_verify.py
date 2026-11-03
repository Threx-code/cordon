"""Whether Cordon's own installation is the one its release built (release item 75, note 75).

Cordon checks that its data is genuine -- the shipped advisory digests, the feed's signatures, the
cache's local seal -- but a modified `site-packages/cordon_scanner` (a poisoned CI image, a tampered
wheel cache, a dependency confusion on an internal mirror) would scan on and report clean. This reads
the installation against the wheel's own manifest, the dist-info `RECORD`:

```
  RECORD ──► every listed file: present, its size and sha256 as recorded
        │     a .py or .so inside the package that RECORD does not list: reported
        │     a .pth in site-packages that no installed distribution lists: reported
        ▼
  CONSISTENT (every file as recorded) / MODIFIED (the files, by name) / UNVERIFIED (why)
```

Offline this is never "verified": whoever can edit Cordon's files can edit its RECORD too. Only the
online step (`release_check`) ties the RECORD to the release workflow's signature, and only that is
reported as verified. The strong form runs this from a separate, trusted copy against `--target`.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
from dataclasses import dataclass, field
from enum import Enum
from importlib import metadata
from pathlib import Path
from typing import Final

DISTRIBUTION: Final = "cordon-scanner"
PACKAGES: Final = ("cordon_scanner", "cordon_sandbox")
"""The import packages the wheel installs: a file inside one that RECORD does not list was added."""

_CODE_SUFFIXES: Final = (".py", ".pyc", ".so", ".pyd", ".dylib", ".dll")
_READ: Final = 1 << 20


class InstallState(Enum):
    VERIFIED = "verified"
    CONSISTENT = "consistent with its own RECORD"
    MODIFIED = "modified"
    UNVERIFIED = "unverified"


@dataclass(frozen=True)
class InstallReport:
    """What the installation check found. `problems` names each file that differs, and why."""

    state: InstallState
    version: str = ""
    root: str = ""
    checked: int = 0
    problems: tuple[str, ...] = ()
    reason: str = ""
    record: tuple[tuple[str, str, int], ...] = field(default=(), repr=False)

    def as_dict(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "version": self.version,
            "root": self.root,
            "checked": self.checked,
            "problems": list(self.problems),
            "reason": self.reason,
        }


class InstallRecord:
    """The installed distribution's RECORD, read and checked against the files on disk."""

    @staticmethod
    def find(target: Path | None) -> metadata.Distribution | None:
        """The cordon-scanner distribution installed in `target` (a site-packages directory), or the
        running one's when `target` is None."""
        if target is None:
            try:
                return metadata.distribution(DISTRIBUTION)
            except metadata.PackageNotFoundError:
                return None
        for found in metadata.distributions(path=[str(target)]):
            if (found.metadata["Name"] or "").lower().replace("_", "-") == DISTRIBUTION:
                return found
        return None

    @staticmethod
    def parse(text: str) -> list[tuple[str, str, int]] | None:
        """RECORD's rows as (path, sha256 hex, size); the RECORD itself and .pyc rows carry no hash and
        are kept with an empty one. None when a row is malformed: a RECORD that does not parse is not
        evidence of anything."""
        rows: list[tuple[str, str, int]] = []
        for row in csv.reader(io.StringIO(text)):
            if not row:
                continue
            if len(row) != 3:
                return None
            path, digest, size = row
            if not digest:
                rows.append((path, "", -1))
                continue
            algorithm, _, encoded = digest.partition("=")
            if algorithm != "sha256" or not encoded or not size.isdigit():
                return None
            try:
                raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            except ValueError:
                return None
            rows.append((path, raw.hex(), int(size)))
        return rows

    @staticmethod
    def _digest(path: Path) -> tuple[str, int]:
        hasher = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            while chunk := handle.read(_READ):
                hasher.update(chunk)
                size += len(chunk)
        return hasher.hexdigest(), size

    @classmethod
    def check(cls, target: Path | None = None) -> InstallReport:
        """Every RECORD row against the file on disk, and every code file RECORD does not list."""
        dist = cls.find(target)
        if dist is None:
            return InstallReport(
                InstallState.UNVERIFIED, reason="no cordon-scanner distribution is installed there"
            )
        version = dist.version or ""
        text = dist.read_text("RECORD")
        if text is None:
            return InstallReport(
                InstallState.UNVERIFIED,
                version=version,
                reason="the installation has no RECORD (not a wheel install, or an editable one)",
            )
        rows = cls.parse(text)
        if rows is None:
            return InstallReport(
                InstallState.MODIFIED,
                version=version,
                problems=("RECORD: a row does not parse",),
            )
        root = Path(str(dist.locate_file("")))
        problems: list[str] = []
        listed: set[str] = set()
        checked = 0
        for path, digest, size in rows:
            listed.add(path)
            if not digest:
                continue
            on_disk = root / path
            if not on_disk.is_file() or on_disk.is_symlink():
                problems.append(f"{path}: missing")
                continue
            found, length = cls._digest(on_disk)
            checked += 1
            if length != size or found != digest:
                problems.append(f"{path}: changed")
        problems.extend(cls._unlisted(root, listed))
        return InstallReport(
            InstallState.MODIFIED if problems else InstallState.CONSISTENT,
            version=version,
            root=str(root),
            checked=checked,
            problems=tuple(problems),
            record=tuple(rows),
        )

    #: Run in a child: `marshal` is not safe against crafted input, and the cache is the attacker's
    #: to write. Code objects compare without their file name, so a cache compiled where the
    #: installation was built still matches its source read from anywhere (`--target`).
    _CHILD: Final = (
        "import json, marshal, sys\n"
        "bad = []\n"
        "for cached, source in json.load(sys.stdin):\n"
        "    try:\n"
        "        body = open(cached, 'rb').read()[16:]\n"
        "        code = compile(open(source, 'rb').read(), source, 'exec', dont_inherit=True)\n"
        "        if marshal.loads(body) != code:\n"
        "            bad.append(cached)\n"
        "    except Exception:\n"
        "        bad.append(cached)\n"
        "print(json.dumps(bad))\n"
    )

    @classmethod
    def _stale_caches(cls, caches: list[tuple[Path, Path]]) -> set[Path] | None:
        """The caches whose code is not their source's, checked in an isolated child; None when the
        child could not answer (it crashed or ran out of time): every cache is then unchecked."""
        import json
        import subprocess
        import sys

        if not caches:
            return set()
        try:
            done = subprocess.run(  # noqa: S603  (fixed argv: this interpreter, a constant script)
                [sys.executable, "-I", "-S", "-c", cls._CHILD],
                input=json.dumps([[str(c), str(s)] for c, s in caches]),
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
            if done.returncode != 0:
                return None
            return {Path(p) for p in json.loads(done.stdout)}
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return None

    @staticmethod
    def _this_interpreters_cache(cached: Path) -> Path | None:
        """The source a `__pycache__/<name>.<tag>.pyc` of this interpreter compiles; None for another
        interpreter's cache, which this one never runs."""
        import importlib.util
        import sys

        tag = sys.implementation.cache_tag
        if not tag or not cached.name.endswith(f".{tag}.pyc"):
            return None
        try:
            return Path(importlib.util.source_from_cache(str(cached)))
        except ValueError:
            return None

    @staticmethod
    def _unlisted(root: Path, listed: set[str]) -> list[str]:
        """Code files inside Cordon's packages that RECORD does not list, and .pth files in the
        site-packages directory that no installed distribution lists (a .pth runs at every start)."""
        out: list[str] = []
        caches: list[tuple[Path, Path]] = []
        for package in PACKAGES:
            base = root / package
            if not base.is_dir():
                continue
            for file in sorted(base.rglob("*")):
                relative = file.relative_to(root).as_posix()
                if "__pycache__" in file.parts:
                    # Written at install, so never in RECORD; but this interpreter runs a cached
                    # .pyc instead of its source when the header matches, so its code must be the
                    # source's own.
                    source = (
                        InstallRecord._this_interpreters_cache(file) if file.is_file() else None
                    )
                    if source is not None:
                        caches.append((file, source))
                    continue
                if file.is_file() and file.suffix in _CODE_SUFFIXES and relative not in listed:
                    out.append(f"{relative}: not in RECORD")
        stale = InstallRecord._stale_caches(caches)
        if stale is None:
            out.extend(
                f"{c.relative_to(root).as_posix()}: compiled cache could not be checked"
                for c, _ in caches
            )
        else:
            out.extend(
                f"{c.relative_to(root).as_posix()}: compiled cache differs from its source"
                for c in sorted(stale)
            )
        owned: set[str] = set()
        for other in metadata.distributions(path=[str(root)]):
            for entry in other.files or ():
                owned.add(entry.as_posix())
        for pth in sorted(root.glob("*.pth")):
            if pth.name not in owned:
                out.append(f"{pth.name}: a .pth no installed distribution lists")
        return out


__all__ = ["DISTRIBUTION", "InstallRecord", "InstallReport", "InstallState"]
