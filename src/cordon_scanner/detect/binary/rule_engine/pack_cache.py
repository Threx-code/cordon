"""cordon-rule's compiled-pack cache: a rule collection read and prepared once per version, then
loaded.

What is kept is the work before the condition closures are built -- the parsed rules with their
strings' searches prepared (`Strings.prepare`), which is most of a first compile -- written with the
standard library's pickle, so a later `Rules.compile` of the same text skips reading and preparing.
The closures are built again on every load (they are functions, which are not kept).

An entry is used only when everything that made it is the same, and is refused otherwise:

    key      the rule text, its externals, the modules the scan provides, this cache's FORMAT,
             and a digest of the rule engine's own source (a different engine never reads it)
    files    every file its includes read, by path and sha256, checked on load
    owner    the entry is the current user's and writable by no one else -- a pickle runs code
             when it is read, so an entry another user could have written is never loaded

A refused or unreadable entry is a cache miss: the rules are compiled as if there were none.
"""

from __future__ import annotations

import hashlib
import json
import os
import pickle
import tempfile
from pathlib import Path
from typing import Any, ClassVar


class PackCache:
    """Entries under one directory, one file per key."""

    FORMAT: ClassVar[int] = 1
    _ENGINE: ClassVar[str] = ""

    def __init__(self, root: Path) -> None:
        self.root = root

    @staticmethod
    def engine_digest() -> str:
        """A digest of the rule engine's source files: what a kept entry was made by."""
        if not PackCache._ENGINE:
            from cordon_scanner.foundation.paths import PackagePaths

            here = PackagePaths.root() / "detect" / "binary" / "rule_engine"
            digest = hashlib.sha256()
            for path in sorted(here.glob("*.py")):
                digest.update(path.name.encode() + b"\0" + path.read_bytes())
            PackCache._ENGINE = digest.hexdigest()[:16]
        return PackCache._ENGINE

    @staticmethod
    def key(text: str, externals: dict[str, Any], modules: frozenset[str]) -> str:
        made_of = json.dumps(
            [
                PackCache.FORMAT,
                PackCache.engine_digest(),
                sorted(modules),
                sorted(externals.items(), key=str),
            ],
            default=repr,
        )
        return hashlib.sha256(
            made_of.encode() + b"\0" + text.encode("utf-8", "surrogateescape")
        ).hexdigest()

    @staticmethod
    def _sha(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def get(self, key: str) -> Any:
        """What `put` kept under `key`, or None: absent, refused or unreadable."""
        path = self.root / key
        try:
            st = path.stat()
            if st.st_uid != os.getuid() or st.st_mode & 0o022:
                return None
            with path.open("rb") as handle:
                header = json.loads(handle.readline())
                if header.get("format") != PackCache.FORMAT or header.get("key") != key:
                    return None
                if header.get("engine") != PackCache.engine_digest():
                    return None
                for name, sha in header.get("files", []):
                    if PackCache._sha(Path(name)) != sha:
                        return None
                return pickle.loads(handle.read())  # noqa: S301 -- this user's own entry
        except (OSError, ValueError, EOFError, pickle.UnpicklingError, AttributeError, ImportError):
            return None

    def put(self, key: str, value: Any, files: list[Path]) -> None:
        """Keep `value` under `key`, with the files it was read from; a failure keeps nothing."""
        try:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            header = {
                "format": PackCache.FORMAT,
                "key": key,
                "engine": PackCache.engine_digest(),
                "files": [[str(p), PackCache._sha(p)] for p in files],
            }
            body = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
            fd, tmp = tempfile.mkstemp(dir=self.root, prefix=".pack-")
            with os.fdopen(fd, "wb") as handle:
                handle.write(json.dumps(header).encode() + b"\n" + body)
            Path(tmp).chmod(0o600)
            Path(tmp).replace(self.root / key)
        except (OSError, pickle.PicklingError, TypeError, AttributeError, RecursionError):
            return


__all__ = ["PackCache"]
