"""cordon-rule's compiled-pack cache: a rule collection read and prepared once per version, then
loaded.

What is kept is the work before the condition closures are built -- the parsed rules with their
strings' searches prepared (`Strings.prepare`), which is most of a first compile -- written with the
standard library's pickle, so a later `Rules.compile` of the same text skips reading and preparing.
The closures are built again on every load (they are functions, which are not kept).

An entry is used only when everything that made it is the same, and is refused otherwise:

    key      the rule text, its externals, the modules the scan provides, this cache's FORMAT,
             and `made_by`: a digest of the rule engine's own source (a different engine never
             reads it) and the build running it -- interpreted or compiled, and the interpreter's
             ABI (`build_kind`) -- also in the signed header, checked on load
    files    every file its includes read, by path and sha256, checked on load
    owner    the entry is the current user's and writable by no one else
    mac      HMAC-SHA256 over the entry's bytes, with a per-user key kept 0600 in the cache
             directory (made as the scan cache makes its own), checked before anything is
             unpickled: a pickle runs code when it is read, so a same-user process, a restored
             backup or a truncation that wrote the directory without the key is never loaded

A refused or unreadable entry is a cache miss, counted in `refused`: the rules are compiled as
if there were none. An entry read is counted in `loaded`. (A pickle-free form would need every rule-tree class written to and read
from plain data; the key keeps the pickle to what this user's own compiles wrote.)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import pickle
import secrets
import tempfile
from pathlib import Path
from typing import Any, ClassVar


class PackCache:
    """Entries under one directory, one file per key."""

    FORMAT: ClassVar[int] = 2
    _ENGINE: ClassVar[str] = ""
    _BUILD: ClassVar[str] = ""

    KEY_NAME: ClassVar[str] = ".pack-key"

    def __init__(self, root: Path, made_by: str | None = None) -> None:
        """`made_by` names what writes and reads the entries; by default this engine and build
        (a test names another to see an entry refused across them)."""
        self.root = root
        self.made_by = made_by or f"{PackCache.engine_digest()} {PackCache.build_kind()}"
        self.refused = 0
        self.loaded = 0
        self._key: bytes | None = None

    def secret(self) -> bytes | None:
        """The per-user key entries are signed with: 32 random bytes, 0600, this user's; made on
        first use, made again if anyone else could read it. None when it can be neither read
        nor made, and then nothing is kept or loaded."""
        if self._key is not None:
            return self._key or None
        path = self.root / PackCache.KEY_NAME
        try:
            st = path.stat()
            if st.st_uid == os.getuid() and not st.st_mode & 0o077 and st.st_size >= 32:
                self._key = path.read_bytes()
                return self._key
            path.unlink()
        except OSError:
            pass
        try:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            material = secrets.token_bytes(32)
            with os.fdopen(fd, "wb") as handle:
                handle.write(material)
            self._key = material
            return material
        except OSError:
            self._key = b""
            return None

    def _mac(self, data: bytes) -> str | None:
        key = self.secret()
        return hmac.new(key, data, "sha256").hexdigest() if key else None

    def sign(self, data: bytes) -> str | None:
        """HMAC-SHA256 of `data` under this directory's per-user key; None when there is no key."""
        return self._mac(data)

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
    def build_kind() -> str:
        """Which build of the engine is running, so an entry one build kept is never read by
        another: "python" when every rule-engine module runs from source, else "compiled:" and a
        digest of the compiled files (mypyc's modules and its shared runtime), with the
        interpreter's ABI (cache tag, ABI flags, machine). A pickle names classes, not layouts: a
        compiled class reading an interpreted class's state, or the other way, is refused here."""
        if not PackCache._BUILD:
            import platform
            import sys

            prefix = "cordon_scanner.detect.binary.rule_engine."
            compiled = sorted(
                str(getattr(module, "__file__", ""))
                for name, module in list(sys.modules.items())
                if (name.startswith(prefix) or name.endswith("__mypyc"))
                and str(getattr(module, "__file__", "")).endswith((".so", ".pyd"))
            )
            kind = "python"
            if compiled:
                digest = hashlib.sha256()
                for path in compiled:
                    digest.update(path.encode() + b"\0" + Path(path).read_bytes())
                kind = "compiled:" + digest.hexdigest()[:16]
            abi = (
                f"{sys.implementation.cache_tag}{getattr(sys, 'abiflags', '')}-{platform.machine()}"
            )
            PackCache._BUILD = f"{kind} {abi}"
        return PackCache._BUILD

    def key(self, text: str, externals: dict[str, Any], modules: frozenset[str]) -> str:
        made_of = json.dumps(
            [
                PackCache.FORMAT,
                self.made_by,
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
                self.refused += 1
                return None
            raw = path.read_bytes()
            mac_line, _, signed = raw.partition(b"\n")
            expected = self._mac(signed)
            if expected is None or not hmac.compare_digest(
                mac_line.decode("ascii", "replace"), expected
            ):
                self.refused += 1
                return None
            header_line, _, body = signed.partition(b"\n")
            header = json.loads(header_line)
            if header.get("format") != PackCache.FORMAT or header.get("key") != key:
                return None
            if header.get("made_by") != self.made_by:
                return None
            for name, sha in header.get("files", []):
                if PackCache._sha(Path(name)) != sha:
                    return None
            value = pickle.loads(body)  # noqa: S301 -- signed with this user's key, checked above
            self.loaded += 1
            return value
        except FileNotFoundError:
            return None
        except (OSError, ValueError, EOFError, pickle.UnpicklingError, AttributeError, ImportError):
            self.refused += 1
            return None

    @staticmethod
    def dumps(value: Any) -> bytes | None:
        """`value` pickled now, to keep later (`put`); None when it cannot be."""
        try:
            return pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
        except (pickle.PicklingError, TypeError, AttributeError, RecursionError):
            return None

    def put(self, key: str, body: bytes, files: list[Path]) -> None:
        """Keep the pickled `body` under `key`, with the files it was read from; a failure keeps
        nothing."""
        try:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            header = {
                "format": PackCache.FORMAT,
                "key": key,
                "made_by": self.made_by,
                "files": [[str(p), PackCache._sha(p)] for p in files],
            }
            signed = json.dumps(header).encode() + b"\n" + body
            mac = self._mac(signed)
            if mac is None:
                return
            fd, tmp = tempfile.mkstemp(dir=self.root, prefix=".pack-")
            with os.fdopen(fd, "wb") as handle:
                handle.write(mac.encode() + b"\n" + signed)
            Path(tmp).chmod(0o600)
            Path(tmp).replace(self.root / key)
        except (OSError, pickle.PicklingError, TypeError, AttributeError, RecursionError):
            return


__all__ = ["PackCache"]
