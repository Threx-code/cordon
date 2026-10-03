"""The per-install key a secret's evidence hash is computed with.

A secret finding's evidence is a hash of the matched value, and it travels into SARIF, CI logs and
cloud uploads. An unsalted SHA-256 of a short or partly known credential is recoverable by
guessing offline: hash every candidate, compare. Keyed with a secret that never leaves the machine,
the hash still identifies the same value within one install -- which is all deduplication, the
history pass and the issuer check use it for -- and says nothing to anyone without the key.

The key lives beside the scan cache's own key (`ScanCache.key_dir`, owner-only), created once.
Where that directory cannot be written, a per-process key is used: the hash is then stable for one
run, which is still everything the scanner itself needs.
"""

from __future__ import annotations

import hmac
import os
import secrets
import threading
from pathlib import Path

KEY_NAME = ".cordon-evidence-key"
KEY_BYTES = 32


class EvidenceKey:
    """The key, loaded or created once per process."""

    _key: bytes | None = None
    _lock = threading.Lock()

    @classmethod
    def key(cls) -> bytes:
        with cls._lock:
            if cls._key is None:
                cls._key = cls._load_or_create() or secrets.token_bytes(KEY_BYTES)
            return cls._key

    @classmethod
    def _load_or_create(cls) -> bytes | None:
        from cordon_scanner.core.cache import ScanCache

        try:
            directory = ScanCache.key_dir()
            path = directory / KEY_NAME
            if path.is_file() and not path.is_symlink():
                raw = path.read_bytes()
                if len(raw) == KEY_BYTES:
                    return raw
            directory.mkdir(parents=True, exist_ok=True)
            return cls._create(path)
        except OSError:
            return None

    @staticmethod
    def _create(path: Path) -> bytes | None:
        fresh = secrets.token_bytes(KEY_BYTES)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raw = path.read_bytes()
            return raw if len(raw) == KEY_BYTES else None
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(fresh)
        return fresh

    @classmethod
    def digest(cls, raw: bytes) -> str:
        return "hmac-sha256:" + hmac.new(cls.key(), raw, "sha256").hexdigest()
