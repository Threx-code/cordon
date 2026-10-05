"""Seals on what this machine itself wrote into the cache directory.

The cache directory is not a trusted place. Its location is chosen by the environment
(`CORDON_CACHE_DIR`, `XDG_CACHE_HOME`), CI systems restore it from caches other jobs wrote, and
the scan cache already treats an attacker who can write it as in scope. The advisory database a
sync installs there, the feed's overlays and its stored root were read from it on trust, by
modification time: plant an empty advisory file with a matching digest list, a withdrawal overlay
and a self-signed root at version 999, and every later scan on that cache matched nothing and
trusted the planter's keys for future feed updates.

What this machine writes there is now sealed with a MAC under its per-install key, which lives in
`ScanCache.key_dir` -- owner-only, and not movable by the environment. A file without a valid seal
was not written by this install and is not read. The package's own shipped data needs no seal: it
is inside the installed package, which is the trust anchor everything else is checked against.
"""

from __future__ import annotations

import hmac
import json
from typing import Any

SEAL_KEY = "_seal"


class LocalSeal:
    """Seal and check JSON documents this install writes."""

    @staticmethod
    def _canonical(document: dict[str, Any]) -> bytes:
        body = {k: v for k, v in document.items() if k != SEAL_KEY}
        return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

    @classmethod
    def mac(cls, label: str, document: dict[str, Any]) -> str:
        from cordon_scanner.core.evidence_key import EvidenceKey

        message = b"cordon-local-seal\0" + label.encode() + b"\0" + cls._canonical(document)
        return hmac.new(EvidenceKey.key(), message, "sha256").hexdigest()

    @classmethod
    def sealed(cls, label: str, document: dict[str, Any]) -> dict[str, Any]:
        """The document with its seal added."""
        return {
            **{k: v for k, v in document.items() if k != SEAL_KEY},
            SEAL_KEY: cls.mac(label, document),
        }

    @classmethod
    def valid(cls, label: str, document: object) -> bool:
        if not isinstance(document, dict):
            return False
        recorded = document.get(SEAL_KEY)
        return isinstance(recorded, str) and hmac.compare_digest(recorded, cls.mac(label, document))

    @staticmethod
    def unsealed(document: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in document.items() if k != SEAL_KEY}
