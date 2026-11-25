"""Skill folders and models the feed condemned or holds, matched by their tree digest and by nothing else.

The backend captures two ecosystems that have no name and version to match on: `skills` (a folder, digested by `ArtifactDigests.of_tree`, the digest
`decide/resolve/skill.py` computes locally) and `huggingface` (a model, digested by `ArtifactDigests.of_model` from the digests of its files). A feed
record for either carries `digests`, each the `sha256:<hex>` the backend computed; the scanner holds the same two functions and the same golden
vectors (`tests/unit/contracts/tree_digest_vectors.json`, `model_digest_vectors.json`), so the same folder or model is the same digest on both sides.

    a confirmed malicious record carries the digest  ->  a known hit   (blocks)
    a provisional record carries it                  ->  a held hit    (paused until the hold is decided)

A withdrawn record matches nothing. A folder or model that differs by one byte, one path or one mode is another digest and matches nothing. A digest of
one ecosystem never matches a record of the other.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, ClassVar, Final

DIGEST_ECOSYSTEMS: Final[tuple[str, ...]] = ("skills", "huggingface")


@dataclass(frozen=True, slots=True)
class DigestHit:
    """What the feed says about one digest: the record, and whether it is only a hold."""

    ecosystem: str
    record: dict[str, Any]
    provisional: bool

    @property
    def identifier(self) -> str:
        return str(self.record.get("id", ""))


class DigestFeed:
    SHAPE: ClassVar[re.Pattern[str]] = re.compile(r"^(?:sha256:)?([0-9a-fA-F]{64})$")

    @classmethod
    def key(cls, digest: object) -> str | None:
        """The 64 lowercase hex digits of a `sha256:<hex>` (or bare hex) digest, or None for anything else."""
        found = cls.SHAPE.match(digest) if isinstance(digest, str) else None
        return found.group(1).lower() if found else None

    @classmethod
    def load(cls, ecosystem: str) -> dict[str, DigestHit]:
        """Digest key to hit for one ecosystem: confirmed records first, then holds for digests no confirmed record names."""
        from cordon_scanner.intel.registry import FeedStore

        index: dict[str, DigestHit] = {}
        upserts, withdrawn = FeedStore.read_overlay(ecosystem)
        for record in upserts:
            if record.get("malicious") and str(record.get("id")) not in withdrawn:
                for digest in record.get("digests") or ():
                    key = cls.key(digest)
                    if key is not None:
                        index[key] = DigestHit(ecosystem, record, False)
        for record in FeedStore.read_provisional(ecosystem):
            for digest in record.get("digests") or ():
                key = cls.key(digest)
                if key is not None:
                    index.setdefault(key, DigestHit(ecosystem, record, True))
        return index

    @classmethod
    def lookup(cls, ecosystem: str, digest: str) -> DigestHit | None:
        """The feed's verdict on a skill folder or a model, or None when it says nothing about it (or the ecosystem is not one it matches by digest)."""
        key = cls.key(digest)
        if ecosystem not in DIGEST_ECOSYSTEMS or key is None:
            return None
        try:
            return cls.load(ecosystem).get(key)
        except (OSError, ValueError):
            return None


__all__ = ["DIGEST_ECOSYSTEMS", "DigestFeed", "DigestHit"]
