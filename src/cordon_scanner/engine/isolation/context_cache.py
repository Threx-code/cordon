"""The scan context kept between scans of the same tree (4 Nov).

The context worker re-reads every file of a scan to work out what runs at install and at import and
the dependency graph; a warm 20,000-file scan spent 10 s of its 24.6 s doing it again for a tree that
had not changed. Its accepted document is kept in the scan cache, under a key covering everything
the answer depends on (`ContextStage.cache_digest`), read and authenticated exactly as a file's entry
is, and checked by `ContextFacts.accept` as a fresh one is before the scan believes it.
"""

from __future__ import annotations

from cordon_scanner.engine.cache import CacheKey, ScanCache


class ContextCache:
    """A scan context's document in the scan cache: filed as no file's, not counted as a file's hit."""

    @staticmethod
    def key(digest: str) -> CacheKey:
        return CacheKey(
            content_hash=digest,
            rulepack_hash="context",
            config_hash="context",
            detector_signature="context",
            path="<scan context>",
            language="context",
        )

    @staticmethod
    def get(cache: ScanCache, digest: str, limit: int) -> str | None:
        """The cached document, or None: aged, bounded by `limit` and authenticated as a file's entry
        is (`ScanCache.get_entry`), without moving the file hit and miss counts."""
        hits, misses = cache.hits, cache.misses
        try:
            entry = cache.get_entry(ContextCache.key(digest), limit=limit)
        finally:
            cache.hits, cache.misses = hits, misses
        return None if entry is None or not entry[1] else entry[1]

    @staticmethod
    def put(cache: ScanCache, digest: str, document: str, limit: int) -> None:
        cache.put(ContextCache.key(digest), (), document, limit=limit)


__all__ = ["ContextCache"]
