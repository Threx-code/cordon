"""The advisory records of one verified data file, looked up by package name from disk.

```
  verified advisory file (sha256 checked against its manifest, as before)
        │  first use, once per file version
        ▼
  <cache>/advisory-index/<file sha256>-v<schema>.sqlite   built to a temporary name, renamed in
  <cache>/advisory-index/<file sha256>-v<schema>.seal     {source sha256, sqlite sha256}, MAC'd
        │                                                  with this install's key (`core.local_seal`)
        │  every process, before SQLite reads a byte of it
        ▼
  seal valid  ∧  source sha256 = the verified file's  ∧  sqlite sha256 = the file on disk
        │ yes                                           │ no
        ▼                                               ▼
  opened read-only (mode=ro, query_only, trusted_schema   rebuilt from the verified file; if that
  off, no extensions); one parameterised SELECT per name  cannot be done, the caller reads in memory
```

Why. Holding an ecosystem's records as Python objects cost 305 MB per process for npm and PyPI
alone, held for the whole run and multiplied by every worker; a scan asks about a few hundred
names. On disk, a process holds a connection, and every worker shares the operating system's page
cache.

What it trusts. The cache directory is not trusted: the environment chooses it and CI restores it
from caches other jobs wrote (see `core.local_seal`). So nothing there is opened by SQLite until
its seal -- which only this install can produce -- and its full SHA-256 agree. That also keeps a
crafted database file away from SQLite's parser: an unverified file is never handed to it. The
trust anchor is the install itself; a process able to rewrite Cordon's own code or key could make it
report anything, and no data format changes that.
"""

from __future__ import annotations

import contextlib
import json
import os
import threading
import urllib.parse
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, Final

SCHEMA: Final = 2
LABEL: Final = "advisory-index"


class AdvisoryIndex:
    """One verified file's records, read by name from a sealed SQLite file."""

    def __init__(self, connection: Any, count: int) -> None:
        self._connection = connection
        self._lock = threading.Lock()
        self.count = count

    def get(self, name: str) -> tuple[dict[str, object], ...]:
        """Every record stored under this (lowercased) name, as the data file holds them."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT record FROM advisories WHERE name = ? ORDER BY position", (name,)
            ).fetchall()
        return tuple(json.loads(row[0]) for row in rows)

    def names(self) -> list[str]:
        """Every name with a record, once each."""
        with self._lock:
            return [
                row[0] for row in self._connection.execute("SELECT DISTINCT name FROM advisories")
            ]

    def count_except(self, identifiers: frozenset[str]) -> int:
        """How many records remain once those with these identifiers are set aside."""
        if not identifiers:
            return self.count
        with self._lock:
            removed = 0
            ordered = sorted(identifiers)
            for start in range(0, len(ordered), 500):
                chunk = ordered[start : start + 500]
                marks = ",".join("?" * len(chunk))
                # Placeholders only: the identifiers are bound, never written into the SQL.
                row = self._connection.execute(
                    f"SELECT COUNT(*) FROM advisories WHERE identifier IN ({marks})",  # noqa: S608
                    chunk,
                ).fetchone()
                removed += int(row[0])
        return self.count - removed

    @staticmethod
    def directory() -> Path:
        from cordon_scanner.engine.cache import ScanCache

        return ScanCache.default_cache_dir() / "advisory-index"

    @classmethod
    def for_file(
        cls, source_digest: str, records: Callable[[], Iterable[dict[str, object]]]
    ) -> AdvisoryIndex | None:
        """The index for the verified file with this digest, built from `records` if needed.

        None when SQLite is unavailable or the index can be neither verified nor built: the caller
        then reads the records in memory, as before. Never an unverified index.
        """
        try:
            import sqlite3  # noqa: F401 - a Python built without it falls back
        except ImportError:
            return None
        base = cls.directory() / f"{source_digest}-v{SCHEMA}"
        database, seal = base.with_suffix(".sqlite"), base.with_suffix(".seal")
        found = cls._verified(database, seal, source_digest)
        if found is None and cls._build(database, seal, source_digest, records()):
            found = cls._verified(database, seal, source_digest)
        return found

    @staticmethod
    def _verified(database: Path, seal: Path, source_digest: str) -> AdvisoryIndex | None:
        """Open the index only if its seal is this install's and both digests agree."""
        import sqlite3

        from cordon_scanner.engine.local_seal import LocalSeal
        from cordon_scanner.intel.advisories.advisories import AdvisoryFiles

        try:
            document = json.loads(seal.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not LocalSeal.valid(LABEL, document) or not isinstance(document, dict):
            return None
        try:
            if (
                document.get("schema") != SCHEMA
                or document.get("source_sha256") != source_digest
                or document.get("sqlite_sha256") != AdvisoryFiles.digest_of(database)
            ):
                return None
        except OSError:
            return None
        address = f"file:{urllib.parse.quote(str(database))}?mode=ro"
        try:
            connection = sqlite3.connect(address, uri=True, check_same_thread=False)
            if hasattr(connection, "enable_load_extension"):
                connection.enable_load_extension(False)
            connection.execute("PRAGMA query_only = ON")
            with contextlib.suppress(sqlite3.DatabaseError):
                connection.execute("PRAGMA trusted_schema = OFF")
            count = int(
                connection.execute("SELECT value FROM meta WHERE key = 'count'").fetchone()[0]
            )
        except (sqlite3.Error, TypeError, ValueError):
            return None
        return AdvisoryIndex(connection, count)

    @staticmethod
    def _build(
        database: Path, seal: Path, source_digest: str, records: Iterable[dict[str, object]]
    ) -> bool:
        """Write the index to a temporary name, rename it into place, then seal it."""
        import sqlite3

        from cordon_scanner.engine.local_seal import LocalSeal
        from cordon_scanner.intel.advisories.advisories import AdvisoryFiles

        try:
            database.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            return False
        temporary = database.with_name(f"{database.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            connection = sqlite3.connect(str(temporary))
            try:
                connection.execute(
                    "CREATE TABLE advisories (name TEXT NOT NULL, position INTEGER NOT NULL, "
                    "identifier TEXT NOT NULL, record TEXT NOT NULL)"
                )
                connection.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                written = [0]

                def rows() -> Iterable[tuple[str, int, str, str]]:
                    # Streamed into SQLite rather than collected first: the build holds no second
                    # copy of the data beside the records it is given.
                    for position, raw in enumerate(records):
                        written[0] += 1
                        yield (
                            str(raw["name"]).lower(),
                            position,
                            str(raw.get("id", "")),
                            json.dumps(raw, sort_keys=True),
                        )

                connection.executemany("INSERT INTO advisories VALUES (?, ?, ?, ?)", rows())
                count = written[0]
                connection.execute("CREATE INDEX advisories_by_name ON advisories (name)")
                connection.execute("INSERT INTO meta VALUES ('count', ?)", (str(count),))
                connection.commit()
            finally:
                connection.close()
            temporary.replace(database)
            document = {
                "schema": SCHEMA,
                "source_sha256": source_digest,
                "sqlite_sha256": AdvisoryFiles.digest_of(database),
            }
            seal.write_text(json.dumps(LocalSeal.sealed(LABEL, document)), encoding="utf-8")
        except (OSError, sqlite3.Error, KeyError, TypeError, ValueError):
            with contextlib.suppress(OSError):
                temporary.unlink()
            return False
        return True


__all__ = ["AdvisoryIndex"]
