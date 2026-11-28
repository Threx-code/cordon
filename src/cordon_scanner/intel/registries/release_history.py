"""What an earlier, established release of a package contained -- acquired online, read offline.

A finding in code the package has shipped unchanged for months is a different claim from the
same finding in code that appeared in this release. Compromised releases arrive as a diff: a new
lifecycle script, a new file, a changed one. The prebuilt-binary installer or the notifier that
has been in every release since the first is not a new attack, and on the long tail it is most of
what a reader of capabilities alone reports (review 98).

```
  cordon-scanner intel acquire <target>  (network: registries only)
        │  for each release: the newest earlier release published >= MIN_AGE_DAYS before it,
        │  downloaded through the registry clients' pinned, digest-checked paths, hashed per file
        ▼
  <cache>/release-history/<ecosystem>/<name>@<version>.json        (local, plain JSON)
        │
        ▼
  cordon scan <target>                   (no network: reads the store, or nothing)
        a suspicious finding in a file byte-identical to the established release is reported
        below the gate; a file that is new or changed keeps its grade
```

The baseline must be OLD, not merely earlier: an attacker who publishes twice controls both
releases. Age is measured by the registry's own publish times, never by anything in the package.

Nothing here runs during a scan. `load` reads a file; `acquire` is the only function that touches
the network, and the CLI refuses it under CORDON_OFFLINE.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.foundation.files.atomic import AtomicFile

if TYPE_CHECKING:  # from the source
    from cordon_scanner.foundation.content import FileContent
    from cordon_scanner.intel.base import ReleaseArchiveReader

MIN_AGE_DAYS: Final = 90
"""How much older the baseline release must be than the one scanned.

Long enough that a release has been installed, read and reported on by the ecosystem if it was
malicious -- malicious packages are typically removed within days -- and short enough that an
actively maintained package has one."""

STORE_VERSION: Final = 3

YOUNG_DEPENDENCY_DAYS: Final = 30
"""A dependency a release introduces that was itself first published this recently before the
release is the shape of a dependency injection: the compromised release of an established package
pulls in a name created for the attack (review 98: `@mastra/*` 2026-06-17)."""


@dataclass(frozen=True, slots=True)
class Baseline:
    """The established release a scanned release is compared with."""

    ecosystem: str
    name: str
    version: str
    baseline_version: str | None
    baseline_published: str | None = None
    published: str | None = None
    files: dict[str, str] = field(default_factory=dict)
    """Per file, its path with the release's version replaced by `{version}`, and its sha256."""
    dependencies: tuple[str, ...] = ()
    """The runtime dependencies the established release declared."""
    introduced: dict[str, str] = field(default_factory=dict)
    """Each dependency this release declares and the established one did not, with when the
    registry says it was first published ("" when the registry has no record of it)."""
    obfuscated: tuple[str, ...] = ()
    """The established release's files (by `ReleaseHistory.key`) that already had an
    obfuscator's output shape. Obfuscated output differs on every build, so an unchanged hash is
    no test for it; that the file was obfuscated months ago is."""

    def unchanged(self, key: str, digest: str) -> bool:
        return bool(self.baseline_version) and self.files.get(key) == digest

    def to_dict(self) -> dict[str, Any]:
        return {
            "store_version": STORE_VERSION,
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "baseline_version": self.baseline_version,
            "baseline_published": self.baseline_published,
            "published": self.published,
            "files": self.files,
            "dependencies": list(self.dependencies),
            "introduced": self.introduced,
            "obfuscated": list(self.obfuscated),
        }


class ReleaseHistory:
    """Acquire (online) and load (offline) the established release behind a scanned one."""

    @classmethod
    def ecosystems(cls) -> frozenset[str]:
        """The ecosystems whose established release can be acquired: the history is read (`covered`) and the archive is fetched and
        checked. Every other ecosystem answers `None`, which changes nothing about a scan."""
        from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources

        return cls.covered() & ArchiveSources.fetchable()

    # -- the store (offline) ------------------------------------------------------------------

    @staticmethod
    def store_dir() -> Path:
        from cordon_scanner.foundation.paths import StatePaths

        return StatePaths.default_cache_dir() / "release-history"

    @staticmethod
    def _entry(root: Path, ecosystem: str, name: str, version: str) -> Path:
        quoted = urllib.parse.quote(f"{name}@{version}", safe="")
        return root / ecosystem / f"{quoted[:200]}.json"

    @classmethod
    def load(
        cls, ecosystem: str, name: str, version: str, root: Path | None = None
    ) -> Baseline | None:
        """The stored baseline, or None. Reads one file; never the network."""
        path = cls._entry(root or cls.store_dir(), ecosystem, name, version)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or data.get("store_version") != STORE_VERSION:
            return None
        files = data.get("files")
        introduced = data.get("introduced")
        return Baseline(
            ecosystem=ecosystem,
            name=name,
            version=version,
            baseline_version=data.get("baseline_version") or None,
            baseline_published=data.get("baseline_published"),
            published=data.get("published"),
            files={str(k): str(v) for k, v in files.items()} if isinstance(files, dict) else {},
            dependencies=tuple(str(d) for d in data.get("dependencies") or ()),
            introduced=(
                {str(k): str(v) for k, v in introduced.items()}
                if isinstance(introduced, dict)
                else {}
            ),
            obfuscated=tuple(str(k) for k in data.get("obfuscated") or ()),
        )

    @classmethod
    def save(cls, baseline: Baseline, root: Path | None = None) -> Path:
        path = cls._entry(
            root or cls.store_dir(), baseline.ecosystem, baseline.name, baseline.version
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        # Staged under its own name, never a shared `.tmp` (`AtomicFile`).
        AtomicFile.write(path, json.dumps(baseline.to_dict(), sort_keys=True))
        return path

    # -- comparing (offline) ------------------------------------------------------------------

    @staticmethod
    def key(member_path: str, version: str) -> str:
        """A file's path inside its release, comparable across releases.

        The archive's own name is dropped and the version is written as `{version}`: an sdist's
        root is `name-1.2.3/`, a Go module's `example.com/m@v1.2.3/`, and the same file in the
        next release lives under a different root."""
        member = member_path.split("!", 1)[1] if "!" in member_path else member_path
        if not version:
            return member
        return re.sub(rf"(?<![\w.])(v?){re.escape(version)}(?!\w)", r"\1{version}", member)

    @classmethod
    def fingerprint(
        cls, data: bytes, filename: str, version: str, reader: ReleaseArchiveReader
    ) -> dict[str, str]:
        """Every file of a published archive, keyed by `key`, hashed. Read in memory."""
        return {
            cls.key(member_path, version): hashlib.sha256(member).hexdigest()
            for member_path, member in reader.members(data, filename)
        }

    @classmethod
    def obfuscated(
        cls, data: bytes, filename: str, version: str, reader: ReleaseArchiveReader
    ) -> tuple[str, ...]:
        """The archive's files with an obfuscator's output shape, keyed by `key`. Matched, never
        decoded: the same signatures `SUSPECT.OBFUSCATION.PACKED.001` reports."""
        return tuple(
            sorted(
                cls.key(member_path, version)
                for member_path, member in reader.members(data, filename)
                if reader.packed(member_path, member)
            )
        )

    @staticmethod
    def declared(
        data: bytes, filename: str, ecosystem: str, reader: ReleaseArchiveReader
    ) -> frozenset[str]:
        """The runtime dependencies a published archive declares, read the way the scan reads
        them (the ecosystem's `declared_dependencies`)."""
        from cordon_scanner.ecosystems.registry import EcosystemRegistry
        from cordon_scanner.foundation.content import FileContent

        files = [
            _ReleaseFile(member, FileContent.from_bytes(member, payload))
            for member, payload in reader.members(data, filename)
        ]
        return EcosystemRegistry.declared_dependencies(files, ecosystem)

    # -- acquiring (online) -------------------------------------------------------------------

    @staticmethod
    def _when(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return (
            parsed if parsed.tzinfo else parsed.replace(tzinfo=datetime.now().astimezone().tzinfo)
        )

    #: The ecosystem ids a history is asked under that are another's: Open VSX is the editor extensions' registry, `vscode`.
    ALIASES: ClassVar[dict[str, str]] = {"openvsx": "vscode"}

    @classmethod
    def readers(cls) -> dict[str, Callable[[str, str], dict[str, datetime]]]:
        """The ecosystems whose history is not their registry record's: ecosystem -> reader of (name, version). Editor
        extensions are read from Open VSX until their registry record exists."""
        from cordon_scanner.intel.registries.openvsx import OpenVsx

        return {"vscode": OpenVsx.timeline}

    @classmethod
    def covered(cls) -> frozenset[str]:
        """Every ecosystem a release history is read for: the ones whose registry record holds one, and the ones read apart."""
        from cordon_scanner.intel.registries.record_sources.table import RecordSources

        return RecordSources.ids() | frozenset(cls.readers())

    @classmethod
    def timeline(cls, ecosystem: str, name: str, version: str) -> dict[str, datetime]:
        """When the registry says each release was published: the release history the ecosystem's registry record is built from
        (`RecordSource`), so the two never disagree on what the releases are. Network."""
        from datetime import UTC

        from cordon_scanner.intel.registries.record_sources.base import RecordBuilder, RecordFetch
        from cordon_scanner.intel.registries.record_sources.table import RecordSources
        from cordon_scanner.intel.registries.registry_request import RegistryError

        ecosystem = cls.ALIASES.get(ecosystem, ecosystem)
        reader = cls.readers().get(ecosystem)
        if reader is not None:
            return dict(reader(name, version))
        source = RecordSources.of(ecosystem)
        if source is None:
            return {}
        try:
            documents = RecordFetch.documents(source, name, version)
        except (RegistryError, ValueError):
            return {}
        if documents is None:
            return {}
        out: dict[str, datetime] = {}
        for release in RecordBuilder.releases_of(source, name, version, documents):
            out.setdefault(release.version, release.published.replace(tzinfo=UTC))
        return out

    @classmethod
    def established(
        cls, ecosystem: str, name: str, version: str
    ) -> tuple[str, datetime, datetime] | None:
        """The newest release published at least `MIN_AGE_DAYS` before `version`: (release, its
        time, the scanned release's time). Network."""
        times = cls.timeline(ecosystem, name, version)
        # A release is written with or without its `v` (a Go module's always has one): the registry's own spelling is the key.
        spelling = next(
            (s for s in (version, f"v{version}", version.removeprefix("v")) if s in times), version
        )
        current = times.get(spelling)
        if current is None:
            return None
        cutoff = current - timedelta(days=MIN_AGE_DAYS)
        older = [(when, release) for release, when in times.items() if when <= cutoff]
        if not older:
            return None
        when, release = max(older)
        return release, when, current

    @classmethod
    def first_published(cls, ecosystem: str, name: str) -> str:
        """When the registry says a package was first published (its earliest release), ISO-8601, or "" when it cannot be said. Network."""
        times = cls.timeline(ecosystem, name, "")
        return min(times.values()).isoformat() if times else ""

    @classmethod
    def acquire(
        cls,
        ecosystem: str,
        name: str,
        version: str,
        root: Path | None = None,
        current_dependencies: tuple[str, ...] = (),
        *,
        reader: ReleaseArchiveReader,
    ) -> Baseline:
        """Fetch, hash and store the established release behind `name@version`. Network.

        A release with no established predecessor is stored too, as such: the scan then knows the
        question was asked and the answer is "nothing to compare with"."""
        from cordon_scanner.intel.registries.archive_sources.table import ArchiveSources

        ecosystem = cls.ALIASES.get(ecosystem, ecosystem)
        eco = ecosystem
        found = cls.established(eco, name, version)
        if found is None:
            baseline = Baseline(ecosystem, name, version, None)
        else:
            release, when, current = found
            archive = ArchiveSources.package_archive(eco, name, release)
            established = cls.declared(archive.data, archive.filename, ecosystem, reader)
            introduced = {
                dependency: cls.first_published(eco, dependency)
                for dependency in sorted(set(current_dependencies) - set(established))[:40]
            }
            baseline = Baseline(
                ecosystem=ecosystem,
                name=name,
                version=version,
                baseline_version=archive.version,
                baseline_published=when.isoformat(),
                published=current.isoformat(),
                files=cls.fingerprint(archive.data, archive.filename, archive.version, reader),
                dependencies=tuple(sorted(established)),
                introduced=introduced,
                obfuscated=cls.obfuscated(archive.data, archive.filename, archive.version, reader),
            )
        cls.save(baseline, root)
        return baseline


@dataclass(frozen=True)
class _ReleaseFile:
    """One file of a release, as an ecosystem reads it (`ecosystems.base.ReleaseFile`)."""

    path: str
    content: FileContent


__all__ = ["MIN_AGE_DAYS", "YOUNG_DEPENDENCY_DAYS", "Baseline", "ReleaseHistory"]
