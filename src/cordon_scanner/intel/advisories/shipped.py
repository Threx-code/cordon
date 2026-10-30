"""The advisories Cordon ships inside the package: the bundled records that always apply, and the
shipped database files, verified against their digests before a record is trusted, and indexed for
look-up by ecosystem and name.
"""

from __future__ import annotations

import gzip
from collections.abc import Mapping
from pathlib import Path
from typing import ClassVar

from cordon_scanner.foundation.once import OneOff
from cordon_scanner.intel.advisories.advisories import (
    _REFUSED_SYNCED,
    _SHARED_DATA,
    _TAMPERED,
    ADVISORY_ECOSYSTEMS,
    Advisory,
    AdvisoryDatabase,
    AdvisoryFiles,
    IndexedRecords,
)
from cordon_scanner.intel.base import IntelUpdates


class ShippedAdvisories:
    """The generated advisory records, read and cached per ecosystem."""

    _generation: ClassVar[int] = IntelUpdates.current()
    """The `IntelUpdates` generation the caches were filled at."""

    @staticmethod
    def _current() -> None:
        """Reread from the next question on, when intelligence was installed since the caches
        were filled."""
        now = IntelUpdates.current()
        if now != ShippedAdvisories._generation:
            ShippedAdvisories.reset_caches()
            ShippedAdvisories._generation = now

    @staticmethod
    def _advisory_from_dict(ecosystem: str, raw: dict[str, object]) -> Advisory:
        versions_raw = raw.get("versions")
        versions = tuple(str(v) for v in versions_raw) if isinstance(versions_raw, list) else ()
        return Advisory(
            ecosystem=ecosystem,
            name=str(raw["name"]),
            versions=versions,
            malicious=bool(raw.get("malicious", False)),
            summary=str(raw.get("summary", "")),
            reference=str(raw.get("reference", "")),
            identifier=str(raw.get("id", "")),
            severity=str(raw.get("severity", "")),
            aliases=tuple(str(a) for a in aliases_raw)
            if isinstance(aliases_raw := raw.get("aliases"), list)
            else (),
            symbols=tuple(str(x) for x in symbols_raw)
            if isinstance(symbols_raw := raw.get("symbols"), list)
            else (),
            introduced=(str(raw["introduced"]) if raw.get("introduced") else None),
            fixed=(str(raw["fixed"]) if raw.get("fixed") else None),
            last_affected=(str(raw["last_affected"]) if raw.get("last_affected") else None),
            repositories=tuple(str(r) for r in repositories_raw)
            if isinstance(repositories_raw := raw.get("repositories"), list)
            else (),
        )

    @staticmethod
    def _read_shipped(ecosystem: str) -> list[dict[str, object]]:
        """One ecosystem's generated advisory file, parsed, or an empty list.

        Missing or malformed is normal rather than an error:
        `scripts/build/build_advisory_db.py` has not been run in this checkout, or the
        sdist did not ship the directory, and `BUNDLED` carries coverage on its own
        either way.
        """
        verified = ShippedAdvisories._verified_file(ecosystem)
        return [] if verified is None else ShippedAdvisories._parse(verified[0])

    @staticmethod
    def _verified_file(ecosystem: str) -> tuple[Path, str] | None:
        """The freshest copy of one ecosystem's file and its SHA-256, only if it may be read.

        Checked against the manifest that shipped beside it. A file whose digest does not match is
        not read at all: half-trusted advisory data is worse than none, because the count still
        looks healthy. `tampered_files` records it so the detector can report the loss rather than
        let the scan come back quietly smaller.
        """
        found = AdvisoryFiles._newer_root(ecosystem)
        if found is None:
            return None
        path, name = found
        try:
            digest = AdvisoryFiles.digest_of(path)
        except OSError:
            _TAMPERED.add(name)
            return None
        recorded = AdvisoryFiles._digest_manifest(path.parent)
        if recorded and name in recorded and digest != recorded[name]:
            _TAMPERED.add(name)
            return None
        return path, digest

    @staticmethod
    def _parse(path: Path) -> list[dict[str, object]]:
        try:
            data = AdvisoryFiles._read_records(path)
        except (OSError, ValueError, EOFError, gzip.BadGzipFile):
            return []
        if not isinstance(data, list):
            return []
        return [raw for raw in data if isinstance(raw, dict) and raw.get("name")]

    @staticmethod
    @OneOff.cache
    def _shipped_raw(ecosystem: str) -> Mapping[str, tuple[dict[str, object], ...]]:
        """One ecosystem's generated records, grouped by normalised package name.

        Read once per ecosystem per process, lazily, the same as `intel/real.py`'s
        `_shipped`. Grouped but *not* turned into `Advisory` objects: building every
        record of an ecosystem costs more than reading and grouping it, and a scan
        asks about a few hundred names. `AdvisoryDatabase` constructs the ones it is
        actually asked for.

        The returned mapping is shared by every database in the process and is
        treated as read-only.
        """
        # The feed's verified deltas, on top of whichever database file won. An upsert replaces the
        # record with the same id; a withdrawal removes it. Applied here, once per ecosystem, so a
        # delta never has to rewrite a quarter of a million records to add one.
        from cordon_scanner.intel.advisories.osv_delta import OsvDelta
        from cordon_scanner.intel.malware.feed import FeedStore

        upserts, withdrawn = FeedStore.read_overlay(_SHARED_DATA.get(ecosystem, ecosystem))
        # Then what OSV changed since the database was built (`intel/osv_delta`), on top of both.
        changed, delta_withdrawn = OsvDelta.read_overlay(_SHARED_DATA.get(ecosystem, ecosystem))
        newer = {str(r.get("id")) for r in changed}
        upserts = [r for r in upserts if str(r.get("id")) not in newer] + changed
        withdrawn = withdrawn | delta_withdrawn
        replaced = {str(r.get("id")) for r in upserts} | withdrawn
        # On disk when it can be: a sealed SQLite index of the verified file, read by name
        # (`intel/advisory_index`). In memory otherwise -- no SQLite, or no writable cache.
        verified = ShippedAdvisories._verified_file(ecosystem)
        if verified is not None:
            from cordon_scanner.intel.advisories.advisory_index import AdvisoryIndex

            path, digest = verified
            index = AdvisoryIndex.for_file(digest, lambda: ShippedAdvisories._parse(path))
            if index is not None:
                return IndexedRecords(index, upserts, frozenset(replaced))
        grouped: dict[str, list[dict[str, object]]] = {}
        for raw in [] if verified is None else ShippedAdvisories._parse(verified[0]):
            if replaced and str(raw.get("id", "")) in replaced:
                continue
            grouped.setdefault(str(raw["name"]).lower(), []).append(raw)
        for raw in upserts:
            if raw.get("name"):
                grouped.setdefault(str(raw["name"]).lower(), []).append(raw)
        return {name: tuple(records) for name, records in grouped.items()}

    @staticmethod
    def reset_caches() -> None:
        """Forget what was read, so the next question sees data a feed update just installed."""
        ShippedAdvisories._shipped_raw.cache_clear()
        ShippedAdvisories._shipped.cache_clear()
        _REFUSED_SYNCED.clear()
        with AdvisoryDatabase.SHARED_LOCK:
            AdvisoryDatabase.shared = None

    @staticmethod
    def records(ecosystem: str) -> Mapping[str, tuple[dict[str, object], ...]]:
        """One ecosystem's generated records by lowercased name (`DeferredRecords`)."""
        ShippedAdvisories._current()
        return ShippedAdvisories._shipped_raw(ecosystem)

    @staticmethod
    def advisory(ecosystem: str, raw: dict[str, object]) -> Advisory:
        """One generated record as an `Advisory` (`DeferredRecords`)."""
        return ShippedAdvisories._advisory_from_dict(ecosystem, raw)

    @staticmethod
    def database() -> AdvisoryDatabase:
        """The set that ships with this release: `BUNDLED` plus, when present,
        the generated OSV-derived sets in `intel/data/`.

        The generated sets are deferred, not loaded: constructing this object is
        a stat per ecosystem, and the first `matching()` for an ecosystem is
        what reads that ecosystem's file.

        One per process, shared: each instance merges an ecosystem's records the first time it is
        asked about it, and a new instance per caller re-merged npm's quarter of a million names
        on every scan -- 38 merges and 0.7 s of a 0.9 s warm scan of a 4 KB package. A feed
        update clears it with the other caches (`reset_caches`).
        """
        ShippedAdvisories._current()
        with AdvisoryDatabase.SHARED_LOCK:
            if AdvisoryDatabase.shared is None:
                AdvisoryDatabase.shared = AdvisoryDatabase(
                    BUNDLED,
                    meta=AdvisoryFiles._meta(),
                    deferred=ADVISORY_ECOSYSTEMS,
                    source=ShippedAdvisories,
                )
            return AdvisoryDatabase.shared

    @staticmethod
    @OneOff.cache
    def _shipped(ecosystem: str) -> tuple[Advisory, ...]:
        """Every generated record for one ecosystem, as `Advisory` objects.

        The whole-set view, for the coverage floors in
        `tests/unit/intel/advisories/test_advisory_coverage.py` and anything else that asks what
        exists rather than what matches. A scan goes through `AdvisoryDatabase`,
        which never builds more than the names it was asked about.
        """
        records: list[Advisory] = []
        for raws in ShippedAdvisories._shipped_raw(ecosystem).values():
            for raw in raws:
                try:
                    records.append(ShippedAdvisories._advisory_from_dict(ecosystem, raw))
                except (KeyError, TypeError, ValueError):
                    continue
        return tuple(records)


BUNDLED: tuple[Advisory, ...] = (
    Advisory(
        ecosystem="npm",
        name="event-stream",
        versions=("3.3.6",),
        malicious=True,
        summary=(
            "Handed to a new maintainer who added a dependency containing an "
            "encrypted payload targeting a specific cryptocurrency wallet."
        ),
        reference="https://github.com/advisories/GHSA-mh6f-8j2x-4483",
        identifier="GHSA-mh6f-8j2x-4483",
    ),
    Advisory(
        ecosystem="npm",
        name="flatmap-stream",
        versions=("0.1.1",),
        malicious=True,
        summary="Published solely to carry the event-stream payload.",
        reference="https://github.com/advisories/GHSA-9x64-5r7x-2q53",
        identifier="GHSA-9x64-5r7x-2q53",
    ),
    Advisory(
        ecosystem="npm",
        name="ua-parser-js",
        versions=("0.7.29", "0.8.0", "1.0.0"),
        malicious=True,
        summary=(
            "Maintainer account compromised; the released versions installed a "
            "cryptocurrency miner and a credential stealer."
        ),
        reference="https://github.com/advisories/GHSA-pjwm-rvh2-c87w",
        identifier="GHSA-pjwm-rvh2-c87w",
    ),
    Advisory(
        ecosystem="npm",
        name="coa",
        versions=("2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.0.1", "3.1.3"),
        malicious=True,
        summary="Maintainer account compromised; released versions ran a credential stealer.",
        reference="https://github.com/advisories/GHSA-73qr-pfmq-6rp8",
        identifier="GHSA-73qr-pfmq-6rp8",
    ),
    Advisory(
        ecosystem="npm",
        name="rc",
        versions=("1.2.9", "1.3.9", "2.3.9"),
        malicious=True,
        summary="Maintainer account compromised; same payload as the coa incident.",
        reference="https://github.com/advisories/GHSA-g2q5-5433-rhrf",
        identifier="GHSA-g2q5-5433-rhrf",
    ),
    Advisory(
        ecosystem="npm",
        name="node-ipc",
        versions=("10.1.1", "10.1.2"),
        malicious=True,
        summary=(
            "The maintainer added code that overwrote files on machines "
            "geolocated to Russia or Belarus."
        ),
        reference="https://github.com/advisories/GHSA-97m3-w2cp-4xx6",
        identifier="GHSA-97m3-w2cp-4xx6",
    ),
    Advisory(
        ecosystem="npm",
        name="node-ipc",
        # A separate incident from the file-overwriting releases above, and a
        # separate advisory. Folding the two into one record made the
        # identifier wrong for whichever version matched.
        versions=("9.2.2",),
        malicious=True,
        summary=(
            "Imports a dependency that writes a file into user directories on "
            "install, added without a version bump signalling it."
        ),
        reference="https://github.com/advisories/GHSA-8gr3-2gjw-jj7g",
        identifier="GHSA-8gr3-2gjw-jj7g",
    ),
    Advisory(
        ecosystem="pypi",
        name="ctx",
        versions=(
            "0.1.2-1",
            "0.1.2-2",
            "0.1.4",
            "0.2",
            "0.2.1",
            "0.2.2",
            "0.2.2.1",
            "0.2.3",
            "0.2.4",
            "0.2.5",
            "0.2.6",
        ),
        malicious=True,
        summary="Abandoned package taken over; released versions exfiltrated environment variables.",
        reference="https://osv.dev/vulnerability/PYSEC-2022-199",
        identifier="PYSEC-2022-199",
    ),
    Advisory(
        ecosystem="pypi",
        name="torchtriton",
        versions=("2.0.0",),
        malicious=True,
        summary=(
            "Dependency-confusion package on PyPI shadowing an internal PyTorch "
            "dependency; uploaded system and credential data on install."
        ),
        reference="https://pytorch.org/blog/compromised-nightly-dependency/",
        # No advisory database carries this incident, so there is no identifier
        # to give. Empty rather than invented: an identifier is a claim that a
        # reader can look up, and one that resolves to nothing -- or worse, to
        # an unrelated advisory -- is more damaging than none at all.
        identifier="",
    ),
)
"""Documented supply-chain incidents, with the versions actually affected.

Small on purpose. This is not a substitute for an advisory feed; it is the set
whose absence made `Category.VULNERABLE` and `Confidence.CONFIRMED` unreachable,
and it is the set most likely to matter to somebody who installs this tool and
scans a lockfile they inherited. Organisations with a feed load their own with
`--advisories`.

Every identifier and version list here was checked against the OSV API rather
than written from memory. That check is the reason for several corrections: an
identifier belonging to an unrelated advisory, two incidents in one record, and
one entry whose identifier did not exist at all. A wrong identifier in a
security tool is worse than a missing one, because it survives review -- it has
the right shape, and the reader who follows it lands on a real page about a
different problem.
"""


__all__ = ["BUNDLED", "ShippedAdvisories"]
