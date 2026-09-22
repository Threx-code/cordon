"""Known-bad packages, and the advisories that name them.

`Category.VULNERABLE` was defined, documented ("A known weakness in something
depended upon. CVE, GHSA, OSV"), threaded through severity floors, policy,
filtering and every reporter -- and emitted by nothing. `Confidence.CONFIRMED`
was documented as reserved for "an exact package-and-version match against the
threat-intelligence database", and there was no such database. So the highest
confidence level the model defines was unreachable, and a whole finding category
existed only as a type.

This module is that database. Two kinds of record, and the distinction matters
more than it looks:

**Malicious.** The package version *is* the attack: a compromised release of an
otherwise legitimate package, or a package published solely to attack. Matching
one is not a judgement call, so it is reported as `MALICIOUS` at `CONFIRMED`
confidence -- the one place that level is warranted, because the finding is an
exact identity match against a recorded incident rather than an inference from
behaviour. A malicious release is also, always, a short enumerable list of
versions -- a compromise happens to specific uploads, never to "everything from
here on", so this category is exact-version-only by construction.

**Vulnerable.** The package version contains a known weakness. Reported as
`VULNERABLE`, which is a different claim: the dependency is not hostile, it is
exposed. Unlike a compromise, a vulnerability's affected set is usually a
*range* -- introduced at some version, fixed at some later one -- because an
actively maintained package keeps releasing inside the window. Matching a
range needs a version comparator, which `intel/versions.py` now provides; a
range match is therefore one small inferential step (does this version fall
between these two?) rather than a bare identity check, so it is reported at
`HIGH` confidence rather than `CONFIRMED` -- see `Advisory.is_range`.

Two sources, merged by `AdvisoryDatabase.bundled()`:

- `BUNDLED` below: a small, hand-verified set of well-known supply-chain
  incidents, each checked against the OSV API and written with a real summary
  a reader can act on without following the link.
- `intel/data/advisories-<ecosystem>.json`: a much larger set built from OSV's
  own bulk per-ecosystem export by `scripts/build_advisory_db.py`, refreshed on
  a schedule (see `.github/workflows/refresh-advisories.yml`) the same way
  `intel/data/*.txt`'s popular-package allowlists already are. Bundled with the
  release, not fetched at scan time -- a scan must still work offline. Missing
  is normal, not an error: a checkout where the sync script has not run yet, or
  a build that predates it, falls back to `BUNDLED` alone.

`AdvisoryDatabase.from_file` loads an organisation's own export instead of
either of these -- see its docstring for why that is a replacement, not a
merge.
"""

from __future__ import annotations

import functools
import gzip
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Final

DATA_DIR: Final = Path(__file__).parent / "data"

DIGESTS_NAME: Final = "advisories-digests.json"
"""A manifest of the advisory files' SHA-256 digests, written when they are.

Why this exists. `MALWARE.DEPENDENCY.KNOWN.001` is the only rule in the pack
permitted to report `Confidence.CONFIRMED`, and it -- along with
`VULNERABLE.DEPENDENCY.KNOWN.001` -- is driven entirely by these JSON files.
`RuleLoader.load_builtin` guards the rule pack against truncation with a count
floor; nothing guarded the data at all. A compromised refresh job, a
compromised maintainer account, or a bad dependency of
`scripts/build_advisory_db.py` could delist one npm package -- the one being
shipped that week -- and the scan would report a clean result with the count
still in the tens of thousands.

What it is and is not. Verifying a digest against a manifest that travels in
the same wheel proves the two agree, not that either is authentic. What makes
it worth having is the wheel's own signature: the release is cosign-signed with
SLSA provenance, so the manifest is covered by that attestation, and an edit to
a data file after the fact has to also edit a manifest inside a signed
artefact. That is the same argument `Guard`'s `.cordon-guard.sha256` makes for
hooks in a scanned repository -- tampering is not prevented, it is made unable
to be silent -- applied here to the tool's own most-trusted data."""


class DigestMismatch(Exception):
    """An advisory file's contents do not match the manifest shipped with it."""


def _digest_manifest(root: Path) -> dict[str, str]:
    """The digests recorded for this root, or empty when there is no manifest.

    Empty is not a failure. A checkout that has never run
    `scripts/build_advisory_db.py` has neither data nor manifest, and the sdist
    may ship neither -- so an absent manifest means "nothing to check against",
    while a present one that disagrees means something to say out loud.
    """
    try:
        data = json.loads((root / DIGESTS_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items() if isinstance(v, str)}


def digest_of(path: Path) -> str:
    """The SHA-256 of a file, hex, read in bounded chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_data_dir(root: Path = DATA_DIR) -> tuple[str, ...]:
    """The names of any advisory files that disagree with the manifest.

    Every file the manifest names is checked, so a DELETED file is a mismatch
    too -- which is the cheapest way to water the database down and the one a
    digest-per-present-file scheme would miss entirely.
    """
    recorded = _digest_manifest(root)
    if not recorded:
        return ()
    bad: list[str] = []
    for name, expected in sorted(recorded.items()):
        path = root / name
        try:
            if digest_of(path) != expected:
                bad.append(name)
        except OSError:
            bad.append(name)
    return tuple(bad)


#: Ecosystems an advisory file may exist for. Gradle and Maven name the same
#: artefacts, so one file serves both -- the same sharing `intel/real.py`
#: already does for its own per-ecosystem data.
_SHARED_DATA: Final[dict[str, str]] = {"gradle": "maven"}
ADVISORY_ECOSYSTEMS: Final[tuple[str, ...]] = (
    "npm",
    "pypi",
    "cargo",
    "gomod",
    "maven",
    "gradle",
    "nuget",
    "composer",
    "rubygems",
    "pub",
    "hex",
    "cran",
    "swift",
)


@dataclass(frozen=True, slots=True)
class Advisory:
    """One record about one package."""

    ecosystem: str
    name: str
    versions: tuple[str, ...] = ()
    """Exact affected versions -- the only form a `malicious=True` record
    takes (see the module docstring). A `malicious=False` record may use this
    instead of a range when its source already enumerated the affected set."""

    malicious: bool = False
    summary: str = ""
    reference: str = ""
    identifier: str = ""
    severity: str = ""
    """The source's own severity rating (`low`/`moderate`/`medium`/`high`/
    `critical`), mapped to a `Severity` by the detector. Empty means the
    source gave none, which the detector treats as `HIGH` -- unrated is not
    the same claim as low, and defaulting there would under-report."""

    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    """A range in OSV's own vocabulary: affected from `introduced` (inclusive,
    `"0"` for "no lower bound") up to `fixed` (exclusive) or through
    `last_affected` (inclusive). Only consulted when `versions` is empty --
    see `affects`."""

    def __post_init__(self) -> None:
        if self.versions and (self.introduced or self.fixed or self.last_affected):
            raise ValueError(
                f"{self.ecosystem}/{self.name}: an advisory is an exact list or a "
                f"range, never both -- a record with both is ambiguous about "
                f"which one governs a version in the list but outside the range"
            )

    @property
    def is_range(self) -> bool:
        """Whether this record's affected set is a range rather than a list.

        A range match is an inference (a version comparison); an exact-list
        match is an identity check. The detector uses this to decide between
        `HIGH` and `CONFIRMED` confidence.
        """
        return not self.versions and bool(self.introduced or self.fixed or self.last_affected)

    def affects(self, version: str | None) -> bool:
        """Whether this record covers a resolved version.

        A dependency with no resolved version does not match. Reporting one
        would mean flagging a package by name alone, and the name is shared with
        every version that was never compromised.
        """
        if not version:
            return False
        if self.versions:
            if version in self.versions:
                return True
            # The same release, spelled differently. An enumerated record lists
            # versions as the upstream feed spells them -- OSV names Django's
            # release "3.2" -- while a lockfile may pin the equivalent "3.2.0",
            # which `pip install` resolves to that same release. String equality
            # makes those two different package-versions; the comparator that
            # decides the range branch below decides this one too.
            from cordon_scanner.intel.versions import compare

            return any(compare(self.ecosystem, version, known) == 0 for known in self.versions)
        if self.is_range:
            from cordon_scanner.intel.versions import in_range

            return in_range(
                self.ecosystem,
                version,
                introduced=self.introduced,
                fixed=self.fixed,
                last_affected=self.last_affected,
            )
        return False


@dataclass(frozen=True, slots=True)
class DatabaseMeta:
    """When and from where the bundled OSV-derived data was built.

    Reported once per scan by `AdvisoryDetector` so a user sees how current
    the coverage is, the way `trivy`'s DB banner or `grype db check` do,
    rather than a bundled snapshot silently standing in for a live one.
    """

    built_at: str = ""
    sources: tuple[str, ...] = ()
    record_count: int = 0
    filtered: bool = False
    """Whether this build kept only malicious entries and high/critical
    vulnerabilities (`scripts/build_advisory_db.py`'s default, to bound the
    wheel's size) rather than everything OSV reported. A user reading a
    coverage note that says "27,000 records" needs to know that number is a
    deliberate cut, not the whole of what exists -- `AdvisoryDetector`'s
    staleness note says so when this is `True`."""


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
        introduced=(str(raw["introduced"]) if raw.get("introduced") else None),
        fixed=(str(raw["fixed"]) if raw.get("fixed") else None),
        last_affected=(str(raw["last_affected"]) if raw.get("last_affected") else None),
    )


def user_sync_dir() -> Path:
    """Where `cordon-scanner advisories sync` writes.

    Not inside the installed package -- a running CLI has no business writing
    into `site-packages`, and a system install usually cannot anyway.
    `ScanCache.default_cache_dir()` is the same environment-directed cache
    root scan results already use (honours `CORDON_CACHE_DIR`/
    `XDG_CACHE_HOME`, falls back to `~/.cache/cordon`); safe to share here
    because, unlike the cache's MAC key (`ScanCache.key_dir`), nothing about
    this location needs to resist an attacker who controls the environment --
    a sync is an operator running a command, not a scan reading a target.
    """
    from cordon_scanner.core.cache import ScanCache

    return ScanCache.default_cache_dir() / "advisories"


def _read_meta(root: Path) -> DatabaseMeta:
    path = root / "advisories-meta.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return DatabaseMeta()
    if not isinstance(data, dict):
        return DatabaseMeta()
    return DatabaseMeta(
        built_at=str(data.get("built_at", "")),
        sources=tuple(str(s) for s in data.get("sources") or ()),
        record_count=int(data.get("record_count", 0)),
        filtered=bool(data.get("filtered", False)),
    )


def data_file_names(ecosystem: str) -> tuple[str, ...]:
    """The file names one ecosystem's advisories may be stored under, best first.

    Compressed first. The advisory data is the largest thing in the wheel by an
    order of magnitude and it is JSON, which is the most compressible shape
    there is -- so it ships gzipped, and a scan reads it through `gzip` rather
    than carrying thirty megabytes of text to save a decompression that takes
    milliseconds once per process.

    The uncompressed name is still read, because a cache directory written by an
    earlier `advisories sync` holds one and a user is owed their sync rather than
    a silent fall back to the wheel.
    """
    base = _SHARED_DATA.get(ecosystem, ecosystem)
    return (f"advisories-{base}.json.gz", f"advisories-{base}.json")


def _read_records(path: Path) -> object:
    """One advisory file's parsed contents, gzipped or plain."""
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            return json.load(handle)
    return json.loads(path.read_text(encoding="utf-8"))


def _newer_root(ecosystem: str) -> tuple[Path, str] | None:
    """The path and manifest name of the freshest copy of one ecosystem's file.

    Per-file, not per-directory. An earlier version of this compared the two
    roots wholesale by their `advisories-meta.json` `built_at` and used
    whichever was newer for *every* ecosystem -- so `advisories sync --only
    cargo` (a newer, but partial, user directory) silently made every other
    ecosystem's coverage disappear, because the wheel's otherwise-current npm
    and pypi files were never looked at again. Comparing file by file means a
    narrow sync can only ever add freshness, never remove coverage the wheel
    already had.

    The user directory is examined first so that a tie in modification time
    resolves to the copy the operator asked for.
    """
    best: tuple[float, Path, str] | None = None
    for root in (user_sync_dir(), DATA_DIR):
        for name in data_file_names(ecosystem):
            path = root / name
            try:
                mtime = path.stat().st_mtime
            except OSError:
                continue
            if best is None or mtime > best[0]:
                best = (mtime, path, name)
            break
    return (best[1], best[2]) if best is not None else None


_TAMPERED: set[str] = set()
"""Advisory files refused this process because their digest did not match.

Module-level because `_shipped` is `functools.cache`d and lazy: the check
happens on first use of an ecosystem, which is well after the database object
was built, so the result has to be readable afterwards rather than returned."""


def tampered_files() -> tuple[str, ...]:
    """Advisory files that were refused, for the detector to report."""
    return tuple(sorted(_TAMPERED))


def _read_shipped(ecosystem: str) -> list[dict[str, object]]:
    """One ecosystem's generated advisory file, parsed, or an empty list.

    Missing or malformed is normal rather than an error:
    `scripts/build_advisory_db.py` has not been run in this checkout, or the
    sdist did not ship the directory, and `BUNDLED` carries coverage on its own
    either way.
    """
    found = _newer_root(ecosystem)
    if found is None:
        return []
    path, name = found
    # Checked against the manifest that shipped beside it. A file whose digest
    # does not match is not read at all: half-trusted advisory data is worse
    # than none, because the count still looks healthy. `tampered_files`
    # records it so the detector can report the loss rather than let the scan
    # come back quietly smaller.
    recorded = _digest_manifest(path.parent)
    if recorded and name in recorded:
        try:
            if digest_of(path) != recorded[name]:
                _TAMPERED.add(name)
                return []
        except OSError:
            _TAMPERED.add(name)
            return []
    try:
        data = _read_records(path)
    except (OSError, ValueError, EOFError, gzip.BadGzipFile):
        return []
    if not isinstance(data, list):
        return []
    return [raw for raw in data if isinstance(raw, dict) and raw.get("name")]


@functools.cache
def _shipped_raw(ecosystem: str) -> dict[str, tuple[dict[str, object], ...]]:
    """One ecosystem's generated records, grouped by normalised package name.

    Read once per ecosystem per process, lazily, the same as `intel/real.py`'s
    `_shipped`. Grouped but *not* turned into `Advisory` objects: building every
    record of an ecosystem costs more than reading and grouping it, and a scan
    asks about a few hundred names. `AdvisoryDatabase` constructs the ones it is
    actually asked for.

    The returned mapping is shared by every database in the process and is
    treated as read-only.
    """
    grouped: dict[str, list[dict[str, object]]] = {}
    for raw in _read_shipped(ecosystem):
        grouped.setdefault(str(raw["name"]).lower(), []).append(raw)
    return {name: tuple(records) for name, records in grouped.items()}


@functools.cache
def _shipped(ecosystem: str) -> tuple[Advisory, ...]:
    """Every generated record for one ecosystem, as `Advisory` objects.

    The whole-set view, for the coverage floors in
    `tests/unit/test_advisory_coverage.py` and anything else that asks what
    exists rather than what matches. A scan goes through `AdvisoryDatabase`,
    which never builds more than the names it was asked about.
    """
    records: list[Advisory] = []
    for raws in _shipped_raw(ecosystem).values():
        for raw in raws:
            try:
                records.append(_advisory_from_dict(ecosystem, raw))
            except (KeyError, TypeError, ValueError):
                continue
    return tuple(records)


def _meta() -> DatabaseMeta:
    """The fresher of the two roots' own metadata, for the coverage note.

    A courtesy figure, not a per-file audit trail -- the same simplification
    `grype db check` and `trivy`'s DB banner make, reporting one version for
    a database assembled from many original publish dates. `_shipped` is
    what actually decides which file backs a given match; this only decides
    what date a human reads.
    """
    user_meta = _read_meta(user_sync_dir())
    wheel_meta = _read_meta(DATA_DIR)
    return user_meta if user_meta.built_at > wheel_meta.built_at else wheel_meta


class AdvisoryDatabase:
    """The advisories this installation knows about.

    Populated one ecosystem at a time, on the first question about it. The
    bundled set is a quarter of a million records across thirteen ecosystems,
    and building all of them is work a scan mostly does not need: an npm project
    needs npm, and a target with no dependency graph needs none of it, since
    `AdvisoryDetector.inspect` only runs for a `GraphUnit`.
    """

    def __init__(
        self,
        advisories: tuple[Advisory, ...] = (),
        *,
        meta: DatabaseMeta | None = None,
        deferred: tuple[str, ...] = (),
    ) -> None:
        self._by_key: dict[tuple[str, str], list[Advisory]] = {}
        #: How many records exist per ecosystem, counted as they are read rather
        #: than as they are built, so `covers` can answer without materialising.
        self._counts: dict[str, int] = {}
        for advisory in advisories:
            self._add(advisory)
            self._counts[advisory.ecosystem] = self._counts.get(advisory.ecosystem, 0) + 1
        #: Generated records for a loaded ecosystem, still as parsed JSON and
        #: keyed the same way, built into `Advisory` objects by the first
        #: question about that package name.
        self._raw: dict[tuple[str, str], tuple[dict[str, object], ...]] = {}
        self.meta = meta or DatabaseMeta()
        self._deferred = set(deferred)
        #: The curated records, by the identity a generated record would collide
        #: on. Only these suppress a shipped record -- see `_load`.
        self._curated = {
            (a.ecosystem, a.name.lower(), a.identifier) for a in advisories if a.identifier
        }

    def _add(self, advisory: Advisory) -> None:
        self._by_key.setdefault((advisory.ecosystem, advisory.name.lower()), []).append(advisory)

    def _load(self, ecosystem: str) -> None:
        """Merge one ecosystem's generated set in, once.

        `BUNDLED`'s hand-written entries take precedence on a collision -- they
        carry a summary written for a reader, and the point of curating them by
        hand was never to be silently duplicated by a generated pass over the
        same incident.

        The collision key is (ecosystem, **name**, identifier), because an
        advisory identifier is not unique within an ecosystem in either of the
        two ways OSV uses it: one GHSA names several packages -- every
        `tensorflow` advisory also names `tensorflow-gpu` and `tensorflow-cpu` --
        and one GHSA becomes several records when the affected set is several
        disjoint version windows. Keyed on the identifier alone, each of those
        siblings looks like a duplicate of the first and is dropped.
        """
        if ecosystem not in self._deferred:
            return
        self._deferred.discard(ecosystem)
        for name, raws in _shipped_raw(ecosystem).items():
            key = (ecosystem, name)
            existing = self._raw.get(key)
            self._raw[key] = raws if existing is None else existing + raws
            self._counts[ecosystem] = self._counts.get(ecosystem, 0) + len(raws)

    def _materialise(self, key: tuple[str, str]) -> None:
        """Build the `Advisory` objects for one package name, once."""
        raws = self._raw.pop(key, None)
        if raws is None:
            return
        ecosystem, name = key
        for raw in raws:
            try:
                advisory = _advisory_from_dict(ecosystem, raw)
            except (KeyError, TypeError, ValueError):
                continue
            if (ecosystem, name, advisory.identifier) in self._curated:
                continue
            self._add(advisory)

    def _load_all(self) -> None:
        for ecosystem in tuple(self._deferred):
            self._load(ecosystem)
        for key in tuple(self._raw):
            self._materialise(key)

    def __len__(self) -> int:
        """Every record, which means loading every ecosystem.

        A total is a question about the whole database, so it cannot be answered
        lazily. Nothing on the scan path asks for it -- `is_empty` is what the
        detector uses -- so this stays exact rather than becoming an estimate.
        """
        self._load_all()
        return sum(len(v) for v in self._by_key.values())

    @property
    def is_empty(self) -> bool:
        """Whether there is nothing here to match against, without loading.

        The detector reports an empty database as a coverage loss, and that
        check runs on every scan with a dependency graph -- so answering it must
        not undo the laziness. A deferred ecosystem counts as content when its
        file is on disk: whether that file then parses is the question
        `tampered_files` and the parse itself answer, each with their own
        report.
        """
        if self._by_key or self._raw:
            return False
        return all(_newer_root(ecosystem) is None for ecosystem in self._deferred)

    def covers(self, ecosystem: str) -> bool:
        """Whether this database holds any record for an ecosystem at all.

        Asked instead of "is there a feed configured for it", because a feed can
        be configured, requested and still produce nothing -- and a list of
        configured sources would then report an ecosystem as covered while no
        record existed to match against. What a scan is entitled to know is
        whether anything was there.
        """
        self._load(ecosystem)
        return self._counts.get(ecosystem, 0) > 0

    @classmethod
    def bundled(cls) -> AdvisoryDatabase:
        """The set that ships with this release: `BUNDLED` plus, when present,
        the generated OSV-derived sets in `intel/data/`.

        The generated sets are deferred, not loaded: constructing this object is
        a stat per ecosystem, and the first `matching()` for an ecosystem is
        what reads that ecosystem's file.
        """
        return cls(BUNDLED, meta=_meta(), deferred=ADVISORY_ECOSYSTEMS)

    @classmethod
    def from_file(cls, path: str | Path) -> AdvisoryDatabase:
        """Load an export, for an organisation that maintains its own.

        The format is a JSON list of objects with the fields of :class:`Advisory`.
        Deliberately plain: an air-gapped site has to be able to produce this
        from an OSV dump with a short script and no network access at scan time.

        Replaces the bundled database entirely rather than adding to it --
        see `AdvisoryDetector.__init__` and `TestVulnerableCategory` in
        `tests/integration/test_review_advisories.py` for why: stating what an
        organisation acts on and silently supplementing it with the shipped
        list would produce findings it did not choose.
        """
        from cordon_scanner.core.errors import ConfigError

        file = Path(path)
        try:
            data = _read_records(file)
        except (OSError, ValueError, EOFError, gzip.BadGzipFile) as exc:
            raise ConfigError(f"{file}: advisory file is not readable JSON: {exc}") from exc
        if not isinstance(data, list):
            raise ConfigError(f"{file}: advisory file must be a JSON list")

        records: list[Advisory] = []
        for index, raw in enumerate(data):
            if not isinstance(raw, dict):
                raise ConfigError(f"{file}: entry {index} is not an object")
            versions = tuple(str(v) for v in raw.get("versions") or ())
            introduced = str(raw["introduced"]) if raw.get("introduced") else None
            fixed = str(raw["fixed"]) if raw.get("fixed") else None
            last_affected = str(raw["last_affected"]) if raw.get("last_affected") else None
            if not versions and not (introduced or fixed or last_affected):
                raise ConfigError(
                    f"{file}: entry {index} is missing 'versions' (or a range: "
                    f"'introduced'/'fixed'/'last_affected') -- a record must name what it affects"
                )
            try:
                records.append(
                    Advisory(
                        ecosystem=str(raw["ecosystem"]),
                        name=str(raw["name"]),
                        versions=versions,
                        malicious=bool(raw.get("malicious", False)),
                        summary=str(raw.get("summary", "")),
                        reference=str(raw.get("reference", "")),
                        identifier=str(raw.get("id", "")),
                        severity=str(raw.get("severity", "")),
                        introduced=introduced,
                        fixed=fixed,
                        last_affected=last_affected,
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ConfigError(f"{file}: entry {index} is missing {exc}") from exc
        return cls(tuple(records))

    def matching(self, ecosystem: str, name: str, version: str | None) -> tuple[Advisory, ...]:
        """Every record covering this exact package and version."""
        return tuple(a for a in self.for_package(ecosystem, name) if a.affects(version))

    def for_package(self, ecosystem: str, name: str) -> tuple[Advisory, ...]:
        """Every record about a package, whatever version it names.

        What `matching` filters. Asked separately because the useful half of a
        vulnerability finding is the version to move to, and deciding that means
        looking at the advisories the current version does *not* match: a fix for
        one of them is not a fix if the next advisory names it too.
        """
        self._load(ecosystem)
        key = (ecosystem, name.lower())
        self._materialise(key)
        return tuple(self._by_key.get(key, ()))


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

__all__ = [
    "BUNDLED",
    "DATA_DIR",
    "Advisory",
    "AdvisoryDatabase",
    "DatabaseMeta",
    "user_sync_dir",
]
