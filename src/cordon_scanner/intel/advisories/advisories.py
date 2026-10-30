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

Two sources, merged by `ShippedAdvisories.database()`:

- `BUNDLED` below: a small, hand-verified set of well-known supply-chain
  incidents, each checked against the OSV API and written with a real summary
  a reader can act on without following the link.
- `intel/data/advisories-<ecosystem>.json`: a much larger set built from OSV's
  own bulk per-ecosystem export by `scripts/build/build_advisory_db.py`, refreshed on
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

import gzip
import hashlib
import json
import threading
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Final, Protocol

from cordon_scanner.foundation.files.seal import SEAL_KEY, LocalSeal
from cordon_scanner.foundation.paths import PackagePaths

DATA_DIR: Final = PackagePaths.data("intel")

DIGESTS_NAME: Final = "advisories-digests.json"
"""A manifest of the advisory files' SHA-256 digests, written when they are.

Why this exists. `MALWARE.DEPENDENCY.KNOWN.001` is the only rule in the pack
permitted to report `Confidence.CONFIRMED`, and it -- along with
`VULNERABLE.DEPENDENCY.KNOWN.001` -- is driven entirely by these JSON files.
`RuleLoader.load_builtin` guards the rule pack against truncation with a count
floor; nothing guarded the data at all. A compromised refresh job, a
compromised maintainer account, or a bad dependency of
`scripts/build/build_advisory_db.py` could delist one npm package -- the one being
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
_REFUSED_SYNCED: set[str] = set()
"""Synced files refused for want of this install's seal. Reported; never blocks the shipped copy."""


class DigestMismatch(Exception):
    """An advisory file's contents do not match the manifest shipped with it."""


class AdvisoryFiles:
    """Where advisory files live, which copy is newest, and whether they match their digests."""

    @staticmethod
    def _digest_manifest(root: Path) -> dict[str, str]:
        """The digests recorded for this root, or empty when there is no manifest.

        Empty is not a failure. A checkout that has never run
        `scripts/build/build_advisory_db.py` has neither data nor manifest, and the sdist
        may ship neither -- so an absent manifest means "nothing to check against",
        while a present one that disagrees means something to say out loud.
        """
        try:
            data = json.loads((root / DIGESTS_NAME).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if not isinstance(data, dict):
            return {}
        return {str(k): str(v) for k, v in data.items() if isinstance(v, str) and k != SEAL_KEY}

    @staticmethod
    def seal_manifest(root: Path) -> None:
        """Seal a digest manifest this install just wrote or verified. See `core.local_seal`."""
        path = root / DIGESTS_NAME
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if isinstance(data, dict):
            sealed = LocalSeal.sealed("advisory-manifest", data)
            path.write_text(json.dumps(sealed, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    @staticmethod
    def trusted_user_file(name: str) -> Path | None:
        """A file in the synced directory, only if this install wrote it.

        The directory is chosen by the environment and restored from shared CI caches, so a
        file there is read only when the directory's digest manifest carries this install's
        seal and lists the file with a matching digest. Anything else is refused and reported --
        and refusing it never removes the shipped copy, which would turn a planted file into a
        way to delete coverage.
        """
        root = AdvisoryFiles.user_sync_dir()
        path = root / name
        if not path.is_file():
            return None
        try:
            manifest = json.loads((root / DIGESTS_NAME).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            manifest = None
        if not LocalSeal.valid("advisory-manifest", manifest):
            _REFUSED_SYNCED.add(name)
            return None
        assert isinstance(manifest, dict)  # noqa: S101 - established by valid()
        try:
            matches = manifest.get(name) == AdvisoryFiles.digest_of(path)
        except OSError:
            matches = False
        if not matches:
            _REFUSED_SYNCED.add(name)
            return None
        return path

    @staticmethod
    def refused_synced_files() -> tuple[str, ...]:
        """Synced files that were not read because this install did not write them."""
        return tuple(sorted(_REFUSED_SYNCED))

    @staticmethod
    def digest_of(path: Path) -> str:
        """The SHA-256 of a file, hex, read in bounded chunks."""
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def verify_data_dir(root: Path = DATA_DIR) -> tuple[str, ...]:
        """The names of any advisory files that disagree with the manifest.

        Every file the manifest names is checked, so a DELETED file is a mismatch
        too -- which is the cheapest way to water the database down and the one a
        digest-per-present-file scheme would miss entirely.
        """
        recorded = AdvisoryFiles._digest_manifest(root)
        if not recorded:
            return ()
        bad: list[str] = []
        for name, expected in sorted(recorded.items()):
            path = root / name
            try:
                if AdvisoryFiles.digest_of(path) != expected:
                    bad.append(name)
            except OSError:
                bad.append(name)
        return tuple(bad)

    @staticmethod
    def user_sync_dir() -> Path:
        """Where `cordon-scanner advisories sync` writes.

        Not inside the installed package -- a running CLI has no business writing
        into `site-packages`, and a system install usually cannot anyway.
        `StatePaths.default_cache_dir()` is the same environment-directed cache
        root scan results already use (honours `CORDON_CACHE_DIR`/
        `XDG_CACHE_HOME`, falls back to `~/.cache/cordon`); safe to share here
        because, unlike the cache's MAC key (`ScanCache.key_dir`), nothing about
        this location needs to resist an attacker who controls the environment --
        a sync is an operator running a command, not a scan reading a target.
        """
        from cordon_scanner.foundation.paths import StatePaths

        return StatePaths.synced_intel_dir()

    @staticmethod
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

    @staticmethod
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

    @staticmethod
    def _read_records(path: Path) -> object:
        """One advisory file's parsed contents, gzipped or plain."""
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                return json.load(handle)
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
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
        for root in (AdvisoryFiles.user_sync_dir(), DATA_DIR):
            for name in AdvisoryFiles.data_file_names(ecosystem):
                path = root / name
                if (
                    root != DATA_DIR
                    and path.exists()
                    and AdvisoryFiles.trusted_user_file(name) is None
                ):
                    break
                try:
                    mtime = path.stat().st_mtime
                except OSError:
                    continue
                if best is None or mtime > best[0]:
                    best = (mtime, path, name)
                break
        return (best[1], best[2]) if best is not None else None

    @staticmethod
    def tampered_files() -> tuple[str, ...]:
        """Advisory files that were refused, for the detector to report."""
        return tuple(sorted(_TAMPERED))

    @staticmethod
    def _meta() -> DatabaseMeta:
        """The fresher of the two roots' own metadata, for the coverage note.

        A courtesy figure, not a per-file audit trail -- the same simplification
        `grype db check` and `trivy`'s DB banner make, reporting one version for
        a database assembled from many original publish dates. `_shipped` is
        what actually decides which file backs a given match; this only decides
        what date a human reads.
        """
        user_meta = (
            AdvisoryFiles._read_meta(AdvisoryFiles.user_sync_dir())
            if AdvisoryFiles.trusted_user_file("advisories-meta.json") is not None
            else DatabaseMeta()
        )
        wheel_meta = AdvisoryFiles._read_meta(DATA_DIR)
        return user_meta if user_meta.built_at > wheel_meta.built_at else wheel_meta


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
    "vscode",
    "actions",
    "git",
    "hackage",
    "julia",
    "opam",
    # Followed by Cordon's registry watchers (cordon-backend), matched from the feed alone: conda and
    # cocoapods and bazel by name and exact version, the recipe registries (homebrew, conan, vcpkg,
    # nix) by the recipe file's digest (`detect/supply/recipe_digests`). Galaxy is `ansible` here.
    "conda",
    "ansible",
    "cocoapods",
    "bazel",
    "homebrew",
    "conan",
    "vcpkg",
    "nix",
    # The watch-list registries and MCP (cordon-backend task 22), from the feed alone: a Terraform
    # module and an image by name and exact version (an image's digest is one of its versions), a Helm
    # chart by name and version only from a repository the record names, and an MCP bundle by its
    # digest (`recipe_digests`).
    "helm",
    "terraform",
    "image",
    "mcp",
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

    aliases: tuple[str, ...] = ()
    """Other identifiers for the same vulnerability -- the CVE ids OSV lists as aliases, which is
    what exploited-vulnerability catalogues key on."""

    symbols: tuple[str, ...] = ()
    """The vulnerable functions, as `import/path:Symbol` or `import/path:Type.Method`, where the
    source names them -- the Go vulnerability database does for nearly every record. What lets a
    finding say whether first-party code calls the vulnerable code, not merely the package."""

    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    """A range in OSV's own vocabulary: affected from `introduced` (inclusive,
    `"0"` for "no lower bound") up to `fixed` (exclusive) or through
    `last_affected` (inclusive). Only consulted when `versions` is empty --
    see `affects`."""

    repositories: tuple[str, ...] = ()
    """For a Helm chart, every spelling of the chart repository the record is about (its URL, its
    OCI location, `registry:<name>`): a chart is named by its chart name alone, and two repositories'
    `redis` are different code, so the record matches a dependency only from one of these."""

    matched_through: str = ""
    """How a record not about the package itself was matched to it (`intel/
    upstream_advisories`): `upstream` through the repository and ref, Go module or registry
    archive its ecosystem names; `inferred` through a tag found in the repository it names.
    Empty for a record about the package, matched by its own name and version."""

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
            from cordon_scanner.intel.advisories.versions import Versions

            return any(
                Versions.compare(self.ecosystem, version, known) == 0 for known in self.versions
            )
        if self.is_range:
            from cordon_scanner.intel.advisories.versions import Versions

            return Versions.in_range(
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
    vulnerabilities (`scripts/build/build_advisory_db.py`'s default, to bound the
    wheel's size) rather than everything OSV reported. A user reading a
    coverage note that says "27,000 records" needs to know that number is a
    deliberate cut, not the whole of what exists -- `AdvisoryDetector`'s
    staleness note says so when this is `True`."""


class IndexedRecords(Mapping[str, tuple[dict[str, object], ...]]):
    """One ecosystem's records by lowercased name, read from its sealed index on demand.

    The same mapping `_shipped_raw` returns from memory, with the same overlay: a record whose id
    the feed or the OSV delta replaced or withdrew is left out, and their records are added. A name
    with no record left is absent, exactly as it would be from the in-memory grouping.
    """

    def __init__(
        self,
        index: Any,
        upserts: list[dict[str, object]],
        replaced: frozenset[str],
    ) -> None:
        self._index = index
        self._replaced = replaced
        self._upserts: dict[str, list[dict[str, object]]] = {}
        for raw in upserts:
            if raw.get("name"):
                self._upserts.setdefault(str(raw["name"]).lower(), []).append(raw)
        self.record_count = index.count_except(replaced) + sum(
            len(v) for v in self._upserts.values()
        )

    def __getitem__(self, name: str) -> tuple[dict[str, object], ...]:
        records = [r for r in self._index.get(name) if str(r.get("id", "")) not in self._replaced]
        records += self._upserts.get(name, [])
        if not records:
            raise KeyError(name)
        return tuple(records)

    def __iter__(self) -> Iterator[str]:
        for name in dict.fromkeys([*self._index.names(), *self._upserts]):
            if name in self:
                yield name

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        try:
            self[name]
        except KeyError:
            return False
        return True

    def __len__(self) -> int:
        return sum(1 for _ in self)


_TAMPERED: set[str] = set()
"""Advisory files refused this process because their digest did not match.

Module-level because `_shipped` is `functools.cache`d and lazy: the check
happens on first use of an ecosystem, which is well after the database object
was built, so the result has to be readable afterwards rather than returned."""


class DeferredRecords(Protocol):
    """Where a database's deferred ecosystems come from: each one's generated records by
    lowercased name, and how one record becomes an `Advisory`. Handed in by whoever builds the
    database (`ShippedAdvisories.database`), so this type depends on no source of records."""

    def records(self, ecosystem: str) -> Mapping[str, tuple[dict[str, object], ...]]: ...
    def advisory(self, ecosystem: str, raw: dict[str, object]) -> Advisory: ...


class AdvisoryDatabase:
    """The advisories this installation knows about.

    Populated one ecosystem at a time, on the first question about it. The
    bundled set is a quarter of a million records across thirteen ecosystems,
    and building all of them is work a scan mostly does not need: an npm project
    needs npm, and a target with no dependency graph needs none of it, since
    `AdvisoryDetector.inspect` only runs for a `GraphUnit`.
    """

    shared: ClassVar[AdvisoryDatabase | None] = None
    """The one bundled instance in this process (`ShippedAdvisories.database`); `None` until first asked, and again
    after a feed update (`ShippedAdvisories.reset_caches`)."""
    SHARED_LOCK: ClassVar[threading.Lock] = threading.Lock()

    def __init__(
        self,
        advisories: tuple[Advisory, ...] = (),
        *,
        meta: DatabaseMeta | None = None,
        deferred: tuple[str, ...] = (),
        source: DeferredRecords | None = None,
    ) -> None:
        self._by_key: dict[tuple[str, str], list[Advisory]] = {}
        #: How many records exist per ecosystem, counted as they are read rather
        #: than as they are built, so `covers` can answer without materialising.
        self._counts: dict[str, int] = {}
        self._lock = threading.RLock()
        for advisory in advisories:
            self._add(advisory)
            self._counts[advisory.ecosystem] = self._counts.get(advisory.ecosystem, 0) + 1
        #: Each loaded ecosystem's generated records by lowercased name -- an on-disk index or
        #: an in-memory grouping (`DeferredRecords.records`) -- read for a name, and built
        #: into `Advisory` objects, by the first question about that name.
        self._sources: dict[str, Mapping[str, tuple[dict[str, object], ...]]] = {}
        self._built: set[tuple[str, str]] = set()
        self.meta = meta or DatabaseMeta()
        self._deferred = set(deferred) if source is not None else set()
        self._source = source
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
        if ecosystem not in self._deferred or self._source is None:
            return
        # Under the lock, and marked loaded only once merged: the instance is shared by every
        # caller in the process (`ShippedAdvisories.database`), and a thread that saw the mark before the merge ended
        # would answer from half a database.
        with self._lock:
            if ecosystem not in self._deferred:
                return
            source = self._source.records(ecosystem)
            self._sources[ecosystem] = source
            count = (
                source.record_count
                if isinstance(source, IndexedRecords)
                else sum(len(raws) for raws in source.values())
            )
            self._counts[ecosystem] = self._counts.get(ecosystem, 0) + count
            self._deferred.discard(ecosystem)

    def _materialise(self, key: tuple[str, str]) -> None:
        """Build the `Advisory` objects for one package name, once. Wholly under the lock: a
        thread that returned while another was still adding this name's records would read
        none of them."""
        with self._lock:
            if key in self._built or self._source is None:
                return
            self._built.add(key)
            ecosystem, name = key
            source = self._sources.get(ecosystem)
            raws = source.get(name) if source is not None else None
            if not raws:
                return
            for raw in raws:
                try:
                    advisory = self._source.advisory(ecosystem, raw)
                except (KeyError, TypeError, ValueError):
                    continue
                if (ecosystem, name, advisory.identifier) in self._curated:
                    continue
                self._add(advisory)

    def _load_all(self) -> None:
        for ecosystem in tuple(self._deferred):
            self._load(ecosystem)
        for ecosystem, source in tuple(self._sources.items()):
            for name in source:
                self._materialise((ecosystem, name))

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
        if self._by_key or any(self._counts.get(e, 0) for e in self._sources):
            return False
        return all(AdvisoryFiles._newer_root(ecosystem) is None for ecosystem in self._deferred)

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
        from cordon_scanner.foundation.errors import ConfigError

        file = Path(path)
        try:
            data = AdvisoryFiles._read_records(file)
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
        # Equal records under two spellings are one record, kept in first-seen order. A dict, not
        # `a not in found` over a list: that compared every record with every other, and a
        # package with thousands of records (the Linux kernel's, Go's standard library) made one
        # scan spend ten minutes here.
        found: dict[Advisory, None] = {}
        for spelling in AdvisoryDatabase.spellings(ecosystem, name):
            key = (ecosystem, spelling)
            self._materialise(key)
            found.update(dict.fromkeys(self._by_key.get(key, ())))
        return AdvisoryDatabase._as_named(ecosystem, name, tuple(found))

    WHOLE_ITEM_RECORDS: Final = frozenset({"vscode"})
    """Marketplaces whose malicious records condemn the item, not some of its uploads: an editor
    extension found malicious is removed whole, and a recommendation names no version at all."""

    CASE_SENSITIVE_NAMES: Final = frozenset({"npm"})
    """Registries where two names differing only in case are two packages. npm stopped accepting
    capitals in 2017 and kept the packages published before then: `Orchestrator` is not
    `orchestrator` (gulp 3's task runner), and MAL-2025-28475 is about the first one only."""

    @staticmethod
    def _as_named(ecosystem: str, name: str, records: tuple[Advisory, ...]) -> tuple[Advisory, ...]:
        """The records about this package as the registry names it, and as each record claims it.

        Two corrections to the lowercased index, both about what a record says rather than how it
        was stored:

        * a case-sensitive registry's records match only their exact spelling;
        * a malicious record that lists its exact versions claims those versions. OSV's import of
          the OpenSSF malicious-packages data also gives such a record an open range from "0",
          which for a name published only to attack says the same thing, and for an established
          package with years of honest releases says every one of them is malware: MAL-2024-10244
          names `roboter` 2.0.2, and its open range blocked `roboter` 12.7.0. The explicit list
          stands and the open range does not: a compromise happens to specific uploads (see the
          module docstring), and an upload the list does not name gets its own record.
        """
        records = tuple(a for a in records if not (a.malicious and a.identifier in NOT_MALWARE))
        if ecosystem in AdvisoryDatabase.CASE_SENSITIVE_NAMES:
            exact = name.strip()
            records = tuple(a for a in records if a.name == exact)
        if ecosystem in AdvisoryDatabase.WHOLE_ITEM_RECORDS:
            return records
        listed = {a.identifier for a in records if a.malicious and a.versions and a.identifier}
        if not listed:
            return records
        return tuple(
            a
            for a in records
            if not (
                a.malicious
                and a.identifier in listed
                and not a.versions
                and a.introduced in (None, "0")
                and a.fixed is None
                and a.last_affected is None
            )
        )

    @staticmethod
    def spellings(ecosystem: str, name: str) -> tuple[str, ...]:
        """Every key a package name may be stored under.

        The database keeps names as OSV publishes them, lowercased; PyPI's records are PEP 503
        normalised (runs of `-`, `_` and `.` fold to one `-`), and crates.io treats `-` and `_` as
        one name. A caller holding the name as a package's own metadata spells it
        (`amino.fix`, `whatsfly_labfox`) missed the record under the normalised key: three
        known-malicious PyPI releases went unreported in the identity benchmark for exactly that.
        """
        import re

        lowered = name.strip().lower()
        forms = [lowered]
        if ecosystem == "pypi":
            forms.append(re.sub(r"[-_.]+", "-", lowered))
        elif ecosystem == "cargo":
            forms.extend((lowered.replace("_", "-"), lowered.replace("-", "_")))
        return tuple(dict.fromkeys(forms))


NOT_MALWARE: Final = {
    "MAL-2023-462": (
        "fsevents 1.0.0 to 1.2.10 carry no malicious code: their install script fetched a prebuilt "
        "binary from a storage bucket that was later abandoned and could be claimed (GitHub's "
        "GHSA-xv2f-5jw4-v95m). That is a vulnerability, and it is recorded as one -- "
        "GHSA-8r6j-v8pm-fqw3 / CVE-2023-45311, critical, fixed in 1.2.11 -- which still reports. "
        "As malware it blocked 45 of 1,943 published VS Code extensions, every one shipping the "
        "module already built, where no install script runs."
    ),
}
"""Malicious-package records reviewed and found to describe something that is not malware, by id,
with the reason. Each one must name the record that reports the real risk in its place."""


__all__ = ["DATA_DIR", "Advisory", "AdvisoryDatabase", "AdvisoryFiles", "DatabaseMeta"]
