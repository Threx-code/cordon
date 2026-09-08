"""Scan orchestration.

The engine is the application core. It knows the *shape* of a scan -- which
phases run, in what order, with what feeding what -- and nothing about how any
individual step is implemented. It holds references to protocols, never to
concrete detectors, ecosystems or reporters.

That separation is what makes the rest of the architecture work. A new detector
is registered, not wired in. A new output format never touches this file. And
because detectors are pure functions over immutable units, moving execution from
a loop to a process pool to a distributed queue is a deployment decision rather
than a rewrite.

Phases:

    Source -> Inventory -> Plan -> Execute -> Correlate -> Judge

Each has one input type and one output type, so a phase can be replaced,
parallelised or cached without disturbing its neighbours.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING

from cordon.archive.safe import ArchiveReader
from cordon.core.cache import CacheKey, ScanCache
from cordon.core.config import Config
from cordon.core.content import FileContent, Skipped
from cordon.core.errors import ArchiveError, DetectorError, SourceError
from cordon.core.models import (
    Category,
    Confidence,
    Dependency,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Hook,
    LanguageStat,
    Location,
    Project,
    RedactionMode,
    Repository,
    RiskScore,
    ScanResult,
    ScanStats,
    Severity,
)
from cordon.core.parallel import ParallelScanner
from cordon.core.policy import PolicyGate, SuppressionMatcher
from cordon.core.scoring import RiskScorer
from cordon.core.walker import Walker
from cordon.detect.base import FileUnit, GraphUnit, ScanContext, Unit
from cordon.ecosystems.registry import EcosystemRegistry
from cordon.langs.registry import LanguageRegistry
from cordon.rules.loader import RuleLoader, RuleSet
from cordon.sources.base import FileSource, WorkingTreeSource
from cordon.version import SCHEMA_VERSION, __version__

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from cordon.detect.base import Detector

NO_RISK = RiskScore(value=0, base=0, confidence_multiplier=1.0)


@dataclass
class _Accumulator:
    """Mutable state for one scan.

    Deliberately local to a single run. The engine itself holds no per-scan
    state, which is what makes one Scanner instance reusable and safe to share.
    """

    findings: list[Finding] = field(default_factory=list)
    complete: bool = True
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    rules_evaluated: int = 0


class Engine:
    """Runs the phases. Holds no per-scan state."""

    @staticmethod
    def _operational(
        *,
        path: str,
        rule_id: str,
        message: str,
        remediation: str,
        category: Category = Category.OPERATIONAL,
        severity: Severity = Severity.INFO,
    ) -> Finding:
        """Build a finding about the scan itself.

        Every degradation produces one of these. A file that was not examined is
        indistinguishable in the output from one that was examined and found clean,
        so coverage loss must always be stated rather than inferred.
        """
        return Finding(
            rule_id=rule_id,
            category=category,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            message=message,
            location=Location(path=path),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(f"{rule_id}:{path}".encode()),
                redaction=RedactionMode.NONE,
            ),
            remediation=remediation,
            # No reporting threshold may hide a finding that says coverage was
            # lost. See PolicyGate.filter_for_reporting.
            always_report=True,
            explanation=Explanation(
                summary="Reported so that reduced coverage is never silent.",
                matched_rule=rule_id,
            ),
            risk=NO_RISK,
            detector="engine",
        )

    def __init__(
        self,
        config: Config,
        *,
        rules: RuleSet | None = None,
        detectors: Sequence[Detector] | None = None,
        source: FileSource | None = None,
    ) -> None:
        self.config = config
        self.rules = rules if rules is not None else RuleSet(RuleLoader.load_builtin())
        self.detectors = tuple(detectors) if detectors is not None else self._default_detectors()
        self.scorer = RiskScorer()
        self.cache = ScanCache(config.cache_dir, enabled=config.use_cache)
        # Where files and their bytes come from. The default is the working
        # tree; a git source narrows the set or, in staged mode, changes the
        # bytes themselves.
        self.source: FileSource = source if source is not None else WorkingTreeSource()

    @staticmethod
    def _default_detectors() -> tuple[Detector, ...]:
        from cordon.core.registry import Registry

        return Registry.default_detectors()

    # -- Entry point -----------------------------------------------------

    def scan(self, target: str | Path) -> ScanResult:
        """Scan a target and return a complete, sorted result."""
        started = time.monotonic()
        acc = _Accumulator()

        root = Path(target).resolve()
        if root.is_file() and ArchiveReader.is_archive(root.name):
            return self._scan_archive(root, acc, started)
        inventory = self.inventory(root, acc)
        ctx = self._context(inventory)

        deadline = started + self.config.limits.total_timeout

        # Manifest hooks are discovered while scanning, and they change the
        # context every later finding is scored against: the same capability
        # pair means something different inside a lifecycle script. So files are
        # collected first, hooks are folded into the context, and detectors run
        # against the completed picture.
        units = list(self._units(root, inventory, acc, deadline))

        dependencies = self._build_graph(units, acc)
        hook_paths = set(ctx.install_hook_paths) | self._manifest_hook_paths(units)
        ctx = replace(
            ctx,
            dependencies=dependencies,
            install_hook_paths=frozenset(hook_paths),
        )

        file_detectors = [
            d
            for d in self.detectors
            if self._detector_enabled(d, ctx)
            and not (d.requires.dependencies and d.requires.content is False)
        ]
        signature = ScanCache.detector_signature(file_detectors)

        # A source whose bytes are not what is on disk cannot be parallelised:
        # workers re-read by path, so a staged scan would silently examine the
        # working tree instead of the index.
        workers = (
            ParallelScanner.worker_count(self.config.limits.max_workers, len(units))
            if self.source.parallel_safe
            else 1
        )
        if workers > 1:
            acc.findings.extend(
                self._scan_parallel(units, root, ctx, acc, file_detectors, signature)
            )
        else:
            for unit in units:
                acc.findings.extend(self._inspect_file(unit, ctx, acc, file_detectors, signature))

        if dependencies:
            graph_unit = GraphUnit(dependencies=dependencies)
            for detector in self.detectors:
                if not detector.requires.dependencies:
                    continue
                if not self._detector_enabled(detector, ctx):
                    continue
                acc.findings.extend(self._run(detector, graph_unit, ctx, acc))

        # A suppression that expired is reported, not merely inactive: the
        # finding it was hiding reappears at the same moment somebody is told
        # why, rather than as an unexplained new failure weeks later.
        matcher = SuppressionMatcher(self.config)
        acc.findings.extend(matcher.expiry_findings())
        findings = matcher.apply(acc.findings)

        result = ScanResult(
            findings=findings,
            repository=inventory,
            dependencies=dependencies,
            stats=ScanStats(
                cache_hits=self.cache.hits,
                cache_misses=self.cache.misses,
                dependencies=len(dependencies),
                files_scanned=acc.files_scanned,
                files_skipped=acc.files_skipped,
                bytes_scanned=acc.bytes_scanned,
                rules_evaluated=len(self.rules),
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            complete=acc.complete,
            schema_version=SCHEMA_VERSION,
            engine_version=__version__,
            rulepack_version=self.rules.packs[0].version if self.rules.packs else "0.0.0",
            rulepack_hash=self.rules.content_hash,
            config_hash=self.config.fingerprint(),
        )

        return PolicyGate.filter_for_reporting(result, self.config).sorted()

    # -- Archives ---------------------------------------------------------

    def _scan_archive(self, path: Path, acc: _Accumulator, started: float) -> ScanResult:
        """Scan an archive without writing any of it to disk.

        Members are held in memory and never materialised. Nothing that was
        never written can be executed, followed, or left behind by a crash,
        which removes a class of problem rather than mitigating it.

        A rejected member becomes an OPERATIONAL finding. An archive that was
        refused and one that was clean must never look alike, which is the same
        rule the rest of the engine follows for skipped files.
        """
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise SourceError(f"cannot read {path}: {exc}") from exc

        ctx = self._context(Repository(root=str(path)))
        # Deliberately uncached. The archive has to be read and expanded in full
        # either way, so caching would skip only the matching, and a stale entry
        # keyed on an archive whose contents changed under the same name is a
        # risk with almost no payoff.
        units: list[FileUnit] = []

        try:
            for member_path, member_data in ArchiveReader.walk_archive(
                data, path=path.name, limits=self.config.limits
            ):
                units.append(
                    FileUnit(
                        content=FileContent.from_bytes(
                            member_path, member_data, self.config.limits
                        ),
                        language=LanguageRegistry.identify_language(member_path.rpartition("!")[2]),
                    )
                )
                acc.files_scanned += 1
                acc.bytes_scanned += len(member_data)
        except ArchiveError as exc:
            acc.complete = False
            acc.findings.append(
                Engine._operational(
                    path=path.name,
                    rule_id="OPERATIONAL.ARCHIVE.REJECTED",
                    message=f"The archive was refused and not scanned: {exc.message}",
                    remediation=(
                        "Treat a refused archive as unexamined. If the limits are wrong "
                        "for this input, raise them deliberately rather than assuming "
                        "the archive is clean."
                    ),
                    severity=Severity.MEDIUM,
                )
            )

        # Manifests inside a package determine whether its code runs at install
        # time, which is the whole reason a package archive is worth scanning.
        hook_paths = self._manifest_hook_paths(units)
        ctx = replace(ctx, install_hook_paths=frozenset(hook_paths))

        detectors = [d for d in self.detectors if self._detector_enabled(d, ctx)]
        for unit in units:
            for detector in detectors:
                if detector.requires.dependencies and detector.requires.content is False:
                    continue
                acc.findings.extend(self._run(detector, unit, ctx, acc))

        result = ScanResult(
            findings=tuple(acc.findings),
            repository=Repository(root=str(path), file_count=acc.files_scanned),
            stats=ScanStats(
                files_scanned=acc.files_scanned,
                bytes_scanned=acc.bytes_scanned,
                rules_evaluated=len(self.rules),
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            complete=acc.complete,
            schema_version=SCHEMA_VERSION,
            engine_version=__version__,
            rulepack_version=self.rules.packs[0].version if self.rules.packs else "0.0.0",
            rulepack_hash=self.rules.content_hash,
            config_hash=self.config.fingerprint(),
        )
        return PolicyGate.filter_for_reporting(result, self.config).sorted()

    # -- Phase 0: inventory ----------------------------------------------

    def inventory(self, root: Path, acc: _Accumulator | None = None) -> Repository:
        """Determine what the target is.

        Consumed by every detector's applicability check, which is what makes
        detector selection automatic rather than configured. A user should not
        have to declare that their repository contains Terraform; the tool should
        observe it.
        """
        walker = self._walker()
        languages: dict[str, tuple[int, int]] = {}
        evidence: dict[str, set[str]] = {}
        hooks: list[Hook] = []
        manifests: dict[str, list[str]] = {}
        lockfiles: dict[str, list[str]] = {}
        total_bytes = 0
        file_count = 0

        for entry in walker.walk(root):
            if entry.is_symlink:
                continue
            file_count += 1
            total_bytes += entry.size

            language = LanguageRegistry.identify_language(entry.rel_path)
            if language:
                files, size = languages.get(language, (0, 0))
                languages[language] = (files + 1, size + entry.size)
                evidence.setdefault(language, set()).add(
                    f"*{Path(entry.rel_path).suffix}"
                    if Path(entry.rel_path).suffix
                    else entry.rel_path
                )

            hooks.extend(self._hooks_for(entry.rel_path))

            eco = EcosystemRegistry.manifest_ecosystem(entry.rel_path)
            if eco:
                manifests.setdefault(eco, []).append(entry.rel_path)
                hooks.extend(self._manifest_hooks(entry.real_path, entry.rel_path, eco))
            lock = EcosystemRegistry.lockfile_ecosystem(entry.rel_path)
            if lock:
                lockfiles.setdefault(lock, []).append(entry.rel_path)

        stats = tuple(
            LanguageStat(
                language=language,
                files=files,
                bytes=size,
                share=(size / total_bytes) if total_bytes else 0.0,
                evidence=tuple(sorted(evidence.get(language, ()))),
            )
            # Sorted by size then name: byte-weighted ranking reflects what the
            # repository actually is better than file count, which over-weights
            # many small config files. The name breaks ties so the order is
            # deterministic.
            for language, (files, size) in sorted(
                languages.items(), key=lambda kv: (-kv[1][1], kv[0])
            )
        )

        if acc is not None and walker.stats.limit_hit:
            acc.complete = False

        # A project is a subtree with its own manifest. Modelling a monorepo as
        # N projects is what keeps detector selection correct: without it, a
        # polyglot tree gets the union of every rule applied to every file.
        projects: list[Project] = []
        for eco_id, paths in sorted(manifests.items()):
            for manifest_path in sorted(paths):
                directory = manifest_path.rpartition("/")[0]
                projects.append(
                    Project(
                        path=directory,
                        ecosystem=eco_id,
                        manifests=(manifest_path,),
                        lockfiles=tuple(
                            p
                            for p in lockfiles.get(eco_id, ())
                            if p.rpartition("/")[0] == directory
                        ),
                    )
                )

        return Repository(
            root=str(root),
            languages=stats,
            projects=tuple(projects),
            ecosystems=tuple(sorted(set(manifests) | set(lockfiles))),
            hooks=tuple(hooks),
            file_count=file_count,
            total_bytes=total_bytes,
        )

    def _manifest_hooks(self, real_path: Path, rel_path: str, ecosystem_id: str) -> list[Hook]:
        """Lifecycle hooks declared inside a manifest.

        Parsed during inventory rather than inferred from the filename, because
        a `postinstall` entry is the single most useful thing this phase can
        surface: it names code that runs before any other control, and it is
        invisible from the path alone.
        """
        ecosystem = EcosystemRegistry.get(ecosystem_id)
        if ecosystem is None:
            return []
        loaded = FileContent.load(real_path, rel_path, self.config.limits)
        if isinstance(loaded, Skipped):
            return []
        try:
            return list(ecosystem.parse_manifest(loaded).hooks)
        except Exception:
            return []

    @staticmethod
    def _hooks_for(rel_path: str) -> Iterator[Hook]:
        """Identify paths that execute during install, build or version control.

        First-class because execution context is the largest single multiplier in
        the risk model. Detecting these before scanning is what lets the same
        capability pair be quiet in application code and decisive here.

        This is the filename-level pass. Manifest lifecycle scripts are found by
        the manifest detector, which can parse them properly.
        """
        name = rel_path.rpartition("/")[2]
        if name in {"setup.py", "conanfile.py", "build.rs", "binding.gyp"}:
            yield Hook(kind="build", path=rel_path, name=name)
        elif rel_path.startswith(".githooks/") or "/.git/hooks/" in f"/{rel_path}":
            yield Hook(kind="githook", path=rel_path, name=name)
        elif rel_path.startswith(".github/workflows/"):
            yield Hook(kind="ci", path=rel_path, name=name)

    # -- Phase 1: planning and unit production ---------------------------

    def _walker(self) -> Walker:
        return Walker(
            exclude=self.config.exclude,
            include=self.config.include,
            limits=self.config.limits,
        )

    def _context(self, inventory: Repository) -> ScanContext:
        return ScanContext(
            config=self.config,
            rules=self.rules,
            repository=inventory,
            install_hook_paths=frozenset(h.path for h in inventory.hooks),
            scorer=self.scorer,
            offline=self.config.offline,
        )

    def _units(
        self,
        root: Path,
        inventory: Repository,
        acc: _Accumulator,
        deadline: float,
    ) -> Iterator[FileUnit]:
        """Produce one unit per scannable file.

        A generator rather than a list, so memory stays bounded on a repository
        of unknown size. That is a security property as much as an efficiency
        one: the input is attacker-controlled and its size is not known in
        advance.
        """
        walker = self._walker()

        # Counted here rather than read from walker.stats, because the source
        # sits between the walker and this loop. A git mode narrows the walker's
        # output, and that narrowing is invisible to the walker's own counters:
        # `--tracked` in a repository where nothing is tracked once yielded zero
        # files while the stats reported a full traversal, so the scan examined
        # nothing and reported clean.
        selected = 0
        # Files classified as binary artefacts. Counted so the scan can say how
        # many files it did not examine as source: a file that was skipped and a
        # file that was examined and found clean must not look the same.
        binary: list[str] = []

        for entry in self.source.entries(root, walker):
            selected += 1

            # `>=`, not `>`. A budget of zero means no time is allowed, and on
            # platforms with a coarse monotonic clock the first reading can equal
            # the start time exactly, so a strict comparison silently never
            # trips. That made --timeout 0 a no-op on Windows.
            if time.monotonic() >= deadline:
                # A partial result a human can act on beats a stack trace, and
                # marking it partial is what stops it being read as a pass.
                acc.complete = False
                acc.findings.append(
                    Engine._operational(
                        path=str(root),
                        rule_id="OPERATIONAL.SCAN.TIMEOUT",
                        message=(
                            f"The scan exceeded its {self.config.limits.total_timeout:.0f}s "
                            f"budget and stopped early. Results are partial."
                        ),
                        remediation=(
                            "Raise limits.total_timeout, narrow the scan with --include, "
                            "or scan projects individually."
                        ),
                    )
                )
                return

            if entry.is_symlink:
                acc.files_skipped += 1
                acc.findings.append(
                    Engine._operational(
                        path=entry.rel_path,
                        rule_id="OPERATIONAL.FILE.SYMLINK",
                        message="Symbolic link was recorded but not followed.",
                        remediation="No action needed. Links are never dereferenced.",
                        severity=Severity.INFO,
                    )
                )
                continue

            loaded = self.source.load(entry, self.config.limits)
            if isinstance(loaded, Skipped):
                acc.files_skipped += 1
                acc.complete = False
                acc.findings.append(
                    Engine._operational(
                        path=entry.rel_path,
                        rule_id="OPERATIONAL.FILE.UNREADABLE",
                        message=f"File could not be read ({loaded.reason}); it was not scanned.",
                        remediation="Check permissions, or exclude the path deliberately.",
                    )
                )
                continue

            if loaded.is_binary:
                binary.append(entry.rel_path)

            acc.files_scanned += 1
            acc.bytes_scanned += len(loaded.raw)

            yield FileUnit(
                content=loaded, language=LanguageRegistry.identify_language(entry.rel_path)
            )

        if walker.stats.limit_hit:
            acc.complete = False
            acc.findings.append(
                Engine._operational(
                    path=str(root),
                    rule_id="OPERATIONAL.SCAN.LIMIT",
                    message=f"Traversal stopped early: {walker.stats.limit_hit}",
                    remediation="Raise the relevant limit or narrow the scan.",
                )
            )

        # -- Configuration that reduced coverage ---------------------------
        #
        # The scan target is untrusted input, and its configuration file is part
        # of it. Without an organisation policy there is no ceiling, so a
        # repository can legitimately exclude paths and disable detectors -- and
        # a hostile one can do the same to blind the scan entirely.
        #
        # That cannot be prevented without a policy, so it is made loud instead.
        # Every one of these findings exists because a scan that examined
        # nothing and a scan that found nothing must never look alike.
        acc.findings.extend(
            self._coverage_findings(
                walker.stats, root, selected, complete=acc.complete, binary=binary
            )
        )

        # An exclusion matching nothing is either a mistake or a hole held open
        # for a file that does not exist yet. Both are worth surfacing: commit a
        # file at that path and it would be skipped by the very check meant to
        # examine it.
        for pattern in walker.stats.unmatched_patterns:
            acc.findings.append(
                Engine._operational(
                    path=pattern,
                    rule_id="POLICY.EXCLUDE.UNMATCHED",
                    category=Category.POLICY,
                    severity=Severity.LOW,
                    message=(
                        f"Exclusion pattern {pattern!r} matched nothing. An exclusion "
                        f"for a path that does not exist silently skips any file later "
                        f"committed there."
                    ),
                    remediation="Remove the pattern, or correct it to match its intended path.",
                )
            )

    def _inspect_file(
        self,
        unit: FileUnit,
        ctx: ScanContext,
        acc: _Accumulator,
        detectors: list[Detector],
        signature: str,
    ) -> list[Finding]:
        """Run every file detector over one unit, via the cache.

        The cache is keyed on content plus everything that could change a
        finding, so a hit is provably identical to a cold run. A test asserts
        that equivalence rather than assuming it, because a stale cached "clean"
        is a false negative and false negatives are the failure that matters.
        """
        key = self._cache_key(unit, ctx, signature)

        cached = self.cache.get(key)
        if cached is not None:
            return list(cached)

        produced: list[Finding] = []
        budget = self.config.limits.per_file_timeout
        started = time.monotonic()

        for detector in detectors:
            # Checked between detectors rather than inside one. Python's `re`
            # cannot be interrupted mid-match -- a single call holds the
            # interpreter until it returns -- so nothing in this process can
            # bound one pathological regex. What this does bound is
            # accumulation: fifty detectors and several hundred rules over a
            # very large file. The single-regex case is prevented at load time
            # instead, by PatternCompiler rejecting the shapes that backtrack.
            #
            # Stating the division plainly because the previous docstring did
            # not: it named this timeout as the backstop for catastrophic
            # regexes, the timeout was never implemented, and had it been it
            # could not have stopped the case it was named for.
            if budget > 0 and time.monotonic() - started >= budget:
                acc.complete = False
                produced.append(
                    Engine._operational(
                        path=unit.path,
                        rule_id="OPERATIONAL.FILE.TIMEOUT",
                        message=(
                            f"This file exceeded its {budget:.0f}s budget, so the "
                            f"remaining detectors did not run on it. Results for this "
                            f"file are partial."
                        ),
                        remediation=(
                            "Raise limits.per_file_timeout, or exclude the file if it "
                            "is generated output rather than source."
                        ),
                    )
                )
                # Not cached below, because acc.complete is now False.
                return produced

            produced.extend(self._run(detector, unit, ctx, acc))

        # Only a complete result is cached. Caching the output of a run that hit
        # a limit would make the degradation permanent and invisible.
        if acc.complete:
            self.cache.put(key, produced)

        return produced

    def _scan_parallel(
        self,
        units: list[FileUnit],
        root: Path,
        ctx: ScanContext,
        acc: _Accumulator,
        detectors: list[Detector],
        signature: str,
    ) -> list[Finding]:
        """Inspect files across a worker pool.

        The cache is consulted in this process first, so only genuine misses are
        distributed. A warm scan therefore does almost no cross-process work,
        which is the case a commit-time hook actually hits.

        A pool that cannot start falls back to serial execution. On a platform
        where processes cannot be spawned, a slower scan is the correct outcome;
        a failed one is not.
        """
        by_path = {unit.path: unit for unit in units}
        pending: list[tuple[int, str, int]] = []
        results: list[Finding] = []

        for index, unit in enumerate(units):
            key = self._cache_key(unit, ctx, signature)
            cached = self.cache.get(key)
            if cached is not None:
                results.extend(cached)
            else:
                pending.append((index, unit.path, len(unit.content.raw)))

        if not pending:
            return results

        produced = ParallelScanner.run(
            config=self.config,
            root=str(root),
            files=pending,
            workers=ParallelScanner.worker_count(self.config.limits.max_workers, len(pending)),
        )

        if not produced:
            # The pool did not run. Fall back rather than lose coverage.
            for _index, path, _size in pending:
                unit = by_path[path]
                results.extend(self._inspect_file(unit, ctx, acc, detectors, signature))
            return results

        for index, findings in produced:
            unit = units[index]
            results.extend(findings)
            if acc.complete:
                self.cache.put(self._cache_key(unit, ctx, signature), findings)

        return results

    def _cache_key(self, unit: FileUnit, ctx: ScanContext, signature: str) -> CacheKey:
        return CacheKey(
            content_hash=unit.content.sha256,
            rulepack_hash=self.rules.content_hash,
            config_hash=self.config.fingerprint(),
            detector_signature=signature,
            path=unit.path,
            in_install_hook=ctx.in_install_hook(unit.path),
            language=unit.language or "",
        )

    # -- Dependency graph ------------------------------------------------

    def _build_graph(self, units: list[FileUnit], acc: _Accumulator) -> tuple[Dependency, ...]:
        """Build the resolved graph from lockfiles.

        Never by invoking the package manager and never over the network (C2,
        C4). Running the ecosystem's own resolver would execute untrusted
        tooling against attacker-controlled metadata inside the tool whose whole
        purpose is avoiding that, and it would make results non-reproducible
        because a resolver consults a live registry.
        """
        collected: list[Dependency] = []
        for unit in units:
            ecosystem_id = EcosystemRegistry.lockfile_ecosystem(unit.path)
            if ecosystem_id is None:
                continue
            ecosystem = EcosystemRegistry.get(ecosystem_id)
            if ecosystem is None:
                continue
            graph = ecosystem.parse_lockfile(unit.content)
            if graph.parse_error or not graph.entries:
                continue
            project = unit.path.rpartition("/")[0]
            collected.extend(ecosystem.to_dependencies(graph, project=project or None))

            if len(collected) > self.config.limits.max_dependencies:
                acc.complete = False
                acc.findings.append(
                    Engine._operational(
                        path=unit.path,
                        rule_id="OPERATIONAL.GRAPH.LIMIT",
                        message=(
                            f"The dependency graph exceeded "
                            f"{self.config.limits.max_dependencies} entries and was "
                            f"truncated. Dependency analysis is partial."
                        ),
                        remediation="Raise limits.max_dependencies, or scan projects separately.",
                    )
                )
                break

        # Deduplicated by package URL and sorted, so the graph is deterministic
        # regardless of the order lockfiles were encountered in.
        unique: dict[str, Dependency] = {}
        for dependency in collected:
            existing = unique.get(dependency.purl)
            # Keep the shallowest occurrence: depth drives the risk score, and
            # the closest path to the root is the honest one.
            if existing is None or dependency.depth < existing.depth:
                unique[dependency.purl] = dependency
        return tuple(sorted(unique.values(), key=lambda d: d.purl))

    @staticmethod
    def _manifest_hook_paths(units: list[FileUnit]) -> set[str]:
        """Paths that execute at install time, according to their manifests."""
        paths: set[str] = set()
        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            if ecosystem_id is None:
                continue
            ecosystem = EcosystemRegistry.get(ecosystem_id)
            if ecosystem is None:
                continue
            manifest = ecosystem.parse_manifest(unit.content)
            if manifest.hooks:
                paths.add(unit.path)
        return paths

    def _coverage_findings(
        self,
        stats,
        root: Path,
        selected: int,
        *,
        complete: bool,
        binary: Sequence[str] = (),
    ) -> list[Finding]:
        """Report configuration that reduced what was examined.

        None of this is prevented, because a repository has legitimate reasons
        to exclude generated directories and to turn off a detector that does
        not apply. What is guaranteed is that the reduction appears in the
        output, so a reviewer can see that a clean result was produced by not
        looking.
        """
        findings: list[Finding] = []

        # Files that exist but hold no source to examine. One aggregated finding
        # rather than one per file: a repository with four hundred icons would
        # otherwise drown the report, and a report nobody reads is the same
        # outcome as not reporting.
        #
        # Reported at INFO and not treated as incompleteness. A PNG is not a
        # degraded scan, it is a file with nothing for a source rule to match.
        # Marking every repository with an image as incomplete would make
        # `fail_on_incomplete` unusable, and an unusable control is worse than
        # an absent one.
        if binary:
            sample = ", ".join(sorted(binary)[:5])
            more = f" and {len(binary) - 5} more" if len(binary) > 5 else ""
            findings.append(
                Engine._operational(
                    path=str(root),
                    rule_id="OPERATIONAL.FILE.BINARY",
                    severity=Severity.INFO,
                    message=(
                        f"{len(binary)} file(s) were not examined as source because "
                        f"they are binary artefacts: {sample}{more}."
                    ),
                    remediation=(
                        "No action needed for genuine binaries. The classification "
                        "is made from the file's extension and leading bytes, never "
                        "from its contents, so a source file cannot be excluded from "
                        "scanning by what it contains."
                    ),
                )
            )

        # Nothing at all was examined, but the tree is not empty. `selected` is
        # what actually reached the detectors, which is not the same as what the
        # walker yielded whenever a source narrowed the set.
        if selected == 0 and stats.files_seen > 0:
            # Always reported, never silent. The source decides only whether an
            # empty selection is a warning or a note: an empty staged set is an
            # ordinary commit, an empty tracked set is a blinded pipeline.
            normal = self.source.empty_selection_is_normal
            findings.append(
                Engine._operational(
                    path=str(root),
                    rule_id="POLICY.COVERAGE.NOTHING_SCANNED",
                    category=Category.POLICY,
                    severity=Severity.INFO if normal else Severity.HIGH,
                    message=(
                        f"No files were examined, although {stats.files_seen} were "
                        f"present. Everything was removed by configuration or by the "
                        f"selected source ({self.source.describe()}), so this result "
                        f"reports that nothing was looked at rather than that nothing "
                        f"was found."
                    ),
                    remediation=(
                        "Review the exclude patterns and any --staged, --tracked or "
                        "--git-diff selection. A clean scan that examined no files is "
                        "not a clean scan."
                    ),
                )
            )
        elif stats.files_seen >= _BROAD_EXCLUSION_MIN_FILES:
            dropped = stats.files_dropped_by_config
            share = dropped / stats.files_seen
            # A repository excluding most of itself may be correct -- a large
            # vendored tree, a generated directory -- but it is worth stating,
            # because it is also exactly what blinding the scanner looks like.
            # The floor on tree size is there so a five-file repository with one
            # generated directory does not produce this every run; a check that
            # fires constantly on correct configuration gets excluded itself.
            if share >= _BROAD_EXCLUSION_SHARE:
                findings.append(
                    Engine._operational(
                        path=str(root),
                        rule_id="POLICY.COVERAGE.BROAD_EXCLUSION",
                        category=Category.POLICY,
                        severity=Severity.MEDIUM,
                        message=(
                            f"Configuration removed {dropped} of {stats.files_seen} "
                            f"files ({share:.0%}) before any check ran. That may be "
                            f"correct for a repository with a large generated or "
                            f"vendored tree, and it is also what blinding a scanner "
                            f"looks like, so it is reported either way."
                        ),
                        remediation=(
                            "Confirm the exclusions are intended. Narrow any that "
                            "cover more than the generated output they were written "
                            "for."
                        ),
                    )
                )

        # A detector turned off in a config that came from the scan target.
        if self.config.from_untrusted_source:
            disabled = sorted(name for name, on in self.config.detectors.items() if on is False)
            if disabled:
                findings.append(
                    Engine._operational(
                        path=str(root),
                        rule_id="POLICY.COVERAGE.DETECTOR_DISABLED",
                        category=Category.POLICY,
                        severity=Severity.MEDIUM,
                        message=(
                            f"The repository's own configuration disabled "
                            f"{len(disabled)} detector(s): {', '.join(disabled)}. "
                            f"Those checks did not run."
                        ),
                        remediation=(
                            "Confirm each is genuinely inapplicable. An organisation "
                            "policy can require detectors that a repository may not "
                            "disable."
                        ),
                    )
                )

            for setting in self.config.reduced_limits:
                # An incomplete scan does not fail the build by default, and
                # that default is right: making it fatal would break pipelines
                # on the first genuinely large repository and teach people to
                # append `|| true`, which is worse than the failure it prevents.
                #
                # It is not right here. This scan is incomplete *because the
                # scan target asked for it to be*, which is not the same thing
                # as a repository that outgrew a default, so it fails.
                truncated = not complete
                findings.append(
                    Engine._operational(
                        path=str(root),
                        rule_id="POLICY.CONFIG.LIMIT_REDUCED",
                        category=Category.POLICY,
                        severity=Severity.HIGH if truncated else Severity.MEDIUM,
                        message=(
                            f"{setting} was lowered below the built-in default by the "
                            f"repository's own configuration, which narrows what the "
                            f"scan reaches. A lowered limit is an exclusion written in "
                            f"a form that produces no exclusion patterns to report, so "
                            f"it is reported here instead."
                            + (
                                " The scan did not finish, so this limit is what stopped it."
                                if truncated
                                else ""
                            )
                        ),
                        remediation=(
                            "Confirm the reduction is intended. If the scan is slow, "
                            "narrow it with exclusions, which are visible, rather than "
                            "with a limit, which is not."
                        ),
                    )
                )

            for setting in self.config.clamped_settings:
                findings.append(
                    Engine._operational(
                        path=str(root),
                        rule_id="POLICY.CONFIG.CLAMPED",
                        category=Category.POLICY,
                        severity=Severity.LOW,
                        message=(
                            f"{setting} was set by the repository's own configuration "
                            f"and reduced to the built-in default. A configuration "
                            f"file inside the scan target cannot raise a resource "
                            f"limit or add a rule pack, because both can be used "
                            f"against the machine running the scan."
                        ),
                        remediation=(
                            "Pass the value on the command line, which is operator "
                            "input, or set it in an organisation policy."
                        ),
                    )
                )

        return findings

    # -- Phase 2: execution ----------------------------------------------

    def _detector_enabled(self, detector: Detector, ctx: ScanContext) -> bool:
        if not self.config.detector_enabled(detector.id):
            return False
        if detector.requires.network and ctx.offline:
            return False
        return detector.applicable(ctx)

    def _run(
        self, detector: Detector, unit: Unit, ctx: ScanContext, acc: _Accumulator
    ) -> list[Finding]:
        """Run one detector over one unit, containing its failures.

        A detector that raises must not abort the scan, because one broken
        detector silently reducing coverage across every file is far worse than
        one loud finding saying it broke. The scan continues and reports itself
        as incomplete.
        """
        try:
            produced = list(detector.inspect(unit, ctx))
        except Exception as exc:
            acc.complete = False
            return [
                Engine._operational(
                    path=getattr(unit, "path", "<graph>"),
                    rule_id="OPERATIONAL.DETECTOR.FAILED",
                    message=(
                        f"Detector {detector.id!r} failed on this file, so its checks "
                        f"did not run: {type(exc).__name__}: {exc}"
                    ),
                    remediation="Report this with the file that triggered it.",
                    severity=Severity.MEDIUM,
                )
            ]

        # The engine asserts that a file detector reports only about the file it
        # was given. A detector that reports about somewhere else is a bug, and
        # accepting it silently would make findings untraceable to their source.
        #
        # Graph and repository units have no single path, so the check applies
        # only where it is meaningful. Asserting `unit.path` unconditionally is
        # what made every graph detector crash the scan.
        if isinstance(unit, FileUnit):
            for finding in produced:
                if (
                    finding.category is not Category.OPERATIONAL
                    and finding.location.path != unit.path
                ):
                    raise DetectorError(
                        f"detector {detector.id!r} produced a finding for "
                        f"{finding.location.path!r} while inspecting {unit.path!r}"
                    )
        return produced


# A scan that skipped most of the tree is worth reporting; a small repository
# with one generated directory is not. The floor keeps the check from firing on
# correct configuration, which is how a check gets turned off.
_BROAD_EXCLUSION_SHARE = 0.8
_BROAD_EXCLUSION_MIN_FILES = 25


__all__ = ["Engine"]
