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

import contextlib
import time
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.analysis.shared.languages import LanguageRegistry
from cordon_scanner.decide.policy import PolicyGate
from cordon_scanner.decide.scoring import RiskScorer
from cordon_scanner.detect.base import (
    FileUnit,
    GraphUnit,
    ScanContext,
)
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.engine.cache import ScanCache
from cordon_scanner.engine.pipeline.accumulator import Accumulator
from cordon_scanner.engine.pipeline.archive_stages import ArchiveStages
from cordon_scanner.engine.pipeline.constants import REPOSITORY_SCOPE
from cordon_scanner.engine.pipeline.coverage import Coverage
from cordon_scanner.engine.pipeline.dependencies import Dependencies
from cordon_scanner.engine.pipeline.detection import Detection
from cordon_scanner.engine.pipeline.facts import TreeFacts
from cordon_scanner.engine.pipeline.graph import Graph
from cordon_scanner.engine.pipeline.hooks import Hooks
from cordon_scanner.engine.pipeline.images import Images
from cordon_scanner.engine.pipeline.operational import OperationalFinding
from cordon_scanner.engine.pipeline.stages import ScanStages
from cordon_scanner.engine.pipeline.units import Units
from cordon_scanner.engine.progress import NullProgress, Progress
from cordon_scanner.engine.walker import (
    WalkEntry,
    Walker,
)
from cordon_scanner.foundation.collector import Collector
from cordon_scanner.foundation.config import Config
from cordon_scanner.foundation.content import FileContent, Skipped
from cordon_scanner.foundation.errors import SourceError
from cordon_scanner.foundation.models import (
    Hook,
    LanguageStat,
    Project,
    Repository,
    ScanResult,
    ScanStats,
    Severity,
)
from cordon_scanner.foundation.paths import ContainerPaths
from cordon_scanner.rules.loader import RuleLoader, RuleSet
from cordon_scanner.sources.archive import ArchiveReader
from cordon_scanner.sources.base import FileSource, WorkingTreeSource
from cordon_scanner.version import SCHEMA_VERSION, __version__

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Sequence

    from cordon_scanner.detect.base import Detector


class Engine:
    """Runs the phases. Holds no per-scan state."""

    def __init__(
        self,
        config: Config,
        *,
        rules: RuleSet | None = None,
        detectors: Sequence[Detector] | None = None,
        source: FileSource | None = None,
        progress: Progress | None = None,
        shadowed: Sequence[tuple[str, str, str]] = (),
    ) -> None:
        self.config = config
        # Entry points that tried to take a built-in's name. Reported rather
        # than refused: refusing turned one entry-point line into a denial of
        # service against every scan.
        self.shadowed = tuple(shadowed)
        self.rules = rules if rules is not None else RuleSet(RuleLoader.load_builtin())
        self.detectors = tuple(detectors) if detectors is not None else self._default_detectors()
        self.scorer = RiskScorer()
        self.cache = ScanCache(config.cache_dir, enabled=config.use_cache)
        # Where files and their bytes come from. The default is the working
        # tree; a git source narrows the set or, in staged mode, changes the
        # bytes themselves.
        self.source: FileSource = source if source is not None else WorkingTreeSource()
        # Reports what the scan is doing. `NullProgress` rather than `None`, so
        # every call site is unconditional and there is no branch that can be
        # wrong in only one of the two modes.
        self.progress: Progress = progress if progress is not None else NullProgress()
        # Archives opened during a directory scan, by content hash, and the
        # counters reported in `ScanStats`: opened, members, milliseconds.
        self._expansions: dict[str, list[tuple[str, bytes]] | None] = {}
        self._archive_stats = [0, 0, 0]
        # What an ingested SBOM itself lists as vulnerable: `(document, vulnerability, purl,
        # name, version, tool)`, reported once the scan's own matching has run.
        self._sbom_listed: list[tuple[str, Any, str, str, str | None, str]] = []
        # True while the scan TARGET is an archive, where its members' lockfiles are
        # the package's own graph rather than a vendored artefact's.
        self._scanning_archive = False
        self.coverage = Coverage(self)
        self.stages = ScanStages(self)
        self.archive_stages = ArchiveStages(self)
        self.units = Units(self)
        self.detection = Detection(self)
        self.dependencies = Dependencies(self)

    @staticmethod
    def _default_detectors() -> tuple[Detector, ...]:
        from cordon_scanner.engine.registry import Registry

        return Registry.default_detectors()

    # -- Entry point -----------------------------------------------------

    def scan(self, target: str | Path) -> ScanResult:
        """Scan a target and return a complete, sorted result."""
        try:
            return Collector.during(self._scan, target)  # foundation/collector: GC relaxed
        finally:
            # In a `finally`: the progress line is a partial line with no newline, so leaving it
            # puts a traceback or an error message on the same row as a half-drawn progress bar.
            self.progress.finish()

    def scan_host(self, root: str | Path, home: str | Path | None = None) -> ScanResult:
        """What an installed system holds (advanced gap M7): its distribution's packages and the
        language packages installed outside any project, read from the metadata their installers
        left (`images/host.py`), then matched as an image's are -- language packages against the
        advisory database, OS packages through OSV with `--online`. Files are not content-scanned:
        that is what `scan` of a directory is for."""
        try:
            return self._scan_host(Path(root), Path(home) if home is not None else None)
        finally:
            self.progress.finish()

    def _scan_host(self, root: Path, home: Path | None) -> ScanResult:
        from cordon_scanner.images.host import HostFilesystem

        started = time.monotonic()
        acc = Accumulator(finding_cap=self.config.limits.max_findings)
        intel = self._intel_status(acc)
        if not root.is_dir():
            raise SourceError(f"--host needs a directory to read as a filesystem root: {root}")
        self.progress.phase("inventory")
        inventory = HostFilesystem(root, home).inventory()
        for problem in inventory.problems:
            acc.complete = False
            acc.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.HOST.PARTIAL",
                    message=f"Part of the host was not read: {problem}.",
                    remediation="Run as a user that can read the package databases, or say so beside the result.",
                    severity=Severity.LOW,
                )
            )
        dependencies = Images.image_dependencies(inventory)
        ctx = replace(self._context(Repository(root=str(root))), image=inventory)
        if dependencies:
            ctx = replace(ctx, dependencies=Graph.packages(dependencies))
            graph_unit = GraphUnit(dependencies=Graph.packages(dependencies))
            self.progress.phase("dependencies")
            with self._sealed_scan():
                for detector in self.detectors:
                    if detector.requires.dependencies and self.detection.enabled(detector, ctx):
                        acc.add(self.detection.run(detector, graph_unit, ctx, acc))
        dependencies = self.detection.annotated(dependencies, acc.findings, ctx, [])
        result = ScanResult(
            findings=tuple(acc.findings),
            dependencies=dependencies,
            repository=Repository(root=str(root), file_count=0),
            target_kind="host",
            stats=ScanStats(
                files_scanned=0,
                bytes_scanned=0,
                dependencies=len(dependencies),
                rules_evaluated=len(self.rules),
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            complete=acc.complete and acc.advisory_complete,
            content_complete=acc.complete,
            advisory_complete=acc.advisory_complete,
            schema_version=SCHEMA_VERSION,
            engine_version=__version__,
            rulepack_version=self.rules.version,
            rulepack_hash=self.rules.content_hash,
            config_hash=self.config.fingerprint(),
        )
        return replace(PolicyGate.filter_for_reporting(result, self.config).sorted(), intel=intel)

    def _scan(self, target: str | Path) -> ScanResult:
        started = time.monotonic()
        acc = Accumulator(finding_cap=self.config.limits.max_findings)

        root = ScanStages.resolve_target(target, acc)
        intel = self._intel_status(acc)
        if root.is_file() and ArchiveReader.is_archive(root.name):
            with self._sealed_scan():
                return replace(self._scan_archive(root, acc, started), intel=intel)
        self.progress.phase("identifying")
        # One traversal for both phases where the source permits it. A git
        # source narrows the scan set, so there the inventory still describes
        # the whole repository and the two traversals are genuinely different.
        walker = self._walker()
        walked = list(walker.walk(root)) if self.source.yields_the_whole_walk else None
        # `total_timeout: 0` is "no budget", as every other check on it reads it -- not a budget
        # already spent, which stopped a scan before its first file.
        deadline = (
            started + self.config.limits.total_timeout
            if self.config.limits.total_timeout > 0
            else float("inf")
        )
        inventory = self.inventory(root, acc, walked=walked, walker=walker)
        ctx = self._context(
            inventory, deadline=deadline if self.config.limits.total_timeout > 0 else None
        )

        units = self.stages.read_units(root, inventory, acc, deadline, walked, walker)

        dependencies, ingested = self.stages.dependencies(units, acc, root)
        ctx = self.stages.install_context(units, acc, ctx, dependencies)

        self.stages.detect(units, acc, root, ctx, dependencies)

        self.stages.after_detection(dependencies, acc, units, ctx, inventory)

        findings, verdict, dependencies = self.stages.fold_and_judge(acc, units, ctx, dependencies)
        result = ScanResult(
            findings=findings,
            verdict=verdict,
            repository=inventory,
            dependencies=dependencies,
            sources=Graph.configured_sources(units),
            target_kind="sbom" if ingested else "source",
            stats=ScanStats(
                cache_hits=self.cache.hits,
                cache_misses=self.cache.misses,
                archives_expanded=self._archive_stats[0],
                archive_members=self._archive_stats[1],
                archive_ms=self._archive_stats[2],
                dependencies=len(dependencies),
                files_scanned=acc.files_scanned,
                files_skipped=acc.files_skipped,
                bytes_scanned=acc.bytes_scanned,
                rules_evaluated=len(self.rules),
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            complete=acc.complete and acc.advisory_complete,
            content_complete=acc.complete,
            advisory_complete=acc.advisory_complete,
            schema_version=SCHEMA_VERSION,
            engine_version=__version__,
            rulepack_version=self.rules.version,
            rulepack_hash=self.rules.content_hash,
            config_hash=self.config.fingerprint(),
            intel=intel,
        )

        return PolicyGate.filter_for_reporting(result, self.config).sorted()

    @contextlib.contextmanager
    def _sealed_scan(self) -> Iterator[None]:
        """Seal the network for the detector phase of a scan that may not use it (gap G1).

        Intel is pulled before this (`_intel_status`), so the scan phase itself has no reason to
        reach the network. When the config forbids network (a plain offline scan), the seal makes
        that an enforced invariant rather than a promise: any `getaddrinfo` a detector, parser or
        third-party library attempts inside here is refused by `NetworkGuard`. Entered in the
        parent before the worker pool forks, so workers inherit the seal. When network is allowed
        (`--online`, `--model`), detectors legitimately resolve input-named hosts, so the seal is
        not applied and `NetworkGuard`'s public-only filter governs instead.
        """
        if self.config.constraints.allow_network:
            yield
            return
        from cordon_scanner.engine.netguard import NetworkGuard

        with NetworkGuard.sealed():
            yield

    def _intel_status(self, acc: Accumulator) -> dict[str, Any]:
        """Refresh from the signed feed when allowed, and say how current the intel is.

        Stale intel is not a clean scan: a package that turned malicious since the intel was
        built matches nothing. So past `max_intel_age` the scan says so and is incomplete.
        """
        from cordon_scanner.intel.malware import feed

        use_feed = self.config.intel_feed and not feed.FeedClient.offline_requested()
        if use_feed:
            self.progress.phase("intel")
        status = feed.FeedClient.status(use_feed=use_feed, max_age=self.config.max_intel_age)
        if status.stale:
            acc.advisory_complete = False
            age = (
                f"{status.age_seconds // 3600} hours old"
                if status.age_seconds is not None
                else "of unknown age"
            )
            reason = f" The feed could not be used: {status.error}." if status.error else ""
            acc.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.INTEL.STALE",
                    message=(
                        f"The threat intel behind this scan is {age}, past the "
                        f"{status.max_age_seconds} second limit, so recently published "
                        f"malware and advisories may not be matched.{reason}"
                    ),
                    remediation=(
                        "Let the scan reach OSV (osv-vulnerabilities.storage.googleapis.com), "
                        "which it asks for what changed unless --offline, CORDON_OFFLINE or "
                        "CORDON_NO_ADVISORY_REFRESH is set; or run `cordon-scanner advisories "
                        "sync`, `cordon-scanner intel update`, or install a current signed "
                        "bundle with `cordon-scanner bundle install`."
                    ),
                    severity=Severity.MEDIUM,
                )
            )
        return status.to_dict()

    # -- Archives ---------------------------------------------------------

    def _scan_archive(self, path: Path, acc: Accumulator, started: float) -> ScanResult:
        """Scan an archive without writing any of it to disk.

        Members are held in memory and never materialised. Nothing that was
        never written can be executed, followed, or left behind by a crash,
        which removes a class of problem rather than mitigating it.

        A rejected member becomes an OPERATIONAL finding. An archive that was
        refused and one that was clean must never look alike, which is the same
        rule the rest of the engine follows for skipped files.
        """
        self._scanning_archive = True
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

        # Members the extractor refused. Collected rather than discarded: a
        # package shipping a payload member that was oversize, a symlink, a
        # traversal name or past the entry cap was scanned, reported nothing
        # about that member, and returned complete.
        rejected: list[tuple[str, str, str]] = []

        # The directory path computes a deadline and a retained-byte budget;
        # this one returned before reaching either, so `cordon-scanner scan
        # package.tgz` had no wall-clock bound at all and a 2 GiB memory bound
        # that was never compared against the configured one. That is the
        # amplifier behind the tar-bomb finding: the limits existed and this
        # path did not consult them.
        # `total_timeout: 0` is "no budget", as every other check on it reads it -- not a budget
        # already spent, which stopped a scan before its first file.
        deadline = (
            started + self.config.limits.total_timeout
            if self.config.limits.total_timeout > 0
            else float("inf")
        )
        retained = 0

        image, members = self.archive_stages.source(data, acc, path, rejected, deadline)

        self.archive_stages.read_members(
            members, deadline, acc, path, retained, units, rejected, image
        )

        ctx = self.archive_stages.context(units, acc, ctx, image)

        detectors, units_left = self.archive_stages.parallel(units, deadline, acc, path, ctx)
        self.archive_stages.serial(units_left, deadline, acc, path, detectors, ctx, units)

        dependencies, target_kind, ctx = self.archive_stages.dependencies(units, acc, image, ctx)
        dependencies, verdict = self.archive_stages.verdict(acc, ctx, image, units, dependencies)
        result = ScanResult(
            findings=tuple(acc.findings),
            verdict=verdict,
            dependencies=dependencies,
            repository=Repository(root=str(path), file_count=acc.files_scanned),
            target_kind=target_kind,
            image=image.identity.to_dict() if image is not None else None,
            stats=ScanStats(
                files_scanned=acc.files_scanned,
                bytes_scanned=acc.bytes_scanned,
                dependencies=len(dependencies),
                rules_evaluated=len(self.rules),
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            complete=acc.complete and acc.advisory_complete,
            content_complete=acc.complete,
            advisory_complete=acc.advisory_complete,
            schema_version=SCHEMA_VERSION,
            engine_version=__version__,
            rulepack_version=self.rules.version,
            rulepack_hash=self.rules.content_hash,
            config_hash=self.config.fingerprint(),
        )
        return PolicyGate.filter_for_reporting(result, self.config).sorted()

    # -- Phase 0: inventory ----------------------------------------------

    def inventory(
        self,
        root: Path,
        acc: Accumulator | None = None,
        *,
        walked: Sequence[WalkEntry] | None = None,
        walker: Walker | None = None,
    ) -> Repository:
        """Determine what the target is.

        Consumed by every detector's applicability check, which is what makes
        detector selection automatic rather than configured. A user should not
        have to declare that their repository contains Terraform; the tool should
        observe it.
        """
        # Shared with `_units` when the caller has one, so the traversal
        # counters both phases read are the same counters. Creating a second
        # walker here left `_coverage_findings` reading a set of stats nobody
        # had walked with: a source that selected nothing then produced no
        # NOTHING_SCANNED finding, because as far as those stats were concerned
        # the tree was empty rather than unexamined.
        walker = walker if walker is not None else self._walker()
        # Materialised once by `_scan` and handed to both phases when the source
        # yields the walker's own output, which is the default and the case a
        # large monorepo actually hits. Walking twice cost a fifth of a warm
        # scan of fifty thousand files in `stat` calls that answered the same
        # question twice.
        traversal: Iterable[WalkEntry] = walked if walked is not None else walker.walk(root)
        languages: dict[str, tuple[int, int]] = {}
        evidence: dict[str, set[str]] = {}
        hooks: list[Hook] = []
        # Directories that are importable Python packages. Collected during the
        # walk because `_hooks_for` sees one path at a time and the question
        # `PACKAGED_BUILD_FILENAMES` asks is about a file's neighbours. This set
        # rather than every path walked, which on a large monorepo is tens of
        # megabytes held to answer a question about a handful of files.
        package_directories: set[str] = set()
        manifests: dict[str, list[str]] = {}
        lockfiles: dict[str, list[str]] = {}
        total_bytes = 0
        file_count = 0
        seen_paths: set[str] = set()
        deferred: list[tuple[Path, str, str]] = []

        file_count, total_bytes = self.inventory_walk(
            traversal,
            file_count,
            total_bytes,
            seen_paths,
            languages,
            evidence,
            package_directories,
            hooks,
            manifests,
            deferred,
            lockfiles,
        )

        frozen = frozenset(seen_paths)
        for real_path, rel_path, eco in deferred:
            hooks.extend(self._manifest_hooks(real_path, rel_path, eco, frozen))

        stats = Engine.inventory_stats(languages, total_bytes, evidence)

        hooks = [hook for hook in hooks if Hooks.hook_executes(hook, package_directories)]

        if acc is not None and walker.stats.limit_hit:
            acc.complete = False

        # A project is a subtree with its own manifest. Modelling a monorepo as
        # N projects is what keeps detector selection correct: without it, a
        # polyglot tree gets the union of every rule applied to every file.
        projects: list[Project] = []
        Engine.manifest_projects(manifests, projects, lockfiles)

        is_git, revision, remote, at_repository_root = TreeFacts.provenance(root)
        return Repository(
            root=str(root),
            is_git=is_git,
            scanned_repository_root=at_repository_root,
            languages=stats,
            projects=tuple(projects),
            ecosystems=tuple(sorted(set(manifests) | set(lockfiles))),
            hooks=tuple(hooks),
            file_count=file_count,
            total_bytes=total_bytes,
            revision=revision,
            remote=remote,
        )

    @staticmethod
    def inventory_stats(
        languages: dict[str, tuple[int, int]], total_bytes: int, evidence: dict[str, set[str]]
    ) -> tuple[LanguageStat, ...]:
        """The tree's languages as statistics, largest first."""
        return tuple(
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

    def inventory_walk(
        self,
        traversal: Iterable[WalkEntry],
        file_count: int,
        total_bytes: int,
        seen_paths: set[str],
        languages: dict[str, tuple[int, int]],
        evidence: dict[str, set[str]],
        package_directories: set[str],
        hooks: list[Hook],
        manifests: dict[str, list[str]],
        deferred: list[tuple[Path, str, str]],
        lockfiles: dict[str, list[str]],
    ) -> tuple[int, int]:
        """The traversal's files, counted by language, with manifests and lockfiles noted."""
        for entry in traversal:
            if entry.is_symlink:
                continue
            file_count += 1
            total_bytes += entry.size
            seen_paths.add(entry.rel_path)

            language = LanguageRegistry.identify_language(entry.rel_path)
            if language:
                files, size = languages.get(language, (0, 0))
                languages[language] = (files + 1, size + entry.size)
                evidence.setdefault(language, set()).add(
                    f"*{Path(entry.rel_path).suffix}"
                    if Path(entry.rel_path).suffix
                    else entry.rel_path
                )

            if ContainerPaths.basename(entry.rel_path) == "__init__.py":
                package_directories.add(entry.rel_path.rpartition("/")[0])

            hooks.extend(Hooks.hooks_for(entry.rel_path))

            eco = EcosystemRegistry.manifest_ecosystem(entry.rel_path)
            if eco:
                manifests.setdefault(eco, []).append(entry.rel_path)
                if hasattr(EcosystemRegistry.get(eco), "hooks_from_tree"):
                    # Its install-time code is a file beside the manifest: read once the whole
                    # tree has been walked, as the manifest detector reads it.
                    deferred.append((entry.real_path, entry.rel_path, eco))
                else:
                    hooks.extend(self._manifest_hooks(entry.real_path, entry.rel_path, eco))
            lock = EcosystemRegistry.lockfile_ecosystem(entry.rel_path)
            if lock:
                lockfiles.setdefault(lock, []).append(entry.rel_path)
        return file_count, total_bytes

    @staticmethod
    def manifest_projects(
        manifests: dict[str, list[str]], projects: list[Project], lockfiles: dict[str, list[str]]
    ) -> None:
        """The projects each ecosystem's manifests describe."""
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

    def _manifest_hooks(
        self,
        real_path: Path,
        rel_path: str,
        ecosystem_id: str,
        tree: frozenset[str] | None = None,
    ) -> list[Hook]:
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
            manifest = ecosystem.parse_manifest(loaded)
            hooks_from_tree = getattr(ecosystem, "hooks_from_tree", None)
            if tree is not None and hooks_from_tree is not None:
                manifest = hooks_from_tree(manifest, tree)
            return list(manifest.hooks)
        except Exception:  # noqa: BLE001
            return []

    # -- Phase 1: planning and unit production ---------------------------

    def _walker(self) -> Walker:
        return Walker(
            exclude=self.config.exclude,
            include=self.config.include,
            limits=self.config.limits,
        )

    def _context(self, inventory: Repository, deadline: float | None = None) -> ScanContext:
        return ScanContext(
            config=self.config,
            rules=self.rules,
            repository=inventory,
            deadline=deadline,
            # `projectbuild` is in neither. A Makefile is not an install hook -- see
            # `PROJECT_BUILD_FILENAMES` -- and it is not a pipeline either, so it gets
            # no context multiplier and is scored on what it actually contains.
            install_hook_paths=frozenset(
                h.path for h in inventory.hooks if h.kind not in ("ci", "projectbuild")
            ),
            ci_hook_paths=frozenset(h.path for h in inventory.hooks if h.kind == "ci"),
            scorer=self.scorer,
            offline=self.config.offline,
        )

    # -- Dependency graph ------------------------------------------------

    def _agent_tool_paths(
        self, units: Sequence[FileUnit], agent_run: set[str], hooks: set[str]
    ) -> frozenset[str]:
        """Agent-run code and the modules it imports, less anything a real install hook reaches.

        An MCP server's file importing the SDK hands its API calls to `client.py` and `core.py`;
        those run on the agent's tool calls exactly as the server does (review 98: serper's
        `core.py` sending SERPER_API_KEY to google.serper.dev was blocked while the same call in
        the server file was not). What `setup.py` or a lifecycle script also reaches keeps the
        install grade."""
        if not agent_run:
            return frozenset()
        tools = agent_run | Hooks.hook_import_closure(units, agent_run)
        tools |= Hooks.hook_js_closure(units, tools)
        if hooks:
            real = hooks | Hooks.hook_import_closure(units, hooks)
            real |= Hooks.hook_js_closure(units, real)
            tools -= real - agent_run
        return frozenset(tools)

    #: How many files of one kind the capability profile labels: the files that run at install or
    #: on import are a handful in any real package; past this the rest are not read again.
    _PROFILE_FILES: ClassVar[int] = 50

    def _intent_observation(
        self, units: Sequence[FileUnit], ctx: ScanContext, labels: dict[str, Any]
    ) -> Any:
        """When each effect of the package runs, and what hides it (`core/intent.py`); None for a
        package the intent layer does not read."""
        from cordon_scanner.decide.intent import IntentObserver
        from cordon_scanner.detect.code.capability.detector import CapabilityDetector
        from cordon_scanner.detect.code.download_flow import DownloadFlow

        detector = next((d for d in self.detectors if isinstance(d, CapabilityDetector)), None)
        if detector is None or not IntentObserver.applies(ctx):
            return None
        files = [u for u in units if isinstance(u, FileUnit)]

        def label(unit: FileUnit) -> list[tuple[str, int]]:
            labelled = TreeFacts.labelled_once(detector, unit, ctx, labels)
            out = [(hit.capability.value, hit.byte_start) for hit in (labelled or ((),))[0]]
            lines = DownloadFlow.runs_download(unit.content.text, unit.language)
            if lines:
                raw = unit.content.raw
                starts = [0, *(i + 1 for i, b in enumerate(raw) if b == 10)]
                out += [("runs_download", starts[min(n, len(starts)) - 1]) for n in lines]
            return out

        return IntentObserver.observe(
            files, ctx, label, lambda seeds: Hooks.hook_js_closure(files, seeds)
        )

    def _capability_profile(
        self, units: Sequence[FileUnit], ctx: ScanContext, labels: dict[str, Any] | None = None
    ) -> dict[str, float]:
        """What the code that runs on its own can do: the capabilities of the files an install
        runs, of the files importing the package runs first, and of the scripts an agent runs.

        A rule reports a combination it was written for; most malware that no rule names still
        does, at install or on import, things a library's entry point does not -- start a
        process, reach the network, decode and evaluate (review 98: a `setup.py` that clones a
        repository and runs a script from it raised nothing). The verdict weighs the profile with
        everything else; on its own it blocks nothing.
        """
        from cordon_scanner.detect.code.capability.detector import CapabilityDetector
        from cordon_scanner.detect.code.download_flow import DownloadFlow
        from cordon_scanner.detect.code.reached_flows import ReachedFlows

        detector = next((d for d in self.detectors if isinstance(d, CapabilityDetector)), None)
        if detector is None:
            return {}
        out: dict[str, float] = {}
        places = {
            "install": ctx.install_hook_paths | ctx.install_entry_paths,
            "import": ctx.import_entry_paths,
            "agent": ctx.agent_run_paths,
        }
        for place, paths in places.items():
            held: set[str] = set()
            read = 0
            for unit in units:
                if unit.path not in paths or unit.content.size > 1_000_000:
                    continue
                if read >= Engine._PROFILE_FILES:
                    break
                read += 1
                try:
                    labelled = TreeFacts.labelled_once(detector, unit, ctx, labels)
                except Exception:  # noqa: BLE001, S112
                    continue
                if labelled is not None:
                    held |= {hit.capability.value for hit in labelled[0]}
                if "runs_download" not in held and DownloadFlow.runs_download(
                    unit.content.text, unit.language
                ):
                    held.add("runs_download")
            out[f"{place}_files"] = float(read)
            out[f"{place}_capabilities"] = float(len(held))
            out.update({f"{place}_can_{name}": 1.0 for name in held})
        return out | ReachedFlows.of(units, ctx)  # what the reached code does with what it reads

    # -- Phase 2: execution ----------------------------------------------


__all__ = ["Engine"]
