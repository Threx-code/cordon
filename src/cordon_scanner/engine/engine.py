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

import base64
import binascii
import contextlib
import io
import posixpath
import re
import time
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.analysis.shared.inline_programs import InlinePrograms
from cordon_scanner.analysis.shared.languages import LanguageRegistry
from cordon_scanner.decide.policy import PolicyGate, SuppressionMatcher
from cordon_scanner.decide.scoring import RiskScorer
from cordon_scanner.detect.agents.agent_judge import JudgeGate
from cordon_scanner.detect.base import (
    FileUnit,
    GraphUnit,
    RepositoryUnit,
    ScanContext,
    Unit,
)
from cordon_scanner.detect.supply.composer_plugins import ComposerPluginHooks
from cordon_scanner.ecosystems.base import Coordinate, LockEntry, LockGraph
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.engine.cache import CacheKey, ScanCache
from cordon_scanner.engine.entries import PackageEntries
from cordon_scanner.engine.package_format import PackageFormat
from cordon_scanner.engine.parallel import MAX_CARRIED_BYTES, ParallelScanner, WorkItem
from cordon_scanner.engine.pipeline.accumulator import Accumulator
from cordon_scanner.engine.pipeline.archives import ArchiveMembers
from cordon_scanner.engine.pipeline.ceilings import Ceilings
from cordon_scanner.engine.pipeline.constants import (
    ADVISORY_DETECTORS,
    ALWAYS_RUN,
    ARCHIVE_SLICE,
    BLINDING_SETTINGS,
    BROAD_EXCLUSION_MIN_FILES,
    BROAD_EXCLUSION_SHARE,
    CERTIFICATE_BLOCK,
    DER_STRING,
    DROP_POINT_SECRETS,
    HONOURED_PINS,
    PACKAGED_BUILD_FILENAMES,
    REPOSITORY_SCOPE,
    TEST_IDENTITY,
)
from cordon_scanner.engine.pipeline.graph import Graph
from cordon_scanner.engine.pipeline.history import History
from cordon_scanner.engine.pipeline.hooks import Hooks
from cordon_scanner.engine.pipeline.operational import OperationalFinding
from cordon_scanner.engine.pipeline.releases import ReleaseChecks
from cordon_scanner.engine.pipeline.results import ResultFolding
from cordon_scanner.engine.progress import NullProgress, Progress
from cordon_scanner.engine.walker import (
    INSTALLED_CODE_PRUNE_DIRS,
    WalkEntry,
    Walker,
    WalkStats,
)
from cordon_scanner.engine.window_pass import WindowPass
from cordon_scanner.foundation.collector import Collector
from cordon_scanner.foundation.config import Config
from cordon_scanner.foundation.content import FileContent, Skipped
from cordon_scanner.foundation.errors import ArchiveError, SourceError
from cordon_scanner.foundation.models import (
    AUTHOR_TIME_HOOKS,
    Category,
    Confidence,
    Dependency,
    Finding,
    Hook,
    LanguageStat,
    Project,
    Repository,
    ScanResult,
    ScanStats,
    Scope,
    Severity,
)
from cordon_scanner.foundation.paths import ContainerPaths
from cordon_scanner.rules.loader import RuleLoader, RuleSet
from cordon_scanner.sources.archive import ArchiveReader
from cordon_scanner.sources.base import FileSource, Rejection, WorkingTreeSource
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
        dependencies = self._image_dependencies(inventory)
        ctx = replace(self._context(Repository(root=str(root))), image=inventory)
        if dependencies:
            ctx = replace(ctx, dependencies=Graph.packages(dependencies))
            graph_unit = GraphUnit(dependencies=Graph.packages(dependencies))
            self.progress.phase("dependencies")
            with self._sealed_scan():
                for detector in self.detectors:
                    if detector.requires.dependencies and self._detector_enabled(detector, ctx):
                        acc.add(self._run(detector, graph_unit, ctx, acc))
        dependencies = self._annotated(dependencies, acc.findings, ctx, [])
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

        # Recorded before resolving, because resolving is what loses it. The
        # walker never follows a link found during traversal; a link *named as
        # the target* is the one path where a link's destination is read, and it
        # is operator-directed rather than an attack. Reported so the absolute
        # guarantee stated elsewhere has its one exception visible.
        named = Path(target)
        root = named.resolve()
        if named.is_symlink():
            acc.append(
                OperationalFinding.build(
                    path=str(named),
                    rule_id="OPERATIONAL.FILE.SYMLINK_TARGET",
                    message=(
                        f"The scan target is a symbolic link and its destination "
                        f"({root}) was read. Links found during traversal are never "
                        f"followed; this one was named on the command line."
                    ),
                    remediation="Scan the destination directly if that was not intended.",
                    severity=Severity.INFO,
                )
            )
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

        # Manifest hooks are discovered while scanning, and they change the
        # context every later finding is scored against: the same capability
        # pair means something different inside a lifecycle script. So files are
        # collected first, hooks are folded into the context, and detectors run
        # against the completed picture.
        self.progress.phase("reading")
        units = []
        for unit in self._units(root, inventory, acc, deadline, walked=walked, walker=walker):
            units.append(unit)
            self.progress.advance(unit.path)
        units.extend(self._inline_hook_units(units))
        units.extend(self._deobfuscated_units(units))

        self.progress.phase("dependencies")
        dependencies = self._build_graph(units, acc)
        # A bill of materials named as the target is its inventory; in a tree it is a claim to
        # compare with what the tree resolves (`detect/sbom.py`), never counted twice.
        ingested = self._sbom_dependencies(units, acc) if root.is_file() else ()
        # Repositories checked out as git submodules, at the commits their gitlinks pin.
        from cordon_scanner.detect.source.submodules import Submodules

        submodules, unreadable = Submodules.dependencies(
            units, root if root.is_dir() else root.parent
        )
        for path, problem in unreadable:
            acc.complete = False
            acc.append(
                OperationalFinding.build(
                    path=path,
                    rule_id="OPERATIONAL.MANIFEST.UNPARSED",
                    message=f"This .gitmodules could not be read: {problem}. Its submodules are not in the inventory.",
                    remediation="Fix the file so `git submodule` reads it.",
                    severity=Severity.MEDIUM,
                )
            )
        dependencies = (*dependencies, *ingested, *submodules)
        manifest_hooks, consumer_hooks, ci_scripts = self._manifest_hook_paths(units, acc)
        hook_paths = (
            set(ctx.install_hook_paths)
            | manifest_hooks
            | Hooks.nuget_hooks(units)
            | Hooks.gem_extension_hooks(units)
            | ComposerPluginHooks.paths(units)
        )
        # A skill's scripts run when the agent uses the skill, on the user's machine and unasked:
        # the trust boundary an install hook has (review 98: a skill script reading files and
        # posting them out was graded as a library's, at MEDIUM).
        skill_scripts = Engine._skill_scripts(units)
        agent_run = skill_scripts | ReleaseChecks.mcp_server_sources(units)
        agent_tools = self._agent_tool_paths(units, agent_run, hook_paths)
        # Only a skill's scripts take the install grade. An MCP server runs when the agent calls
        # a tool the user asked it to use: downloading a browser, starting a detached emulator or
        # writing its config is the tool's work, and graded as install code it blocked 40 of 863
        # real MCP packages (review 98). What a server's handlers do with the agent's input is
        # read by `detect/mcp_code.py` instead -- a shell behind a secret prefix, a hidden copy of
        # every argument, a gate that turns the tool later, secrets gathered by name.
        hook_paths |= skill_scripts
        # What runs at install time is the hook and everything it imports. The
        # context stopped at the hook file, so moving the payload into a helper
        # module -- no obfuscation, just ordinary package structure -- avoided
        # the escalation entirely.
        entries = frozenset(hook_paths)
        hook_paths |= Hooks.hook_import_closure(units, hook_paths)
        hook_paths |= Hooks.hook_js_closure(units, hook_paths)
        hook_paths, entries, consumer_hooks = Hooks.outside_extensions(
            units, hook_paths, entries, consumer_hooks
        )
        # And which of those files' bodies the hooks actually reach. A file is
        # in the closure because something imports it, which runs its top level
        # and defines its functions -- it does not call them.
        # Every function of agent-run code is an entry point: the agent calls them by name.
        deferred = Engine._entry_points_reached(
            self._hook_deferred_lines(units, hook_paths, entries), agent_run
        )
        ctx = replace(
            ctx,
            dependencies=Graph.packages(dependencies),
            install_hook_paths=frozenset(hook_paths),
            tree_paths=frozenset(unit.path for unit in units),
            shipped_native_paths=Engine._shipped_native(units),
            install_entry_paths=entries,
            agent_run_paths=agent_tools,
            consumer_install_paths=frozenset(consumer_hooks),
            install_deferred_lines=deferred,
            ci_hook_paths=ctx.ci_hook_paths | frozenset(ci_scripts),
        )
        ctx = Hooks.lifted_inherit(ctx)

        file_detectors = [
            d
            for d in self.detectors
            if self._detector_enabled(d, ctx)
            and not (d.requires.dependencies and d.requires.content is False)
        ]
        signature = ScanCache.detector_signature(file_detectors)

        # A source whose bytes are not what is on disk cannot have its files
        # re-read by a worker: a staged scan would examine the working tree
        # instead of the index. Such a source is parallelised by sending the
        # bytes the parent already read, so the worker reads nothing at all.
        #
        # Bounded by `MAX_CARRIED_BYTES`: above that the scan stays serial
        # rather than pickling an unbounded amount of a repository into a pool.
        carry_content = not self.source.parallel_safe
        carried_bytes = sum(len(u.content.raw) for u in units) if carry_content else 0
        parallelisable = not carry_content or carried_bytes <= MAX_CARRIED_BYTES
        workers = (
            ParallelScanner.worker_count(
                self.config.limits.max_workers,
                len(units),
                carried_bytes if carry_content else sum(u.content.size for u in units),
            )
            if parallelisable
            else 1
        )
        self.progress.phase("scanning", total=len(units))
        with self._sealed_scan():
            if workers > 1:
                acc.add(
                    self._scan_parallel(
                        units,
                        root,
                        ctx,
                        acc,
                        file_detectors,
                        signature,
                        carry_content=carry_content,
                    )
                )
            else:
                for unit in units:
                    acc.add(self._inspect_file(unit, ctx, acc, file_detectors, signature))
                    self.progress.advance(unit.path)
            acc.add(ReleaseChecks.unexamined_install_code(acc.findings, ctx))
            acc.add(ReleaseChecks.native_code_in_a_pure_wheel(units, ctx))
            acc.add(ReleaseChecks.known_malicious_release(units, ctx))
            acc.add(ReleaseChecks.placeholder_release(units, ctx))
            acc.add(ReleaseChecks.borrowed_server_name(units, ctx))

            if dependencies:
                self.progress.phase("graph")
                graph_unit = GraphUnit(dependencies=Graph.packages(dependencies))
                for detector in self.detectors:
                    if not detector.requires.dependencies:
                        continue
                    if not self._detector_enabled(detector, ctx):
                        continue
                    acc.add(self._run(detector, graph_unit, ctx, acc))
            acc.add(self._sbom_listed_findings(acc.findings, ctx))

        # Reachability annotates the vulnerability findings just produced, using
        # the imports of the files just scanned -- so it runs here, after the
        # graph pass and while `units` is still in hand. Opt-in, because it reads
        # every source file. It only ever lowers or tags a finding, never removes
        # one, so it is safe to run over the accumulator in place.
        if self.config.reachability and dependencies:
            from cordon_scanner.detect.supply import reachability

            acc.findings[:] = reachability.ImportReachability.annotate(
                acc.findings, units, dependencies
            )

        acc.findings[:] = Ceilings.person_run_ceiling(acc.findings, units, ctx)
        acc.findings[:] = Ceilings.graded_by_what_it_does(acc.findings, ctx)

        # Repository-scoped detectors. `RepositoryUnit` existed and nothing
        # produced one, so a detector asking about the repository rather than
        # about a file had no way to run at all -- the port was declared and
        # never wired.
        repository_unit = RepositoryUnit(repository=inventory)
        with self._sealed_scan():
            for detector in self.detectors:
                if not detector.requires.repository:
                    continue
                if not self._detector_enabled(detector, ctx):
                    continue
                acc.add(self._run(detector, repository_unit, ctx, acc))

        if acc.capped:
            # Appended directly: the cap is full by definition, and the one
            # finding that explains why must not be the one it drops.
            acc.findings.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.SCAN.FINDING_LIMIT",
                    message=(
                        f"The scan reached its limit of {acc.finding_cap} findings and "
                        f"stopped recording more. Results are partial."
                    ),
                    remediation=(
                        "Raise limits.max_findings, or narrow the scan. A repository "
                        "that produces this many findings usually has one systemic "
                        "cause worth fixing first."
                    ),
                )
            )

        # A suppression that expired is reported, not merely inactive: the
        # finding it was hiding reappears at the same moment somebody is told
        # why, rather than as an unexplained new failure weeks later.
        matcher = SuppressionMatcher(self.config)
        acc.add(matcher.expiry_findings())
        findings = ResultFolding.key_table(
            ResultFolding.credential_name(
                ResultFolding.polyglot_corpus(
                    ResultFolding.key_corpus(
                        ResultFolding.idiom(
                            ResultFolding.repeats(
                                ResultFolding.graded_pair(matcher.apply(acc.findings))
                            )
                        )
                    )
                )
            )
        )

        labels: dict[str, Any] = {}
        graded, verdict = Ceilings.verdict(
            Ceilings.hardening_tier(
                Hooks.onto_manifest(Engine._test_identity_keys(list(findings), units), units),
                self.config.policy,
            ),
            units,
            {**self._capability_profile(units, ctx, labels), **History.registry_facts(units)},
            self._intent_observation(units, ctx, labels),
        )
        findings = tuple(graded)
        dependencies = self._annotated(dependencies, findings, ctx, units)
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

        # A container image is read the way a runtime assembles it -- layers squashed, whiteouts
        # applied -- rather than as nested tarballs, whose layer members are far past any per-member
        # limit and whose files would be scanned once per layer that touched them.
        image = self._image_inventory(data, acc)
        members: Iterable[tuple[str, bytes]]
        if image is not None:
            from cordon_scanner.images import oci

            members = (
                (f"{path.name}!{member}", payload)
                for member, payload in oci.ImageLayers.added_files(
                    data,
                    image,
                    max_file_bytes=self.config.limits.max_file_bytes,
                    max_total_bytes=self.config.limits.max_memory_bytes or (1 << 30),
                )
            )
        else:
            members = ArchiveReader.walk_archive(
                data,
                path=path.name,
                limits=self.config.limits,
                rejected=rejected,
                deadline=deadline if self.config.limits.total_timeout > 0 else None,
            )

        try:
            for member_path, member_data in members:
                if self.config.limits.total_timeout > 0 and time.monotonic() > deadline:
                    acc.complete = False
                    acc.append(
                        OperationalFinding.build(
                            path=path.name,
                            rule_id="OPERATIONAL.SCAN.TIMEOUT",
                            message=(
                                f"Expanding this archive exceeded the "
                                f"{self.config.limits.total_timeout:.0f}s budget, so the "
                                f"remaining members were not examined."
                            ),
                            remediation=(
                                "Raise --timeout, or treat an archive this large as "
                                "something to unpack and scan as a directory."
                            ),
                            severity=Severity.MEDIUM,
                        )
                    )
                    break

                retained += len(member_data)
                if (
                    self.config.limits.max_memory_bytes > 0
                    and retained > self.config.limits.max_memory_bytes
                ):
                    acc.complete = False
                    acc.append(
                        OperationalFinding.build(
                            path=path.name,
                            rule_id="OPERATIONAL.SCAN.MEMORY_LIMIT",
                            message=(
                                f"Expanded members reached the "
                                f"{self.config.limits.max_memory_bytes} byte ceiling, so "
                                f"the remaining members were not examined."
                            ),
                            remediation="Raise limits.max_memory_bytes, or scan unpacked.",
                            severity=Severity.MEDIUM,
                        )
                    )
                    break

                member_content = FileContent.from_member(
                    member_path, member_data, self.config.limits
                )
                if member_content.truncated:
                    acc.complete = acc.complete and ArchiveMembers.read_to_end(member_content)
                    acc.append(ArchiveMembers.truncated_note(member_path, member_content))
                units.append(
                    FileUnit(
                        content=member_content,
                        language=LanguageRegistry.of_file(member_path, member_content),
                    )
                )
                acc.files_scanned += 1
                acc.bytes_scanned += len(member_data)
        except ArchiveError as exc:
            acc.complete = False
            acc.append(
                OperationalFinding.build(
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

        for member_path, reason, detail in rejected:
            # A link has no content of its own: refusing it leaves nothing unread.
            acc.complete = acc.complete and reason == Rejection.LINK
            acc.append(
                ArchiveMembers.rejected(member_path, reason, detail, image=image is not None)
            )

        # Manifests inside a package determine whether its code runs at install
        # time, which is the whole reason a package archive is worth scanning.
        units.extend(self._inline_hook_units(units))
        units.extend(self._deobfuscated_units(units))
        hook_paths, consumer_hooks, ci_scripts = self._manifest_hook_paths(units, acc)
        # The same install-time picture a directory scan builds: filename hooks (`setup.py`, a
        # `.pth`), and everything the hooks import or run. A downloaded sdist or tarball is the
        # commonest thing to vet, and it was the one target that skipped all three.
        hook_paths |= {
            unit.path
            for unit in units
            if not Hooks.under_fixture_directory(unit.path)
            and any(
                hook.kind not in ("ci", "projectbuild")
                for hook in Hooks.hooks_for(unit.path.rpartition("!")[2])
            )
        }
        hook_paths |= Hooks.nuget_hooks(units)
        hook_paths |= Hooks.gem_extension_hooks(units)
        hook_paths |= ComposerPluginHooks.paths(units)
        skill_scripts = Engine._skill_scripts(units)
        agent_run = skill_scripts | ReleaseChecks.mcp_server_sources(units)
        agent_tools = self._agent_tool_paths(units, agent_run, hook_paths)
        # Only a skill's scripts take the install grade. An MCP server runs when the agent calls
        # a tool the user asked it to use: downloading a browser, starting a detached emulator or
        # writing its config is the tool's work, and graded as install code it blocked 40 of 863
        # real MCP packages (review 98). What a server's handlers do with the agent's input is
        # read by `detect/mcp_code.py` instead -- a shell behind a secret prefix, a hidden copy of
        # every argument, a gate that turns the tool later, secrets gathered by name.
        hook_paths |= skill_scripts
        entries = frozenset(hook_paths)
        hook_paths |= Hooks.hook_import_closure(units, hook_paths)
        hook_paths |= Hooks.hook_js_closure(units, hook_paths)
        hook_paths, entries, consumer_hooks = Hooks.outside_extensions(
            units, hook_paths, entries, consumer_hooks
        )
        ctx = replace(
            ctx,
            install_hook_paths=frozenset(hook_paths),
            tree_paths=frozenset(unit.path for unit in units),
            shipped_native_paths=Engine._shipped_native(units),
            install_entry_paths=entries,
            agent_run_paths=agent_tools,
            consumer_install_paths=frozenset(consumer_hooks),
            ci_hook_paths=ctx.ci_hook_paths | frozenset(ci_scripts),
            install_deferred_lines=Engine._entry_points_reached(
                self._hook_deferred_lines(units, hook_paths, entries), agent_run
            ),
            # Known before any file is examined, so a detector can tell an image's files from a
            # source tree's: an image's executables are what it ships.
            image=image if image is not None else ctx.image,
            # And so can a published package's: its `build/` and `bin/` are what runs, and the
            # typosquat grading asks which format it is.
            package_distribution=bool(early_format := PackageFormat.of(units)),
            distribution=early_format,
            import_entry_paths=PackageEntries.of(units, early_format),
            library_entry_paths=PackageEntries.of(units, early_format, with_bin=False),
            library_closure_paths=frozenset(
                Hooks.hook_js_closure(
                    units, set(PackageEntries.of(units, early_format, with_bin=False))
                )
            ),
            declared_dependencies=History.declared_dependencies(units, early_format),
            package_repository=PackageEntries.repository(units, early_format),
        )
        ctx = Hooks.lifted_inherit(ctx)

        detectors = [d for d in self.detectors if self._detector_enabled(d, ctx)]
        self.progress.phase("scanning", total=len(units))
        # An image or a large archive is thousands of members (a Grafana image adds eleven
        # thousand files): across the worker pool, as a directory is, with each member's bytes
        # carried since it has no path on disk. In slices, so the scan's deadline is still checked.
        content_detectors = [
            d for d in detectors if not (d.requires.dependencies and d.requires.content is False)
        ]
        workers = ParallelScanner.worker_count(
            self.config.limits.max_workers, len(units), sum(len(u.content.raw) for u in units)
        )
        if workers > 1:
            from cordon_scanner.engine.cache import ScanCache

            signature = ScanCache.detector_signature(content_detectors)
            for start in range(0, len(units), ARCHIVE_SLICE):
                if self.config.limits.total_timeout > 0 and time.monotonic() > deadline:
                    acc.complete = False
                    acc.append(
                        OperationalFinding.build(
                            path=path.name,
                            rule_id="OPERATIONAL.SCAN.TIMEOUT",
                            message=f"The {self.config.limits.total_timeout:.0f}s budget was reached with members still unexamined.",
                            remediation="Raise --timeout, or unpack and scan as a directory.",
                            severity=Severity.MEDIUM,
                        )
                    )
                    break
                acc.add(
                    self._scan_parallel(
                        units[start : start + ARCHIVE_SLICE],
                        path.parent,
                        ctx,
                        acc,
                        content_detectors,
                        signature,
                        carry_content=True,
                    )
                )
            units_left: list[FileUnit] = []
        else:
            units_left = units
        for unit in units_left:
            # The same budget the directory path applies between units. Most of
            # the cost of a hostile archive is here rather than in extraction --
            # a fifty-thousand-member archive expands in a second and then takes
            # eight to match against -- so a deadline that only covered
            # expansion bounded the wrong half.
            if self.config.limits.total_timeout > 0 and time.monotonic() > deadline:
                acc.complete = False
                acc.append(
                    OperationalFinding.build(
                        path=path.name,
                        rule_id="OPERATIONAL.SCAN.TIMEOUT",
                        message=(
                            f"The {self.config.limits.total_timeout:.0f}s budget was reached "
                            f"with members still unexamined."
                        ),
                        remediation="Raise --timeout, or unpack and scan as a directory.",
                        severity=Severity.MEDIUM,
                    )
                )
                break
            member_detectors = [
                d
                for d in detectors
                if not (d.requires.dependencies and d.requires.content is False)
            ]
            produced: list[Finding] = []
            for detector in member_detectors:
                produced.extend(self._run(detector, unit, ctx, acc))
            # The rest of an oversized member, a window at a time, as `_inspect_file` reads one.
            windowed, intact = WindowPass.run(
                unit,
                member_detectors,
                lambda detector, part: self._run(detector, part, ctx, acc),
                produced,
            )
            produced.extend(windowed)
            if not intact:
                acc.complete = False
                produced.append(ArchiveMembers.changed_while_read(unit.path))
            acc.add(produced)
            self.progress.advance(unit.path)
        acc.add(ReleaseChecks.unexamined_install_code(acc.findings, ctx))
        acc.add(ReleaseChecks.native_code_in_a_pure_wheel(units, ctx))
        acc.add(ReleaseChecks.known_malicious_release(units, ctx))
        acc.add(ReleaseChecks.placeholder_release(units, ctx))
        acc.add(ReleaseChecks.borrowed_server_name(units, ctx))

        # A published archive carries its own manifests and lockfiles, and
        # "is this tarball a known-malicious release?" is the question most
        # people open one to ask. Building the graph from the members is what
        # lets the advisory, licence and dependency detectors answer it --
        # without it they had no `GraphUnit` to inspect, so scanning a package
        # archive silently skipped every check about its dependencies.
        self.progress.phase("dependencies")
        dependencies = self._build_graph(units, acc)
        if image is not None:
            self._report_image_contents(image, acc)
        package = PackageFormat.of(units)
        target_kind = "image" if image is not None else "package" if package else "archive"
        if package:
            # A consumer's installer resolves from the package's declared metadata, never from a
            # lockfile shipped inside it: those pins are the maintainers' own environment. The
            # exception is a file that installer reads and obeys (`HONOURED_PINS`): what it pins
            # is what installing the package brings in. An archive that may be a repository
            # snapshot instead is graded both ways (`PackageFormat.union`, review 98 #18).
            both = PackageFormat.renamed_npm(units)
            repository = Ceilings.person_run_ceiling(list(acc.findings), units, ctx) if both else []
            ctx = replace(ctx, package_distribution=True, distribution=package)
            acc.add(History.young_dependency_introduced(units, package, ctx))
            acc.findings[:] = Ceilings.impersonator_runs_downloads(
                self._publisher_hygiene(
                    self._publisher_secrets(
                        History.established_release_ceiling(
                            Ceilings.author_time_ceiling(
                                acc.findings, units, package, ctx.install_hook_paths
                            ),
                            units,
                            package,
                            hook_paths=ctx.install_hook_paths,
                        )
                    ),
                    self.config.policy.advisory_domains,
                )
            )
            acc.findings[:] = PackageFormat.union(acc.findings, repository)
            honoured = HONOURED_PINS.get(package)
            dependencies = tuple(
                replace(d, scope=Scope.DEV)
                if not both
                and d.scope in (Scope.RUNTIME, Scope.UNKNOWN)
                and not (honoured and honoured.search(d.declared_in or ""))
                else d
                for d in dependencies
            )
        elif image is None:
            # A source tree read from an archive: graded as a repository (`_person_run_ceiling`).
            acc.findings[:] = Ceilings.person_run_ceiling(acc.findings, units, ctx)
            if History.history_distribution(units) == "openvsx":
                # An editor extension against its own established release (`intel/openvsx.py`).
                acc.findings[:] = History.established_release_ceiling(
                    acc.findings, units, "openvsx", hook_paths=ctx.install_hook_paths
                )
        acc.findings[:] = Ceilings.graded_by_what_it_does(acc.findings, ctx)
        if image is not None:
            acc.findings[:] = Ceilings.image_start_ceiling(acc.findings, units)
            ctx = replace(ctx, image=image)
            installed = self._image_dependencies(image)
            present = {(d.ecosystem, d.name.lower(), d.version) for d in installed}
            # An image's inventory is what is installed in it. A lockfile or manifest inside it
            # names what the application was built from, development packages and ranges
            # included; an entry counts only where the same package is installed.
            dependencies = (
                *(d for d in dependencies if (d.ecosystem, d.name.lower(), d.version) in present),
                *installed,
            )
        if dependencies:
            ctx = replace(ctx, dependencies=Graph.packages(dependencies))
            graph_unit = GraphUnit(dependencies=Graph.packages(dependencies))
            for detector in self.detectors:
                if not detector.requires.dependencies:
                    continue
                if not self._detector_enabled(detector, ctx):
                    continue
                acc.add(self._run(detector, graph_unit, ctx, acc))

        labels: dict[str, Any] = {}
        acc.findings[:], verdict = Ceilings.verdict(
            Ceilings.hardening_tier(
                Hooks.onto_manifest(Engine._test_identity_keys(acc.findings, units), units),
                self.config.policy,
            ),
            units,
            {**self._capability_profile(units, ctx, labels), **History.registry_facts(units)},
            self._intent_observation(units, ctx, labels),
        )
        dependencies = self._annotated(dependencies, acc.findings, ctx, units)
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

        frozen = frozenset(seen_paths)
        for real_path, rel_path, eco in deferred:
            hooks.extend(self._manifest_hooks(real_path, rel_path, eco, frozen))

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

        hooks = [hook for hook in hooks if Hooks.hook_executes(hook, package_directories)]

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

        is_git, revision, remote, at_repository_root = self._provenance(root)
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
    def _provenance(root: Path) -> tuple[bool, str | None, str | None, bool]:
        """The commit and remote this scan describes.

        `Repository` declared both fields, `to_dict` serialised both, and
        nothing ever set either -- so every report and every SARIF upload
        recorded `null` for the two values that say *which* code was examined.
        A result nobody can tie to a commit is a result nobody can act on later:
        it says a repository was clean without saying which version of it.

        `GitRepository.discover` already computed both, including stripping any
        credential from the remote, and its answer was simply never asked for.

        `is_git` had the identical defect and is returned here for the same
        reason. It gated whether any repository-scoped detector runs at all, so
        leaving it false meant the history checks were shipped and never
        executed -- a detector that cannot run is indistinguishable from one
        that found nothing.

        Failure is silent on purpose. A directory that is not a repository is
        the ordinary case, not a degraded scan, and it is already visible in the
        report as an absent revision.
        """
        from cordon_scanner.sources.git import GitRepository

        try:
            info = GitRepository.discover(root)
        except (SourceError, OSError):  # pragma: no cover - defensive
            return (False, None, None, False)
        if info is None:
            return (False, None, None, False)
        # Whether the target is the repository root, which is a different question
        # from whether a repository is above it. Resolved on both sides, so a
        # symlinked or relative target does not read as a subdirectory of itself.
        try:
            at_root = Path(info.root).resolve() == Path(root).resolve()
        except OSError:  # pragma: no cover - defensive
            at_root = False
        return (True, info.revision, info.remote, at_root)

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

    def _units(
        self,
        root: Path,
        inventory: Repository,
        acc: Accumulator,
        deadline: float,
        *,
        walked: Sequence[WalkEntry] | None = None,
        walker: Walker | None = None,
    ) -> Iterator[FileUnit]:
        """Produce one unit per scannable file.

        A generator, but `scan` collects it into a list, because manifest hooks
        are discovered during this pass and change the context every later
        finding is scored against -- so detection cannot begin until the pass is
        complete. The generator therefore does not bound memory on its own, and
        the docstring here used to claim it did.

        What bounds it is `limits.max_memory_bytes`, enforced below as a running
        budget over retained content. The input is attacker-controlled and its
        size is not known in advance, so the ceiling has to be real rather than
        implied by the shape of the code.
        """
        walker = walker if walker is not None else self._walker()

        # A file an install hook executes is that interpreter's language,
        # whatever the file is called.
        implied_languages = Hooks.languages_from_hooks(inventory)

        # Counted here rather than read from walker.stats, because the source
        # sits between the walker and this loop. A git mode narrows the walker's
        # output, and that narrowing is invisible to the walker's own counters:
        # `--tracked` in a repository where nothing is tracked once yielded zero
        # files while the stats reported a full traversal, so the scan examined
        # nothing and reported clean.
        selected = 0
        # Bytes of file content this scan is holding. `max_memory_bytes` was
        # declared, documented and checked nowhere.
        retained = 0
        # Files classified as binary artefacts. Counted so the scan can say how
        # many files it did not examine as source: a file that was skipped and a
        # file that was examined and found clean must not look the same.
        binary: list[str] = []
        lfs_pointers: list[str] = []
        # Archives left closed because expansion is off. See `expand_archives`.
        unopened: list[str] = []

        selection: Iterable[WalkEntry] = (
            walked if walked is not None else self.source.entries(root, walker)
        )
        for entry in selection:
            selected += 1

            # `>=`, not `>`. A budget of zero means no time is allowed, and on
            # platforms with a coarse monotonic clock the first reading can equal
            # the start time exactly, so a strict comparison silently never
            # trips. That made --timeout 0 a no-op on Windows.
            if time.monotonic() >= deadline:
                # A partial result a human can act on beats a stack trace, and
                # marking it partial is what stops it being read as a pass.
                acc.complete = False
                acc.append(
                    OperationalFinding.build(
                        path=REPOSITORY_SCOPE,
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
                acc.append(
                    OperationalFinding.build(
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
                acc.append(
                    OperationalFinding.build(
                        path=entry.rel_path,
                        rule_id="OPERATIONAL.FILE.UNREADABLE",
                        message=f"File could not be read ({loaded.reason}); it was not scanned.",
                        remediation="Check permissions, or exclude the path deliberately.",
                    )
                )
                continue

            expanded: list[FileUnit] | None = None
            if ArchiveReader.is_archive(entry.rel_path):
                if self.config.expand_archives:
                    expanded = self._expand_member_units(entry.rel_path, loaded, acc, deadline)
                else:
                    unopened.append(entry.rel_path)

            if loaded.is_binary and expanded is None:
                binary.append(entry.rel_path)

            if loaded.is_lfs_pointer:
                lfs_pointers.append(entry.rel_path)

            if loaded.truncated:
                # A file examined in part is not a file examined. Truncation was
                # reported at INFO and left `complete` true, so
                # `fail_on_incomplete` -- the one organisation control that
                # catches the timeout variant of this -- did not catch the
                # sharpest one: `max_file_bytes: 65536` in a repository's own
                # config, which reads as ordinary tuning and pads a payload out
                # of reach. Unless the windows read it to its end: then every text rule saw
                # every byte, and only the whole-file parsers stopped at the limit.
                acc.complete = acc.complete and ArchiveMembers.read_to_end(loaded)
                # Said here, for every such file. It was said by the capability detector, which
                # returns before it for a binary file and for one no rule applies to -- so a
                # repository with a 12 MB font was incomplete, failed the Action's default gate,
                # and gave no reason.
                if entry.rel_path not in acc.rejected_archives:
                    acc.append(ArchiveMembers.truncated_note(entry.rel_path, loaded))

            retained += len(loaded.streamed or loaded.raw)
            if 0 < self.config.limits.max_memory_bytes <= retained:
                acc.complete = False
                acc.append(
                    OperationalFinding.build(
                        path=REPOSITORY_SCOPE,
                        rule_id="OPERATIONAL.SCAN.MEMORY_LIMIT",
                        message=(
                            f"Retained content reached the "
                            f"{self.config.limits.max_memory_bytes} byte budget after "
                            f"{acc.files_scanned} files, so the remaining files were "
                            f"not examined. Results are partial."
                        ),
                        remediation=(
                            "Raise limits.max_memory_bytes, exclude generated or "
                            "vendored directories, or scan the repository in parts."
                        ),
                    )
                )
                return

            acc.files_scanned += 1
            acc.bytes_scanned += len(loaded.raw)

            language = LanguageRegistry.identify_language(entry.rel_path)
            if language is None:
                language = implied_languages.get(entry.rel_path)
            if language is None:
                # An extensionless script -- `install`, `preinstall`,
                # `configure` -- got `language=None` and therefore only the
                # language-agnostic rules, although its shebang says exactly
                # what it is. Extensionless install scripts are a normal
                # shipping form and a normal place for a payload.
                language = LanguageRegistry.language_from_interpreter(loaded.shebang or "")
            if language is None and not loaded.is_binary:
                # And, last, what the content looks like. A file with neither a
                # known extension nor a shebang got no language at all, so a
                # payload in `postinstall` or `payload.dat` was examined by none
                # of the language rules while the identical bytes in
                # `postinstall.sh` were CRITICAL. See
                # `LanguageRegistry.identify_from_content` for why this is the
                # last step and never overrides a filename.
                language = LanguageRegistry.identify_from_content(loaded.text)

            yield FileUnit(content=loaded, language=language)

            # Members after the archive itself, each budgeted like a file: an
            # archive is the cheapest way to put a lot of content in front of a
            # scanner, so its members count against the same memory ceiling.
            for member in expanded or ():
                retained += len(member.content.raw)
                if 0 < self.config.limits.max_memory_bytes <= retained:
                    acc.complete = False
                    acc.append(
                        OperationalFinding.build(
                            path=entry.rel_path,
                            rule_id="OPERATIONAL.SCAN.MEMORY_LIMIT",
                            message=(
                                f"Retained content reached the "
                                f"{self.config.limits.max_memory_bytes} byte budget while "
                                f"expanding this archive, so the remaining files were not "
                                f"examined. Results are partial."
                            ),
                            remediation=(
                                "Raise limits.max_memory_bytes, or exclude vendored "
                                "artefacts deliberately."
                            ),
                        )
                    )
                    return
                acc.files_scanned += 1
                acc.bytes_scanned += len(member.content.raw)
                yield member

        if unopened:
            # An archive that was not opened is content that was not examined. Said
            # once, with the paths, and it makes the scan incomplete: `--no-expand`
            # buys speed, not a clean result.
            acc.complete = False
            sample = ", ".join(sorted(unopened)[:5])
            more = f" and {len(unopened) - 5} more" if len(unopened) > 5 else ""
            acc.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.ARCHIVE.NOT_EXPANDED",
                    message=(
                        f"{len(unopened)} archive(s) were not opened because archive "
                        f"expansion is off, so their contents were not examined: "
                        f"{sample}{more}."
                    ),
                    remediation="Scan without --no-expand, or set scan.expand_archives: true.",
                )
            )

        if walker.stats.limit_hit:
            acc.complete = False
            acc.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
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
        acc.add(
            self._coverage_findings(
                walker.stats,
                root,
                selected,
                complete=acc.complete,
                binary=binary,
                lfs_pointers=lfs_pointers,
                examined=acc.files_scanned,
            )
        )

        # L5 - traversal limits that dropped paths without a word.
        # `max_path_depth` incremented `dirs_pruned` and `max_path_bytes` pushed
        # the path into `stats.errors`; neither reached a finding, so both were
        # silent skips against the limits module's own invariant that reaching a
        # limit is never one.
        #
        # Only the second half landed. `dirs_pruned` is shared with
        # `node_modules` and every configured exclusion, so a depth cut stayed
        # invisible: a payload under seventy directories gave `files_scanned:
        # 1`, `complete: true`, no findings and exit 0. The walker now records
        # those paths separately, and this is where they are said out loud.
        if walker.stats.too_deep:
            sample = ", ".join(walker.stats.too_deep[:5])
            more = (
                f" and {len(walker.stats.too_deep) - 5} more"
                if len(walker.stats.too_deep) > 5
                else ""
            )
            acc.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.WALK.TOO_DEEP",
                    message=(
                        f"{len(walker.stats.too_deep)} directory tree(s) went deeper than "
                        f"the configured limit of {self.config.limits.max_path_depth} and "
                        f"everything below them was not examined: {sample}{more}."
                    ),
                    remediation=(
                        "Raise scan.limits.max_path_depth, or scan the deep tree "
                        "directly. Nothing under the cut was read, so nothing under "
                        "it was found clean -- and making a tree deep is the "
                        "cheapest way to put a file out of a scanner's reach."
                    ),
                )
            )
            acc.complete = False

        if walker.stats.errors:
            sample = ", ".join(path for path, _ in walker.stats.errors[:5])
            more = (
                f" and {len(walker.stats.errors) - 5} more" if len(walker.stats.errors) > 5 else ""
            )
            acc.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.WALK.ERROR",
                    message=(
                        f"{len(walker.stats.errors)} path(s) could not be traversed and were "
                        f"not examined: {sample}{more}."
                    ),
                    remediation=(
                        "Check permissions and path lengths. A path the walker could "
                        "not reach is not a path that was found clean."
                    ),
                    severity=Severity.MEDIUM,
                )
            )
            acc.complete = False

        for group, name, provider in self.shadowed:
            acc.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="POLICY.PLUGIN.SHADOWED",
                    category=Category.POLICY,
                    severity=Severity.HIGH,
                    message=(
                        f"The package {provider!r} registers {name!r} in {group}, which "
                        f"is the name of a built-in. It was not loaded; the built-in "
                        f"ran. A package that can replace a detector can disable it."
                    ),
                    remediation=(
                        "Uninstall the package, or report it if you did not install it "
                        "deliberately."
                    ),
                )
            )

        # Directories the built-in prune list skipped. Reported, because they
        # were not: a file never walked was indistinguishable in the output from
        # one scanned and found clean, which is the failure this whole file
        # exists to prevent, applied to the tool's own defaults.
        #
        # `node_modules` is why this matters rather than being tidy. It is where
        # an installed malicious dependency's code and lifecycle scripts live,
        # so a scan run after `npm install` could not see the dependency code it
        # was there to examine and said nothing about that.
        if walker.stats.pruned_dirs:
            names = sorted(walker.stats.pruned_dirs)
            sample = ", ".join(names[:6])
            more = f" and {len(names) - 6} more" if len(names) > 6 else ""
            acc.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="POLICY.COVERAGE.PRUNED",
                    category=Category.POLICY,
                    severity=Severity.LOW,
                    message=(
                        f"{len(names)} director(ies) were skipped by the built-in prune "
                        f"list and not examined: {sample}{more}. These normally hold "
                        f"build output or an installed dependency tree, which is "
                        f"reproducible from the manifests that were scanned -- but "
                        f"installed dependency code is also where a malicious package's "
                        f"payload actually runs from."
                    ),
                    remediation=(
                        "Pass --include with a pattern covering the directory to scan "
                        "it, for example --include 'node_modules/**'."
                    ),
                )
            )
            # An installed dependency tree or an editor execution vector was
            # skipped, so code that runs was not read. A default scan still only
            # carries the low note above, but the result is marked incomplete so
            # `--fail-on-incomplete` fails on it -- the same stance the walker
            # takes toward an archive pruned past its depth limit, applied to
            # the directory where an installed malicious package's payload runs.
            skipped_code = set(walker.stats.pruned_dirs) & set(INSTALLED_CODE_PRUNE_DIRS)
            # A narrowed scan (`--staged`, `--tracked`, `--git-diff`) still walks the working
            # tree once, for the repository inventory, and that walk prunes `node_modules/` on
            # every developer machine. Marking the scan incomplete for it failed a pre-commit
            # hook under any policy with `fail_on_incomplete` - on every commit, for a directory
            # holding nothing the commit contained. What decides it for a narrowed scan is
            # whether a path it was ASKED to read lies under a pruned directory.
            narrowed_to: frozenset[str] | None = getattr(self.source, "selected_paths", None)
            if narrowed_to is not None:
                skipped_code = {
                    name
                    for name in skipped_code
                    if any(name in path.split("/")[:-1] for path in narrowed_to)
                }
            if skipped_code:
                acc.complete = False

        # An exclusion matching nothing is either a mistake or a hole held open
        # for a file that does not exist yet. Both are worth surfacing: commit a
        # file at that path and it would be skipped by the very check meant to
        # examine it.
        for pattern in walker.stats.unmatched_patterns:
            acc.append(
                OperationalFinding.build(
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
        acc: Accumulator,
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
        # `perf_counter`, not `monotonic`. Windows' monotonic clock ticks about
        # every 15 milliseconds, so a per-file budget smaller than one tick
        # measured zero elapsed time and never tripped -- the same coarse-clock
        # failure that made `--timeout 0` a no-op there. perf_counter is the
        # high-resolution timer and is what a sub-second budget needs.
        started = time.perf_counter()
        skipped: list[str] = []
        skipped_judge = False

        for detector in JudgeGate.last(detectors):
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
            #
            # The budget never cuts the detectors that find malware and secrets. It did, and that
            # was a way to hide a payload: pad a file with near-miss credentials so an earlier
            # detector spends the budget, and `capability` never ran on it -- an INFO note and a
            # passing scan. Those detectors' patterns are validated linear at load and the file is
            # capped in size, so their cost is bounded without the budget; the total timeout still
            # ends the scan. What the budget cuts now is everything else, and it says which.
            if (
                budget > 0
                and time.perf_counter() - started >= budget
                and detector.id not in ALWAYS_RUN
            ):
                skipped.append(detector.id)
                continue

            # The judge reads the grey band only, after every other detector (review 98, AG-5).
            if detector.id == JudgeGate.ID and not JudgeGate.wants(produced):
                skipped_judge = True
                continue
            produced.extend(self._run(detector, unit, ctx, acc))

        # The rest of an oversized file, a window at a time (`core/windows.py`). The workers make
        # the same call (`ParallelScanner._inspect_batch`), so a parallel scan reads as far.
        windowed, intact = WindowPass.run(
            unit,
            [
                d
                for d in detectors
                if d.id not in skipped and not (d.id == JudgeGate.ID and skipped_judge)
            ],
            lambda detector, part: self._run(detector, part, ctx, acc),
            produced,
        )
        produced.extend(windowed)
        if not intact:
            acc.complete = False
            produced.append(ArchiveMembers.changed_while_read(unit.path))

        if skipped:
            acc.complete = False
            produced.append(
                OperationalFinding.build(
                    path=unit.path,
                    rule_id="OPERATIONAL.FILE.TIMEOUT",
                    message=(
                        f"This file exceeded its {budget:.0f}s budget, so these detectors did not "
                        f"run on it: {', '.join(skipped)}. The malware, obfuscation, secret and "
                        f"binary detectors ran in full."
                    ),
                    remediation=(
                        "Raise limits.per_file_timeout, or exclude the file if it "
                        "is generated output rather than source."
                    ),
                )
            )
            # Not cached below, because acc.complete is now False.
            return produced

        # Every finding carries the hash of the file it came from, recorded once here
        # rather than in each of eleven detectors. `_collapse_repeats` is the only
        # reader: it is what lets "the same credential in 179 directories" be told from
        # "179 files that happen to start with the same RSA header".
        produced = [
            f.with_file_hash(unit.content.sha256) if f.location.path == unit.path else f
            for f in produced
        ]

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
        acc: Accumulator,
        detectors: list[Detector],
        signature: str,
        *,
        carry_content: bool = False,
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
        pending: list[WorkItem] = []
        results: list[Finding] = []

        for index, unit in enumerate(units):
            key = self._cache_key(unit, ctx, signature)
            cached = self.cache.get(key)
            if cached is not None:
                results.extend(cached)
                # A cache hit is a file accounted for. Counting only the misses
                # made a warm scan appear to stall at zero and then finish.
                self.progress.advance(unit.path)
            else:
                # The parent's content hash travels with the work item, so the
                # worker can tell whether it read the same bytes -- and, for a
                # source the worker must not re-read, the bytes themselves.
                pending.append(
                    (
                        index,
                        unit.path,
                        len(unit.content.raw),
                        unit.content.sha256,
                        # An archive member has no path on disk to re-read. The whole of an
                        # oversized one travels, so the worker can sweep it as well. Nor does
                        # a hook's inline program (`core.inline_programs`).
                        unit.content.carried
                        if carry_content or "!" in unit.path or "#" in unit.path
                        else None,
                    )
                )

        if not pending:
            return results

        def report(indices: Sequence[int]) -> None:
            # Called as each batch's results arrive, so the count moves while
            # the pool is still working. Advancing after `run` returned meant a
            # parallel scan sat at 0 for its whole duration and then jumped to
            # complete, which reads exactly like the hang it exists to rule out.
            for index in indices:
                self.progress.advance(units[index].path)

        produced = ParallelScanner.run(
            config=self.config,
            root=str(root),
            files=pending,
            workers=ParallelScanner.worker_count(
                self.config.limits.max_workers, len(pending), sum(item[2] for item in pending)
            ),
            # The set the parent already filtered. Without it the worker ran
            # every detector it could find, and a scan's findings depended on
            # the machine's core count.
            detector_ids=[getattr(d, "id", "") for d in detectors],
            # The parent already walked the tree. Sending the result costs one
            # pickle; recomputing it costs a full traversal per worker.
            inventory=ctx.repository,
            # And the parts of the context the inventory cannot produce: which
            # FILES an install hook runs, and the import closure around them. A
            # worker rebuilding the context from the inventory alone knows that
            # `package.json` declares a `postinstall` and not that it runs
            # `scripts/setup.js`, so every composite gated on
            # `ctx.in_install_hook` was silently off in parallel.
            install_hook_paths=ctx.install_hook_paths,
            ci_hook_paths=ctx.ci_hook_paths,
            # And which bodies inside that closure the hooks never reach, for
            # the same reason: a worker cannot derive it, and one that had the
            # paths without it would apply install-time context more widely than
            # the parent does.
            install_deferred_lines=ctx.install_deferred_lines,
            # An image's members are judged as an image's: a binary there is what it ships.
            image=ctx.image,
            install_entry_paths=ctx.install_entry_paths,
            consumer_install_paths=ctx.consumer_install_paths,
            package_facts={
                "package_distribution": ctx.package_distribution,
                "distribution": ctx.distribution,
                "tree_paths": ctx.tree_paths,
                "import_entry_paths": ctx.import_entry_paths,
                "package_repository": ctx.package_repository,
            },
            on_batch=report,
        )

        if produced is None:
            # The pool did not run. Fall back rather than lose coverage. `None`
            # rather than an empty list, so a pool that ran and legitimately
            # found nothing is not re-scanned from scratch.
            for _index, path, _size, _digest, _carried in pending:
                unit = by_path[path]
                results.extend(self._inspect_file(unit, ctx, acc, detectors, signature))
                self.progress.advance(unit.path)
            return results

        for index, findings, trusted in produced:
            unit = units[index]
            results.extend(findings)
            if not trusted:
                # The worker could not read the file, or read different bytes
                # than the parent hashed. Reported exactly as the serial path
                # reports an unreadable file, and never cached: storing it would
                # file a result under a key describing content the result was
                # not produced from.
                acc.complete = False
                results.append(
                    OperationalFinding.build(
                        path=unit.path,
                        rule_id="OPERATIONAL.FILE.UNREADABLE",
                        message=(
                            "A worker could not read this file, or read different "
                            "content than the scan had already hashed, so its checks "
                            "did not run on the content being reported."
                        ),
                        remediation=(
                            "Re-run the scan on a tree nothing else is writing to, or pass -j 1."
                        ),
                    )
                )
                continue
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

    @staticmethod
    def _publisher_hygiene(findings: list[Finding], advisory: frozenset[Any]) -> list[Finding]:
        """How a published package's own repository was kept, as against what it installs.

        A `.github/workflows/*.yml`, a `Dockerfile` or a release setting that ended up inside a
        tarball describes its publisher's repository and runs for nobody who installs it. These
        domains never fail a build (`Policy.advisory_domains`), and in a package scan they were
        most of what a clean package still warned about: unpinned actions, lockfile integrity,
        an unpinned base image (review 98, FP-8). Reported at INFO -- in JSON and SARIF for anyone
        auditing the publisher, out of the default report. A MALICIOUS finding is untouched.
        """
        from cordon_scanner.foundation.taxonomy import Taxonomy

        out: list[Finding] = []
        for finding in findings:
            if (
                finding.category is not Category.MALICIOUS
                and finding.severity > Severity.INFO
                and (
                    Taxonomy.domain_of(finding.rule_id) in advisory
                    or finding.rule_id.startswith(("POLICY.RELEASE.", "POLICY.LOCKFILE."))
                )
            ):
                finding = replace(finding, severity=Severity.INFO)
            out.append(finding)
        return out

    @staticmethod
    def _certificate_names(raw: bytes) -> bytes:
        """The printable names in the certificates a file holds: subject and issuer fields."""
        names: list[bytes] = []
        for block in CERTIFICATE_BLOCK.findall(raw[:200_000])[:8]:
            try:
                der = base64.b64decode(b"".join(block.split()), validate=False)
            except (ValueError, binascii.Error):
                continue
            names.extend(m.group(2)[: m.group(1)[0]] for m in DER_STRING.finditer(der))
        return b" ".join(names)

    @staticmethod
    def _test_identity_keys(findings: list[Finding], units: Sequence[FileUnit]) -> list[Finding]:
        """A private key whose certificate says it is for testing is a test key (review 98, FP-6).

        OpenSSL's `apps/` ships `client.pem` and `server2.pem` issued by "OpenSSL Test
        Intermediate CA ... FOR TESTING PURPOSES ONLY", and `ca-key.pem` beside "Server test
        cert"; every Bazel module that vendors OpenSSL carried 6 such blocks. Judged from the
        certificate in the key's own file or its directory, never from a path: a real key in
        `certs/` beside a real certificate keeps its grade. Reported at LOW, not withdrawn."""
        keys = [
            f
            for f in findings
            if f.rule_id == "SECRET.PRIVATE_KEY.001" and f.severity >= Severity.HIGH
        ]
        if not keys:
            return findings
        directories = {f.location.path.rpartition("/")[0] for f in keys}
        testing: dict[str, bool] = {}
        for unit in units:
            directory = unit.path.rpartition("/")[0]
            if directory not in directories or testing.get(directory):
                continue
            raw = unit.content.raw
            if b"BEGIN CERTIFICATE" in raw[:200_000]:
                names = Engine._certificate_names(raw)
                testing[directory] = bool(names and TEST_IDENTITY.search(names))
        out: list[Finding] = []
        for finding in findings:
            if finding in keys and testing.get(finding.location.path.rpartition("/")[0]):
                finding = replace(
                    finding,
                    severity=Severity.LOW,
                    message=finding.message
                    + " The certificate beside it names a test identity, so this is read as a "
                    "test key: confirm it is not used anywhere real.",
                )
            out.append(finding)
        return out

    @staticmethod
    def _publisher_secrets(findings: list[Finding]) -> list[Finding]:
        """A credential committed inside a published package, graded for whoever installs it.

        The key is its publisher's: they leaked it and they are the ones who can rotate it.
        Nothing about it acts on the machine that installs the package, so for that consumer it
        is reported, in full, at MEDIUM, and does not stop the build. In 40 such blocks read
        from 441 real npm and PyPI packages (review 98) every one was the publisher's own token
        -- a `.coveralls.yml` repo token, a `.env`, a demo's API key. A repository's own
        secrets are untouched: this runs only for a recognised published package. Code that
        USES a credential (harvesting, exfiltration) is a different rule and keeps its grade, and
        so does a token that is a place to post to (`DROP_POINT_SECRETS`).
        """
        out: list[Finding] = []
        for finding in findings:
            if (
                finding.rule_id.startswith("SECRET.")
                and finding.rule_id not in DROP_POINT_SECRETS
                and finding.category is not Category.MALICIOUS
                and finding.severity > Severity.MEDIUM
            ):
                finding = replace(
                    finding,
                    severity=Severity.MEDIUM,
                    message=finding.message
                    + " It ships inside a published package, so the exposure is its publisher's"
                    " to rotate; it does not act on whoever installs the package, and is reported"
                    " below the gate.",
                )
            out.append(finding)
        return out

    @staticmethod
    def _shipped_native(units: Iterable[FileUnit]) -> frozenset[str]:
        """Paths whose bytes begin with ELF, PE or Mach-O magic: a binary the package ships (census A)."""
        from cordon_scanner.detect.binary.binary import NATIVE_FORMATS, BinaryDetector

        ids = ((u.path, BinaryDetector.identify(u.content.raw)) for u in units if u.content)
        return frozenset(p for p, f in ids if f is not None and f.name in NATIVE_FORMATS)

    @staticmethod
    def _entry_points_reached(
        deferred: frozenset[tuple[str, int, int]], agent_run: set[str]
    ) -> frozenset[tuple[str, int, int]]:
        """Deferred bodies, less those in code an agent runs: a skill script's functions and an MCP
        server's handlers are called by the agent by name, so none of them is unreached. Counted as
        deferred, a skill script appending to `/etc/passwd` and `/etc/crontab` from its functions
        had no install-time finding at all (review 98)."""
        return frozenset(t for t in deferred if t[0] not in agent_run)

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

    @staticmethod
    def _skill_scripts(units: Sequence[FileUnit]) -> set[str]:
        """Scripts an agent skill ships (`CapabilityDetector._skill_script`)."""
        from types import SimpleNamespace

        from cordon_scanner.detect.code.capability.detector import CapabilityDetector

        tree = SimpleNamespace(tree_paths=frozenset(u.path for u in units))
        return {
            u.path
            for u in units
            if CapabilityDetector._skill_script(u.path, tree)  # type: ignore[arg-type]
        }

    #: How many files of one kind the capability profile labels: the files that run at install or
    #: on import are a handful in any real package; past this the rest are not read again.
    _PROFILE_FILES: ClassVar[int] = 50

    @staticmethod
    def _labelled_once(
        detector: Any, unit: FileUnit, ctx: ScanContext, cache: dict[str, Any] | None
    ) -> Any:
        """`detector.labelled(unit, ctx)`, computed once per file for everything that asks."""
        if cache is None:
            return detector.labelled(unit, ctx)
        if unit.path not in cache:
            try:
                cache[unit.path] = detector.labelled(unit, ctx)
            except Exception as error:  # re-raised to each caller below  # noqa: BLE001
                cache[unit.path] = error
        held = cache[unit.path]
        if isinstance(held, Exception):
            raise held
        return held

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
            labelled = Engine._labelled_once(detector, unit, ctx, labels)
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
                    labelled = Engine._labelled_once(detector, unit, ctx, labels)
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

    def _image_inventory(self, data: bytes, acc: Accumulator) -> Any:
        """The OS packages of a container image tarball, or None when the archive is not one.

        What could not be read is stated and marks the scan incomplete: an image whose package
        database was skipped must not read as an image with no vulnerable packages.
        """
        import tarfile

        from cordon_scanner.images import oci

        # Is it an image at all? Asked of the archive in whatever compression it uses. This was
        # asked with `mode="r:"` (uncompressed only), so every gzip tarball - every npm package,
        # every sdist - failed the OPEN, and the failure was reported as "an image whose layers could
        # not be read", marking the scan incomplete. An archive that is not a tar, or is a tar with no
        # image manifest, is simply not an image.
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                if not oci.ImageLayers.is_image(archive):
                    return None
        except (tarfile.TarError, OSError, ValueError, EOFError):
            if oci.ImageLayers.cut_short(data):
                acc.complete = False
                acc.append(
                    OperationalFinding.build(
                        path=REPOSITORY_SCOPE,
                        rule_id="OPERATIONAL.IMAGE.UNREADABLE",
                        message="The target is a container image archive that ends early: its layers begin and the archive stops before its manifest, so nothing in it was inventoried.",
                        remediation="Export the image again with `docker save` or `skopeo copy ... oci-archive:` and rescan.",
                    )
                )
            return None
        try:
            inventory = oci.ImageLayers.read_image(data)
        except (tarfile.TarError, OSError, ValueError, KeyError, EOFError) as exc:
            acc.complete = False
            acc.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.IMAGE.UNREADABLE",
                    message=f"The target looks like a container image and its layers could not be read ({type(exc).__name__}), so its operating-system packages were not inventoried.",
                    remediation="Export the image again with `docker save` or `skopeo copy ... oci-archive:` and rescan.",
                )
            )
            return None
        platforms = oci.ImageLayers.platforms(data)
        if len(platforms) > 1:
            # Every platform's operating-system packages, each read from its own manifest; the
            # files are content-scanned on the first platform only, and the contents note says so.
            inventory.platform = platforms[0][1]
            for index, label in platforms[1:]:
                try:
                    other = oci.ImageLayers.read_image(data, index)
                except (tarfile.TarError, OSError, ValueError, KeyError, EOFError) as exc:
                    inventory.problems.append(
                        f"the {label} image could not be read ({type(exc).__name__})"
                    )
                    continue
                other.platform = label
                inventory.other_platforms.append(other)
        release = inventory.release
        if inventory.packages and (release is None or release.advisory_source is None):
            inventory.problems.append(
                f"the distribution ({release.pretty_name or release.id if release else 'no os-release'}) "
                f"has no advisory source Cordon reads (OSV, or Amazon's ALAS), so its packages cannot be matched"
            )
        for problem in inventory.problems:
            acc.complete = False
            acc.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.IMAGE.PARTIAL",
                    message=f"Part of the image's operating-system inventory is missing: {problem}.",
                    remediation="Rescan an image exported without zstd compression, or check the distribution is supported.",
                )
            )
        from cordon_scanner.images.distrodb import DistroDatabase

        synced = inventory.release is not None and DistroDatabase.covers(
            inventory.release.osv_ecosystem
        )
        if inventory.packages and self.config.offline and not synced:
            acc.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.IMAGE.NOT_MATCHED",
                    message=(
                        f"{len(inventory.packages)} operating-system packages were inventoried and not "
                        f"matched against distribution advisories: none are synced on this machine for "
                        f"this distribution, and matching through OSV's API needs --online (it sends the "
                        f"package names and versions to OSV)."
                    ),
                    remediation=(
                        "Run `cordon-scanner advisories sync --os <family>` once (debian, ubuntu, "
                        "alpine, wolfi, chainguard, rocky, almalinux, redhat, suse, opensuse) to match "
                        "offline, or scan with --online."
                    ),
                )
            )
        return inventory

    @staticmethod
    def _report_image_contents(inventory: Any, acc: Accumulator) -> None:
        """Say what of the image was content-scanned and what was not, and why."""
        from cordon_scanner.images.oci import OVERSIZE, OVERSIZE_STRINGS

        skipped = ", ".join(
            f"{count} ({reason})" for reason, count in sorted(inventory.skipped.items())
        )
        acc.append(
            OperationalFinding.build(
                path=REPOSITORY_SCOPE,
                rule_id="OPERATIONAL.IMAGE.CONTENTS",
                message=(
                    f"{inventory.added_files} files the image adds beyond its distribution's packages were "
                    f"scanned"
                    + (
                        f" (and {inventory.binaries_as_strings} past the per-file limit as their "
                        f"printable strings and build metadata)"
                        if inventory.binaries_as_strings
                        else ""
                    )
                    + (
                        f", {inventory.removed_files} file(s) a later layer removed were scanned in "
                        f"the layer that holds them"
                        if inventory.removed_files
                        else ""
                    )
                    + f", and {len(inventory.language_packages)} installed language packages were "
                    f"inventoried. Not content-scanned: {skipped or 'nothing'}."
                    + (
                        f" A multi-platform image: the operating-system packages of all "
                        f"{1 + len(inventory.other_platforms)} platforms were inventoried, and the "
                        f"files content-scanned on {inventory.platform}."
                        if getattr(inventory, "other_platforms", None)
                        else ""
                    )
                ),
                remediation="None needed; the counts say what this scan covered.",
            )
        )
        oversize = inventory.skipped.get(OVERSIZE, 0) + inventory.skipped.get(OVERSIZE_STRINGS, 0)
        if oversize:
            acc.complete = False
            acc.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.IMAGE.PARTIAL",
                    message=(
                        "Part of the image was not fully examined: "
                        + "; ".join(
                            f"{inventory.skipped[reason]} file(s) {reason}"
                            for reason in (OVERSIZE, OVERSIZE_STRINGS)
                            if inventory.skipped.get(reason)
                        )
                        + "."
                    ),
                    remediation="Raise limits.max_file_bytes to read them.",
                )
            )

    def _sbom_dependencies(self, units: list[FileUnit], acc: Accumulator) -> tuple[Dependency, ...]:
        """The components of a CycloneDX or SPDX document, validated and attributed to it."""
        from cordon_scanner.engine.sbom_ingest import SbomDocument, SbomInventory

        out: list[Dependency] = []
        self._sbom_listed = []
        for unit in units:
            data, unreadable = SbomDocument.recognise(unit.content.text, unit.path)
            if unreadable:
                acc.complete = False
                acc.append(
                    OperationalFinding.build(
                        path=unit.path,
                        rule_id="OPERATIONAL.SBOM.INVALID",
                        message=f"This file is named or shaped as a bill of materials and was not read: {unreadable}. Nothing from it is in the inventory.",
                        remediation="Regenerate the document with its tool, or validate it against the CycloneDX or SPDX schema.",
                        severity=Severity.MEDIUM,
                    )
                )
                continue
            if data is None:
                continue
            reading = SbomDocument.read(data)
            for problem in reading.problems[:20]:
                acc.complete = False
                acc.append(
                    OperationalFinding.build(
                        path=unit.path,
                        rule_id="OPERATIONAL.SBOM.INVALID",
                        message=f"Part of this bill of materials could not be believed: {problem}. What it says there was not read into the inventory.",
                        remediation="Regenerate the document with its tool, or validate it against the CycloneDX or SPDX schema.",
                        severity=Severity.MEDIUM,
                    )
                )
            if len(reading.problems) > 20:
                acc.append(
                    OperationalFinding.build(
                        path=unit.path,
                        rule_id="OPERATIONAL.SBOM.INVALID",
                        message=f"{len(reading.problems) - 20} further problems in this bill of materials were not listed.",
                        remediation="Regenerate the document with its tool.",
                        severity=Severity.MEDIUM,
                    )
                )
            records = SbomInventory.dependencies(unit.path, reading)
            out.extend(records)
            by_key = {
                component.key: record
                for component, record in zip(reading.components, records, strict=True)
            }
            for listed in reading.vulnerabilities:
                for key in listed.affects:
                    record = by_key.get(key)
                    if record is not None:
                        self._sbom_listed.append(
                            (
                                unit.path,
                                listed,
                                record.purl,
                                record.name,
                                record.version,
                                reading.tool,
                            )
                        )
        return tuple(out)

    def _sbom_listed_findings(self, findings: Sequence[Finding], ctx: ScanContext) -> list[Finding]:
        """What an ingested SBOM itself lists as affecting its components, where the scan's own
        advisory matching did not already say so. A listed vulnerability the document rules out
        is not applied: a scan target cannot vouch for its own vulnerabilities (`--vex` can)."""
        from cordon_scanner.decide.vex import RULED_OUT, VexDocuments

        if not self._sbom_listed:
            return []
        known: dict[str, set[str]] = {}
        for finding in findings:
            if finding.category is Category.VULNERABLE and finding.location.package:
                known.setdefault(finding.location.package.split("?", 1)[0].lower(), set()).update(
                    VexDocuments.identifiers_of(finding)
                )
        out: list[Finding] = []
        ruled_out: dict[str, int] = {}
        seen: set[tuple[str, str]] = set()
        for path, listed, purl, name, version, tool in self._sbom_listed:
            if listed.state in RULED_OUT:
                ruled_out[path] = ruled_out.get(path, 0) + 1
                continue
            names = {listed.identifier, *listed.aliases}
            if (
                names & known.get(purl.split("?", 1)[0].lower(), set())
                or (purl, listed.identifier) in seen
            ):
                continue
            seen.add((purl, listed.identifier))
            severity = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
            }.get(listed.severity or "", Severity.MEDIUM)
            finding = OperationalFinding.build(
                path=path,
                rule_id="VULNERABLE.SBOM.LISTED.001",
                message=(
                    f"{name} {version or ''} is listed in {path} as affected by {listed.identifier}"
                    + (f" ({listed.state})" if listed.state else "")
                    + f", by {tool}. The advisory data this scan matched against does not name it for this "
                    f"version, so it rests on the document's word."
                ),
                remediation="Look the advisory up and upgrade past it, or record why it does not apply as a VEX statement.",
                category=Category.VULNERABLE,
                severity=severity,
            )
            out.append(
                replace(
                    finding,
                    location=replace(finding.location, package=purl),
                    confidence=Confidence.MEDIUM,
                    risk=ctx.scorer.score(severity, Confidence.MEDIUM),
                    detector="sbom",
                    references=(listed.reference,) if listed.reference else (),
                )
            )
        for path, count in sorted(ruled_out.items()):
            out.append(
                OperationalFinding.build(
                    path=path,
                    rule_id="OPERATIONAL.SBOM.VEX_NOT_APPLIED",
                    message=(
                        f"{path} rules out {count} vulnerabilit{'y' if count == 1 else 'ies'} for its own components. A scan "
                        f"target cannot vouch for its own vulnerabilities, so none was applied; the scan's own matching stands."
                    ),
                    remediation="Pass the document with --vex to apply its statements, if its author is trusted to make them.",
                )
            )
        return out

    @staticmethod
    def _image_dependencies(inventory: Any) -> tuple[Dependency, ...]:
        """An image's installed dependencies; for a multi-platform image, every platform's.

        An operating-system package installed on every platform is listed once, unlabelled; one
        installed on some is labelled with exactly those. Language packages come from the files,
        content-scanned on the first platform, and are not labelled: they would read as present on
        that platform alone."""
        primary = Engine._image_dependencies_of(inventory)
        others = getattr(inventory, "other_platforms", None) or []
        if not others:
            return primary
        from cordon_scanner.images.packages import OsPackage

        system = set(OsPackage.PURL_TYPE.values())
        merged: dict[tuple[str, str, str | None], Dependency] = {}
        seen_on: dict[tuple[str, str, str | None], list[str]] = {}
        for platform_inventory, dependencies in (
            (inventory, primary),
            *((other, Engine._image_dependencies_of(other)) for other in others),
        ):
            for dependency in dependencies:
                key = (dependency.ecosystem, dependency.name, dependency.version)
                merged.setdefault(key, dependency)
                seen_on.setdefault(key, []).append(platform_inventory.platform)
        everywhere = 1 + len(others)
        return tuple(
            replace(
                dependency,
                platform=(
                    *dependency.platform,
                    *(f"platform {label}" for label in seen_on[key] if label),
                ),
            )
            if dependency.ecosystem in system and len(seen_on[key]) < everywhere
            else dependency
            for key, dependency in merged.items()
        )

    @staticmethod
    def _image_dependencies_of(inventory: Any) -> tuple[Dependency, ...]:
        from cordon_scanner.foundation.dependencies import NAMED_BY_FILE
        from cordon_scanner.images.packages import OsPackage

        where = OsPackage.DATABASE
        languages = tuple(
            Dependency(
                purl=package.purl,
                ecosystem=package.ecosystem,
                name=package.name,
                version=package.version,
                direct=True,
                declared_in=package.path,
                # The checksum the build recorded where it recorded one (Go). Otherwise these are
                # bytes already installed in the image, not something still to be fetched whose
                # hash could be missing -- and never `local`, which would hide their advisories.
                integrity=package.integrity or "installed-in-image",
                # A binary's architecture and whether it is signed, where it came from one.
                platform=package.platform,
                resolved_from=NAMED_BY_FILE if package.named_by_file else None,
            )
            for package in inventory.language_packages
        )
        from cordon_scanner.images.packages import PackageGraph

        # The installed graph: what each package requires, from the asked-for ones down. Each
        # manager's packages are their own graph -- an image holds one, but nothing assumes it.
        operating_system: list[Dependency] = []
        for manager in OsPackage.MANAGERS:
            packages = [p for p in inventory.packages if p.manager == manager]
            if not packages:
                continue
            edges = PackageGraph.edges(packages)
            direct = PackageGraph.direct(packages, edges)
            depth = {index: 0 for index, asked in enumerate(direct) if asked}
            parents: dict[int, set[str]] = {index: set() for index in range(len(packages))}
            frontier = list(depth)
            while frontier:
                following: list[int] = []
                for index in frontier:
                    for child in edges[index]:
                        parents[child].add(packages[index].name)
                        if child not in depth:
                            depth[child] = depth[index] + 1
                            following.append(child)
                frontier = following
            for index, package in enumerate(packages):
                operating_system.append(
                    Dependency(
                        purl=package.purl(inventory.release),
                        ecosystem=OsPackage.PURL_TYPE[manager],
                        name=package.name,
                        version=package.version,
                        direct=direct[index],
                        # Installed automatically and required by nothing now (what `apt
                        # autoremove` would take): a dependency of nothing in the graph.
                        depth=depth.get(index, 1),
                        parents=tuple(sorted(parents[index])),
                        declared_in=where[manager],
                    )
                )
        identity = inventory.identity
        base: tuple[Dependency, ...] = ()
        if identity.base_name:
            from cordon_scanner.ecosystems.infra.image import ImageReference

            reference = ImageReference.parse(identity.base_name)
            if reference is not None:
                version = reference.tag
                digest = identity.base_digest or reference.digest
                base = (
                    Dependency(
                        purl=f"pkg:docker/{reference.familiar}"
                        + (f"@{version}" if version else ""),
                        ecosystem="image",
                        name=reference.familiar,
                        version=version,
                        direct=True,
                        integrity=digest,
                        resolved_from=f"registry:{reference.registry}"
                        if reference.registry
                        else None,
                        declared_in="image-config/labels",
                        declared_spec=version or "",
                    ),
                )
        return base + languages + tuple(operating_system)

    def _build_graph(self, units: list[FileUnit], acc: Accumulator) -> tuple[Dependency, ...]:
        """Build the resolved graph from lockfiles.

        Never by invoking the package manager and never over the network (C2,
        C4). Running the ecosystem's own resolver would execute untrusted
        tooling against attacker-controlled metadata inside the tool whose whole
        purpose is avoiding that, and it would make results non-reproducible
        because a resolver consults a live registry.
        """
        Graph.unread_dependency_files(units, acc)
        collected: list[Dependency] = []
        companions: list[tuple[str | None, str, Any, LockGraph]] = []
        completing: set[tuple[str | None, str, str]] = set()
        fragments: dict[tuple[str, str], tuple[Any, list[tuple[LockEntry, str]]]] = {}
        # `(member directory, ecosystem) -> the lockfile's directory`: a workspace member's
        # manifest is resolved by the root lockfile, so it is joined to that graph, not graphed
        # again on its own (which put a second, unresolved copy of each of its dependencies in).
        workspace_members: dict[tuple[str, str], str | None] = {}
        tree: dict[str, Any] | None = None
        for unit in units:
            if "!" in unit.path and not self._scanning_archive:
                # A lockfile inside a vendored archive describes that artefact's own
                # build, not what this project installs. Its members are scanned for
                # content; they do not become this project's dependency graph.
                continue
            ecosystem_id = EcosystemRegistry.lockfile_ecosystem(unit.path)
            if ecosystem_id is None:
                continue
            ecosystem = EcosystemRegistry.get(ecosystem_id)
            if ecosystem is None:
                continue
            # Contained. `Engine._run` exists so that "a detector that raises
            # must not abort the scan", and this call site and the manifest one
            # below bypassed it and called an ecosystem parser straight from
            # `scan()`. `inventory` wraps the identical call, so the
            # inconsistency sat within one file: a parser raising on a crafted
            # lockfile terminated the whole scan with exit 2, which reads as
            # "the scanner broke" and gets a pipeline to skip the step.
            try:
                # A lockfile read with the files beside it, where the ecosystem keeps part of the
                # record apart (an Ansible collection's signatures, in its `.info/GALAXY.yml`).
                in_tree = getattr(ecosystem, "parse_lockfile_in_tree", None)
                if in_tree is not None:
                    if tree is None:
                        tree = {u.path: u.content for u in units}
                    graph = in_tree(unit.content, tree)
                else:
                    graph = ecosystem.parse_lockfile(unit.content)
            except Exception as exc:  # noqa: BLE001
                acc.complete = False
                acc.append(
                    OperationalFinding.build(
                        path=unit.path,
                        rule_id="OPERATIONAL.PARSER.FAILED",
                        message=(
                            f"The {ecosystem_id} lockfile parser failed on this file, so "
                            f"its dependencies are not in the graph: {type(exc).__name__}"
                        ),
                        remediation="Report this with the file that triggered it.",
                        severity=Severity.MEDIUM,
                    )
                )
                continue
            if graph.parse_error or not graph.entries:
                continue
            project = unit.path.rpartition("/")[0]
            # `.mvn/checksums/`, `gradle/verification-metadata.xml`, `gradle/dependency-locks/`:
            # files that belong to the project directories above them.
            for _ in range(max(0, min(graph.owner_levels, 8))):
                project = project.rpartition("/")[0]
            if graph.fragment:
                pieces = fragments.setdefault((project, ecosystem_id), (ecosystem, []))[1]
                pieces.extend((entry, unit.path) for entry in graph.entries)
                continue
            if graph.completed_by_companion:
                completing.add((project or None, ecosystem_id, unit.path))
            if graph.companion:
                # `go.sum`, `vendor/modules.txt`: facts about the resolution beside them, applied
                # once every resolving file has been read. `vendor/` belongs to its parent module.
                owner = (
                    project.rpartition("/")[0]
                    if project.endswith("vendor") and not graph.owner_levels
                    else project
                )
                companions.append((owner or None, ecosystem_id, ecosystem, graph))
                continue
            for member in graph.workspaces:
                if not isinstance(member, str) or not member:
                    continue  # a parser's mistake must not end the scan
                joined = posixpath.normpath(posixpath.join(project, member) if project else member)
                if joined not in (".", "") and not joined.startswith(".."):
                    workspace_members[(joined, ecosystem_id)] = project or None
            collected.extend(
                replace(dependency, declared_in=unit.path)
                for dependency in ecosystem.to_dependencies(graph, project=project or None)
            )

            if len(collected) > self.config.limits.max_dependencies:
                acc.complete = False
                acc.append(
                    OperationalFinding.build(
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

        for (project, ecosystem_id), (ecosystem, pieces) in sorted(
            fragments.items(), key=lambda item: item[0]
        ):
            # The pieces of one installed tree, joined: an edge in one keg's receipt reaches the
            # keg it names. Each record keeps the file that holds it as its location.
            from cordon_scanner.engine.inventory import DependencyRecords

            where = {(entry.name, entry.version): path for entry, path in pieces}
            merged_graph = LockGraph(
                path=pieces[0][1],
                ecosystem=ecosystem_id,
                entries=tuple(entry for entry, _ in pieces),
            )
            merged = tuple(ecosystem.to_dependencies(merged_graph, project=project or None))
            chains = DependencyRecords._paths(merged)
            collected.extend(
                replace(
                    dependency,
                    declared_in=where.get(
                        (dependency.name, dependency.version or ""), pieces[0][1]
                    ),
                    dependency_path=chains.get(id(dependency), (dependency.name,)),
                )
                for dependency in merged
            )

        # Per project AND ecosystem. A lockfile resolves its own ecosystem's
        # manifests and says nothing about anyone else's, so a `requirements.txt`
        # cannot stand in for the `conanfile.txt` beside it. Keyed per path
        # alone, it did, and those dependencies left the graph entirely.
        collected = Graph.apply_companions(collected, companions)
        collected.extend(Graph.companion_completions(collected, companions, completing))
        # A resolved entry naming a package this repository defines, with no registry hash of
        # its own -- `app` depending on `core` in one Maven reactor -- is built from that module's
        # source here, not downloaded. An entry the registry hashed is left alone: that is a
        # published package, whatever a local directory happens to be called.
        defined = Graph.workspace_members(units)
        if defined:
            collected = [
                replace(d, local=True)
                if not d.local and not d.integrity and Graph.defined_member(d, defined)
                else d
                for d in collected
            ]
        workspace_members.update(Graph.members_by_name(units, collected, workspace_members))
        workspace_members.update(
            Graph.members_by_lock_reference(units, collected, workspace_members)
        )
        covered = {(d.project, d.ecosystem) for d in collected} | set(workspace_members)
        collected = Graph.join_manifests(units, collected, covered, workspace_members)
        collected = Graph.propagate_scopes(collected)
        # Exact pins in a build with no lockfile are completed by its companions too: Gradle's
        # verification metadata holds the hash of `guava:33.3.1-jre` whether or not the build
        # also locks.
        collected.extend(
            Graph.apply_companions(self._declared_graph(units, acc, covered=covered), companions)
        )

        # Deduplicated by project and package URL, and sorted, so the graph is deterministic
        # regardless of the order lockfiles were encountered in. Per project: two services in
        # one repository that each require the same module each depend on it, and each needs
        # its own fix -- one record for both left the second service's use out of the inventory.
        # Within a project, one record however many times the lockfile lists it.
        from cordon_scanner.ecosystems.packages.npm import LockScopes

        unique: dict[tuple[str | None, str], Dependency] = {}
        for dependency in collected:
            key = (dependency.project, dependency.purl)
            existing = unique.get(key)
            # Keep the shallowest occurrence: depth drives the risk score, and
            # the closest path to the root is the honest one. At equal depth, the scope that
            # reaches furthest: a module on both the compile and the runtime classpath ships.
            if (
                existing is None
                or dependency.depth < existing.depth
                or (
                    dependency.depth == existing.depth
                    and LockScopes.rank(dependency.scope) < LockScopes.rank(existing.scope)
                )
            ):
                unique[key] = dependency
        resolved = list(unique.values())
        if not self.config.offline:
            resolved = Graph.resolve_maven_ranges(resolved)
        return tuple(sorted(resolved, key=lambda d: (d.purl, d.project or "")))

    def _annotated(
        self,
        dependencies: tuple[Dependency, ...],
        findings: Iterable[Finding],
        ctx: ScanContext,
        units: list[FileUnit],
    ) -> tuple[Dependency, ...]:
        """Each dependency's shared record: its check statuses, path and locations."""
        if not dependencies:
            return dependencies
        from cordon_scanner.engine.inventory import DependencyRecords, InventoryContext

        findings = tuple(findings)
        advisory = next((d for d in self.detectors if d.id == "advisory"), None)
        database = (
            getattr(advisory, "_database", None)
            if advisory is not None and self._detector_enabled(advisory, ctx)
            else None
        )
        failed = any(
            f.rule_id == "OPERATIONAL.DETECTOR.FAILED" and "'advisory'" in f.message
            for f in findings
        )
        wanted = {d.declared_in for d in dependencies} | {d.manifest_path for d in dependencies}
        texts = {u.path: u.content.text for u in units if u.path in wanted}
        return DependencyRecords.annotate(
            dependencies,
            findings,
            InventoryContext(
                advisory_database=database,
                advisory_failed=failed,
                offline=ctx.offline,
                checks=ctx.checks,
                texts=texts,
            ),
        )

    def _declared_graph(
        self,
        units: list[FileUnit],
        acc: Accumulator,
        *,
        covered: set[tuple[str | None, str]],
    ) -> list[Dependency]:
        """Manifest-declared dependencies, for projects no lockfile resolved.

        A repository without a lockfile is not a repository without
        dependencies. It is the common case for a library, and it was a hole:
        the graph was built from lockfiles alone, so `lodahs` in a
        `package.json` with no `package-lock.json` produced no finding at all,
        while the identical typo beside a lockfile was reported at high. The
        check that matters most for an unpinned project was the one that did
        not run.

        These are declared, not resolved: the version is a range, nothing
        records where they would come from, and no integrity hash exists. So
        they carry `version=None` and no source, and the rules that need a
        resolved version -- advisory matching, integrity, release age -- skip
        them of their own accord rather than guessing. What does apply is
        everything about the *name*, which is what typosquatting, combosquatting
        and dependency confusion are attacks on.

        Only for a project and ecosystem a lockfile did not already cover, so a
        repository with both does not get each dependency twice in different
        states -- while a second ecosystem in the same directory, which that
        lockfile says nothing about, is still read.
        """
        collected: list[Dependency] = []
        members = Graph.workspace_members(units)
        by_path = {u.path: u for u in units}
        contents = {u.path: u.content for u in units}

        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            if ecosystem_id is None:
                continue
            ecosystem = EcosystemRegistry.get(ecosystem_id)
            if ecosystem is None:
                continue

            project = unit.path.rpartition("/")[0] or None
            if (project, ecosystem_id) in covered:
                continue

            try:
                manifest = Graph.manifest_of(ecosystem, unit, contents)
            except Exception:  # noqa: BLE001, S112
                # Deliberately silent here, and not a swallowed failure.
                # `_manifest_hook_paths` parses the same file, under the same
                # predicate, in the same scan, and reports
                # OPERATIONAL.PARSER.FAILED for it. A second finding would say
                # nothing the first did not.
                continue

            if manifest.parse_error:
                continue

            # What the file includes: pip's `-r` adds another file's requirements to this one,
            # and `-c` pins whatever they resolve to. An included file the walk would not graph
            # on its own (`-r common.txt`) is read here; one it would is left to its own pass.
            declarations = [(unit.path, d) for d in manifest.dependencies]
            pins: dict[str, tuple[str, str]] = {}
            for kind, path, included in Graph.included(manifest, unit.path, by_path, ecosystem):
                if kind == "requirements" and EcosystemRegistry.manifest_ecosystem(path) is None:
                    declarations.extend((path, d) for d in included.dependencies)
                elif kind == "constraints":
                    for constraint in included.dependencies:
                        pin = Graph.exact_pin(constraint.spec)
                        if pin:
                            pins.setdefault(ecosystem.normalize_name(constraint.name), (pin, path))

            for source_path, declared in declarations:
                # A manifest may carry another ecosystem's packages -- conda's
                # nested `pip:` list is PyPI -- and they are graphed as what they
                # are, so the advisory and typosquat layers can reach them.
                declared_id = declared.ecosystem or ecosystem_id
                implementation = (
                    ecosystem
                    if declared_id == ecosystem_id
                    else EcosystemRegistry.get(declared_id) or ecosystem
                )
                name = implementation.normalize_name(declared.name)
                # An exact pin is a resolved version, whatever file it is
                # written in. `django==3.2` in an `environment.yml` installs
                # 3.2 and nothing else, and treating it as unresolved meant the
                # advisory layer skipped it -- in a file whose own ecosystem has
                # no advisory feed, so nothing else was going to match it
                # either. A range stays unresolved, because a range is a
                # decision the resolver has not made yet -- unless a constraints
                # file pins it, which is the resolver's own input.
                # An ecosystem whose versions are not version numbers (an image's tag) says what pins.
                own = getattr(implementation, "exact_pin", None)
                pinned = (
                    own(declared.spec)
                    if own is not None
                    else Graph.exact_pin(declared.spec, declared_id)
                )
                constrained = None if pinned or declared.editable else pins.get(name)
                if constrained is not None:
                    pinned = constrained[0]
                if pinned:
                    # Bounded like every version a lockfile gives: a spec is bounded at the
                    # length of a constraint, which is longer than any real version.
                    pinned = Coordinate.token(pinned, Coordinate.MAX_VERSION) or None
                # Where the project's configuration routes the name (a vcpkg registry serving
                # `acme-*`, NuGet package source mapping), when the declaration names no source.
                routed = declared.source or (
                    Graph.routed_source(declared.name, manifest.source_patterns)
                    if manifest.source_patterns
                    else None
                )
                collected.append(
                    Dependency(
                        # The Package URL type, not the ecosystem id: a Gradle dependency is
                        # `pkg:maven/...`, a Go module `pkg:golang/...`, a gem `pkg:gem/...`.
                        purl=f"pkg:{implementation.purl_type}/{name}"
                        + (f"@{pinned}" if pinned else "")
                        + implementation.qualifiers(declared.platform),
                        ecosystem=declared_id,
                        name=declared.name,
                        version=pinned,
                        direct=True,
                        depth=0,
                        scope=declared.scope,
                        declared_spec=declared.spec,
                        project=project,
                        declared_in=source_path,
                        manifest_path=source_path,
                        resolved_from=routed,
                        integrity=Coordinate.integrity(declared.integrity),
                        resolved_by=f"the constraints file {constrained[1]}"
                        if constrained
                        else None,
                        resolution_note=declared.note,
                        exclusions=declared.exclusions,
                        platform=declared.platform,
                        alias=declared.alias,
                        extras=declared.extras,
                        editable=declared.editable,
                        signature_sources=declared.signature_sources,
                        # Strapi's `packages/cli/cloud` declares `"vitest-config": "5.56.0"`, and
                        # `packages/utils/vitest-config` is that package: the workspace resolves
                        # it locally. Squatters register exactly these names on the registry.
                        local=(declared_id, name) in members
                        or Graph.declared_inside(declared.spec, source_path)
                        or bool(routed and Graph.declared_inside(routed, source_path)),
                    )
                )

            if len(collected) > self.config.limits.max_dependencies:
                acc.complete = False
                acc.append(
                    OperationalFinding.build(
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

        return collected

    @staticmethod
    def _hook_deferred_lines(
        units: list[FileUnit], hooks: set[str], entries: frozenset[str] | None = None
    ) -> frozenset[tuple[str, int, int]]:
        """Bodies inside the closure that the hooks never actually call.

        The closure answers which files run at install time. Importing a module
        runs its top level and defines its functions; it does not call them, and
        a library reached because `setup.py` reads its `__version__` is almost
        entirely functions nothing on that path calls. See
        `core.reachability.CallReachability` for what is and is not treated as
        reachable, and why every approximation there keeps the finding.
        """
        from cordon_scanner.ecosystems.packages.homebrew import NotRunAtInstall
        from cordon_scanner.ecosystems.registry import EcosystemRegistry
        from cordon_scanner.engine.reachability import CallReachability

        # A formula or cask is a hook as a whole; its `service`, `test` and `caveats` blocks are
        # not run by `brew install` (`NotRunAtInstall`).
        brew = frozenset(
            (unit.path, first, last)
            for unit in units
            if unit.path in hooks
            and unit.path.endswith(".rb")
            and EcosystemRegistry.manifest_ecosystem(unit.path) == "homebrew"
            for first, last in NotRunAtInstall.spans(unit.content.text)
        )
        sources = {
            unit.path: unit.content.text
            for unit in units
            if unit.path.endswith(".py") and not unit.content.is_binary
        }
        if not sources:
            return brew
        return brew | CallReachability.deferred_lines(hooks, sources, entries)

    def _expand_member_units(
        self, rel_path: str, loaded: FileContent, acc: Accumulator, deadline: float
    ) -> list[FileUnit] | None:
        """The members of an archive found during a directory scan, as units.

        A vendored `.whl`, `.jar`, `.tgz` or `.nupkg` is part of what a repository
        ships, and one reported as "not examined" let a malicious artefact pass the
        default gate. Members are expanded in memory by the same bounded reader a
        scanned archive uses, named `archive!member` exactly as they are when the
        archive is the target, and never written to disk.

        Expanded once per distinct content per scan: the same wheel vendored in ten
        places is read ten times from disk but opened once. Returns None when the
        archive was refused, so the caller reports it as unexamined rather than as
        opened.
        """
        started = time.monotonic()
        digest = loaded.sha256
        cache = self._expansions
        if digest in cache:
            members = cache[digest]
        else:
            if loaded.truncated:
                members = None
                acc.complete = False
                acc.rejected_archives.add(rel_path)
                acc.append(
                    OperationalFinding.build(
                        path=rel_path,
                        rule_id="OPERATIONAL.ARCHIVE.REJECTED",
                        message=(
                            "The archive is larger than limits.max_file_bytes, so it was "
                            "read in part and could not be opened. Its contents were not "
                            "examined."
                        ),
                        remediation="Raise limits.max_file_bytes, or scan the archive directly.",
                        severity=Severity.MEDIUM,
                    )
                )
            else:
                rejected: list[tuple[str, str, str]] = []
                collected: list[tuple[str, bytes]] = []
                prefix = rel_path.rsplit("/", 1)[-1]
                try:
                    for member_path, member_data in ArchiveReader.walk_archive(
                        loaded.raw,
                        path=prefix,
                        limits=self.config.limits,
                        rejected=rejected,
                        deadline=deadline if self.config.limits.total_timeout > 0 else None,
                    ):
                        collected.append((member_path[len(prefix) :], member_data))
                    members = collected
                except ArchiveError as exc:
                    members = None
                    acc.complete = False
                    acc.append(
                        OperationalFinding.build(
                            path=rel_path,
                            rule_id="OPERATIONAL.ARCHIVE.REJECTED",
                            message=f"The archive was refused and not scanned: {exc.message}",
                            remediation=(
                                "Treat a refused archive as unexamined. If the limits are "
                                "wrong for this input, raise them deliberately."
                            ),
                            severity=Severity.MEDIUM,
                        )
                    )
                directory = rel_path[: -len(prefix)]
                for member_path, reason, detail in rejected:
                    acc.complete = acc.complete and reason == Rejection.LINK
                    acc.append(ArchiveMembers.rejected(directory + member_path, reason, detail))
            cache[digest] = members
            if members is not None:
                self._archive_stats[0] += 1
        self._archive_stats[2] += int((time.monotonic() - started) * 1000)
        if members is None:
            return None
        units: list[FileUnit] = []
        for suffix, data in members:
            member_path = rel_path + suffix
            content = FileContent.from_member(member_path, data, self.config.limits)
            if content.truncated:
                acc.complete = acc.complete and ArchiveMembers.read_to_end(content)
                acc.append(ArchiveMembers.truncated_note(member_path, content))
            units.append(
                FileUnit(content=content, language=LanguageRegistry.of_file(member_path, content))
            )
        self._archive_stats[1] += len(units)
        return units

    _DEOBFUSCATION_MARKERS: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"while\s*\(\s*!!\[\]\s*\)|\batob\s*\(|\bBuffer\s*\.\s*from\s*\(\s*['\"`][A-Za-z0-9+/=_\-]{16}"
        rb"|fromCharCode\s*\(\s*(?:0x[0-9a-fA-F]+|\d+)\s*,|\xf3\xa0[\x80-\x87]|\xef\xb8[\x80-\x8f]"
    )
    """Bytes without which no reversal in `core.deobfuscation` applies: most files pay one search."""

    def _deobfuscated_units(self, units: list[FileUnit]) -> list[FileUnit]:
        """Each obfuscated JavaScript file reversed statically, as a unit of its own.

        Read by every detector with the context of the file it came from (`_lifted_inherit`), so
        what the code does is graded rather than that it was hidden. A file that cannot be
        reversed, or only in part, is not lifted, and its obfuscation finding keeps its grade.
        """
        from cordon_scanner.analysis.shared.deobfuscation import Deobfuscator

        lifted: list[FileUnit] = []
        for unit in units:
            if (
                unit.content.is_binary
                or unit.language not in ("javascript", "typescript")
                or "#" in unit.path
                or not Engine._DEOBFUSCATION_MARKERS.search(unit.content.raw)
            ):
                continue
            recovery = Deobfuscator.recover(unit.content.text, unit.language)
            if recovery is None or recovery.resolved == 0:
                continue
            if recovery.remaining > max(3, recovery.resolved // 20):
                continue
            path = unit.path + Hooks.DEOBFUSCATED
            content = FileContent.from_bytes(
                path, recovery.text.encode("utf-8"), self.config.limits
            )
            lifted.append(FileUnit(content=content, language="javascript"))
        return lifted

    def _inline_hook_units(self, units: list[FileUnit]) -> list[FileUnit]:
        """The programs install hooks carry inline, each as a unit of its own.

        `node -e "<program>"` in a `postinstall` is install-time code like the file
        `node install.js` runs, and is read the same way: by every content detector, with the
        hook's escalation. See `core.inline_programs`. Author-time hooks are left alone, as
        their files are.
        """
        lifted: list[FileUnit] = []
        known = {unit.path for unit in units}
        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            if ecosystem_id is None or ecosystem_id == "image" or unit.content.is_binary:
                continue
            ecosystem = EcosystemRegistry.get(ecosystem_id)
            if ecosystem is None:
                continue
            try:
                hooks = ecosystem.parse_manifest(unit.content).hooks
            except Exception:  # noqa: BLE001, S112
                continue
            for hook in hooks:
                if not hook.command or hook.name.lower() in AUTHOR_TIME_HOOKS:
                    continue
                for program in InlinePrograms.lifted(unit.path, hook.name, hook.command):
                    if program.path in known:
                        continue
                    known.add(program.path)
                    content = FileContent.from_bytes(
                        program.path, program.source.encode("utf-8"), self.config.limits
                    )
                    lifted.append(
                        FileUnit(
                            content=content,
                            language=LanguageRegistry.of_file(program.path, content),
                        )
                    )
        return lifted

    @staticmethod
    def _manifest_hook_paths(
        units: list[FileUnit], acc: Accumulator | None = None
    ) -> tuple[set[str], set[str], set[str]]:
        """Paths that execute at install time, according to their manifests -- and, third, the
        scripts a published GitHub action's composite steps run, which are CI code.

        The inventory's packaging test, here too: fixing only the first place a `setup.py` becomes
        a hook left `hermes_cli/subcommands/setup.py`, an argument parser, seeding an import closure
        of 510 files (`Hooks.hook_executes`). A Dockerfile a dependency vendors is not a hook:
        its RUN steps run when somebody builds that image, never on install (opencv's zlib-ng).
        """
        paths: set[str] = set()
        consumer: set[str] = set()
        ci_scripts: set[str] = set()
        """Paths that run for whoever INSTALLS the package, a subset (`ScanContext.consumer_install_paths`):
        a `setup.py` reaches a consumer only when it overrides a consumer-time command."""
        known = frozenset(unit.path for unit in units)
        package_directories = {
            unit.path.rpartition("/")[0]
            for unit in units
            if ContainerPaths.basename(unit.path) == "__init__.py"
        }
        from cordon_scanner.analysis.shared.source_paths import SourcePaths

        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            if ecosystem_id is None or (
                ecosystem_id == "image" and SourcePaths.is_vendored(unit.path)
            ):
                continue
            if ContainerPaths.basename(unit.path) in PACKAGED_BUILD_FILENAMES and (
                unit.path.rpartition("/")[0] in package_directories
                # And the second half of the same test. Applying only the
                # package-directory half here is the mistake this function's
                # docstring already warns about, one member of the family later:
                # `test/cpp_extensions/setup.py` is a fixture pytorch's own test
                # suite compiles, and it seeded a 507-file closure over `torch`.
                # See `FIXTURE_DIRECTORIES`.
                or Hooks.under_fixture_directory(unit.path)
            ):
                continue
            ecosystem = EcosystemRegistry.get(ecosystem_id)
            if ecosystem is None:
                continue
            try:
                manifest = ecosystem.parse_manifest(unit.content)
                # And the hooks only the tree shows: a CRAN source package's `configure` and
                # `cleanup` beside its DESCRIPTION. The manifest detector and the inventory
                # already ask; without it here those scripts were never install-time code.
                hooks_from_tree = getattr(ecosystem, "hooks_from_tree", None)
                if hooks_from_tree is not None:
                    manifest = hooks_from_tree(manifest, known)
            except Exception as exc:  # noqa: BLE001
                # Same containment as the lockfile path, and reported for the
                # same reason. Catching it and moving on quietly would trade one
                # failure mode (the scan dies) for the worse one (the manifest
                # was never read and nothing says so), which is the trade this
                # whole audit is about.
                if acc is not None:
                    acc.complete = False
                    acc.append(
                        OperationalFinding.build(
                            path=unit.path,
                            rule_id="OPERATIONAL.PARSER.FAILED",
                            message=(
                                f"The {ecosystem_id} manifest parser failed on this file, "
                                f"so its install hooks were not identified: "
                                f"{type(exc).__name__}"
                            ),
                            remediation="Report this with the file that triggered it.",
                            severity=Severity.MEDIUM,
                        )
                    )
                continue
            # Consumer-time hooks only. A `prepare` or a `prepack` runs on the author's
            # machine, not on the machine of anybody who installs the package from a
            # registry -- and marking the script it names as install-time code is what
            # put `MALWARE.ANTI_ANALYSIS.001` at critical on `n8n`'s three-line
            # `scripts/prepare.mjs`, which is the file the anti-analysis composite's own
            # comment cites as the false positive it was corrected for. See
            # `core.models.AUTHOR_TIME_HOOKS`, including what this gives up.
            #
            # The MANIFEST still counts whenever it declares any of them, because
            # `SUSPECT.INSTALL.SCRIPT.001` is about the declaration and grades itself by
            # which kind it is.
            if any(not hook.action_step for hook in manifest.hooks):
                paths.add(unit.path)
            if manifest.hooks:
                # A published action's composite steps run on its consumers' runners as CI code:
                # what they name is read in CI context, not install context (review 98: as
                # install code, 305 of 2,978 benign actions blocked).
                steps = [hook for hook in manifest.hooks if hook.action_step]
                if steps:
                    ci_scripts |= Hooks.hook_script_paths(unit.path, steps, known)
                reaching = [
                    hook
                    for hook in manifest.hooks
                    if hook.name.lower() not in AUTHOR_TIME_HOOKS and hook not in steps
                ]
                if reaching:
                    paths |= Hooks.hook_script_paths(unit.path, reaching, known)
                    paths |= {
                        program.path
                        for hook in reaching
                        for program in InlinePrograms.lifted(
                            unit.path, hook.name, hook.command or ""
                        )
                        if program.path in known
                    }
                consuming = [hook for hook in manifest.hooks if hook.kind == "consumerinstall"]
                if consuming:
                    consumer.add(unit.path)
                    consumer |= Hooks.hook_script_paths(unit.path, consuming, known)
                    consumer |= {
                        program.path
                        for hook in consuming
                        for program in InlinePrograms.lifted(
                            unit.path, hook.name, hook.command or ""
                        )
                        if program.path in known
                    }
        return paths, consumer, ci_scripts

    def _coverage_findings(
        self,
        stats: WalkStats,
        root: Path,
        selected: int,
        *,
        complete: bool,
        binary: Sequence[str] = (),
        lfs_pointers: Sequence[str] = (),
        examined: int = 0,
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
        # Git LFS pointers, aggregated for the same reason binaries are. A repository
        # that tracks its assets through LFS has hundreds, and a checkout without LFS -
        # which is what `actions/checkout` does by default - turns every one of them
        # into a 130-byte text file naming content that is still on a server.
        #
        # Reported rather than passed over, because a file that was not examined must
        # not look like a file that was examined and found clean. Not treated as
        # incompleteness: a repository's images being absent is not a degraded scan of
        # its source, and marking it so would make `fail_on_incomplete` unusable for
        # every project that uses LFS.
        #
        # `unionlabs/union` tracks `*.png`, `*.pdf` and `*.psd`, and a shallow clone of
        # it produced 907 format-mismatch findings before this: every tracked asset
        # reported as a file contradicting its own extension.
        if lfs_pointers:
            sample = ", ".join(sorted(lfs_pointers)[:5])
            more = f" and {len(lfs_pointers) - 5} more" if len(lfs_pointers) > 5 else ""
            findings.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.FILE.LFS_POINTER",
                    severity=Severity.INFO,
                    message=(
                        f"{len(lfs_pointers)} file(s) are Git LFS pointers, so the bytes "
                        f"they name were not fetched and nothing about their content was "
                        f"examined: {sample}{more}."
                    ),
                    remediation=(
                        "Clone with LFS content if these files matter to the scan. "
                        "`actions/checkout` needs `lfs: true`, which is off by default."
                    ),
                )
            )

        if binary:
            sample = ", ".join(sorted(binary)[:5])
            more = f" and {len(binary) - 5} more" if len(binary) > 5 else ""
            findings.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
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

        # Anything the *scan target's own* configuration removed, at any share.
        #
        # BROAD_EXCLUSION below only fires past 80 percent of a tree of at least
        # 25 files, which is right for "this repository excludes most of
        # itself" and useless against the actual attack: one line excluding the
        # one file that carries the finding. That produced output byte-for-byte
        # identical to a clean scan.
        #
        # HIGH, not MEDIUM, because the default gate fails at HIGH. A repository
        # removing a file from its own scan is not a note.
        if self.config.untrusted_exclusions:
            removed = {
                pattern: count
                for pattern, count in stats.excluded_by_pattern.items()
                if pattern in set(self.config.untrusted_exclusions) and count
            }
            dropped = stats.files_dropped_by_config
            if removed or dropped:
                listed = ", ".join(
                    f"{pattern!r} ({count})" for pattern, count in sorted(removed.items())
                ) or ", ".join(repr(p) for p in sorted(self.config.untrusted_exclusions))
                findings.append(
                    OperationalFinding.build(
                        path=REPOSITORY_SCOPE,
                        rule_id="POLICY.COVERAGE.TARGET_EXCLUSION",
                        category=Category.POLICY,
                        severity=Severity.HIGH,
                        message=(
                            f"The repository's own configuration removed {dropped} "
                            f"file(s) from this scan: {listed}. A file the scan target "
                            f"excluded is a file it chose not to have examined, which "
                            f"is reported whatever the count -- one file is enough when "
                            f"it is the right one."
                        ),
                        remediation=(
                            "Confirm each pattern is intended. Exclusions an operator "
                            "needs belong on the command line or in a config passed "
                            "with --config, where they are not supplied by the thing "
                            "being scanned."
                        ),
                    )
                )

        # Nothing at all was examined, but the tree is not empty.
        #
        # The count that matters is what reached a detector and was read, not
        # what the walker selected. Those diverge whenever selected files fail
        # to load, and that gap was the whole bug: make every file in a
        # repository unreadable and each one produced an INFO note, `selected`
        # stayed at its full value, this check never fired, and the scan exited
        # 0. A repository nothing could be read from reported exactly like a
        # repository with nothing in it -- which is the one outcome this tool
        # is built to prevent.
        if examined == 0 and stats.files_seen > 0:
            # Always reported, never silent. An empty *selection* may be
            # ordinary -- an empty staged set is a normal commit -- but files
            # that were selected and then could not be read is never ordinary,
            # whatever the source, so the source's opinion only applies when it
            # selected nothing in the first place.
            unreadable = selected > 0
            normal = self.source.empty_selection_is_normal and not unreadable
            cause = (
                f"{selected} file(s) were selected and none could be read"
                if unreadable
                else (
                    f"everything was removed by configuration or by the selected "
                    f"source ({self.source.describe()})"
                )
            )
            findings.append(
                OperationalFinding.build(
                    path=REPOSITORY_SCOPE,
                    rule_id="POLICY.COVERAGE.NOTHING_SCANNED",
                    category=Category.POLICY,
                    severity=Severity.INFO if normal else Severity.HIGH,
                    message=(
                        f"No files were examined, although {stats.files_seen} were "
                        f"present: {cause}. This result reports that nothing was "
                        f"looked at rather than that nothing was found."
                    ),
                    remediation=(
                        "Review the exclude patterns and any --staged, --tracked or "
                        "--git-diff selection, and check the permissions on the tree. "
                        "A clean scan that examined no files is not a clean scan."
                    ),
                )
            )
        elif stats.files_seen >= BROAD_EXCLUSION_MIN_FILES:
            dropped = stats.files_dropped_by_config
            share = dropped / stats.files_seen
            # A repository excluding most of itself may be correct -- a large
            # vendored tree, a generated directory -- but it is worth stating,
            # because it is also exactly what blinding the scanner looks like.
            # The floor on tree size is there so a five-file repository with one
            # generated directory does not produce this every run; a check that
            # fires constantly on correct configuration gets excluded itself.
            if share >= BROAD_EXCLUSION_SHARE:
                findings.append(
                    OperationalFinding.build(
                        path=REPOSITORY_SCOPE,
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
                    OperationalFinding.build(
                        path=REPOSITORY_SCOPE,
                        rule_id="POLICY.COVERAGE.DETECTOR_DISABLED",
                        category=Category.POLICY,
                        # HIGH, because the default gate fails at HIGH and this
                        # was reported at MEDIUM: `detectors: {manifest: false}`
                        # in the scan target's own config made a CRITICAL
                        # finding disappear and the build pass.
                        severity=Severity.HIGH,
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

            if self.config.disabled_rules:
                names = ", ".join(sorted(self.config.disabled_rules))
                findings.append(
                    OperationalFinding.build(
                        path=REPOSITORY_SCOPE,
                        rule_id="POLICY.COVERAGE.RULE_DISABLED",
                        category=Category.POLICY,
                        severity=Severity.HIGH,
                        message=(
                            f"The repository's own configuration disabled "
                            f"{len(self.config.disabled_rules)} rule(s): {names}. "
                            f"Those checks produced nothing here whatever the code "
                            f"contains."
                        ),
                        remediation=(
                            "Confirm each is genuinely inapplicable. An organisation "
                            "policy can require rules that a repository may not "
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
                    OperationalFinding.build(
                        path=REPOSITORY_SCOPE,
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
                # Weakening the failure gate is reported at HIGH, where the
                # default gate fails, rather than at LOW with the resource
                # limits. Raising a limit is a repository being greedy with the
                # scanning machine; emptying `fail_on` is a repository turning
                # the verdict off for every finding including MALICIOUS at
                # CRITICAL. Those are not the same act and must not read the
                # same in a report.
                gate = setting.startswith("policy.")
                blinding = setting in BLINDING_SETTINGS
                findings.append(
                    OperationalFinding.build(
                        path=REPOSITORY_SCOPE,
                        rule_id=(
                            "POLICY.CONFIG.GATE_WEAKENED"
                            if gate or blinding
                            else "POLICY.CONFIG.CLAMPED"
                        ),
                        category=Category.POLICY,
                        severity=Severity.HIGH if gate or blinding else Severity.LOW,
                        message=(
                            (
                                f"The repository's own configuration tried to weaken the "
                                f"failure gate ({setting}) and was refused. A scan target "
                                f"cannot decide which of its own findings are allowed to "
                                f"fail the build; the built-in gate was used instead."
                            )
                            if gate
                            else (
                                f"The repository's own configuration set {setting}, which "
                                f"switches detection off or loads code into the scanner, and "
                                f"was refused. A scan target cannot choose how closely it is "
                                f"examined; the built-in behaviour was used instead."
                            )
                            if blinding
                            else (
                                f"{setting} was set by the repository's own configuration "
                                f"and reduced to the built-in default. A configuration "
                                f"file inside the scan target cannot raise a resource "
                                f"limit or add a rule pack, because both can be used "
                                f"against the machine running the scan."
                            )
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

    def _drop_disabled(self, produced: list[Finding]) -> list[Finding]:
        """Remove findings whose rule the configuration turned off.

        Applied to every detector's output rather than inside each detector, so
        a rule declared in Python is as disableable as one declared in YAML.
        Operational findings are never dropped: they describe the scan, and a
        configuration that could silence them could hide the fact that it had
        silenced everything else.
        """
        disabled = self.config.disabled_rules
        if not disabled:
            return produced
        return [
            f
            for f in produced
            if f.category is Category.OPERATIONAL or f.always_report or f.rule_id not in disabled
        ]

    def _run(
        self, detector: Detector, unit: Unit, ctx: ScanContext, acc: Accumulator
    ) -> list[Finding]:
        """Run one detector over one unit, containing its failures.

        A detector that raises must not abort the scan, because one broken
        detector silently reducing coverage across every file is far worse than
        one loud finding saying it broke. The scan continues and reports itself
        as incomplete.
        """
        try:
            produced = list(detector.inspect(unit, ctx))
        except Exception as exc:  # noqa: BLE001
            acc.complete = False
            return [
                OperationalFinding.build(
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
            kept: list[Finding] = []
            stray: list[Finding] = []
            for finding in produced:
                if (
                    finding.category is not Category.OPERATIONAL
                    and finding.location.path != unit.path
                ):
                    stray.append(finding)
                else:
                    kept.append(finding)

            if stray:
                # Reported and dropped, not raised. This check sat outside the
                # `try` above, so `DetectorError` propagated out of `scan()` and
                # terminated the run -- meaning a detector that mislabelled one
                # finding killed the entire scan on the first file it touched,
                # inside the very method whose docstring says a broken detector
                # must not abort anything.
                acc.complete = False
                kept.append(
                    OperationalFinding.build(
                        path=unit.path,
                        rule_id="OPERATIONAL.DETECTOR.STRAY_FINDING",
                        message=(
                            f"Detector {detector.id!r} reported {len(stray)} finding(s) "
                            f"about other paths while inspecting this file "
                            f"({stray[0].location.path!r}). They were discarded."
                        ),
                        remediation=(
                            "Report this. A file detector must report only about the "
                            "file it was given, or findings cannot be traced to their "
                            "source."
                        ),
                        severity=Severity.MEDIUM,
                    )
                )
            produced = kept

        # A detector that hit a ceiling of its own knows something the engine
        # cannot observe from outside: that it answered fewer questions than it
        # was asked. Reading it here keeps `complete` meaning the same thing
        # whether the coverage was lost in the walk or inside a detector.
        degrading = [f for f in produced if f.degrades_coverage]
        if any(f.detector in ADVISORY_DETECTORS for f in degrading):
            acc.advisory_complete = False
        if any(f.detector not in ADVISORY_DETECTORS for f in degrading):
            acc.complete = False

        return self._drop_disabled(produced)


__all__ = ["Engine"]
