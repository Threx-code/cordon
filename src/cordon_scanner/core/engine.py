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

import os.path
import re
import time
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from cordon_scanner.archive.safe import ArchiveReader
from cordon_scanner.core.cache import CacheKey, ScanCache
from cordon_scanner.core.config import Config
from cordon_scanner.core.content import FileContent, Skipped
from cordon_scanner.core.errors import ArchiveError, SourceError
from cordon_scanner.core.models import (
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
from cordon_scanner.core.parallel import ParallelScanner
from cordon_scanner.core.paths import basename
from cordon_scanner.core.policy import PolicyGate, SuppressionMatcher
from cordon_scanner.core.progress import NullProgress, Progress
from cordon_scanner.core.scoring import RiskScorer
from cordon_scanner.core.walker import WalkEntry, Walker, WalkStats
from cordon_scanner.detect.base import FileUnit, GraphUnit, ScanContext, Unit
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.langs.registry import LanguageRegistry
from cordon_scanner.rules.loader import RuleLoader, RuleSet
from cordon_scanner.sources.base import FileSource, WorkingTreeSource
from cordon_scanner.version import SCHEMA_VERSION, __version__

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Sequence

    from cordon_scanner.detect.base import Detector

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

    finding_cap: int = 0
    """Ceiling on retained findings, from `limits.max_findings`.

    Zero disables it. The limit was declared and documented -- "a hostile
    repository can otherwise turn a scan into an out-of-memory failure by
    arranging for every line to match. Reaching this cap is itself reported" --
    and never checked anywhere.
    """

    capped: bool = False

    def append(self, finding: Finding) -> bool:
        """Retain one finding if the cap allows it.

        Enforced here rather than at render time, which is where
        `ReportOptions.max_findings` applies -- by then everything is already in
        memory and the limit has prevented nothing.
        """
        if self.finding_cap and len(self.findings) >= self.finding_cap:
            self.capped = True
            self.complete = False
            return False
        self.findings.append(finding)
        return True

    def add(self, produced: Iterable[Finding]) -> None:
        """Retain a batch, stopping at the cap."""
        for finding in produced:
            if not self.append(finding):
                return


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

    @staticmethod
    def _default_detectors() -> tuple[Detector, ...]:
        from cordon_scanner.core.registry import Registry

        return Registry.default_detectors()

    # -- Entry point -----------------------------------------------------

    def scan(self, target: str | Path) -> ScanResult:
        """Scan a target and return a complete, sorted result."""
        try:
            return self._scan(target)
        finally:
            # In a `finally` because the progress line is a partial line with no
            # newline on it. Leaving it there puts a traceback or an error
            # message on the same row as a half-drawn progress bar.
            self.progress.finish()

    def _scan(self, target: str | Path) -> ScanResult:
        started = time.monotonic()
        acc = _Accumulator(finding_cap=self.config.limits.max_findings)

        # Recorded before resolving, because resolving is what loses it. The
        # walker never follows a link found during traversal; a link *named as
        # the target* is the one path where a link's destination is read, and it
        # is operator-directed rather than an attack. Reported so the absolute
        # guarantee stated elsewhere has its one exception visible.
        named = Path(target)
        root = named.resolve()
        if named.is_symlink():
            acc.append(
                Engine._operational(
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
        if root.is_file() and ArchiveReader.is_archive(root.name):
            return self._scan_archive(root, acc, started)
        self.progress.phase("identifying")
        # One traversal for both phases where the source permits it. A git
        # source narrows the scan set, so there the inventory still describes
        # the whole repository and the two traversals are genuinely different.
        walker = self._walker()
        walked = list(walker.walk(root)) if self.source.yields_the_whole_walk else None
        inventory = self.inventory(root, acc, walked=walked, walker=walker)
        ctx = self._context(inventory)

        deadline = started + self.config.limits.total_timeout

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

        self.progress.phase("dependencies")
        dependencies = self._build_graph(units, acc)
        hook_paths = set(ctx.install_hook_paths) | self._manifest_hook_paths(units, acc)
        # What runs at install time is the hook and everything it imports. The
        # context stopped at the hook file, so moving the payload into a helper
        # module -- no obfuscation, just ordinary package structure -- avoided
        # the escalation entirely.
        hook_paths |= self._hook_import_closure(units, hook_paths)
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
        self.progress.phase("scanning", total=len(units))
        if workers > 1:
            acc.add(self._scan_parallel(units, root, ctx, acc, file_detectors, signature))
        else:
            for unit in units:
                acc.add(self._inspect_file(unit, ctx, acc, file_detectors, signature))
                self.progress.advance(unit.path)

        if dependencies:
            self.progress.phase("graph")
            graph_unit = GraphUnit(dependencies=dependencies)
            for detector in self.detectors:
                if not detector.requires.dependencies:
                    continue
                if not self._detector_enabled(detector, ctx):
                    continue
                acc.add(self._run(detector, graph_unit, ctx, acc))

        if acc.capped:
            # Appended directly: the cap is full by definition, and the one
            # finding that explains why must not be the one it drops.
            acc.findings.append(
                Engine._operational(
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
            rulepack_version=self.rules.version,
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
        deadline = started + self.config.limits.total_timeout
        retained = 0

        try:
            for member_path, member_data in ArchiveReader.walk_archive(
                data,
                path=path.name,
                limits=self.config.limits,
                rejected=rejected,
                deadline=deadline if self.config.limits.total_timeout > 0 else None,
            ):
                if self.config.limits.total_timeout > 0 and time.monotonic() > deadline:
                    acc.complete = False
                    acc.append(
                        Engine._operational(
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
                        Engine._operational(
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
            acc.append(
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

        for member_path, reason, detail in rejected:
            acc.complete = False
            acc.append(
                Engine._operational(
                    path=member_path,
                    rule_id="OPERATIONAL.ARCHIVE.MEMBER_REJECTED",
                    message=(
                        f"An archive member was refused ({reason}) and therefore not "
                        f"examined{': ' + detail if detail else ''}."
                    ),
                    remediation=(
                        "A refused member is not a clean member. Inspect it directly if "
                        "the archive is from an untrusted source."
                    ),
                )
            )

        # Manifests inside a package determine whether its code runs at install
        # time, which is the whole reason a package archive is worth scanning.
        hook_paths = self._manifest_hook_paths(units, acc)
        ctx = replace(ctx, install_hook_paths=frozenset(hook_paths))

        detectors = [d for d in self.detectors if self._detector_enabled(d, ctx)]
        self.progress.phase("scanning", total=len(units))
        for unit in units:
            # The same budget the directory path applies between units. Most of
            # the cost of a hostile archive is here rather than in extraction --
            # a fifty-thousand-member archive expands in a second and then takes
            # eight to match against -- so a deadline that only covered
            # expansion bounded the wrong half.
            if self.config.limits.total_timeout > 0 and time.monotonic() > deadline:
                acc.complete = False
                acc.append(
                    Engine._operational(
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
            for detector in detectors:
                if detector.requires.dependencies and detector.requires.content is False:
                    continue
                acc.add(self._run(detector, unit, ctx, acc))
            self.progress.advance(unit.path)

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
            rulepack_version=self.rules.version,
            rulepack_hash=self.rules.content_hash,
            config_hash=self.config.fingerprint(),
        )
        return PolicyGate.filter_for_reporting(result, self.config).sorted()

    # -- Phase 0: inventory ----------------------------------------------

    def inventory(
        self,
        root: Path,
        acc: _Accumulator | None = None,
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
        manifests: dict[str, list[str]] = {}
        lockfiles: dict[str, list[str]] = {}
        total_bytes = 0
        file_count = 0

        for entry in traversal:
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

        revision, remote = self._provenance(root)
        return Repository(
            root=str(root),
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
    def _provenance(root: Path) -> tuple[str | None, str | None]:
        """The commit and remote this scan describes.

        `Repository` declared both fields, `to_dict` serialised both, and
        nothing ever set either -- so every report and every SARIF upload
        recorded `null` for the two values that say *which* code was examined.
        A result nobody can tie to a commit is a result nobody can act on later:
        it says a repository was clean without saying which version of it.

        `GitRepository.discover` already computed both, including stripping any
        credential from the remote, and its answer was simply never asked for.

        Failure is silent on purpose. A directory that is not a repository is
        the ordinary case, not a degraded scan, and it is already visible in the
        report as an absent revision.
        """
        from cordon_scanner.sources.git import GitRepository

        try:
            info = GitRepository.discover(root)
        except (SourceError, OSError):  # pragma: no cover - defensive
            return (None, None)
        if info is None:
            return (None, None)
        return (info.revision, info.remote)

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
    def _languages_from_hooks(inventory: Repository) -> dict[str, str]:
        """Languages implied by what a lifecycle script runs.

        `"postinstall": "node ./payload.png"` names both the interpreter and the
        file. An interpreter handed an explicit path does not consult the
        extension, so the file is JavaScript however it is spelled -- and
        `payload.png` otherwise gets `language=None` and only the
        language-agnostic rules, which is the rename half of the NUL-byte
        evasion.

        Only lifecycle commands are read, and only the token immediately after a
        recognised interpreter. That keeps this from becoming a general
        shell parser: the aim is to stop a rename hiding executed code, not to
        model every command line.
        """
        implied: dict[str, str] = {}
        for hook in inventory.hooks:
            if not hook.command:
                continue

            base = hook.path.rpartition("/")[0]
            tokens = [token for token in re.split(r"[\s;&|()]+", hook.command) if token]
            for index, token in enumerate(tokens):
                language = LanguageRegistry.language_from_interpreter(token)
                if language is None:
                    continue
                for candidate in tokens[index + 1 :]:
                    if candidate.startswith("-"):
                        continue
                    target = candidate.lstrip("./")
                    if not target:
                        break
                    resolved = f"{base}/{target}" if base else target
                    implied.setdefault(resolved, language)
                    break
        return implied

    @staticmethod
    def _hooks_for(rel_path: str) -> Iterator[Hook]:
        """Identify paths that execute during install, build or version control.

        First-class because execution context is the largest single multiplier in
        the risk model. Detecting these before scanning is what lets the same
        capability pair be quiet in application code and decisive here.

        This is the filename-level pass. Manifest lifecycle scripts are found by
        the manifest detector, which can parse them properly.
        """
        name = basename(rel_path)
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
        implied_languages = self._languages_from_hooks(inventory)

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
                    Engine._operational(
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
                acc.append(
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

            if loaded.truncated:
                # A file examined in part is not a file examined. Truncation was
                # reported at INFO and left `complete` true, so
                # `fail_on_incomplete` -- the one organisation control that
                # catches the timeout variant of this -- did not catch the
                # sharpest one: `max_file_bytes: 65536` in a repository's own
                # config, which reads as ordinary tuning and pads a payload out
                # of reach.
                acc.complete = False

            retained += len(loaded.raw)
            if 0 < self.config.limits.max_memory_bytes <= retained:
                acc.complete = False
                acc.append(
                    Engine._operational(
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

            yield FileUnit(content=loaded, language=language)

        if walker.stats.limit_hit:
            acc.complete = False
            acc.append(
                Engine._operational(
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
                examined=acc.files_scanned,
            )
        )

        # L5 - traversal limits that dropped paths without a word.
        # `max_path_depth` incremented `dirs_pruned` and `max_path_bytes` pushed
        # the path into `stats.errors`; neither reached a finding, so both were
        # silent skips against the limits module's own invariant that reaching a
        # limit is never one.
        if walker.stats.errors:
            sample = ", ".join(path for path, _ in walker.stats.errors[:5])
            more = (
                f" and {len(walker.stats.errors) - 5} more" if len(walker.stats.errors) > 5 else ""
            )
            acc.append(
                Engine._operational(
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
                Engine._operational(
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
                Engine._operational(
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

        # An exclusion matching nothing is either a mistake or a hole held open
        # for a file that does not exist yet. Both are worth surfacing: commit a
        # file at that path and it would be skipped by the very check meant to
        # examine it.
        for pattern in walker.stats.unmatched_patterns:
            acc.append(
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
        # `perf_counter`, not `monotonic`. Windows' monotonic clock ticks about
        # every 15 milliseconds, so a per-file budget smaller than one tick
        # measured zero elapsed time and never tripped -- the same coarse-clock
        # failure that made `--timeout 0` a no-op there. perf_counter is the
        # high-resolution timer and is what a sub-second budget needs.
        started = time.perf_counter()

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
            if budget > 0 and time.perf_counter() - started >= budget:
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
        pending: list[tuple[int, str, int, str]] = []
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
                # worker can tell whether it read the same bytes.
                pending.append((index, unit.path, len(unit.content.raw), unit.content.sha256))

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
            workers=ParallelScanner.worker_count(self.config.limits.max_workers, len(pending)),
            # The set the parent already filtered. Without it the worker ran
            # every detector it could find, and a scan's findings depended on
            # the machine's core count.
            detector_ids=[getattr(d, "id", "") for d in detectors],
            # The parent already walked the tree. Sending the result costs one
            # pickle; recomputing it costs a full traversal per worker.
            inventory=ctx.repository,
            on_batch=report,
        )

        if produced is None:
            # The pool did not run. Fall back rather than lose coverage. `None`
            # rather than an empty list, so a pool that ran and legitimately
            # found nothing is not re-scanned from scratch.
            for _index, path, _size, _digest in pending:
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
                    Engine._operational(
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
            # Contained. `Engine._run` exists so that "a detector that raises
            # must not abort the scan", and this call site and the manifest one
            # below bypassed it and called an ecosystem parser straight from
            # `scan()`. `inventory` wraps the identical call, so the
            # inconsistency sat within one file: a parser raising on a crafted
            # lockfile terminated the whole scan with exit 2, which reads as
            # "the scanner broke" and gets a pipeline to skip the step.
            try:
                graph = ecosystem.parse_lockfile(unit.content)
            except Exception as exc:
                acc.complete = False
                acc.append(
                    Engine._operational(
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
            collected.extend(
                replace(dependency, declared_in=unit.path)
                for dependency in ecosystem.to_dependencies(graph, project=project or None)
            )

            if len(collected) > self.config.limits.max_dependencies:
                acc.complete = False
                acc.append(
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

        collected.extend(self._declared_graph(units, acc, covered={d.project for d in collected}))

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

    def _declared_graph(
        self, units: list[FileUnit], acc: _Accumulator, *, covered: set[str | None]
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

        Only for projects a lockfile did not already cover, so a repository with
        both does not get each dependency twice in different states.
        """
        collected: list[Dependency] = []

        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            if ecosystem_id is None:
                continue
            ecosystem = EcosystemRegistry.get(ecosystem_id)
            if ecosystem is None:
                continue

            project = unit.path.rpartition("/")[0] or None
            if project in covered:
                continue

            try:
                manifest = ecosystem.parse_manifest(unit.content)
            except Exception:  # noqa: S112
                # Deliberately silent here, and not a swallowed failure.
                # `_manifest_hook_paths` parses the same file, under the same
                # predicate, in the same scan, and reports
                # OPERATIONAL.PARSER.FAILED for it. A second finding would say
                # nothing the first did not.
                continue

            if manifest.parse_error:
                continue

            for declared in manifest.dependencies:
                name = ecosystem.normalize_name(declared.name)
                collected.append(
                    Dependency(
                        purl=f"pkg:{ecosystem_id}/{name}",
                        ecosystem=ecosystem_id,
                        name=declared.name,
                        version=None,
                        direct=True,
                        depth=0,
                        scope=declared.scope,
                        declared_spec=declared.spec,
                        project=project,
                        declared_in=unit.path,
                    )
                )

            if len(collected) > self.config.limits.max_dependencies:
                acc.complete = False
                acc.append(
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

        return collected

    @staticmethod
    def _hook_import_closure(units: list[FileUnit], hooks: set[str]) -> set[str]:
        """First-party Python files reachable by import from an install hook.

        Read, never executed. Only files present in this scan are followed: a
        payload inside an installed third-party package is not this repository's
        file to judge, and following imports out of the tree would make the
        closure unbounded and mostly irrelevant.
        """
        from cordon_scanner.core.closure import ImportClosure

        sources = {
            unit.path: unit.content.text
            for unit in units
            if unit.path.endswith(".py") and not unit.content.is_binary
        }
        if not sources:
            return set()
        return ImportClosure.resolve(hooks, sources)

    @staticmethod
    def _manifest_hook_paths(units: list[FileUnit], acc: _Accumulator | None = None) -> set[str]:
        """Paths that execute at install time, according to their manifests."""
        paths: set[str] = set()
        known = frozenset(unit.path for unit in units)
        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            if ecosystem_id is None:
                continue
            ecosystem = EcosystemRegistry.get(ecosystem_id)
            if ecosystem is None:
                continue
            try:
                manifest = ecosystem.parse_manifest(unit.content)
            except Exception as exc:
                # Same containment as the lockfile path, and reported for the
                # same reason. Catching it and moving on quietly would trade one
                # failure mode (the scan dies) for the worse one (the manifest
                # was never read and nothing says so), which is the trade this
                # whole audit is about.
                if acc is not None:
                    acc.complete = False
                    acc.append(
                        Engine._operational(
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
            if manifest.hooks:
                paths.add(unit.path)
                paths |= Engine._hook_script_paths(unit.path, manifest.hooks, known)
        return paths

    @staticmethod
    def _hook_script_paths(
        manifest_path: str, hooks: Sequence[Hook], known: frozenset[str]
    ) -> set[str]:
        """Files a lifecycle command runs.

        A manifest declaring `"postinstall": "node install.js"` means
        `install.js` executes at install time, but marking only the manifest
        leaves that file scored as ordinary application code. The same
        credential read and outbound request that is critical in a hook then
        reports as merely suspicious, purely because the code lives one file
        away from the declaration.

        Only paths already present in the scan are added. A command naming a
        file that is not there tells us nothing, and resolving outside the scan
        root would follow attacker-controlled text out of the tree.
        """
        base = PurePosixPath(manifest_path).parent
        found: set[str] = set()

        for hook in hooks:
            for token in re.split(r"[\s;&|]+", hook.command):
                candidate = token.strip("\"'")
                if not candidate or candidate.startswith("-"):
                    continue
                if "." not in PurePosixPath(candidate).name:
                    # No extension: a program name such as `node` or `make`,
                    # not a file in the repository.
                    continue
                resolved = os.path.normpath(str(base / candidate))
                if resolved.startswith(".."):
                    continue
                if resolved in known:
                    found.add(resolved)

        return found

    def _coverage_findings(
        self,
        stats: WalkStats,
        root: Path,
        selected: int,
        *,
        complete: bool,
        binary: Sequence[str] = (),
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
        if binary:
            sample = ", ".join(sorted(binary)[:5])
            more = f" and {len(binary) - 5} more" if len(binary) > 5 else ""
            findings.append(
                Engine._operational(
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
                    Engine._operational(
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
                Engine._operational(
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
                    Engine._operational(
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
                    Engine._operational(
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
                    Engine._operational(
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
                findings.append(
                    Engine._operational(
                        path=REPOSITORY_SCOPE,
                        rule_id=(
                            "POLICY.CONFIG.GATE_WEAKENED" if gate else "POLICY.CONFIG.CLAMPED"
                        ),
                        category=Category.POLICY,
                        severity=Severity.HIGH if gate else Severity.LOW,
                        message=(
                            (
                                f"The repository's own configuration tried to weaken the "
                                f"failure gate ({setting}) and was refused. A scan target "
                                f"cannot decide which of its own findings are allowed to "
                                f"fail the build; the built-in gate was used instead."
                            )
                            if gate
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
                    Engine._operational(
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

        return self._drop_disabled(produced)


REPOSITORY_SCOPE = "."
"""Location for a finding about the scan rather than about one file.

`Location.path` is documented as "Repository-relative, forward-slashed,
normalised. Never absolute, so that results are comparable across machines and
safe to publish", and every operational and coverage finding used the absolute
resolved root. In CI that put runner directory layouts, internal project names
and sometimes usernames into artefacts that are routinely uploaded to third
parties and attached to pull requests."""


# A scan that skipped most of the tree is worth reporting; a small repository
# with one generated directory is not. The floor keeps the check from firing on
# correct configuration, which is how a check gets turned off.
_BROAD_EXCLUSION_SHARE = 0.8
_BROAD_EXCLUSION_MIN_FILES = 25


__all__ = ["Engine"]
