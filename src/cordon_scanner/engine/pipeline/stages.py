"""The steps of scanning a tree, in the order the engine runs them: resolve the target, read every
file into units, build the dependency graph, fold what runs at install and import into the
context, run the file detectors, apply the ceilings that need every finding and the repository
detectors, then fold repeats and reach the package verdict.

Each step takes what it reads and returns what the scan needs after it, so the order and the data
between steps are explicit in `Engine._scan`.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon_scanner.decide.policy import SuppressionMatcher
from cordon_scanner.detect.base import (
    FileUnit,
    GraphUnit,
    RepositoryUnit,
    ScanContext,
)
from cordon_scanner.detect.supply.composer_plugins import ComposerPluginHooks
from cordon_scanner.engine.cache import ScanCache
from cordon_scanner.engine.parallel import MAX_CARRIED_BYTES, ParallelScanner
from cordon_scanner.engine.pipeline.accumulator import Accumulator
from cordon_scanner.engine.pipeline.ceilings import Ceilings
from cordon_scanner.engine.pipeline.constants import REPOSITORY_SCOPE
from cordon_scanner.engine.pipeline.facts import TreeFacts
from cordon_scanner.engine.pipeline.graph import Graph
from cordon_scanner.engine.pipeline.history import History
from cordon_scanner.engine.pipeline.hooks import Hooks
from cordon_scanner.engine.pipeline.operational import OperationalFinding
from cordon_scanner.engine.pipeline.publisher import Publisher
from cordon_scanner.engine.pipeline.releases import ReleaseChecks
from cordon_scanner.engine.pipeline.results import ResultFolding
from cordon_scanner.foundation.files.walk import (
    WalkEntry,
    Walker,
)
from cordon_scanner.foundation.models import Finding, Severity
from cordon_scanner.foundation.results import Dependency, Repository

if TYPE_CHECKING:
    from cordon_scanner.engine.engine import Engine


class ScanStages:
    """The steps of a scan of a tree."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.config = engine.config
        self.detectors = engine.detectors
        self.progress = engine.progress
        self.source = engine.source

    def read_units(
        self,
        root: Path,
        inventory: Repository,
        acc: Accumulator,
        deadline: float,
        walked: list[WalkEntry] | None,
        walker: Walker,
    ) -> list[FileUnit]:
        """Every file the scan reads, with the install hooks written inline and deobfuscated forms."""
        # Manifest hooks are discovered while scanning, and they change the
        # context every later finding is scored against: the same capability
        # pair means something different inside a lifecycle script. So files are
        # collected first, hooks are folded into the context, and detectors run
        # against the completed picture.
        self.progress.phase("reading")
        units = []
        for unit in self.engine.units.read(
            root, inventory, acc, deadline, walked=walked, walker=walker
        ):
            units.append(unit)
            self.progress.advance(unit.path)
        units.extend(self.engine.units.inline_hooks(units))
        units.extend(self.engine.units.deobfuscated(units))
        return units

    def dependencies(
        self, units: list[FileUnit], acc: Accumulator, root: Path
    ) -> tuple[tuple[Dependency, ...], tuple[Dependency, ...]]:
        """The dependency graph: lockfiles and manifests, an SBOM named as the target, and submodules."""
        self.progress.phase("dependencies")
        dependencies = self.engine.dependencies.build(units, acc)
        # A bill of materials named as the target is its inventory; in a tree it is a claim to
        # compare with what the tree resolves (`detect/sbom.py`), never counted twice.
        ingested = self.engine.dependencies.sbom(units, acc) if root.is_file() else ()
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
        return dependencies, ingested

    def install_context(
        self,
        units: list[FileUnit],
        acc: Accumulator,
        ctx: ScanContext,
        dependencies: tuple[Dependency, ...],
    ) -> ScanContext:
        """What runs at install, at import and when an agent calls it, folded into the scan context."""
        manifest_hooks, consumer_hooks, ci_scripts = Hooks.manifest_hook_paths(units, acc)
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
        skill_scripts = TreeFacts.skill_scripts(units)
        agent_run = skill_scripts | ReleaseChecks.mcp_server_sources(units)
        agent_tools = self.engine._agent_tool_paths(units, agent_run, hook_paths)
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
        deferred = TreeFacts.entry_points_reached(
            Hooks.hook_deferred_lines(units, hook_paths, entries), agent_run
        )
        ctx = replace(
            ctx,
            dependencies=Graph.packages(dependencies),
            install_hook_paths=frozenset(hook_paths),
            tree_paths=frozenset(unit.path for unit in units),
            shipped_native_paths=TreeFacts.shipped_native(units),
            install_entry_paths=entries,
            agent_run_paths=agent_tools,
            consumer_install_paths=frozenset(consumer_hooks),
            install_deferred_lines=deferred,
            ci_hook_paths=ctx.ci_hook_paths | frozenset(ci_scripts),
        )
        return Hooks.lifted_inherit(ctx)

    def detect(
        self,
        units: list[FileUnit],
        acc: Accumulator,
        root: Path,
        ctx: ScanContext,
        dependencies: tuple[Dependency, ...],
    ) -> None:
        """Every file detector over every unit, in parallel where the source allows it."""
        file_detectors = [
            d
            for d in self.detectors
            if self.engine.detection.enabled(d, ctx)
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
        with self.engine._sealed_scan():
            if workers > 1:
                acc.add(
                    self.engine.detection.parallel(
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
                    acc.add(
                        self.engine.detection.inspect_file(
                            unit, ctx, acc, file_detectors, signature
                        )
                    )
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
                    if not self.engine.detection.enabled(detector, ctx):
                        continue
                    acc.add(self.engine.detection.run(detector, graph_unit, ctx, acc))
            acc.add(self.engine.dependencies.sbom_listed_findings(acc.findings, ctx))

    def after_detection(
        self,
        dependencies: tuple[Dependency, ...],
        acc: Accumulator,
        units: list[FileUnit],
        ctx: ScanContext,
        inventory: Repository,
    ) -> None:
        """The ceilings that need every finding, the repository-level detectors, and the cap notice."""
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
        with self.engine._sealed_scan():
            for detector in self.detectors:
                if not detector.requires.repository:
                    continue
                if not self.engine.detection.enabled(detector, ctx):
                    continue
                acc.add(self.engine.detection.run(detector, repository_unit, ctx, acc))

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

    def fold_and_judge(
        self,
        acc: Accumulator,
        units: list[FileUnit],
        ctx: ScanContext,
        dependencies: tuple[Dependency, ...],
    ) -> tuple[tuple[Finding, ...], dict[str, Any], tuple[Dependency, ...]]:
        """Suppression expiry, the folds over repeated findings, and the package verdict over what is left."""
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
                Hooks.onto_manifest(Publisher.test_identity_keys(list(findings), units), units),
                self.config.policy,
            ),
            units,
            {
                **self.engine._capability_profile(units, ctx, labels),
                **History.registry_facts(units),
            },
            self.engine._intent_observation(units, ctx, labels),
        )
        findings = tuple(graded)
        dependencies = self.engine.detection.annotated(dependencies, findings, ctx, units)
        return findings, verdict, dependencies

    @staticmethod
    def resolve_target(target: str | Path, acc: Accumulator) -> Path:
        """The target resolved, with an operational finding when it was a symbolic link."""
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
        return root


__all__ = ["ScanStages"]
