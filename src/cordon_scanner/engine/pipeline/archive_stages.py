"""The steps of scanning an archive without writing any of it to disk: an image's layers or an
archive's members as one stream, every member read into a unit or reported as refused, what runs
at install and import among them, the detectors over the members (in parallel when worth it), the
checks on the release as a whole, the dependency graph and what the archive is, and the verdict.
"""

from __future__ import annotations

import re
import time
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.analysis.python.flows.imported_clients import ImportedClients
from cordon_scanner.analysis.python.unparsed_source import UnparsedSource
from cordon_scanner.analysis.shared.languages import LanguageRegistry
from cordon_scanner.decide.code_model import CodeModelPass
from cordon_scanner.detect.base import (
    FileUnit,
    GraphUnit,
    ScanContext,
)
from cordon_scanner.detect.registry import ComposerPluginHooks, ServerSources
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.engine.closure import ImportClosure
from cordon_scanner.engine.entries import PackageEntries
from cordon_scanner.engine.package_format import PackageFormat
from cordon_scanner.engine.pipeline.accumulator import Accumulator
from cordon_scanner.engine.pipeline.archives import ArchiveMembers
from cordon_scanner.engine.pipeline.ceilings import Ceilings
from cordon_scanner.engine.pipeline.constants import (
    ARCHIVE_SLICE,
    DEPENDENCY_BUILD_FILENAMES,
    HONOURED_PINS,
    REPOSITORY_SCOPE,
)
from cordon_scanner.engine.pipeline.facts import TreeFacts
from cordon_scanner.engine.pipeline.graph import Graph
from cordon_scanner.engine.pipeline.history import History
from cordon_scanner.engine.pipeline.hooks import BuildRoots, Hooks
from cordon_scanner.engine.pipeline.images import Images
from cordon_scanner.engine.pipeline.publisher import Publisher
from cordon_scanner.engine.pipeline.releases import ReleaseChecks
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.errors import ArchiveError
from cordon_scanner.foundation.formats.served_json import ServedJson
from cordon_scanner.foundation.models import Scope, Severity
from cordon_scanner.foundation.paths import ContainerPaths
from cordon_scanner.foundation.results import Dependency, OperationalFinding
from cordon_scanner.sources.registry import ArchiveReader

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from cordon_scanner.detect.base import Detector
    from cordon_scanner.engine.engine import Engine


class ArchiveStages:
    """The steps of a scan of an archive."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.config = engine.config
        self.detectors = engine.detectors
        self.progress = engine.progress

    def source(
        self,
        data: bytes,
        acc: Accumulator,
        path: Path,
        rejected: list[tuple[str, str, str]],
        deadline: float,
        *,
        import_library: set[str] | None = None,
    ) -> tuple[Any, Iterator[tuple[str, bytes]]]:
        """An image's layers or a plain archive's members, as one stream of members."""
        # A container image is read the way a runtime assembles it -- layers squashed, whiteouts
        # applied -- rather than as nested tarballs, whose layer members are far past any per-member
        # limit and whose files would be scanned once per layer that touched them.
        image = self.engine.dependencies.image_inventory(data, acc)
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
                import_library=import_library,
            )
        return image, members

    def read_members(
        self,
        members: Iterator[tuple[str, bytes]],
        deadline: float,
        acc: Accumulator,
        path: Path,
        retained: int,
        units: list[FileUnit],
        rejected: list[tuple[str, str, str]],
        image: Any,
        *,
        import_library: set[str] | None = None,
    ) -> None:
        """Every member the archive reader gives, as a unit, and every one it refused, as a finding."""
        try:
            for member_path, member_data in members:
                if self.config.limits.total_timeout > 0 and time.monotonic() > deadline:
                    acc.incomplete(
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
                    acc.incomplete(
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
                    note = ArchiveMembers.truncated_note(member_path, member_content)
                    acc.append(
                        note if ArchiveMembers.read_to_end(member_content) else acc.gap(note)
                    )
                units.append(
                    FileUnit(
                        content=member_content,
                        language=LanguageRegistry.of_file(member_path, member_content),
                        import_library=member_path in (import_library or ()),
                    )
                )
                acc.files_scanned += 1
                acc.bytes_scanned += len(member_data)
                acc.ledger_tree.append(member_path)
        except ArchiveError as exc:
            acc.incomplete(
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
            ArchiveMembers.refuse(acc, member_path, reason, detail, image=image is not None)

    def context(
        self, units: list[FileUnit], acc: Accumulator, ctx: ScanContext, image: Any
    ) -> ScanContext:
        """What runs at install, at import and when an agent calls it, among the archive's members."""
        # Manifests inside a package determine whether its code runs at install
        # time, which is the whole reason a package archive is worth scanning.
        # What a hook runs is read as its interpreter runs it, before anything reads a unit's
        # language: the deobfuscation lift takes only JavaScript, so an obfuscated payload at
        # lib/run.md, run by `node`, was still Markdown when the lift ran (modelling team's review).
        Hooks.hooked_languages(units)
        units.extend(self.engine.units.inline_hooks(units))
        units.extend(self.engine.units.content_readings(units))
        units.extend(self.engine.units.deobfuscated(units))
        hook_paths, consumer_hooks, ci_scripts = Hooks.manifest_hook_paths(units, acc)
        registry = PackageFormat.of(units)
        hook_paths = self._without_foreign_npm_hooks(units, hook_paths, registry)
        foreign_package = self._foreign_package(registry)
        hook_paths |= self._filename_hooks(units)
        skill_scripts = TreeFacts.skill_scripts(units)
        agent_run = skill_scripts | ServerSources.of(units)
        agent_tools = self.engine._agent_tool_paths(units, agent_run, hook_paths)
        # Only a skill's scripts take the install grade. An MCP server runs when the agent calls
        # a tool the user asked it to use: downloading a browser, starting a detached emulator or
        # writing its config is the tool's work, and graded as install code it blocked 40 of 863
        # real MCP packages (review 98). What a server's handlers do with the agent's input is
        # read by `detect/mcp_code.py` instead -- a shell behind a secret prefix, a hidden copy of
        # every argument, a gate that turns the tool later, secrets gathered by name.
        # A skill's scripts run unasked when an agent uses the skill. A SKILL.md in a registry
        # package's source (a PyPI sdist's root, beside its PKG-INFO) is guidance for whoever
        # works on that repository: the package manager installs none of it where an agent loads
        # skills, so the scripts beside it are scanned as what they are, not as install code
        # (pypi-benign F472: barangay, browser-automation-cli, moregan). npm is left out: skills
        # are also distributed as npm packages, and that was not measured.
        if not foreign_package:
            hook_paths |= skill_scripts
        entries = frozenset(hook_paths)
        unshipped: list[tuple[str, str]] = []
        python_closure = Hooks.hook_import_closure(units, hook_paths, unshipped)
        ImportClosure.unshipped_gaps(acc, unshipped)
        # A file that closure runs by its path is Python whatever its name (item 39's suite).
        Hooks.executed_as_python(units, python_closure)
        hook_paths |= python_closure
        hook_paths |= Hooks.hook_js_closure(units, hook_paths)
        hook_paths, entries, consumer_hooks = Hooks.outside_extensions(
            units, hook_paths, entries, consumer_hooks
        )
        ctx = replace(
            ctx,
            install_hook_paths=frozenset(hook_paths),
            tree_paths=frozenset(unit.path for unit in units),
            shipped_native_paths=TreeFacts.shipped_native(units),
            install_entry_paths=entries,
            agent_run_paths=agent_tools,
            consumer_install_paths=frozenset(consumer_hooks),
            ci_hook_paths=ctx.ci_hook_paths | frozenset(ci_scripts),
            install_deferred_lines=TreeFacts.entry_points_reached(
                Hooks.hook_deferred_lines(units, hook_paths, entries), agent_run
            ),
            # Known before any file is examined, so a detector can tell an image's files from a
            # source tree's: an image's executables are what it ships.
            image=image if image is not None else ctx.image,
            # And so can a published package's: its `build/` and `bin/` are what runs, and the
            # typosquat grading asks which format it is.
            package_distribution=bool(early_format := PackageFormat.of(units)),
            distribution=early_format,
            # What the package's own dev, build and start scripts run is used code too (item 72).
            import_entry_paths=(used := PackageEntries.of(units, early_format))
            | (project := PackageEntries.project_run(units, early_format)),
            library_entry_paths=PackageEntries.of(units, early_format, with_bin=False),
            # Seeded from every entry, `bin` included: a command's relative requires run when it
            # does (5E-1: the closure was seeded from the library entries only, so a bin script's
            # helper was in no reach set). And from what the project scripts run.
            library_closure_paths=frozenset(Hooks.hook_js_closure(units, set(used | project))),
            declared_dependencies=EcosystemRegistry.declared_dependencies(units, early_format),
            package_repository=PackageEntries.repository(units, early_format),
        )
        ctx = replace(
            ctx,
            verdict_dependency_names=Ceilings.verdict_dependency_names(units),
            python_imported_clients=ImportedClients.of_units(units),
        )
        ctx = self.unparsed(units, acc, ctx, python_closure)
        ctx = self.import_context(units, ctx, early_format)
        return Hooks.lifted_inherit(ctx)

    @staticmethod
    def _filename_hooks(units: list[FileUnit]) -> set[str]:
        """The same install-time picture a directory scan builds: filename hooks (`setup.py`, a
        `.pth`), NuGet's, a gem's extension, a Composer plugin. A downloaded sdist or tarball is
        the commonest thing to vet, and it was the one target that skipped them. A `setup.py` is
        the build script only where a directory scan would take it as one (`Hooks.hook_executes`):
        beside the sdist's `PKG-INFO`, never inside a package or below the root. Read by the
        member's path in its archive, as the hook names it."""
        directories: set[str] = set()
        for unit in units:
            BuildRoots.note(unit.path.rpartition("!")[2], directories)
        paths = {
            unit.path
            for unit in units
            if not Hooks.under_fixture_directory(unit.path)
            and any(
                hook.kind not in ("ci", "projectbuild") and Hooks.hook_executes(hook, directories)
                for hook in Hooks.hooks_for(unit.path.rpartition("!")[2])
            )
        }
        return (
            paths
            | Hooks.nuget_hooks(units)
            | Hooks.gem_extension_hooks(units)
            | ComposerPluginHooks.paths(units)
        )

    @staticmethod
    def _foreign_package(registry: str) -> bool:
        """A registry package whose installer runs no bundled npm script and loads no skill."""
        return bool(registry) and not EcosystemRegistry.runs_bundled_scripts(registry)

    #: A build step that runs npm, and with it the lifecycle scripts of what node_modules holds.
    _RUNS_NPM: ClassVar[re.Pattern[str]] = re.compile(r"\b(?:npm|yarn|pnpm|bun)\b")

    @classmethod
    def _without_foreign_npm_hooks(
        cls, units: list[FileUnit], hook_paths: set[str], registry: str
    ) -> set[str]:
        """An npm tree vendored inside another registry's package (a Python front end's
        node_modules): pip runs no npm lifecycle script, so esbuild's install.js there is not
        install code -- unless the package's own build runs npm (`npm rebuild`), which would run
        them. npm's own tarballs run their bundled dependencies' scripts and keep them."""
        if not cls._foreign_package(registry):
            return hook_paths
        foreign = {p for p in hook_paths if "/node_modules/" in f"/{p.rpartition('!')[2]}"}
        if not foreign:
            return hook_paths
        builds = [
            u
            for u in units
            if ContainerPaths.basename(u.path.rpartition("!")[2]) in DEPENDENCY_BUILD_FILENAMES
            and not u.content.is_binary
        ]
        if any(cls._RUNS_NPM.search(u.content.text) for u in builds):
            return hook_paths
        return hook_paths - foreign

    def unparsed(
        self, units: list[FileUnit], acc: Accumulator, ctx: ScanContext, python_closure: set[str]
    ) -> ScanContext:
        """What runs at install or import and does not parse is read as Python 2, or is a gap,
        fail closed (09 3a). A reading runs where its file runs (`lifted_inherit`)."""
        python_entries = {p for p in ctx.import_entry_paths if p.endswith(".py")}
        from cordon_scanner.engine.entries import PythonScripts

        # A command's module runs on every invocation, imported by `__init__` or not (S2).
        python_entries |= PythonScripts.targets(units)
        running = python_closure | python_entries | Hooks.hook_import_closure(units, python_entries)
        readings: list[FileUnit] = []
        for unit in list(units):
            if unit.content.is_binary or not UnparsedSource.runs_as_source(unit.path, running):
                continue
            decision = UnparsedSource.decide(unit.content.text)
            if decision.kind == "gap":
                acc.incomplete(UnparsedSource.gap(unit.path))
            elif decision.kind == "broken":
                acc.append(UnparsedSource.broken(unit.path))
            elif decision.reading is not None:
                where = ContainerPaths.reading(unit.path, "python")
                raw = decision.reading.encode("utf-8")
                content = FileContent.from_bytes(where, raw, self.config.limits)
                readings.append(FileUnit(content=content, language="python", project=unit.project))
        if not readings:
            return ctx
        units.extend(readings)
        return replace(ctx, tree_paths=ctx.tree_paths | {r.path for r in readings})

    @staticmethod
    def import_context(units: list[FileUnit], ctx: ScanContext, distribution: str) -> ScanContext:
        """What runs when a consumer imports a published Python package: every importable module and
        what it imports, and the bodies importing never runs (`LoadReach`, reviews/pypi-98/10)."""
        from cordon_scanner.analysis.python.reachability import LoadReach

        modules = PackageEntries.importable_modules(units, distribution)
        if not modules:
            return ctx
        closure = set(modules) | Hooks.hook_import_closure(units, set(modules))
        sources = {
            unit.path: unit.content.text
            for unit in units
            if unit.path in closure and unit.path.endswith(".py") and not unit.content.is_binary
        }
        return replace(
            ctx,
            import_closure_paths=frozenset(closure),
            import_deferred_lines=LoadReach.deferred_lines(sorted(sources), sources),
        )

    def parallel(
        self, units: list[FileUnit], deadline: float, acc: Accumulator, path: Path, ctx: ScanContext
    ) -> list[Detector]:
        """Every member, read by the detectors in supervised workers (item 28)."""
        detectors = [d for d in self.detectors if self.engine.detection.enabled(d, ctx)]
        self.progress.phase("scanning", total=len(units))
        # An image or a large archive is thousands of members (a Grafana image adds eleven
        # thousand files): across the worker pool, as a directory is, with each member's bytes
        # carried since it has no path on disk. In slices, so the scan's deadline is still checked.
        content_detectors = [
            d for d in detectors if not (d.requires.dependencies and d.requires.content is False)
        ]
        # Always in supervised workers, one as readily as many (item 28): a member that kills or
        # hangs its worker costs that member; this process never inspects one.
        from cordon_scanner.engine.cache import CacheSignature

        signature = CacheSignature.scan_signature(content_detectors, ctx, self.config)
        for start in range(0, len(units), ARCHIVE_SLICE):
            if self.config.limits.total_timeout > 0 and time.monotonic() > deadline:
                acc.incomplete(
                    OperationalFinding.build(
                        path=path.name,
                        rule_id="OPERATIONAL.SCAN.TIMEOUT",
                        message=f"The {self.config.limits.total_timeout:.0f}s budget was reached with members still unexamined.",
                        remediation="Raise --timeout, or unpack and scan as a directory.",
                        severity=Severity.MEDIUM,
                    )
                )
                # Every member of the slices never started, by path (item 38's review, change 2).
                acc.ledger_unstarted.update(unit.path for unit in units[start:])
                break
            found = self.engine.detection.parallel(
                units[start : start + ARCHIVE_SLICE],
                path.parent,
                ctx,
                acc,
                content_detectors,
                signature,
                carry_content=True,
                where=path.name,
            )
            acc.add(found)
            if any(f.rule_id == "OPERATIONAL.SCAN.TIMEOUT" for f in found):
                acc.ledger_unstarted.update(unit.path for unit in units[start + ARCHIVE_SLICE :])
                break  # the pool stopped at the budget and said so; no slice after it
        return detectors

    def release_checks(self, acc: Accumulator, ctx: ScanContext, units: list[FileUnit]) -> None:
        """The checks on the release as a whole, after every member was read in the workers. There
        is no per-member pass here: this process never inspects a member (item 28; item 55 deleted
        the loop that was left for one, which no member reached)."""
        if acc.out_of_time(ctx, REPOSITORY_SCOPE, "the release checks"):
            return
        acc.add(ReleaseChecks.unexamined_install_code(acc.findings, ctx))
        acc.add(ReleaseChecks.native_code_in_a_pure_wheel(units, ctx))
        acc.add(ReleaseChecks.known_malicious_release(units, ctx))
        acc.add(ReleaseChecks.known_vulnerable_release(units, ctx))
        acc.add(ReleaseChecks.placeholder_release(units, ctx))
        acc.add(ReleaseChecks.borrowed_server_name(units, ctx))

    def deferred(
        self,
        units: list[FileUnit],
        acc: Accumulator,
        path: Path,
        detectors: list[Detector],
        ctx: ScanContext,
    ) -> None:
        """A rule file reading the scanner's facts, matched over the members now that they exist,
        before every step after detection (`engine/pipeline/facts`)."""
        from cordon_scanner.engine.pipeline.facts import CrossFileFlows, ScanFactsGathering

        if acc.out_of_time(ctx, REPOSITORY_SCOPE, "the cross-file flows"):
            return
        content = [
            d for d in detectors if not (d.requires.dependencies and d.requires.content is False)
        ]
        CrossFileFlows.regrade(
            self.engine, content, units, acc, path.parent, ctx, carry_content=True, where=path.name
        )
        if acc.out_of_time(ctx, REPOSITORY_SCOPE, "the rule file's deferred pass"):
            return
        ScanFactsGathering.deferred(
            self.engine, content, units, acc, path.parent, ctx, carry_content=True, where=path.name
        )

    def dependencies(
        self, units: list[FileUnit], acc: Accumulator, image: Any, ctx: ScanContext
    ) -> tuple[tuple[Dependency, ...], str, ScanContext]:
        """The archive's dependency graph, and what kind of thing it is: an image, a package or an archive."""
        # A published archive carries its own manifests and lockfiles, and
        # "is this tarball a known-malicious release?" is the question most
        # people open one to ask. Building the graph from the members is what
        # lets the advisory, licence and dependency detectors answer it --
        # without it they had no `GraphUnit` to inspect, so scanning a package
        # archive silently skipped every check about its dependencies.
        self.progress.phase("dependencies")
        package = PackageFormat.of(units)
        # A published package's inventory is its root manifest and lockfile (`DependencyScope`):
        # built in the context worker with the rest of what the archive's manifests say (item 56
        # (b)), and applied here, where it was built before, so its findings keep their place.
        dependencies = self.engine.context_stage.archive_dependencies(acc)
        self._hold_not_installed_files(acc, dependencies, ctx)
        if image is not None:
            Images.report_image_contents(image, acc)
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
                Publisher.publisher_hygiene(
                    Publisher.publisher_secrets(
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
                ),
                reached=ctx.install_hook_paths | ctx.import_entry_paths,
            )
            acc.findings[:] = PackageFormat.union(acc.findings, repository)
            honoured = HONOURED_PINS.get(package)

            def demoted(d: Dependency) -> Dependency:
                if (
                    not both
                    and d.scope in (Scope.RUNTIME, Scope.UNKNOWN)
                    and not (honoured and honoured.search(d.declared_in or ""))
                ):
                    return replace(d, scope=Scope.DEV)
                return d

            dependencies = tuple(demoted(d) for d in dependencies)
            # The records outside the install set as well, so each keeps the scope it always had.
            acc.not_installed[:] = [demoted(d) for d in acc.not_installed]
        elif image is None:
            # A source tree read from an archive: graded as a repository (`_person_run_ceiling`).
            acc.findings[:] = Ceilings.person_run_ceiling(acc.findings, units, ctx)
            if History.history_distribution(units) == "openvsx":
                # An editor extension against its own established release (`intel/openvsx.py`).
                acc.findings[:] = History.established_release_ceiling(
                    acc.findings, units, "openvsx", hook_paths=ctx.install_hook_paths
                )
        return dependencies, target_kind, ctx

    def _hold_not_installed_files(
        self, acc: Accumulator, dependencies: tuple[Dependency, ...], ctx: ScanContext
    ) -> None:
        """A not-installed manifest's or lockfile's own findings about its records
        (`NotInstalledFiles`), out of the verdict and kept at their twins for after it."""
        if not acc.not_installed:
            return
        for name in ("manifest", "lockfile"):
            detector = next((d for d in self.detectors if d.id == name), None)
            split = getattr(detector, "not_installed_files", None)
            if callable(split):
                acc.findings[:], held = split(acc.findings, dependencies, acc.not_installed, ctx)
                acc.not_installed_findings.extend(held)

    def not_installed(self, acc: Accumulator, ctx: ScanContext) -> None:
        """What only a file outside the install set records (`acc.not_installed`), from the
        detectors whose finding is about the record itself -- a known advisory (`advisory`), a
        source outside the registry or a lookalike name (`dependency`), a hallucinated name
        (`slopsquat`) -- and a not-installed manifest's own (`acc.not_installed_findings`), added
        once the verdict is reached: at their own info and high rules, they never feed the verdict,
        are never graded by it or by the package's ceilings, and never gate."""
        acc.add(acc.not_installed_findings)
        if not acc.not_installed:
            return
        for name in ("advisory", "dependency", "slopsquat"):
            detector = next((d for d in self.detectors if d.id == name), None)
            # Switched on by the configuration, whatever the install set holds: the detectors'
            # own `applicable` asks about installed dependencies, which a package may have none of.
            if detector is None or not self.config.detector_enabled(detector.id):
                continue
            # Through the registry's detector, as the engine reaches every adapter.
            report = getattr(detector, "not_installed", None)
            if callable(report):
                acc.add(report(acc.not_installed, ctx))

    def verdict(
        self,
        acc: Accumulator,
        ctx: ScanContext,
        image: Any,
        units: list[FileUnit],
        dependencies: tuple[Dependency, ...],
    ) -> tuple[tuple[Dependency, ...], dict[str, Any]]:
        """The ceilings that need every finding, the image's and the graph's, and the package verdict."""
        acc.findings[:] = Ceilings.graded_by_what_it_does(acc.findings, ctx)
        if image is not None:
            acc.findings[:] = Ceilings.image_start_ceiling(acc.findings, units)
            ctx = replace(ctx, image=image)
            installed = Images.image_dependencies(image)
            present = {(d.ecosystem, d.name.lower(), d.version) for d in installed}
            # An image's inventory is what is installed in it. A lockfile or manifest inside it
            # names what the application was built from, development packages and ranges
            # included; an entry counts only where the same package is installed.
            dependencies = (
                *(d for d in dependencies if (d.ecosystem, d.name.lower(), d.version) in present),
                *installed,
            )
        if dependencies and not acc.out_of_time(
            ctx, REPOSITORY_SCOPE, "the dependency graph's checks"
        ):
            ctx = replace(ctx, dependencies=Graph.packages(dependencies))
            graph_unit = GraphUnit(dependencies=Graph.packages(dependencies))
            for detector in self.detectors:
                if not detector.requires.dependencies:
                    continue
                if not self.engine.detection.enabled(detector, ctx):
                    continue
                acc.add(self.engine.detection.run(detector, graph_unit, ctx, acc))

        from cordon_scanner.engine.pipeline.facts import ScanFactsGathering

        # The operator's suppressions and the folds, as a directory scan applies them (they were
        # missing here, so a package was graded differently packed and unpacked); the
        # suppressions are the operator's config, never anything read from inside the archive.
        from cordon_scanner.engine.pipeline.results import ResultFolding

        acc.findings[:], code_model = CodeModelPass.decide(self.engine, acc.findings, ctx)
        acc.findings[:] = ResultFolding.settled(self.config, acc)
        # The package's JSON these read is the context worker's (item 56 (b)), never decoded here.
        with ServedJson.serving(REPOSITORY_SCOPE):
            acc.findings[:], verdict = Ceilings.verdict(
                Ceilings.hardening_tier(
                    Hooks.onto_manifest(Publisher.test_identity_keys(acc.findings, units), units),
                    self.config.policy,
                ),
                units,
                ScanFactsGathering.verdict_facts(self.engine, units, ctx, acc),
                self.engine._intent_observation(units, ctx, acc.facts),
                repository=not ctx.package_distribution,
                facts=acc.facts,
            )
        acc.findings.extend(code_model)
        dependencies = self.engine.detection.annotated(dependencies, acc.findings, ctx, units)
        return dependencies, verdict


__all__ = ["ArchiveStages"]
