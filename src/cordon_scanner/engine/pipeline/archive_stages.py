"""The steps of scanning an archive without writing any of it to disk: an image's layers or an
archive's members as one stream, every member read into a unit or reported as refused, what runs
at install and import among them, the detectors over the members (in parallel when worth it), the
checks on the release as a whole, the dependency graph and what the archive is, and the verdict.
"""

from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon_scanner.analysis.shared.languages import LanguageRegistry
from cordon_scanner.detect.base import (
    FileUnit,
    GraphUnit,
    ScanContext,
)
from cordon_scanner.detect.registry import ComposerPluginHooks, ServerSources
from cordon_scanner.engine.entries import PackageEntries
from cordon_scanner.engine.package_format import PackageFormat
from cordon_scanner.engine.parallel import ParallelScanner
from cordon_scanner.engine.pipeline.accumulator import Accumulator
from cordon_scanner.engine.pipeline.archives import ArchiveMembers
from cordon_scanner.engine.pipeline.ceilings import Ceilings
from cordon_scanner.engine.pipeline.constants import (
    ARCHIVE_SLICE,
    HONOURED_PINS,
)
from cordon_scanner.engine.pipeline.facts import TreeFacts
from cordon_scanner.engine.pipeline.graph import Graph
from cordon_scanner.engine.pipeline.history import History
from cordon_scanner.engine.pipeline.hooks import Hooks
from cordon_scanner.engine.pipeline.images import Images
from cordon_scanner.engine.pipeline.publisher import Publisher
from cordon_scanner.engine.pipeline.releases import ReleaseChecks
from cordon_scanner.engine.window_pass import WindowPass
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.errors import ArchiveError
from cordon_scanner.foundation.models import Finding, Scope, Severity
from cordon_scanner.foundation.results import Dependency, OperationalFinding
from cordon_scanner.intel.registry import ReleaseHistory
from cordon_scanner.sources.base import Rejection
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
    ) -> None:
        """Every member the archive reader gives, as a unit, and every one it refused, as a finding."""
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

        ArchiveStages.refused(rejected, acc, image)

    @staticmethod
    def refused(rejected: list[tuple[str, str, str]], acc: Accumulator, image: Any) -> None:
        """Each member the archive reader refused, as a finding."""
        for member_path, reason, detail in rejected:
            # A link has no content of its own: refusing it leaves nothing unread.
            acc.complete = acc.complete and reason == Rejection.LINK
            acc.append(
                ArchiveMembers.rejected(member_path, reason, detail, image=image is not None)
            )

    def context(
        self, units: list[FileUnit], acc: Accumulator, ctx: ScanContext, image: Any
    ) -> ScanContext:
        """What runs at install, at import and when an agent calls it, among the archive's members."""
        # Manifests inside a package determine whether its code runs at install
        # time, which is the whole reason a package archive is worth scanning.
        units.extend(self.engine.units.inline_hooks(units))
        units.extend(self.engine.units.deobfuscated(units))
        hook_paths, consumer_hooks, ci_scripts = Hooks.manifest_hook_paths(units, acc)
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
        skill_scripts = TreeFacts.skill_scripts(units)
        agent_run = skill_scripts | ServerSources.of(units)
        agent_tools = self.engine._agent_tool_paths(units, agent_run, hook_paths)
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
            import_entry_paths=PackageEntries.of(units, early_format),
            library_entry_paths=PackageEntries.of(units, early_format, with_bin=False),
            library_closure_paths=frozenset(
                Hooks.hook_js_closure(
                    units, set(PackageEntries.of(units, early_format, with_bin=False))
                )
            ),
            declared_dependencies=ReleaseHistory.declared_dependencies(units, early_format),
            package_repository=PackageEntries.repository(units, early_format),
        )
        return Hooks.lifted_inherit(ctx)

    def parallel(
        self, units: list[FileUnit], deadline: float, acc: Accumulator, path: Path, ctx: ScanContext
    ) -> tuple[list[Detector], list[FileUnit]]:
        """The members detectors read in parallel, when the archive is large enough to be worth it."""
        detectors = [d for d in self.detectors if self.engine.detection.enabled(d, ctx)]
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

            signature = ScanCache.scan_signature(content_detectors, ctx, self.config)
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
                    break  # the pool stopped at the budget and said so; no slice after it
            units_left: list[FileUnit] = []
        else:
            units_left = units
        return detectors, units_left

    def serial(
        self,
        units_left: list[FileUnit],
        deadline: float,
        acc: Accumulator,
        path: Path,
        detectors: list[Detector],
        ctx: ScanContext,
        units: list[FileUnit],
    ) -> None:
        """The members left for this process, then the checks on the release as a whole."""
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
                produced.extend(self.engine.detection.run(detector, unit, ctx, acc))
            # The rest of an oversized member, a window at a time, as `_inspect_file` reads one.
            windowed, intact = WindowPass.run(
                unit,
                member_detectors,
                lambda detector, part: self.engine.detection.run(detector, part, ctx, acc),
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
        # A published package's inventory is its root manifest and lockfile (`DependencyScope`).
        published = package if image is None else ""
        dependencies = self.engine.dependencies.build(units, acc, published=published)
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
        return dependencies, target_kind, ctx

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
        if dependencies:
            ctx = replace(ctx, dependencies=Graph.packages(dependencies))
            graph_unit = GraphUnit(dependencies=Graph.packages(dependencies))
            for detector in self.detectors:
                if not detector.requires.dependencies:
                    continue
                if not self.engine.detection.enabled(detector, ctx):
                    continue
                acc.add(self.engine.detection.run(detector, graph_unit, ctx, acc))

        labels: dict[str, Any] = {}
        acc.findings[:], verdict = Ceilings.verdict(
            Ceilings.hardening_tier(
                Hooks.onto_manifest(Publisher.test_identity_keys(acc.findings, units), units),
                self.config.policy,
            ),
            units,
            {
                **self.engine._capability_profile(units, ctx, labels),
                **History.registry_facts(units),
            },
            self.engine._intent_observation(units, ctx, labels),
        )
        dependencies = self.engine.detection.annotated(dependencies, acc.findings, ctx, units)
        return dependencies, verdict


__all__ = ["ArchiveStages"]
