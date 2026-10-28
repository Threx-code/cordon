"""The scan's dependency graph: every lockfile parsed (with the files beside it where the ecosystem
keeps part of the record apart), fragments of one project joined, companion facts applied,
workspace members found, manifests read where no lockfile resolved them, scopes propagated, one
record kept per project and package, and registry facts added unless offline. Also what an SBOM
named as the target lists, and what a container image's package databases install.

A parser that raises is contained: its file's dependencies are missing, and the scan says so.
"""

from __future__ import annotations

import io
import posixpath
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from cordon_scanner.detect.base import (
    FileUnit,
    ScanContext,
)
from cordon_scanner.ecosystems.base import Coordinate, LockEntry, LockGraph
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.engine.pipeline.accumulator import Accumulator
from cordon_scanner.engine.pipeline.constants import REPOSITORY_SCOPE
from cordon_scanner.engine.pipeline.graph import Graph
from cordon_scanner.foundation.models import Category, Confidence, Finding, Severity
from cordon_scanner.foundation.results import Dependency, OperationalFinding

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.ecosystems.base import Ecosystem
    from cordon_scanner.engine.engine import Engine
    from cordon_scanner.images.identity import ImageInventory


class Dependencies:
    """Builds the scan's dependency graph."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.config = engine.config

    def image_inventory(self, data: bytes, acc: Accumulator) -> Any:
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
        self.offline_image(inventory, synced, acc)
        return inventory

    def offline_image(self, inventory: ImageInventory, synced: bool, acc: Accumulator) -> None:
        """Image packages read offline without a synced database: the advisory check is incomplete."""
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

    def sbom(self, units: list[FileUnit], acc: Accumulator) -> tuple[Dependency, ...]:
        """The components of a CycloneDX or SPDX document, validated and attributed to it."""
        from cordon_scanner.engine.sbom_ingest import SbomDocument, SbomInventory

        out: list[Dependency] = []
        self.engine._sbom_listed = []
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
                        self.engine._sbom_listed.append(
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

    def sbom_listed_findings(self, findings: Sequence[Finding], ctx: ScanContext) -> list[Finding]:
        """What an ingested SBOM itself lists as affecting its components, where the scan's own
        advisory matching did not already say so. A listed vulnerability the document rules out
        is not applied: a scan target cannot vouch for its own vulnerabilities (`--vex` can)."""
        from cordon_scanner.decide.vex import RULED_OUT, VexDocuments

        if not self.engine._sbom_listed:
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
        for path, listed, purl, name, version, tool in self.engine._sbom_listed:
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

    def build(self, units: list[FileUnit], acc: Accumulator) -> tuple[Dependency, ...]:
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
            if "!" in unit.path and not self.engine._scanning_archive:
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
            # Contained. `Detection.run` exists so that "a detector that raises
            # must not abort the scan", and this call site and the manifest one
            # below bypassed it and called an ecosystem parser straight from
            # `scan()`. `inventory` wraps the identical call, so the
            # inconsistency sat within one file: a parser raising on a crafted
            # lockfile terminated the whole scan with exit 2, which reads as
            # "the scanner broke" and gets a pipeline to skip the step.
            try:
                graph, tree = Dependencies.parse_lockfile(ecosystem, tree, units, unit)
            except Exception as exc:  # noqa: BLE001
                Dependencies.parser_failed(acc, unit, ecosystem_id, exc)
                continue
            if graph.parse_error or not graph.entries:
                continue
            project = Dependencies.lockfile_project(unit, graph)
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
            Dependencies.lockfile_members(
                graph, project, workspace_members, ecosystem_id, collected, ecosystem, unit
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

        Dependencies.join_fragments(fragments, collected)

        collected = self.complete(collected, companions, completing, units, workspace_members, acc)

        resolved = self.deduplicate(collected)
        return tuple(sorted(resolved, key=lambda d: (d.purl, d.project or "")))

    @staticmethod
    def lockfile_project(unit: FileUnit, graph: Any) -> str:
        """The project a lockfile belongs to: its directory, raised by the levels the lockfile says it sits below its owner."""
        project = unit.path.rpartition("/")[0]
        # `.mvn/checksums/`, `gradle/verification-metadata.xml`, `gradle/dependency-locks/`:
        # files that belong to the project directories above them.
        for _ in range(max(0, min(graph.owner_levels, 8))):
            project = project.rpartition("/")[0]
        return project

    @staticmethod
    def parse_lockfile(
        ecosystem: Ecosystem, tree: dict[str, Any] | None, units: list[FileUnit], unit: FileUnit
    ) -> tuple[Any, dict[str, Any] | None]:
        """A lockfile parsed, with the files beside it where the ecosystem keeps part of the record
        apart; the map of those files is built once and handed back for the next lockfile."""
        # A lockfile read with the files beside it, where the ecosystem keeps part of the
        # record apart (an Ansible collection's signatures, in its `.info/GALAXY.yml`).
        in_tree = getattr(ecosystem, "parse_lockfile_in_tree", None)
        if in_tree is not None:
            if tree is None:
                tree = {u.path: u.content for u in units}
            graph = in_tree(unit.content, tree)
        else:
            graph = ecosystem.parse_lockfile(unit.content)
        return graph, tree

    @staticmethod
    def parser_failed(acc: Accumulator, unit: FileUnit, ecosystem_id: str, exc: Exception) -> None:
        """A lockfile parser that raised: the file's dependencies are missing, and the scan says so."""
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

    def complete(
        self,
        collected: list[Dependency],
        companions: list[tuple[str | None, str, Any, LockGraph]],
        completing: set[tuple[str | None, str, str]],
        units: list[FileUnit],
        workspace_members: dict[tuple[str, str], str | None],
        acc: Accumulator,
    ) -> list[Dependency]:
        """Companion facts applied, workspace members found, manifests joined where no lockfile resolved, scopes propagated."""
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
            Graph.apply_companions(self.declared(units, acc, covered=covered), companions)
        )
        return collected

    def deduplicate(self, collected: list[Dependency]) -> list[Dependency]:
        """One record per project and package URL, the shallowest kept, with registry facts unless offline."""
        # Deduplicated by project and package URL, and sorted, so the graph is deterministic
        # regardless of the order lockfiles were encountered in. Per project: two services in
        # one repository that each require the same module each depend on it, and each needs
        # its own fix -- one record for both left the second service's use out of the inventory.
        # Within a project, one record however many times the lockfile lists it.
        from cordon_scanner.ecosystems.registry import LockScopes

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
        return resolved

    @staticmethod
    def lockfile_members(
        graph: Any,
        project: str,
        workspace_members: dict[tuple[str, str], str | None],
        ecosystem_id: str,
        collected: list[Dependency],
        ecosystem: Ecosystem,
        unit: FileUnit,
    ) -> None:
        """One lockfile's workspace members recorded, and its dependencies taken into the graph."""
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

    @staticmethod
    def join_fragments(
        fragments: dict[tuple[str, str], tuple[Any, list[tuple[LockEntry, str]]]],
        collected: list[Dependency],
    ) -> None:
        """Lockfile fragments of one project and ecosystem, joined into one graph and read as one."""
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

    def declared(
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
            Dependencies.included_declarations(
                manifest, unit, by_path, ecosystem, declarations, pins
            )

            Dependencies.declare(
                declarations, ecosystem_id, ecosystem, pins, manifest, collected, project, members
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
    def included_declarations(
        manifest: Any,
        unit: FileUnit,
        by_path: dict[str, FileUnit],
        ecosystem: Ecosystem,
        declarations: list[tuple[str, Any]],
        pins: dict[str, tuple[str, str]],
    ) -> None:
        """What a manifest includes: further requirements files declare, constraints files pin."""
        for kind, path, included in Graph.included(manifest, unit.path, by_path, ecosystem):
            if kind == "requirements" and EcosystemRegistry.manifest_ecosystem(path) is None:
                declarations.extend((path, d) for d in included.dependencies)
            elif kind == "constraints":
                for constraint in included.dependencies:
                    pin = Graph.exact_pin(constraint.spec)
                    if pin:
                        pins.setdefault(ecosystem.normalize_name(constraint.name), (pin, path))

    @staticmethod
    def declare(
        declarations: list[tuple[str, Any]],
        ecosystem_id: str,
        ecosystem: Ecosystem,
        pins: dict[str, tuple[str, str]],
        manifest: Any,
        collected: list[Dependency],
        project: str | None,
        members: frozenset[tuple[str, str]],
    ) -> None:
        """Each declaration of one manifest as a dependency: its name normalised, its pin, its constraint and its source."""
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
                    resolved_by=f"the constraints file {constrained[1]}" if constrained else None,
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


__all__ = ["Dependencies"]
