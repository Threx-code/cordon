"""Joining what manifests declare with what lockfiles resolve into one dependency graph: workspace
members and their manifests, lock references, overrides, configured sources, included files,
companions a lockfile implies, scopes propagated down the graph, Maven ranges resolved, and the
dependency files the scan could not read.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import replace
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.detect.base import FileUnit
from cordon_scanner.ecosystems.base import WORKSPACE_INHERITED, Coordinate, LockEntry, LockGraph
from cordon_scanner.ecosystems.registry import EcosystemRegistry, RegistryFacts
from cordon_scanner.engine.pipeline.accumulator import Accumulator
from cordon_scanner.foundation.models import Scope, Severity
from cordon_scanner.foundation.results import Dependency, OperationalFinding

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cordon_scanner.ecosystems.base import DeclaredDependency
    from cordon_scanner.engine.pipeline.dependency_scope import DependencyScope
    from cordon_scanner.foundation.content import FileContent


class Graph:
    """Joins manifests and lockfiles into one dependency graph."""

    #: Dependency files in a format no parser here reads, and what to supply instead. Reported,
    #: never skipped silently: a project whose only lockfile is one of these was not resolved.
    UNREAD_DEPENDENCY_FILES: ClassVar[dict[str, tuple[str, str]]] = {}
    """Empty since the bun.lockb reader (review 98, note 28): every dependency file the contract
    names has a parser. The table and its report stay for the next format without one."""

    @staticmethod
    def unread_dependency_files(
        units: list[FileUnit], acc: Accumulator, scope: DependencyScope | None = None
    ) -> None:
        present = {u.path for u in units}
        for unit in units:
            if scope is not None and not scope.reads(unit.path):
                continue
            name = unit.path.rpartition("/")[2]
            known = Graph.UNREAD_DEPENDENCY_FILES.get(name)
            if known is None:
                continue
            directory = unit.path.rpartition("/")[0]
            replacement, why = known
            if (f"{directory}/{replacement}" if directory else replacement) in present:
                continue  # the readable lockfile is beside it and is what was read
            acc.complete = False
            acc.append(
                OperationalFinding.build(
                    path=unit.path,
                    rule_id="OPERATIONAL.LOCKFILE.UNSUPPORTED",
                    message=(
                        f"{name} was not read: {why} The dependencies it resolves are not in "
                        f"the graph from this file."
                    ),
                    remediation=f"Commit `{replacement}` beside it.",
                    severity=Severity.MEDIUM,
                )
            )

    @staticmethod
    def companion_completions(
        collected: list[Dependency],
        companions: list[tuple[str | None, str, Any, LockGraph]],
        completing: set[tuple[str | None, str, str]],
    ) -> list[Dependency]:
        """The indirect modules a pre-1.17 `go.mod` leaves out, from the `go.sum` beside it: each
        module hashed and not already in the graph, at the highest version hashed (what minimal
        version selection settles on), marked indirect and declared in `go.sum`."""
        from cordon_scanner.intel.registry import Versions

        present = {(d.project, d.ecosystem, d.name) for d in collected}
        resolved = {(d.project, d.ecosystem) for d in collected}
        added: list[Dependency] = []
        for owner, ecosystem_id, ecosystem, graph in companions:
            # Go only: other ecosystems' companions (Maven checksums, Gradle verification
            # metadata) record hashes of what something else resolved, never a build of their own.
            if not RegistryFacts.completes_from_checksums(ecosystem_id) or graph.path.endswith(
                "modules.txt"
            ):
                continue
            # Completed where the resolving file leaves indirect modules out (a pre-1.17 go.mod),
            # and where there is no resolving file at all: a go.sum on its own is then the only
            # record of the build there is.
            if (
                not any(p == owner and e == ecosystem_id for p, e, _ in completing)
                and (owner, ecosystem_id) in resolved
            ):
                continue
            highest: dict[str, LockEntry] = {}
            for entry in graph.entries:
                if (owner, ecosystem_id, entry.name) in present or not entry.version:
                    continue
                best = highest.get(entry.name)
                if (
                    best is None
                    or Versions.compare(
                        ecosystem_id, entry.version.lstrip("v"), best.version.lstrip("v")
                    )
                    > 0
                ):
                    highest[entry.name] = entry
            if not highest:
                continue
            completion = LockGraph(
                path=graph.path,
                ecosystem=ecosystem_id,
                entries=tuple(replace(e, direct=False) for _, e in sorted(highest.items())),
            )
            added.extend(
                replace(d, direct=False, depth=max(d.depth, 2))
                for d in ecosystem.to_dependencies(completion, project=owner)
            )
        return added

    @staticmethod
    def apply_companions(
        collected: list[Dependency], companions: list[tuple[str | None, str, Any, LockGraph]]
    ) -> list[Dependency]:
        """Complete each resolved entry with what its companion files record about it: the hash
        `go.sum` holds for that exact module version, the vendored copy `vendor/modules.txt`
        lists. An entry a companion has and the resolution does not (a version `go.sum` still
        hashes but the build no longer selects) adds nothing: it is not in the build."""
        if not companions:
            return collected
        facts: dict[tuple[str | None, str, str, str], LockEntry] = {}
        projects = {d.project for d in collected}
        for owner, ecosystem_id, ecosystem, graph in companions:
            # A tree companion is applied to every project at or below its owner.
            covered = (
                [
                    p
                    for p in projects
                    if owner is None or p == owner or (p or "").startswith(f"{owner}/")
                ]
                if graph.companion_tree
                else [owner]
            )
            for project in covered:
                Graph._companion_facts(facts, project, ecosystem_id, ecosystem, graph)
        out: list[Dependency] = []
        for dependency in collected:
            ecosystem = EcosystemRegistry.get(dependency.ecosystem)
            name = ecosystem.normalize_name(dependency.name) if ecosystem else dependency.name
            fact = facts.get(
                (dependency.project, dependency.ecosystem, name, dependency.version or "")
            )
            if fact is None:
                out.append(dependency)
                continue
            out.append(
                replace(
                    dependency,
                    integrity=dependency.integrity or fact.integrity,
                    resolved_from=dependency.resolved_from
                    if dependency.resolved_from
                    and not (fact.resolved_from or "").startswith("vendored:")
                    else fact.resolved_from or dependency.resolved_from,
                )
            )
        return out

    @staticmethod
    def _companion_facts(
        facts: dict[tuple[str | None, str, str, str], LockEntry],
        project: str | None,
        ecosystem_id: str,
        ecosystem: Any,
        graph: LockGraph,
    ) -> None:
        for entry in graph.entries:
            key = (project, ecosystem_id, ecosystem.normalize_name(entry.name), entry.version)
            previous = facts.get(key)
            if previous is None:
                facts[key] = entry
            else:
                facts[key] = LockEntry(
                    name=entry.name,
                    version=entry.version,
                    integrity=previous.integrity or entry.integrity,
                    resolved_from=previous.resolved_from or entry.resolved_from,
                )

    @staticmethod
    def members_by_lock_reference(
        units: list[FileUnit],
        collected: list[Dependency],
        known: dict[tuple[str, str], str | None],
    ) -> dict[tuple[str, str], str | None]:
        """Manifests that name the lockfile resolving them (`lockfile: "../../mix.lock"` in an
        umbrella app): members of the project that lockfile belongs to, when it was read."""
        locked = {(d.project or "", d.ecosystem) for d in collected}
        contents = {u.path: u.content for u in units}
        out: dict[tuple[str, str], str | None] = {}
        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            ecosystem = EcosystemRegistry.get(ecosystem_id) if ecosystem_id else None
            if ecosystem is None or ecosystem_id is None:
                continue
            project = unit.path.rpartition("/")[0]
            if not project or (project, ecosystem_id) in known:
                continue
            try:
                manifest = Graph.manifest_of(ecosystem, unit, contents)
            except Exception:  # noqa: BLE001, S112
                continue
            owner = manifest.locked_by
            if owner is not None and (owner, ecosystem_id) in locked:
                out[(project, ecosystem_id)] = owner or None
        return out

    @staticmethod
    def members_by_name(
        units: list[FileUnit],
        collected: list[Dependency],
        known: dict[tuple[str, str], str | None],
    ) -> dict[tuple[str, str], str | None]:
        """Workspace members a lockfile does not list by directory (Yarn Classic, Cargo).

        A manifest below a lockfile's directory whose own package name is one of that lockfile's
        local entries is a member it resolves."""
        local: dict[tuple[str | None, str], set[str]] = {}
        for dependency in collected:
            if dependency.local:
                local.setdefault((dependency.project, dependency.ecosystem), set()).add(
                    dependency.name.lower()
                )
        if not local:
            return {}
        found: dict[tuple[str, str], str | None] = {}
        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            project = unit.path.rpartition("/")[0]
            if ecosystem_id is None or not project or (project, ecosystem_id) in known:
                continue
            for (lock_project, lock_ecosystem), names in local.items():
                if lock_ecosystem != ecosystem_id or lock_project == project:
                    continue
                if lock_project and not project.startswith(lock_project + "/"):
                    continue
                ecosystem = EcosystemRegistry.get(ecosystem_id)
                try:
                    manifest = ecosystem.parse_manifest(unit.content) if ecosystem else None
                except Exception:  # noqa: BLE001, S112
                    continue
                if manifest is not None and manifest.name and manifest.name.lower() in names:
                    found[(project, ecosystem_id)] = lock_project
                    break
        return found

    @staticmethod
    def configured_sources(units: list[FileUnit]) -> tuple[tuple[str, str, str], ...]:
        """Every package source the scanned manifests configure, credentials removed."""
        from cordon_scanner.foundation.dependencies import DependencySource

        found: list[tuple[str, str, str]] = []
        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            ecosystem = EcosystemRegistry.get(ecosystem_id) if ecosystem_id else None
            if ecosystem is None or ecosystem_id is None:
                continue
            try:
                manifest = ecosystem.parse_manifest(unit.content)
            except Exception:  # noqa: BLE001, S112
                continue
            for source in manifest.sources:
                # A URL inside the description loses its userinfo and query: a token in an
                # index URL is a credential, and the report is not where it goes.
                cleaned = re.sub(
                    r"(?<!\S)\S+://\S+",
                    lambda m: DependencySource.sanitise(m.group(0)) or "",
                    source,
                )
                found.append((unit.path, ecosystem_id, cleaned))
        return tuple(sorted(set(found)))

    @staticmethod
    def declared_inside(spec: str, manifest_path: str) -> bool:
        """Whether a declaration names a path inside the scanned repository (`path:../lib`,
        `file:packages/util`): the project's own code, not a package from anywhere."""
        if not spec.startswith(("path:", "file:", "link:", "./", "../", "workspace:")):
            return False
        from cordon_scanner.detect.registry import DeclaredSource

        return DeclaredSource.kind(spec, manifest_path) == "inside"

    @staticmethod
    def manifest_of(ecosystem: Any, unit: FileUnit, files: Mapping[str, Any]) -> Any:
        """A manifest parsed with the rest of its build in view, where the ecosystem needs it:
        a Maven module inherits from a parent POM elsewhere in the tree, a .NET project from
        `Directory.Packages.props` above it. Other ecosystems read one file on its own."""
        in_tree = getattr(ecosystem, "parse_in_tree", None)
        if in_tree is not None:
            return in_tree(unit.content, files)
        return ecosystem.parse_manifest(unit.content)

    MAX_INCLUDE_DEPTH: ClassVar[int] = 8

    @staticmethod
    def included(
        manifest: Any, path: str, by_path: dict[str, FileUnit], ecosystem: Any
    ) -> list[tuple[str, str, Any]]:
        """`(kind, path, manifest)` for each file a manifest includes, followed through nested
        includes, each file once, to `MAX_INCLUDE_DEPTH`. A path that leaves the scanned tree or
        is not in it is skipped (and was never going to be readable here)."""
        out: list[tuple[str, str, Any]] = []
        seen = {path}
        pending = [(kind, target, path, 0) for kind, target in getattr(manifest, "includes", ())]
        while pending:
            kind, target, origin, depth = pending.pop(0)
            directory = origin.rpartition("/")[0]
            resolved = posixpath.normpath(
                posixpath.join(directory, target) if directory else target
            )
            if resolved.startswith("..") or resolved in seen or resolved not in by_path:
                continue
            seen.add(resolved)
            parse = getattr(ecosystem, "parse_included", None)
            try:
                included = (
                    parse(by_path[resolved].content)
                    if parse
                    else ecosystem.parse_manifest(by_path[resolved].content)
                )
            except Exception:  # noqa: BLE001, S112
                continue
            out.append((kind, resolved, included))
            if depth + 1 < Graph.MAX_INCLUDE_DEPTH:
                # A constraints file's own `-r` lines are constraints too.
                pending.extend(
                    (kind if kind == "constraints" else nested_kind, nested, resolved, depth + 1)
                    for nested_kind, nested in getattr(included, "includes", ())
                )
        return out

    @staticmethod
    def packages(dependencies: tuple[Dependency, ...]) -> tuple[Dependency, ...]:
        """The dependencies a registry could serve: not the platform requirements.

        `requires-python = ">=3.10"`, Composer's `php` and `ext-json`, Cargo's `rust-version`, a
        Dart SDK constraint: each is in the inventory, and none is a package. `python` on PyPI
        and `php` on Packagist are unrelated distributions, and a typosquat, advisory or registry
        check against them would be a claim about the wrong thing."""
        return tuple(d for d in dependencies if d.scope is not Scope.PLATFORM)

    @staticmethod
    def _override_target(selector: str) -> tuple[str | None, str | None]:
        """`(package, version selector)` an override key applies to.

        `ms`, `ms@2.0.0` (npm, pnpm), `**/ms`, `debug/ms` (Yarn resolutions: the last segment),
        `debug>ms` (pnpm's parent selector) and `@scope/pkg@^1`."""
        text = selector.strip()
        for separator in (">",):
            text = text.rpartition(separator)[2] if separator in text else text
        if "/" in text and not text.startswith("@"):
            text = text.rpartition("/")[2]
        elif text.startswith("@") and text.count("/") > 1:
            text = "/".join(text.split("/")[-2:])
        at = text.find("@", 1 if text.startswith("@") else 0)
        if at > 0:
            return text[:at] or None, text[at + 1 :] or None
        return text or None, None

    @staticmethod
    def propagate_scopes(collected: list[Dependency]) -> list[Dependency]:
        """Carry each direct dependency's scope down to what only it brings in.

        Yarn, Bun and several other lockfiles record no scope: a package needed only by a test
        runner read as runtime. With the direct dependencies' scopes known from the manifest,
        a transitive one reached only through dev dependencies is dev, only through optional
        ones optional -- npm's own rule for its `dev` and `optional` flags."""
        from cordon_scanner.foundation.scopes import LockScopes

        groups: dict[tuple[str | None, str], list[Dependency]] = {}
        for dependency in collected:
            groups.setdefault((dependency.declared_in, dependency.ecosystem), []).append(dependency)
        out: list[Dependency] = []
        for members in groups.values():
            # The workspace's own packages are the project, not its dependencies: a Cargo member
            # lists its dev and build dependencies as edges too, and as a runtime root it made
            # every test-only crate runtime.
            roots: dict[str, set[Scope]] = {}
            for d in members:
                if d.direct and not d.local:
                    roots.setdefault(d.name, set()).add(d.scope)
            if not roots or all(d.direct for d in members):
                out.extend(members)
                continue
            edges: dict[str, set[str]] = {}
            for dependency in members:
                for parent in dependency.parents:
                    edges.setdefault(parent, set()).add(dependency.name)
            scopes = LockScopes.propagate(roots, edges)
            for dependency in members:
                found = scopes.get(dependency.name)
                if (
                    not dependency.direct
                    and dependency.scope is Scope.RUNTIME
                    and found is not None
                    and found is not Scope.RUNTIME
                ):
                    out.append(replace(dependency, scope=found))
                else:
                    out.append(dependency)
        return out

    MAX_RANGE_LOOKUPS: ClassVar[int] = 200

    @staticmethod
    def resolve_maven_ranges(dependencies: list[Dependency]) -> list[Dependency]:
        """A Maven or Gradle range (`[1.2,2.0)`) a pom declares with no lockfile to pin it,
        resolved online to the highest release Maven Central lists inside it -- what Maven itself
        picks -- so its advisories can be matched. Offline it stays unresolved, and says why."""
        from cordon_scanner.intel.registry import (
            MoreRegistries,
            RegistryError,
            VersionRanges,
            Versions,
        )

        listed: dict[str, list[str]] = {}
        out: list[Dependency] = []
        for dependency in dependencies:
            spec = (dependency.declared_spec or "").strip()
            if (
                not RegistryFacts.bracket_ranges(dependency.ecosystem)
                or dependency.version
                or spec[:1] not in ("[", "(")
                or ":" not in dependency.name
            ):
                out.append(dependency)
                continue
            if dependency.name not in listed and len(listed) < Graph.MAX_RANGE_LOOKUPS:
                try:
                    listed[dependency.name] = MoreRegistries.versions("maven", dependency.name)
                except (RegistryError, OSError, ValueError):
                    listed[dependency.name] = []
            admitted = [
                v for v in listed.get(dependency.name, []) if VersionRanges.admits("maven", spec, v)
            ]
            if not admitted:
                out.append(dependency)
                continue
            best = admitted[0]
            for candidate in admitted[1:]:
                if Versions.compare("maven", candidate, best) > 0:
                    best = candidate
            base, sep, query = dependency.purl.partition("?")
            out.append(
                replace(
                    dependency,
                    version=best,
                    purl=f"{base}@{best}" + (f"?{query}" if sep else ""),
                    resolution_note=f"the range {spec} resolved online to {best}, the highest release Maven Central lists inside it",
                )
            )
        return out

    @staticmethod
    def join_manifests(
        units: list[FileUnit],
        collected: list[Dependency],
        covered: set[tuple[str | None, str]],
        members: dict[tuple[str, str], str | None] | None = None,
    ) -> list[Dependency]:
        """Give each locked direct dependency the manifest entry that declared it.

        A lockfile says what resolved; the manifest beside it says what was asked for -- the
        constraint, the platform conditions, the line a reviewer edits. The record carries both
        (`version_constraint` beside `resolved_version`, `manifest_location` beside
        `lockfile_location`), so a pin that has drifted from its declared range is visible.
        """
        declared: dict[tuple[str | None, str, str], tuple[str, DeclaredDependency]] = {}
        declared_from_lock: dict[tuple[str | None, str, str], bool] = {}
        shared: dict[tuple[str | None, str, str], str] = {}
        forced: dict[tuple[str | None, str, str], tuple[str, str, str | None]] = {}
        routed: dict[tuple[str | None, str], dict[str, str]] = {}
        contents = {u.path: u.content for u in units}
        Graph.manifest_declarations(
            units, covered, members, contents, shared, routed, declared, declared_from_lock, forced
        )
        if not declared and not forced:
            return collected
        joined: list[Dependency] = []
        matched: set[tuple[str | None, str, str]] = set()
        present: set[tuple[str | None, str, str]] = set()
        Graph.declared_onto_locked(collected, declared, present, forced, matched, joined, shared)
        Graph.unlocked_declarations(declared, matched, present, units, joined)
        joined = Graph.routed_sources(routed, joined)
        return [
            d
            for d in joined
            if not (
                d.local
                and not d.parents
                and d.manifest_path is None
                and d.ecosystem not in Graph.LOCKS_WITHOUT_ROOTS
            )
        ]

    @staticmethod
    def manifest_declarations(
        units: list[FileUnit],
        covered: set[tuple[str | None, str]],
        members: dict[tuple[str, str], str | None] | None,
        contents: dict[str, FileContent],
        shared: dict[tuple[str | None, str, str], str],
        routed: dict[tuple[str | None, str], dict[str, str]],
        declared: dict[tuple[str | None, str, str], tuple[str, DeclaredDependency]],
        declared_from_lock: dict[tuple[str | None, str, str], bool],
        forced: dict[tuple[str | None, str, str], tuple[str, str, str | None]],
    ) -> None:
        """Every manifest's declarations, keyed by project, ecosystem and name, with what forces or routes them."""
        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            if ecosystem_id is None:
                continue
            project = unit.path.rpartition("/")[0] or None
            if (project, ecosystem_id) not in covered:
                continue
            if members and project is not None and (project, ecosystem_id) in members:
                project = members[(project, ecosystem_id)]
            ecosystem = EcosystemRegistry.get(ecosystem_id)
            if ecosystem is None:
                continue
            try:
                manifest = Graph.manifest_of(ecosystem, unit, contents)
            except Exception:  # noqa: BLE001, S112
                continue
            for shared_name, shared_spec in manifest.shared_specs.items():
                shared.setdefault(
                    (project, ecosystem_id, ecosystem.normalize_name(shared_name)), shared_spec
                )
            if manifest.source_patterns:
                routed.setdefault((project, ecosystem_id), {}).update(manifest.source_patterns)
            # A file that is also a lockfile (a pinned `requirements.txt`) is the manifest of last
            # resort: where `requirements.in` names the same package, that is what was asked for.
            is_lock = EcosystemRegistry.lockfile_ecosystem(unit.path) is not None
            for entry in manifest.dependencies:
                key = (
                    project,
                    entry.ecosystem or ecosystem_id,
                    ecosystem.normalize_name(entry.name),
                )
                if key not in declared or (not is_lock and declared_from_lock.get(key, False)):
                    declared[key] = (unit.path, entry)
                    declared_from_lock[key] = is_lock
            for selector, spec in manifest.overrides.items():
                target, selected = Graph._override_target(str(selector))
                if target:
                    forced.setdefault(
                        (project, ecosystem_id, ecosystem.normalize_name(target)),
                        (
                            f"{selector!s} = {spec!s} in {manifest.override_origin or unit.path}",
                            str(spec),
                            selected,
                        ),
                    )

    @staticmethod
    def declared_onto_locked(
        collected: list[Dependency],
        declared: dict[tuple[str | None, str, str], tuple[str, DeclaredDependency]],
        present: set[tuple[str | None, str, str]],
        forced: dict[tuple[str | None, str, str], tuple[str, str, str | None]],
        matched: set[tuple[str | None, str, str]],
        joined: list[Dependency],
        shared: dict[tuple[str | None, str, str], str],
    ) -> None:
        """Each locked dependency given the manifest entry that declared it, and marked direct."""
        # Lockfiles that say which entries are direct; for the rest (`Pipfile.lock`, `go.sum`),
        # the manifest beside them is the only record of what the project asked for.
        marked = {d.declared_in for d in collected if d.direct}
        manifested = {(k[0], k[1]) for k in declared}
        for dependency in collected:
            ecosystem = EcosystemRegistry.get(dependency.ecosystem)
            name = (
                ecosystem.normalize_name(dependency.name) if ecosystem else dependency.name.lower()
            )
            key = (dependency.project, dependency.ecosystem, name)
            present.add(key)
            override = forced.get(key)
            if override is not None and dependency.version and not dependency.forced_by:
                description, spec, selected = override
                # Forced when the override names this exact version, or applies to every
                # version and resolved to this one -- or is a range (mix's `override: true` on
                # `"~> 2.0"`), which governs whatever version the tree resolved under it.
                exact = Graph.exact_pin(spec, dependency.ecosystem)
                if spec.lstrip("=v") == dependency.version or (
                    selected is None
                    and (
                        exact == dependency.version
                        or (exact is None and not spec.startswith(("path:", "git")))
                    )
                ):
                    dependency = replace(dependency, forced_by=description)
            found = declared.get(key)
            if found is not None and not dependency.direct and dependency.depth > 0:
                # A second copy deeper in the tree (`debug`'s own `ms`) is not the one the
                # manifest declared; only the direct one is joined to the declaration.
                found = None
            if found is not None:
                matched.add(key)
            if found is None or dependency.manifest_path:
                if (
                    found is None
                    and dependency.declared_in not in marked
                    and (dependency.project, dependency.ecosystem) in manifested
                ):
                    # Not declared, in a lockfile that marks nothing: transitive.
                    dependency = replace(dependency, direct=False)
                joined.append(dependency)
                continue
            path, entry = found
            spec = entry.spec
            if spec == WORKSPACE_INHERITED:
                # `{ workspace = true }`: the constraint is the workspace root's.
                spec = shared.get(key, spec)
            joined.append(
                replace(
                    dependency,
                    manifest_path=path,
                    declared_spec=dependency.declared_spec or spec or None,
                    # Both are conditions on the same package: the manifest's marker (`win32`
                    # only) and the lockfile's own (`python >=3.7`).
                    platform=tuple(dict.fromkeys((*entry.platform, *dependency.platform))),
                    direct=True,
                    # What the project asked for decides a direct dependency's scope: a PDM
                    # lockfile cannot tell an optional extra from a dev group, the manifest can.
                    scope=entry.scope,
                    alias=dependency.alias or entry.alias,
                    extras=dependency.extras or entry.extras,
                    editable=dependency.editable or entry.editable,
                    signature_sources=dependency.signature_sources or entry.signature_sources,
                    exclusions=dependency.exclusions or entry.exclusions,
                    # Where the lockfile does not say where it came from (NuGet's does not), the
                    # source the project configures for it (package source mapping) does.
                    resolved_from=dependency.resolved_from or entry.source,
                )
            )

    @staticmethod
    def unlocked_declarations(
        declared: dict[tuple[str | None, str, str], tuple[str, DeclaredDependency]],
        matched: set[tuple[str | None, str, str]],
        present: set[tuple[str | None, str, str]],
        units: list[FileUnit],
        joined: list[Dependency],
    ) -> None:
        """Declared dependencies no lockfile resolved: added as declared, with what forced or shared them."""
        # Declared beside a lockfile that does not resolve it: the two have drifted, and what
        # installs is whatever the range resolves to on the day. Kept in the inventory, unresolved,
        # with the reason -- dropping it hid a dependency the project really asks for.
        defined: frozenset[tuple[str, str]] | None = None
        for key, (path, entry) in sorted(
            declared.items(), key=lambda item: (str(item[0]), item[1][0])
        ):
            # Resolved anywhere in the lockfile's graph is resolved: a pip-compile output is both
            # the lockfile and, by its name, a manifest, and every pin in it is "declared".
            if key in matched or key in present:
                continue
            project, ecosystem_id, name = key
            pinned = Graph.exact_pin(entry.spec, ecosystem_id)
            implementation = EcosystemRegistry.get(ecosystem_id)
            if defined is None:
                defined = Graph.workspace_members(units)
            purl_type = implementation.purl_type if implementation else ecosystem_id
            if Graph.declared_inside(entry.spec, path) or (ecosystem_id, name) in defined:
                # Another project of this build (Gradle's `project(":lib")`), or a module this
                # repository builds (an included build substituting `shared-util`): built from
                # its source here, which no lockfile lists because nothing is fetched for it.
                joined.append(
                    Dependency(
                        purl=f"pkg:{purl_type}/{name}",
                        ecosystem=ecosystem_id,
                        name=entry.name,
                        direct=True,
                        local=True,
                        scope=entry.scope,
                        declared_spec=entry.spec,
                        project=project,
                        declared_in=path,
                        manifest_path=path,
                        platform=entry.platform,
                    )
                )
                continue
            joined.append(
                Dependency(
                    purl=f"pkg:{purl_type}/{name}"
                    + (f"@{pinned}" if pinned else "")
                    + (implementation.qualifiers(entry.platform) if implementation else ""),
                    ecosystem=ecosystem_id,
                    name=entry.name,
                    version=pinned,
                    direct=True,
                    scope=entry.scope,
                    declared_spec=entry.spec,
                    project=project,
                    declared_in=path,
                    manifest_path=path,
                    resolved_from=entry.source,
                    platform=entry.platform,
                    alias=entry.alias,
                    extras=entry.extras,
                    editable=entry.editable,
                    exclusions=entry.exclusions,
                    # A value that is no digest is never echoed: recorded as `malformed:<hash>`.
                    integrity=Coordinate.integrity(entry.integrity),
                    signature_sources=entry.signature_sources,
                    resolution_note=entry.note
                    or "declared in the manifest but absent from the lockfile beside it",
                )
            )

    @staticmethod
    def routed_sources(
        routed: dict[tuple[str | None, str], dict[str, str]], joined: list[Dependency]
    ) -> list[Dependency]:
        """Dependencies a manifest routes to another source, given that source."""
        # A local entry that no manifest declares and nothing in its lockfile depends on is a
        # root of the workspace -- the project itself (a Cargo workspace's own crate, an
        # independent monorepo member) -- not one of its dependencies. A member another member
        # depends on, or that a manifest names, is a path dependency and stays.
        if routed:
            joined = [
                replace(
                    d, resolved_from=Graph.routed_source(d.name, routed[(d.project, d.ecosystem)])
                )
                if not d.resolved_from
                and not d.local
                and (d.project, d.ecosystem) in routed
                and Graph.routed_source(d.name, routed[(d.project, d.ecosystem)])
                else d
                for d in joined
            ]
        return joined

    #: Lockfiles that never list the project itself, so a local entry in one is always a
    #: dependency: Podfile.lock lists the pods installed, never the app. Flutter's Podfile adds
    #: `FlutterMacOS` through a helper (`flutter_install_all_macos_pods`) rather than a `pod` line,
    #: and the rule above took the pod for the project and dropped it.
    LOCKS_WITHOUT_ROOTS: ClassVar[frozenset[str]] = frozenset({"cocoapods"})

    @staticmethod
    def routed_source(name: str, patterns: Mapping[str, str]) -> str | None:
        """The source a pattern routes `name` to: the longest matching pattern, `Prefix.*` or an
        exact name, as NuGet's package source mapping matches."""
        lowered = name.lower()
        best: tuple[int, str] | None = None
        for pattern, source in patterns.items():
            text = pattern.lower()
            matched = lowered == text or (text.endswith("*") and lowered.startswith(text[:-1]))
            if matched and (best is None or len(text) > best[0]):
                best = (len(text), source)
        return best[1] if best else None

    #: Ecosystems where a bare version is a range resolved to its newest match, exact only with
    #: `=`: Cargo reads `1.2.3` as `^1.2.3`, Julia's `[compat]` reads `"1"` as `^1`.
    #: StaticArrays.jl's compat `PrecompileTools = "1"` was taken for version 1, which the General
    #: registry has never held, and reported withdrawn. (NuGet's `1.0` is `1.0` or higher too, but
    #: NuGet installs the lowest match: the version written.)
    BARE_VERSION_IS_A_RANGE: ClassVar[frozenset[str]] = frozenset({"cargo", "julia"})

    _EXACT_PIN = re.compile(r"^(?:==|=)?\s*v?(\d[A-Za-z0-9.+\-_]*)$")
    """A specification that names one version and no other.

    `==3.2`, `=1.19.0`, `4.17.15`. Not `^4.17.0`, `~=3.2`, `>=1,<2`, `1.2.*` or
    anything carrying a comparator, a comma or a wildcard -- each of those is a
    range, and which release it resolves to is the resolver's decision rather
    than the manifest's.
    """

    @staticmethod
    def exact_pin(spec: str, ecosystem: str | None = None) -> str | None:
        """The version a specification pins to, or None if it is a range."""
        text = spec.strip().strip("'\"")
        if ecosystem in Graph.BARE_VERSION_IS_A_RANGE and not text.startswith("="):
            return None
        bracketed = re.fullmatch(r"\[\s*([^,\[\]\s]{1,64})\s*\]", text)
        if bracketed:
            # `[1.2.3]`: NuGet's and Maven's notation for exactly one version.
            text = bracketed.group(1)
        if not text or any(character in text for character in "*,<>~^!| #"):
            return None
        if text.startswith("dev-") or ".x-dev" in text:
            # Composer's branch constraints (`dev-main`, `2.x-dev`): a branch, never a version.
            return None
        found = Graph._EXACT_PIN.match(text)
        return found.group(1) if found else None

    @staticmethod
    def defined_member(dependency: Dependency, defined: frozenset[tuple[str, str]]) -> bool:
        """Whether a dependency names a module this checkout defines, by its ecosystem's own
        name normalisation."""
        ecosystem = EcosystemRegistry.get(dependency.ecosystem)
        name = ecosystem.normalize_name(dependency.name) if ecosystem else dependency.name
        return (dependency.ecosystem, name) in defined

    @staticmethod
    def workspace_members(units: list[FileUnit]) -> frozenset[tuple[str, str]]:
        """The packages this repository itself defines, as `(ecosystem, normalized name)`.

        A manifest's own `name` outside any installed-dependency tree. A dependency on one of
        these names is resolved to the member by the workspace, not fetched from the registry.
        """
        members: set[tuple[str, str]] = set()
        contents = {u.path: u.content for u in units}
        for unit in units:
            if "node_modules/" in f"/{unit.path}" or "site-packages/" in unit.path:
                continue
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            ecosystem = EcosystemRegistry.get(ecosystem_id) if ecosystem_id else None
            if ecosystem is None or ecosystem_id is None:
                continue
            # Whether a manifest in the tree names one of the project's own packages: for most
            # ecosystems always; never for Homebrew; for Conan only a workspace's members.
            defines = getattr(ecosystem, "defines_members", True)
            if callable(defines):
                defines = defines(unit.path, contents)
            if not defines:
                continue
            try:
                # With the build in view: a Gradle project's name is in its settings script, a
                # Maven module's group in its parent POM.
                manifest = Graph.manifest_of(ecosystem, unit, contents)
            except Exception:  # noqa: BLE001, S112
                continue
            if manifest.name:
                members.add((ecosystem_id, ecosystem.normalize_name(manifest.name)))
        return frozenset(members)


__all__ = ["Graph"]
