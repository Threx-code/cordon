"""How PyPI lockfiles are read -- poetry.lock, uv.lock and pdm.lock, Pipfile.lock, and
requirements files pinned with hashes or compiled by pip-tools -- into the dependency graph.

A base of PypiEcosystem: its methods use the ecosystem's id and name normalisation, declared here
for the type checker only."""

from __future__ import annotations

import re
import tomllib
from typing import TYPE_CHECKING, Any

from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    LockEntry,
    LockGraph,
)
from cordon_scanner.ecosystems.packages.python.requirements import (
    _NORMALIZE,
    _REQUIREMENT_NAME,
    PypiManifest,
    PypiRequirement,
)
from cordon_scanner.foundation.models import Scope

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class PypiLockfiles:
    if TYPE_CHECKING:
        id: str

        def normalize_name(self, name: str) -> str: ...

    @staticmethod
    def _first_hash(package: dict[str, Any]) -> str | None:
        files = package.get("files")
        if isinstance(files, list):
            for entry in files:
                if isinstance(entry, dict) and entry.get("hash"):
                    return str(entry["hash"])
        return None

    @staticmethod
    def _str_or_none(value: object) -> str | None:
        return str(value) if isinstance(value, str) and value else None

    @staticmethod
    def _logical_lines(text: str) -> list[str]:
        """Lines with comments removed and `\\` continuations joined, as pip reads them."""
        out: list[str] = []
        pending = ""
        for raw in text.splitlines():
            line = re.sub(r"(^|\s)#.*$", "", raw).rstrip()
            if line.endswith("\\"):
                pending += line[:-1] + " "
                continue
            line = (pending + line).strip()
            pending = ""
            if line:
                out.append(line)
        if pending.strip():
            out.append(pending.strip())
        return out

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        name = content.basename
        if name == "poetry.lock":
            return self._parse_poetry_lock(content)
        if name == "Pipfile.lock":
            return self._parse_pipfile_lock(content)
        if name in {"pdm.lock", "uv.lock"}:
            return self._parse_pep_style_lock(content)
        # Matched on the DIRECTORY as well as the name, exactly as `parse_manifest` does - the
        # two dispatches answer the same question about the same file, and disagreeing is how
        # `requirements/base.txt` reached one parser and not the other.
        #
        # On any path SEGMENT rather than the prefix: in a monorepo the file is
        # `backend/requirements/base.txt`, and a `startswith` check sees only the repository
        # root. That is the same narrowness one level up.
        if name.startswith("requirements") or PypiManifest._in_requirements_dir(content.path):
            return self._parse_pinned_requirements(content)
        return LockGraph(
            path=content.path, ecosystem=self.id, parse_error=f"unsupported lockfile: {name}"
        )

    def _parse_poetry_lock(self, content: FileContent) -> LockGraph:
        try:
            data = tomllib.loads(content.text)
        except (tomllib.TOMLDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=self.id, parse_error=f"invalid TOML: {exc}"
            )
        packages = [p for p in data.get("package") or [] if isinstance(p, dict)]
        markers = PypiLockfiles._edge_markers(
            (p.get("dependencies") or {})
            for p in packages
            if isinstance(p.get("dependencies"), dict)
        )
        entries: list[LockEntry] = []
        for package in packages:
            name = PypiLockfiles._str_or_none(package.get("name"))
            if not name:
                continue
            # Poetry 1 writes `category`; Poetry 2 writes `groups`. Only a package in no runtime
            # group is development-only.
            groups = package.get("groups")
            if isinstance(groups, list) and groups:
                scope = Scope.RUNTIME if "main" in groups else Scope.DEV
            else:
                scope = (
                    Scope.DEV if str(package.get("category", "main")) == "dev" else Scope.RUNTIME
                )
            if package.get("optional") is True and scope is Scope.RUNTIME:
                scope = Scope.OPTIONAL
            raw_source = package.get("source")
            source: dict[str, Any] = raw_source if isinstance(raw_source, dict) else {}
            kind = str(source.get("type") or "")
            resolved = PypiLockfiles._str_or_none(source.get("url"))
            if kind == "git" and resolved:
                commit = source.get("resolved_reference") or source.get("reference") or ""
                resolved = f"git+{resolved}" + (f"#{commit}" if commit else "")
            conditions = list(markers.get(self.normalize_name(name), ()))
            for key, label in (("markers", None), ("python-versions", "python")):
                value = package.get(key)
                if isinstance(value, str) and value.strip() and value.strip() != "*":
                    conditions.append(f"{label} {value.strip()}" if label else value.strip())
            entries.append(
                LockEntry(
                    name=name,
                    version=str(package.get("version", "")),
                    integrity=PypiLockfiles._first_hash(package),
                    resolved_from=resolved,
                    scope=scope,
                    dependencies=tuple(sorted((package.get("dependencies") or {}).keys())),
                    local=kind in ("directory", "file")
                    and not str(resolved or "").startswith(("http", "/")),
                    platform=tuple(conditions),
                )
            )
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))

    @staticmethod
    def _edge_markers(tables: Any) -> dict[str, tuple[str, ...]]:
        """The environment markers under which each package is required, from its parents' edges.

        `colorama = {version = "*", markers = "sys_platform == \\"win32\\""}` makes colorama a
        Windows-only dependency: the condition belongs to the child, whoever writes it."""
        found: dict[str, list[str]] = {}
        unconditional: set[str] = set()
        for table in tables:
            for child, value in table.items():
                key = _NORMALIZE.sub("-", str(child).lower())
                specs = value if isinstance(value, list) else [value]
                for spec in specs:
                    marker = (
                        spec.get("markers") or spec.get("marker")
                        if isinstance(spec, dict)
                        else None
                    )
                    if isinstance(marker, str) and marker.strip():
                        found.setdefault(key, []).append(marker.strip())
                    else:
                        # Required somewhere without a condition: required everywhere.
                        unconditional.add(key)
        return {k: tuple(dict.fromkeys(v)) for k, v in found.items() if k not in unconditional}

    @staticmethod
    def _own_path(package: dict[str, Any]) -> str | None:
        """Where a workspace project of the lock lives (`editable = "."`, `editable = "packages/core"`,
        `virtual = "."`), or None for a package from an index."""
        source = package.get("source")
        if not isinstance(source, dict):
            return None
        path = source.get("editable") or source.get("virtual")
        if isinstance(path, str) and not path.startswith(("/", "..")):
            return path
        return None

    def _parse_pep_style_lock(self, content: FileContent) -> LockGraph:
        """`uv.lock` and `pdm.lock`, which share poetry's `[[package]]` table and
        nothing else about what is inside it.

        Three fields differ, and every one of them is the kind of difference that
        raises rather than degrades. `dependencies` is an array here -- of tables
        carrying a `name` in uv, of requirement strings in PDM -- where poetry
        writes a table, so reading it as a mapping raises `AttributeError` and
        loses the whole file. Artefact hashes live under `sdist.hash` and
        `wheels[].hash` rather than under `files[].hash`. Scope comes from a
        package's membership of a dependency group rather than from a `category`
        key, which neither format writes.

        Anything unrecognised inside a package leaves that package with the
        default rather than dropping it: a resolver adding a field must not empty
        the graph.
        """
        try:
            data = tomllib.loads(content.text)
        except (tomllib.TOMLDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=self.id, parse_error=f"invalid TOML: {exc}"
            )

        packages = data.get("package")
        if not isinstance(packages, list):
            return LockGraph(
                path=content.path,
                ecosystem=self.id,
                parse_error="no [[package]] tables; not a uv or PDM lockfile",
            )

        dev_names = PypiLockfiles._dev_group_names(data)
        tables = [p for p in packages if isinstance(p, dict)]
        markers = PypiLockfiles._pep_style_markers(tables)
        # uv's root: the project itself (`source = { editable = "." }` or `{ virtual = "." }`).
        # Its dependencies are what the project declares; its optional and dev tables, the
        # extras and groups.
        direct: set[str] = set()
        optional: set[str] = set()

        # The workspace's own projects: the root (`editable = "."` or `virtual = "."`) and every
        # member (`editable = "packages/core"`). Each one's dependencies are what the project
        # declares; each member's manifest is joined to this lock (`LockGraph.workspaces`).
        roots = [p for p in tables if PypiLockfiles._own_path(p) is not None]
        workspace_paths = sorted({str(PypiLockfiles._own_path(p)) for p in roots} - {".", ""})
        runtime_direct: set[str] = set()
        development: set[str] = set(dev_names)
        self._root_groups(roots, runtime_direct, optional, development)
        direct |= runtime_direct | optional | (development if roots else set())
        entries = self._pep_style_entries(
            tables, roots, runtime_direct, development, optional, markers, direct
        )
        return LockGraph(
            path=content.path,
            ecosystem=self.id,
            entries=tuple(entries),
            workspaces=tuple(workspace_paths),
        )

    def _root_groups(
        self,
        roots: list[dict[Any, Any]],
        runtime_direct: set[str],
        optional: set[str],
        development: set[str],
    ) -> None:
        """What each workspace project declares: its runtime dependencies, and the names its optional and dev groups add."""
        for root in roots:
            runtime_direct.update(
                self.normalize_name(n) for n in PypiLockfiles._pep_style_dependencies(root)
            )
            for table, target in (
                ("optional-dependencies", optional),
                ("dev-dependencies", development),
            ):
                groups = root.get(table)
                if isinstance(groups, dict):
                    for members in groups.values():
                        for item in members if isinstance(members, list) else ():
                            name = item.get("name") if isinstance(item, dict) else None
                            if isinstance(name, str):
                                target.add(self.normalize_name(name))

    def _pep_style_entries(
        self,
        tables: list[dict[Any, Any]],
        roots: list[dict[Any, Any]],
        runtime_direct: set[str],
        development: set[str],
        optional: set[str],
        markers: dict[str, tuple[str, ...]],
        direct: set[str],
    ) -> list[LockEntry]:
        """One entry per package of the lock, with its scope, markers, source and hashes."""
        entries: list[LockEntry] = []
        for package in tables:
            name = PypiLockfiles._str_or_none(package.get("name"))
            if not name:
                continue
            normalized = self.normalize_name(name)
            if package in roots and PypiLockfiles._own_path(package) in (".", ""):
                continue  # the project itself, not one of its dependencies
            raw_source = package.get("source")
            source: dict[str, Any] = raw_source if isinstance(raw_source, dict) else {}
            resolved = PypiLockfiles._str_or_none(source.get("registry") or source.get("url"))
            if isinstance(source.get("git"), str):
                resolved = "git+" + source["git"]
            local_path = (
                source.get("path")
                or source.get("directory")
                or source.get("editable")
                or source.get("virtual")
            )
            if normalized in runtime_direct:
                scope = Scope.RUNTIME
            elif normalized in development:
                scope = Scope.DEV
            elif normalized in optional:
                scope = Scope.OPTIONAL
            else:
                scope = Scope.RUNTIME
            requires_python = package.get("requires-python") or package.get("requires_python")
            conditions = list(markers.get(normalized, ()))
            if isinstance(requires_python, str) and requires_python.strip():
                conditions.append(f"python {requires_python.strip()}")
            entries.append(
                LockEntry(
                    name=name,
                    version=str(package.get("version", "")),
                    integrity=PypiLockfiles._artefact_hash(package),
                    resolved_from=resolved,
                    scope=scope,
                    dependencies=PypiLockfiles._pep_style_dependencies(package),
                    local=isinstance(local_path, str)
                    and not str(local_path).startswith(("/", "..")),
                    direct=normalized in direct,
                    platform=tuple(conditions),
                )
            )
        return entries

    @staticmethod
    def _pep_style_markers(tables: list[dict[str, Any]]) -> dict[str, tuple[str, ...]]:
        """Edge markers in uv (`{ name = "colorama", marker = "sys_platform == 'win32'" }`) and
        PDM (`"colorama; sys_platform == 'win32'"`) dependency lists."""
        found: dict[str, list[str]] = {}
        unconditional: set[str] = set()
        for package in tables:
            items = package.get("dependencies")
            for item in items if isinstance(items, list) else ():
                if isinstance(item, dict) and isinstance(item.get("name"), str):
                    name, marker = item["name"], item.get("marker")
                elif isinstance(item, str):
                    parsed = PypiRequirement.parse(item)
                    if parsed is None:
                        continue
                    name, marker = parsed[0], parsed[3]
                else:
                    continue
                key = _NORMALIZE.sub("-", str(name).lower())
                if isinstance(marker, str) and marker.strip():
                    found.setdefault(key, []).append(marker.strip())
                else:
                    unconditional.add(key)
        return {k: tuple(dict.fromkeys(v)) for k, v in found.items() if k not in unconditional}

    @staticmethod
    def _pep_style_dependencies(package: dict[str, Any]) -> tuple[str, ...]:
        """The names a uv or PDM `[[package]]` depends on.

        uv writes `[[package.dependencies]]` tables carrying a `name`; PDM writes
        a list of requirement strings. Both arrive here as a list, and a string is
        cut at the first character that cannot belong to a name so that
        `urllib3>=1.26` and `urllib3` produce the same entry.
        """
        raw = package.get("dependencies")
        items: list[Any] = list(raw) if isinstance(raw, list) else []
        # uv records what an extra pulls in under the package's own `optional-dependencies`
        # (`requests` -> `socks` -> `pysocks`). A lock holds only what was activated, so an
        # extra's packages present in it were brought in by that extra.
        optional = package.get("optional-dependencies")
        if isinstance(optional, dict):
            for members in optional.values():
                if isinstance(members, list):
                    items.extend(members)
        if not items:
            return ()
        names: set[str] = set()
        for item in items:
            if isinstance(item, dict):
                name = PypiLockfiles._str_or_none(item.get("name"))
                if name:
                    names.add(name)
            elif isinstance(item, str):
                cut = _REQUIREMENT_NAME.split(item.strip(), maxsplit=1)[0]
                if cut:
                    names.add(cut)
        return tuple(sorted(names))

    @staticmethod
    def _dev_group_names(data: dict[str, Any]) -> frozenset[str]:
        """Normalised names a lockfile places in a development group.

        uv records them under `[manifest] dev-dependencies`; PDM records group
        membership on the package itself. Only names this can establish are
        treated as dev, because marking a runtime dependency dev suppresses
        findings that should fire.
        """
        names: set[str] = set()
        manifest = data.get("manifest")
        if isinstance(manifest, dict):
            groups = manifest.get("dev-dependencies")
            members: list[Any] = []
            if isinstance(groups, dict):
                for group in groups.values():
                    if isinstance(group, list):
                        members.extend(group)
            elif isinstance(groups, list):
                members.extend(groups)
            names.update(
                _REQUIREMENT_NAME.split(str(m).strip(), maxsplit=1)[0]
                for m in members
                if isinstance(m, str)
            )

        for package in data.get("package") or []:
            if not isinstance(package, dict):
                continue
            groups = package.get("groups")
            name = PypiLockfiles._str_or_none(package.get("name"))
            if (
                name
                and isinstance(groups, list)
                and groups
                and all(str(g) not in ("default", "main") for g in groups)
            ):
                names.add(name)

        return frozenset(_NORMALIZE.sub("-", n.strip().lower()) for n in names if n)

    @staticmethod
    def _artefact_hash(package: dict[str, Any]) -> str | None:
        """The hash of a uv or PDM package's own artefact.

        The sdist first, then the first wheel, then poetry's `files` shape so a
        lockfile carrying either layout is read the same way. A resolver that
        records no hash returns `None`, which the integrity rules report as an
        unpinned artefact rather than treating it as verified.
        """
        sdist = package.get("sdist")
        if isinstance(sdist, dict) and sdist.get("hash"):
            return str(sdist["hash"])
        wheels = package.get("wheels")
        if isinstance(wheels, list):
            for wheel in wheels:
                if isinstance(wheel, dict) and wheel.get("hash"):
                    return str(wheel["hash"])
        return PypiLockfiles._first_hash(package)

    def _parse_pipfile_lock(self, content: FileContent) -> LockGraph:
        import json

        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=self.id, parse_error=f"invalid JSON: {exc}"
            )
        entries: list[LockEntry] = []
        for section, scope in (("default", Scope.RUNTIME), ("develop", Scope.DEV)):
            for name, meta in sorted((data.get(section) or {}).items()):
                if not isinstance(meta, dict):
                    continue
                hashes = meta.get("hashes") or []
                resolved = None
                if isinstance(meta.get("git"), str):
                    resolved = f"git+{meta['git']}" + (
                        f"#{meta['ref']}" if isinstance(meta.get("ref"), str) else ""
                    )
                elif isinstance(meta.get("path"), str):
                    resolved = str(meta["path"])
                elif isinstance(meta.get("file"), str):
                    resolved = str(meta["file"])
                markers = meta.get("markers")
                entries.append(
                    LockEntry(
                        name=str(name),
                        version=str(meta.get("version", "")).lstrip("="),
                        integrity=str(hashes[0]) if hashes else None,
                        resolved_from=resolved,
                        scope=scope,
                        # Pipfile.lock lists every package flat, with no edges and no mark of
                        # what was asked for: the Pipfile beside it says which are direct.
                        direct=False,
                        local=isinstance(meta.get("path"), str)
                        and not str(meta["path"]).startswith(("/", "..")),
                        platform=(markers,) if isinstance(markers, str) and markers else (),
                    )
                )
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))

    def _parse_pinned_requirements(self, content: FileContent) -> LockGraph:
        """Treat a fully pinned requirements file as a lockfile.

        Only ``==`` pins count. A range is a declaration of intent, not a record
        of what was installed, and reporting one as resolved would claim a
        precision the file does not have.
        """
        entries: list[LockEntry] = []
        lines = PypiLockfiles._logical_lines(content.text)
        # Where pip resolves these from: one `--index-url` and no extra index means that index
        # serves every pin, which is what a private-registry check needs to know.
        indexes = [
            re.split(r"[=\s]", line, maxsplit=1)[1].strip().split()[0]
            for line in lines
            if re.match(r"^(?:-i|--index-url)[=\s]\s*\S", line)
        ]
        extra = any(re.match(r"^--extra-index-url[=\s]", line) for line in lines)
        index = indexes[0] if len(indexes) == 1 and not extra else None
        # Logical lines: pip-compile writes every `--hash=` on its own continuation line, and
        # joining them first puts each requirement and its hashes on one line. (Kept separate,
        # the trailing `\` once rode into the recorded hash.)
        for line in lines:
            if line.startswith("-"):
                continue
            hashes = re.findall(r"--hash[=\s]\s*(\S+)", line)
            requirement = re.split(r"\s--hash", line, maxsplit=1)[0]
            parsed = PypiRequirement.parse(requirement)
            if parsed is None:
                continue
            name, _extras, spec, marker, is_url = parsed
            if is_url or not spec.startswith("==") or "," in spec or "*" in spec:
                continue  # a range or a URL is not a resolution
            entries.append(
                LockEntry(
                    name=name,
                    version=PypiManifest._version_of(spec[2:].lstrip("=")),
                    integrity=hashes[0] if hashes else None,
                    resolved_from=index,
                    direct=True,
                    platform=(marker,) if marker else (),
                )
            )
        via = PypiLockfiles._pip_compile_via(content.text)
        if via:
            # pip-compile's own record of the graph: `# via requests` under certifi. A package
            # brought in only by other packages is transitive; one `# via -r requirements.in`
            # (or with no comment) is what the project asked for.
            # A parent written `-r requirements.in`, `-c constraints.txt` or `app (pyproject.toml)`
            # is a project file, not a package: the child is declared there directly.
            def from_project(parent: str) -> bool:
                return parent.startswith("-") or "(" in parent

            spelled = {self.normalize_name(e.name): e.name for e in entries}
            children: dict[str, set[str]] = {}
            for child, parents in via.items():
                for parent in parents:
                    if not from_project(parent):
                        children.setdefault(self.normalize_name(parent), set()).add(
                            spelled.get(child, child)
                        )
            entries = [
                LockEntry(
                    name=e.name,
                    version=e.version,
                    integrity=e.integrity,
                    resolved_from=e.resolved_from,
                    direct=(
                        self.normalize_name(e.name) not in via
                        or any(from_project(p) for p in via[self.normalize_name(e.name)])
                    ),
                    platform=e.platform,
                    dependencies=tuple(sorted(children.get(self.normalize_name(e.name), ()))),
                )
                for e in entries
            ]
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))

    @staticmethod
    def _pip_compile_via(text: str) -> dict[str, list[str]]:
        """`{normalised child: [parents]}` from pip-compile's annotations.

        ```
          certifi==2024.2.2           urllib3==2.2.1
              # via requests              # via
                                          #   requests
                                          #   -r requirements.in
        ```
        """
        found: dict[str, list[str]] = {}
        current: str | None = None
        collecting = False
        for raw in text.splitlines():
            stripped = raw.strip()
            if not stripped:
                continue
            if not stripped.startswith("#"):
                if stripped.startswith(("--hash", "-")) or raw[:1].isspace():
                    continue
                parsed = PypiRequirement.parse(stripped.split(" --hash", 1)[0].rstrip("\\ "))
                current = _NORMALIZE.sub("-", parsed[0].lower()) if parsed else None
                collecting = False
                continue
            comment = stripped.lstrip("#").strip()
            if current is None:
                continue
            if comment.startswith("via"):
                collecting = True
                rest = comment[3:].strip()
                if rest:
                    found.setdefault(current, []).extend(
                        p.strip() for p in rest.split(",") if p.strip()
                    )
                else:
                    found.setdefault(current, [])
                continue
            if collecting and raw.startswith("    #   "):
                found.setdefault(current, []).append(comment)
            else:
                collecting = False
        return found


__all__ = ["PypiLockfiles"]
