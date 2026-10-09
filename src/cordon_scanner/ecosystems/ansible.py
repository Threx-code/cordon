"""Ansible: Galaxy roles and collections.

```
  requirements.yml            roles (a Galaxy `namespace.role`, or a git / tarball `src` with a
  roles/requirements.yml      version and `scm`) and collections (`namespace.collection` with a
  collections/requirements.yml  version constraint, a git URL, a tarball, a directory; a `source`
                              Galaxy server such as a private Automation Hub)
  galaxy.yml                  a collection's own metadata: namespace, name, version, dependencies
  meta/main.yml               a role's metadata: its own role dependencies and the collections
                              it uses
  .../ansible_collections/<ns>/<name>/MANIFEST.json
                              an installed collection, as `ansible-galaxy` wrote it: the version
                              resolved and that collection's own dependencies
  roles/<name>/meta/.galaxy_install_info
                              an installed role and the version `ansible-galaxy` resolved
```

Ansible writes no lockfile; what `ansible-galaxy install` put into the project (commonly committed
so plays run the same everywhere) is the resolution, and is read as one. A role or collection runs
as root on every host a play targets.

Playbooks and tasks are the configuration detectors' to judge (`detect/config_files.py`); their
findings stay apart from the package findings here.
"""

from __future__ import annotations

import dataclasses
import json
import re
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.core.datayaml import DataYaml
from cordon_scanner.core.models import Scope
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cordon_scanner.core.content import FileContent


FQCN = re.compile(r"^[A-Za-z0-9_]+\.[A-Za-z0-9_]+$")
GALAXY = "galaxy.ansible.com"


class AnsibleSource:
    """Where a requirement comes from, as a spec the shared layers read."""

    @staticmethod
    def spec(entry: Mapping[str, Any], location: str) -> tuple[str, str | None]:
        """`(spec, source)`: a version or constraint for a Galaxy requirement; a git or archive
        URL (with its ref) for one from elsewhere; `path:` for a directory. The source is a Galaxy
        server other than the public one."""
        version = str(entry.get("version") or "").strip()
        kind = str(entry.get("type") or entry.get("scm") or "").lower()
        if kind in ("dir", "subdirs", "file") or location.startswith(("./", "../", "/", "file://")):
            return f"path:{location.removeprefix('file://')}", None
        if (
            kind in ("git", "hg")
            or location.startswith(("git+", "git@"))
            or location.endswith(".git")
        ):
            url = location.removeprefix("git+")
            url, _, inline = url.partition(",")  # the old `src: url,ref` form
            return f"git+{url}" + (f"#{version or inline}" if (version or inline) else ""), None
        if kind == "url" or location.startswith(("http://", "https://")):
            return location, None
        server = entry.get("source")
        source = None
        if isinstance(server, str) and GALAXY not in server:
            # Another Galaxy server (a private Automation Hub): a registry of the organisation's.
            host = re.sub(r"^[a-z]+://", "", server).split("/", 1)[0]
            source = f"registry:{host}"
        return (version if version not in ("", "*") else "*"), source


class Requirements:
    """requirements.yml: roles and collections."""

    #: What a role requirement may say (ansible-galaxy's RoleRequirement); anything else makes a
    #: bare list something other than a list of roles.
    ROLE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {"src", "name", "version", "scm", "include", "role", "path"}
    )

    @staticmethod
    def entries(value: object) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for entry in value if isinstance(value, list) else []:
            if isinstance(entry, str):
                name, _, version = entry.partition(",")
                out.append(
                    {"name": name.strip(), **({"version": version.strip()} if version else {})}
                )
            elif isinstance(entry, dict):
                out.append(entry)
        return out

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest | None:
        """None for a requirements.yml that is not Galaxy's (pip's own is requirements.txt, but
        other tools use the YAML name too)."""
        try:
            data = DataYaml.load(content.text, source=content.path)
        except ValueError as exc:
            # A requirements YAML no reader can read is reported: Galaxy is the tool that claims the
            # name (pip's is requirements.txt), and an unread file must not pass for an empty one.
            return BaseEcosystem._err(content, ecosystem, f"invalid requirements.yml: {exc}")
        if isinstance(data, list):
            if any(isinstance(e, dict) and set(e) - Requirements.ROLE_KEYS for e in data):
                # A task list that happens to be called requirements.yml (a role's
                # tasks/requirements.yml): `- name: Install ...` with a module beside it.
                return None
            data = {"roles": data}  # the older form: a bare list of roles
        if not isinstance(data, dict) or not ({"roles", "collections"} & set(data)):
            return None
        return Requirements.from_data(data, content, ecosystem)

    @staticmethod
    def from_data(data: dict[str, Any], content: FileContent, ecosystem: str) -> Manifest:
        """Roles and collections from a requirements document already loaded (a requirements.yml,
        or an execution environment's inline `galaxy:`)."""
        declared: list[DeclaredDependency] = []
        sources: list[str] = []
        for section in ("roles", "collections"):
            if (
                section in data
                and data[section] is not None
                and not isinstance(data[section], list)
            ):
                return BaseEcosystem._err(content, ecosystem, f"`{section}` is not a list")
            for entry in Requirements.entries(data.get(section)):
                # A role is fetched from `src` and installed as `name`; a collection's `name` is
                # where it comes from (and `source` is the Galaxy server).
                location = str(
                    (entry.get("src") or entry.get("name"))
                    if section == "roles"
                    else entry.get("name") or ""
                ).strip()
                name = str(entry.get("name") or location).strip()
                if not name:
                    return BaseEcosystem._err(
                        content, ecosystem, f"a {section} entry without a name"
                    )
                spec, server = AnsibleSource.spec(entry, location)
                if "://" in name or name.startswith(("git@", "./", "../", "/")):
                    # Named by where it comes from: a collection tarball by its file name
                    # (`<namespace>-<name>-<version>.tar.gz`), anything else by the repository's.
                    tail = re.sub(r"(?:\.git)?(?:,.*)?$", "", name.rstrip("/")).rsplit("/", 1)[-1]
                    artefact = re.fullmatch(r"([a-z0-9_]+)-([a-z0-9_]+)-\d[\w.+\-]*\.tar\.gz", tail)
                    name = f"{artefact.group(1)}.{artefact.group(2)}" if artefact else tail
                if server:
                    sources.append(f"galaxy server {entry.get('source')}")
                declared.append(
                    DeclaredDependency(
                        name=name,
                        spec=spec,
                        scope=Scope.RUNTIME,
                        field_name=section,
                        source=server,
                    )
                )
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            dependencies=tuple(declared),
            sources=tuple(dict.fromkeys(sources)),
        )


class ExecutionEnvironment:
    """execution-environment.yml: what ansible-builder puts in the container a playbook runs in.

    A base image; Galaxy collections and roles (inline, or a requirements file named here and
    read as one); pip packages, ansible-core and ansible-runner among them, recorded as PyPI's;
    system packages for bindep, which no feed covers and are only listed. Schema versions 1 to 3.
    """

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            data = DataYaml.load(content.text, source=content.path)
        except ValueError as exc:
            return BaseEcosystem._err(
                content, ecosystem, f"invalid execution-environment.yml: {exc}"
            )
        if not isinstance(data, dict):
            return BaseEcosystem._err(content, ecosystem, "an execution environment is not a map")
        dependencies = data.get("dependencies") or {}
        if not isinstance(dependencies, dict):
            return BaseEcosystem._err(content, ecosystem, "`dependencies` is not a map")
        declared: list[DeclaredDependency] = []
        sources: list[str] = []
        image = ExecutionEnvironment.base_image(data)
        if image:
            reference, _, tag = (
                image.rpartition(":") if ":" in image.rsplit("/", 1)[-1] else (image, "", "")
            )
            declared.append(
                DeclaredDependency(
                    name=reference,
                    spec=tag or "latest",
                    scope=Scope.TOOL,
                    field_name="images.base_image",
                    ecosystem="image",
                )
            )
        galaxy = dependencies.get("galaxy")
        if isinstance(galaxy, dict):
            inline = Requirements.from_data(galaxy, content, ecosystem)
            if inline.parse_error:
                return inline
            declared.extend(
                dataclasses.replace(d, field_name=f"dependencies.galaxy.{d.field_name}")
                for d in inline.dependencies
            )
        elif isinstance(galaxy, str):
            sources.append(f"galaxy requirements from {galaxy}")
        from cordon_scanner.ecosystems.pypi import PypiRequirement

        pip: list[tuple[str, str]] = []
        python = dependencies.get("python")
        if isinstance(python, list):
            pip.extend((str(r), "dependencies.python") for r in python)
        elif isinstance(python, str):
            sources.append(f"python requirements from {python}")
        for key in ("ansible_core", "ansible_runner"):
            entry = dependencies.get(key)
            if isinstance(entry, dict) and isinstance(entry.get("package_pip"), str):
                pip.append((entry["package_pip"], f"dependencies.{key}"))
        for requirement, field_name in pip:
            parsed = PypiRequirement.parse(requirement)
            if parsed is None:
                continue
            name, _extras, spec, marker, _url = parsed
            declared.append(
                DeclaredDependency(
                    name=name,
                    spec=spec or "*",
                    field_name=field_name,
                    ecosystem="pypi",
                    platform=(f"marker {marker}",) if marker else (),
                )
            )
        system = dependencies.get("system")
        if isinstance(system, list) and system:
            sources.append(f"{len(system)} system package(s) for bindep, which no feed covers")
        elif isinstance(system, str):
            sources.append(f"system packages from {system}")
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            dependencies=tuple(declared),
            sources=tuple(sources),
        )

    @staticmethod
    def base_image(data: dict[str, Any]) -> str | None:
        images = data.get("images")
        if isinstance(images, dict):
            base = images.get("base_image")
            if isinstance(base, dict) and isinstance(base.get("name"), str):
                return str(base["name"])
        defaults = data.get("build_arg_defaults")
        if isinstance(defaults, dict) and isinstance(defaults.get("EE_BASE_IMAGE"), str):
            return str(defaults["EE_BASE_IMAGE"])
        return None


class CollectionRuntime:
    """meta/runtime.yml: `requires_ansible`, the ansible-core versions a collection supports."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            data = DataYaml.load(content.text, source=content.path)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"invalid meta/runtime.yml: {exc}")
        if not isinstance(data, dict):
            return BaseEcosystem._err(content, ecosystem, "meta/runtime.yml is not a map")
        required = data.get("requires_ansible")
        declared = (
            (
                DeclaredDependency(
                    name="ansible-core",
                    spec=str(required),
                    scope=Scope.PLATFORM,
                    field_name="requires_ansible",
                ),
            )
            if isinstance(required, str) and required.strip()
            else ()
        )
        return Manifest(path=content.path, ecosystem=ecosystem, dependencies=declared)


class GalaxyFile:
    """galaxy.yml: a collection's own metadata."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            data = DataYaml.load(content.text, source=content.path)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"invalid galaxy.yml: {exc}")
        if not isinstance(data, dict) or not data.get("namespace") or not data.get("name"):
            return BaseEcosystem._err(content, ecosystem, "a galaxy.yml without namespace and name")
        dependencies = data.get("dependencies") or {}
        if not isinstance(dependencies, dict):
            return BaseEcosystem._err(content, ecosystem, "`dependencies` is not a map")
        declared = [
            DeclaredDependency(
                name=str(name), spec=str(constraint or "*"), field_name="dependencies"
            )
            for name, constraint in dependencies.items()
        ]
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=f"{data['namespace']}.{data['name']}",
            version=BaseEcosystem._s(data.get("version")),
            dependencies=tuple(declared),
            repository=BaseEcosystem._s(data.get("repository")),
        )


class RoleMeta:
    """A role's meta/main.yml: its role dependencies, and the collections it uses."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            data = DataYaml.load(content.text, source=content.path)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"invalid meta/main.yml: {exc}")
        if not isinstance(data, dict) or ("galaxy_info" not in data and "dependencies" not in data):
            return Manifest(path=content.path, ecosystem=ecosystem)
        declared: list[DeclaredDependency] = []
        for entry in data.get("dependencies") or []:
            if isinstance(entry, str):
                entry = {"role": entry}
            if not isinstance(entry, dict):
                continue
            location = str(entry.get("src") or entry.get("role") or entry.get("name") or "").strip()
            if not location:
                continue
            spec, server = AnsibleSource.spec(entry, location)
            name = str(entry.get("name") or entry.get("role") or location)
            if "://" in name or name.startswith("git@"):
                name = re.sub(r"(?:\.git)?(?:,.*)?$", "", name.rstrip("/")).rsplit("/", 1)[-1]
            declared.append(
                DeclaredDependency(name=name, spec=spec, field_name="dependencies", source=server)
            )
        for collection in data.get("collections") or []:
            if isinstance(collection, str) and FQCN.match(collection):
                declared.append(
                    DeclaredDependency(name=collection, spec="*", field_name="collections")
                )
        info = data.get("galaxy_info") if isinstance(data.get("galaxy_info"), dict) else {}
        role = BaseEcosystem._s((info or {}).get("role_name"))
        namespace = BaseEcosystem._s((info or {}).get("namespace"))
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=f"{namespace}.{role}" if namespace and role else role,
            dependencies=tuple(declared),
        )


class Installed:
    """What `ansible-galaxy install` put into the project: the resolution."""

    @staticmethod
    def collection(content: FileContent, ecosystem: str) -> LockGraph:
        parts = content.path.split("/")
        # <dir>/ansible_collections/<ns>/<name>/MANIFEST.json belongs to <dir>; a `collections/`
        # directory (Ansible's project-local default) belongs to the project above it.
        levels = 4 if len(parts) >= 5 and parts[-5] == "collections" else 3
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"invalid JSON: {exc}",
                owner_levels=levels,
            )
        info = data.get("collection_info")
        if (
            not isinstance(info, dict)
            or not info.get("namespace")
            or not info.get("name")
            or not info.get("version")
        ):
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="a collection MANIFEST.json without namespace, name and version",
                owner_levels=levels,
            )
        listed = info.get("dependencies")
        dependencies: dict[str, Any] = listed if isinstance(listed, dict) else {}
        entry = LockEntry(
            name=f"{info['namespace']}.{info['name']}",
            version=str(info["version"]),
            dependencies=tuple(str(d) for d in dependencies),
        )
        return LockGraph(
            path=content.path, ecosystem=ecosystem, entries=(entry,), owner_levels=levels
        )

    @staticmethod
    def role(content: FileContent, ecosystem: str) -> LockGraph:
        parts = content.path.split("/")
        name = parts[-3] if len(parts) >= 3 else ""
        try:
            data = DataYaml.load(content.text, source=content.path)
        except ValueError as exc:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"invalid install info: {exc}",
                owner_levels=3,
            )
        version = data.get("version") if isinstance(data, dict) else None
        if not name or not isinstance(version, str) or not version:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="a role's install info without its version",
                owner_levels=3,
            )
        return LockGraph(
            path=content.path,
            ecosystem=ecosystem,
            entries=(LockEntry(name=name, version=version.lstrip("v")),),
            owner_levels=3,
        )


class AnsibleGalaxyEcosystem(BaseEcosystem):
    """Galaxy roles and collections, declared and installed."""

    id = "ansible"
    purl_type = "ansible"
    manifest_globs: tuple[str, ...] = (
        "**/requirements.yml",
        "**/requirements.yaml",
        "**/roles/requirements.yml",
        "**/collections/requirements.yml",
        "**/galaxy.yml",
        "**/meta/main.yml",
        "**/meta/runtime.yml",
        "**/execution-environment.yml",
        "**/execution-environment.yaml",
    )
    lockfile_globs: tuple[str, ...] = (
        "**/ansible_collections/*/*/MANIFEST.json",
        "**/meta/.galaxy_install_info",
    )
    registry_hosts: frozenset[str] = frozenset({GALAXY})
    records_integrity = False
    INSTALL_DIRECTORIES: ClassVar[tuple[str, ...]] = ("collections", "roles")

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        return self.parse_in_tree(content, {content.path: content})

    def parse_in_tree(self, content: FileContent, files: Mapping[str, FileContent]) -> Manifest:
        basename = content.basename
        directory = content.path.rpartition("/")[0]
        if basename == "galaxy.yml":
            return GalaxyFile.parse(content, self.id)
        if basename in ("execution-environment.yml", "execution-environment.yaml"):
            return ExecutionEnvironment.parse(content, self.id)
        if basename == "runtime.yml":
            return CollectionRuntime.parse(content, self.id)
        if basename == "main.yml":
            # An installed role's own metadata: its dependencies were installed as roles of their
            # own, each with its install info, and are read there.
            role = directory.rpartition("/")[0]
            if f"{directory}/.galaxy_install_info" in files:
                return Manifest(
                    path=content.path,
                    ecosystem=self.id,
                    sources=(f"installed role {role.rpartition('/')[2]}",),
                )
            return RoleMeta.parse(content, self.id)
        manifest = Requirements.parse(content, self.id)
        if manifest is None:
            return Manifest(path=content.path, ecosystem=self.id)
        # `collections/requirements.yml` and `roles/requirements.yml` belong to the project
        # above them, where ansible-galaxy installs into `collections/` and `roles/`.
        if (
            directory.rpartition("/")[2] in self.INSTALL_DIRECTORIES
            and manifest.parse_error is None
        ):
            return dataclasses.replace(manifest, locked_by=directory.rpartition("/")[0])
        return manifest

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        if content.basename == "MANIFEST.json":
            return Installed.collection(content, self.id)
        return Installed.role(content, self.id)


__all__ = [
    "AnsibleGalaxyEcosystem",
    "AnsibleSource",
    "GalaxyFile",
    "Installed",
    "Requirements",
    "RoleMeta",
]
