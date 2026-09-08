"""PyPI: pyproject.toml, requirements files, Pipfile and Poetry.

``setup.py`` is treated as **source code to analyse, never as a module to
import**. That is the whole point of the rule: a setup script is arbitrary
Python that executes at install time, so importing one to read its metadata
would run exactly the code the scanner exists to inspect. Metadata is recovered
by walking the parsed syntax tree for literal assignments only, using Python's
own ``ast`` module, which parses without executing.
"""

from __future__ import annotations

import ast
import re
import tomllib
from typing import TYPE_CHECKING, Any

from cordon.core.models import Hook, Scope
from cordon.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from cordon.core.content import FileContent

# PEP 508: strip the version specifier, extras and environment marker from a
# requirement to recover the bare name.
_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")

_INLINE_OPTION = re.compile(r"\s-{1,2}[A-Za-z]")
"""The start of a pip option following a requirement on the same line.

`req==1.0 --hash=sha256:...` and `req==1.0 --global-option=x` are both legal.
Anything from here on describes how to install the requirement, not which
requirement it is.
"""


def _cut_options(text: str) -> str:
    """Drop the environment marker and any same-line pip options."""
    body = text.split(";", 1)[0]
    option = _INLINE_OPTION.search(body)
    if option is not None:
        body = body[: option.start()]
    return body.strip().rstrip("\\").strip()


def _version_of(text: str) -> str:
    """The pinned version alone, with no trailing options or continuation."""
    return _cut_options(text)


def _spec_of(text: str) -> str:
    """The version specifier alone, with no trailing options."""
    return _cut_options(text)


_NORMALIZE = re.compile(r"[-_.]+")


class PypiEcosystem(BaseEcosystem):
    @staticmethod
    def _poetry_spec(value: object) -> str:
        """Render a table-valued dependency spec as a string."""
        if isinstance(value, dict):
            for key in ("version", "git", "url", "path"):
                if key in value:
                    return str(value[key])
            return "*"
        return str(value)

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

    id = "pypi"
    purl_type = "pypi"
    manifest_globs: tuple[str, ...] = (
        "**/pyproject.toml",
        "**/setup.py",
        "**/setup.cfg",
        "**/requirements*.txt",
        "**/requirements/*.txt",
        "**/requirements*.in",
        "**/Pipfile",
    )
    lockfile_globs: tuple[str, ...] = (
        "**/poetry.lock",
        "**/Pipfile.lock",
        "**/pdm.lock",
        "**/uv.lock",
        "**/requirements*.txt",
    )
    registry_hosts: frozenset[str] = frozenset(
        {"pypi.org", "files.pythonhosted.org", "pypi.python.org"}
    )

    def normalize_name(self, name: str) -> str:
        """PEP 503 normalisation.

        Runs of ``-``, ``_`` and ``.`` are equivalent and fold to a single
        hyphen, and comparison is case-insensitive. Without this, ``zope.interface``,
        ``zope-interface`` and ``Zope_Interface`` look like three different
        packages, which breaks both advisory matching and typosquat detection in
        opposite directions.
        """
        return _NORMALIZE.sub("-", name.strip().lower())

    # -- Manifests -------------------------------------------------------

    def parse_manifest(self, content: FileContent) -> Manifest:
        name = content.basename
        if name == "pyproject.toml":
            return self._parse_pyproject(content)
        if name == "setup.py":
            return self._parse_setup_py(content)
        if name == "Pipfile":
            return self._parse_pipfile(content)
        if name.startswith("requirements") or content.path.startswith("requirements/"):
            return self._parse_requirements(content)
        return Manifest(path=content.path, ecosystem=self.id)

    def _parse_pyproject(self, content: FileContent) -> Manifest:
        try:
            data = tomllib.loads(content.text)
        except (tomllib.TOMLDecodeError, ValueError) as exc:
            return Manifest(
                path=content.path, ecosystem=self.id, parse_error=f"invalid TOML: {exc}"
            )

        project = data.get("project") or {}
        declared: list[DeclaredDependency] = []

        for spec in project.get("dependencies") or []:
            parsed = self._declared(str(spec), Scope.RUNTIME, "project.dependencies")
            if parsed:
                declared.append(parsed)

        for extra, specs in (project.get("optional-dependencies") or {}).items():
            for spec in specs or []:
                parsed = self._declared(str(spec), Scope.OPTIONAL, f"optional-dependencies.{extra}")
                if parsed:
                    declared.append(parsed)

        # Poetry keeps its dependencies elsewhere.
        poetry = (data.get("tool") or {}).get("poetry") or {}
        for field_name, scope in (
            ("dependencies", Scope.RUNTIME),
            ("dev-dependencies", Scope.DEV),
        ):
            for pkg, spec in (poetry.get(field_name) or {}).items():
                if pkg == "python":
                    continue
                text = spec if isinstance(spec, str) else PypiEcosystem._poetry_spec(spec)
                declared.append(
                    DeclaredDependency(
                        name=str(pkg),
                        spec=text,
                        scope=scope,
                        field_name=f"tool.poetry.{field_name}",
                    )
                )

        hooks: list[Hook] = []
        build = data.get("build-system") or {}
        backend = build.get("build-backend")
        if isinstance(backend, str) and backend.startswith("."):
            # A local build backend is code in this repository that runs during
            # every build, including inside the packaging environment.
            hooks.append(
                Hook(
                    kind="build",
                    path=content.path,
                    name="build-backend",
                    command=backend,
                    ecosystem=self.id,
                )
            )

        return Manifest(
            path=content.path,
            ecosystem=self.id,
            name=PypiEcosystem._str_or_none(project.get("name"))
            or PypiEcosystem._str_or_none(poetry.get("name")),
            version=PypiEcosystem._str_or_none(project.get("version"))
            or PypiEcosystem._str_or_none(poetry.get("version")),
            dependencies=tuple(declared),
            hooks=tuple(hooks),
        )

    def _parse_setup_py(self, content: FileContent) -> Manifest:
        """Recover metadata from setup.py without executing it.

        ``ast.parse`` builds a syntax tree and runs nothing. Only literal
        arguments are read; anything computed is deliberately ignored rather
        than evaluated, because evaluating it is the attack.

        The file is always registered as a build hook regardless of what is
        found, because its mere existence means arbitrary Python executes at
        install time.
        """
        hooks = (
            Hook(
                kind="build",
                path=content.path,
                name="setup.py",
                command="python setup.py",
                ecosystem=self.id,
            ),
        )

        try:
            tree = ast.parse(content.text, filename=content.path)
        except SyntaxError as exc:
            return Manifest(
                path=content.path,
                ecosystem=self.id,
                hooks=hooks,
                parse_error=f"could not parse: {exc}",
            )

        name: str | None = None
        version: str | None = None
        declared: list[DeclaredDependency] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            called = (
                func.id
                if isinstance(func, ast.Name)
                else func.attr
                if isinstance(func, ast.Attribute)
                else ""
            )
            if called != "setup":
                continue

            for keyword in node.keywords:
                if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                    if isinstance(keyword.value.value, str):
                        name = keyword.value.value
                elif keyword.arg == "version" and isinstance(keyword.value, ast.Constant):
                    if isinstance(keyword.value.value, str):
                        version = keyword.value.value
                elif keyword.arg == "install_requires":
                    declared.extend(
                        self._from_literal_list(keyword.value, Scope.RUNTIME, "install_requires")
                    )
                elif keyword.arg == "setup_requires":
                    declared.extend(
                        self._from_literal_list(keyword.value, Scope.BUILD, "setup_requires")
                    )
                elif keyword.arg == "tests_require":
                    declared.extend(
                        self._from_literal_list(keyword.value, Scope.TEST, "tests_require")
                    )

        return Manifest(
            path=content.path,
            ecosystem=self.id,
            name=name,
            version=version,
            dependencies=tuple(declared),
            hooks=hooks,
        )

    def _from_literal_list(
        self, node: ast.expr, scope: Scope, field_name: str
    ) -> list[DeclaredDependency]:
        """Read a list of string literals, ignoring anything computed."""
        if not isinstance(node, (ast.List, ast.Tuple)):
            return []
        out: list[DeclaredDependency] = []
        for element in node.elts:
            if isinstance(element, ast.Constant) and isinstance(element.value, str):
                parsed = self._declared(element.value, scope, field_name)
                if parsed:
                    out.append(parsed)
        return out

    def _parse_requirements(self, content: FileContent) -> Manifest:
        declared: list[DeclaredDependency] = []
        for raw in content.text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                # Options such as -r, -c, --index-url and --hash continuations.
                continue
            parsed = self._declared(line, Scope.RUNTIME, content.basename)
            if parsed:
                declared.append(parsed)
        return Manifest(path=content.path, ecosystem=self.id, dependencies=tuple(declared))

    def _parse_pipfile(self, content: FileContent) -> Manifest:
        try:
            data = tomllib.loads(content.text)
        except (tomllib.TOMLDecodeError, ValueError) as exc:
            return Manifest(
                path=content.path, ecosystem=self.id, parse_error=f"invalid TOML: {exc}"
            )
        declared: list[DeclaredDependency] = []
        for section, scope in (("packages", Scope.RUNTIME), ("dev-packages", Scope.DEV)):
            for pkg, spec in (data.get(section) or {}).items():
                text = spec if isinstance(spec, str) else PypiEcosystem._poetry_spec(spec)
                declared.append(
                    DeclaredDependency(name=str(pkg), spec=text, scope=scope, field_name=section)
                )
        return Manifest(path=content.path, ecosystem=self.id, dependencies=tuple(declared))

    @staticmethod
    def _declared(spec: str, scope: Scope, field_name: str) -> DeclaredDependency | None:
        text = spec.split(";", 1)[0].strip()  # drop the environment marker
        if not text or text.startswith("-"):
            return None
        if "@" in text and not text.startswith("@"):
            # PEP 508 direct reference: `name @ https://...`
            name, _, url = text.partition("@")
            return DeclaredDependency(
                name=name.strip(), spec=url.strip(), scope=scope, field_name=field_name
            )
        match = _REQUIREMENT.match(text)
        if not match:
            return None
        return DeclaredDependency(
            name=match.group(1),
            spec=_spec_of(match.group(2)) or "*",
            scope=scope,
            field_name=field_name,
        )

    # -- Lockfiles -------------------------------------------------------

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        name = content.basename
        if name == "poetry.lock":
            return self._parse_poetry_lock(content)
        if name == "Pipfile.lock":
            return self._parse_pipfile_lock(content)
        if name in {"pdm.lock", "uv.lock"}:
            return self._parse_poetry_lock(content)  # same TOML package-table shape
        if name.startswith("requirements"):
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
        entries: list[LockEntry] = []
        for package in data.get("package") or []:
            if not isinstance(package, dict):
                continue
            name = PypiEcosystem._str_or_none(package.get("name"))
            if not name:
                continue
            category = str(package.get("category", "main"))
            entries.append(
                LockEntry(
                    name=name,
                    version=str(package.get("version", "")),
                    integrity=PypiEcosystem._first_hash(package),
                    resolved_from=PypiEcosystem._str_or_none(
                        (package.get("source") or {}).get("url")
                    ),
                    scope=Scope.DEV if category == "dev" else Scope.RUNTIME,
                    dependencies=tuple(sorted((package.get("dependencies") or {}).keys())),
                )
            )
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))

    def _parse_pipfile_lock(self, content: FileContent) -> LockGraph:
        import json

        try:
            data = json.loads(content.text)
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
                entries.append(
                    LockEntry(
                        name=str(name),
                        version=str(meta.get("version", "")).lstrip("="),
                        integrity=str(hashes[0]) if hashes else None,
                        scope=scope,
                        direct=True,
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
        current_hashes: list[str] = []
        pending: tuple[str, str] | None = None

        def flush() -> None:
            nonlocal pending, current_hashes
            if pending:
                entries.append(
                    LockEntry(
                        name=pending[0],
                        version=pending[1],
                        integrity=current_hashes[0] if current_hashes else None,
                        direct=True,
                    )
                )
            pending, current_hashes = None, []

        for raw in content.text.splitlines():
            stripped = raw.split("#", 1)[0].strip()
            if not stripped:
                continue
            if stripped.startswith("--hash="):
                current_hashes.append(stripped[len("--hash=") :])
                continue
            if stripped.startswith("-"):
                continue
            flush()
            name, sep, version = stripped.partition("==")
            if sep:
                # Options may follow the pin on the same line -- `--hash=` is
                # the common one and is legal there. Cutting only at `;` read
                # them as part of the version.
                pending = (
                    name.strip().split("[", 1)[0],
                    _version_of(version),
                )
        flush()
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))


__all__ = ["PypiEcosystem"]
