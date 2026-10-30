"""Package checks: a package named by an agent, turned into something the scanner reads exactly.

A package and version become the lockfile a project depending on that release would hold, written
into a private temporary directory and scanned offline. The verdict is therefore the one a real
project would get -- malicious releases, known vulnerabilities, typosquats, documented AI
hallucinations, manifest checks -- from the same detectors, not from a second implementation that
could drift from them. Each form below was checked against a real affected release in each
ecosystem (`tests/unit/mcp/test_mcp_packages.py`).

An install command (`npm install a b@2`, `pip install -r x`, `cargo add c`) is split into the
packages it names, with what cannot be checked by name said rather than skipped: a URL, a git
source, a local path, a custom index.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Any, ClassVar, Final

#: The ecosystems a package check accepts, by the name the advisory database uses.
ECOSYSTEMS: Final[tuple[str, ...]] = (
    "npm",
    "pypi",
    "cargo",
    "gomod",
    "maven",
    "nuget",
    "composer",
    "rubygems",
    "pub",
    "hex",
    "cran",
    "swift",
)

#: Package-URL types for the ecosystems whose published archive the scanner can fetch and scan.
FETCHABLE: Final[dict[str, str]] = {
    "npm": "npm",
    "pypi": "pypi",
    "cargo": "cargo",
    "rubygems": "gem",
    "nuget": "nuget",
    "gomod": "golang",
    "hex": "hex",
    "pub": "pub",
    "maven": "maven",
}

ALIASES: Final[dict[str, str]] = {
    "pip": "pypi",
    "python": "pypi",
    "node": "npm",
    "javascript": "npm",
    "crates": "cargo",
    "crates.io": "cargo",
    "rust": "cargo",
    "go": "gomod",
    "golang": "gomod",
    "gem": "rubygems",
    "ruby": "rubygems",
    "packagist": "composer",
    "php": "composer",
    "dart": "pub",
    "flutter": "pub",
    "elixir": "hex",
    "erlang": "hex",
    "r": "cran",
    "swiftpm": "swift",
    "dotnet": "nuget",
    ".net": "nuget",
    "java": "maven",
    "gradle": "maven",
}

_NAME: Final = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9@._~+:/-]{0,213}$")
_VERSION: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~!-]{0,127}$")


class PackageError(ValueError):
    """A package the caller named that cannot be checked as named."""


@dataclass(frozen=True, slots=True)
class PackageSpec:
    ecosystem: str
    name: str
    version: str | None = None
    note: str = ""
    """Why the version is absent, or anything else the caller should know about this entry."""

    @staticmethod
    def ecosystem_of(value: str) -> str:
        key = value.strip().lower()
        key = ALIASES.get(key, key)
        if key not in ECOSYSTEMS:
            raise PackageError(
                f"unsupported ecosystem {value!r}; supported: {', '.join(ECOSYSTEMS)}"
            )
        return key

    @classmethod
    def of(
        cls, ecosystem: str, name: str, version: str | None = None, note: str = ""
    ) -> PackageSpec:
        eco = cls.ecosystem_of(ecosystem)
        name = name.strip()
        if not _NAME.match(name) or ".." in name or "\\" in name:
            raise PackageError(f"not a valid {eco} package name: {name[:80]!r}")
        if eco == "maven" and name.count(":") != 1:
            raise PackageError(f"a Maven package is named group:artifact, not {name!r}")
        if version is not None:
            version = version.strip().removeprefix("v") if eco != "gomod" else version.strip()
            if not version:
                version = None
            elif not _VERSION.match(version):
                raise PackageError(f"not a valid version for {name}: {version[:40]!r}")
        return cls(eco, name, version, note)

    @property
    def label(self) -> str:
        return f"{self.ecosystem}:{self.name}" + (f"@{self.version}" if self.version else "")

    @property
    def purl(self) -> str | None:
        kind = FETCHABLE.get(self.ecosystem)
        if kind is None:
            return None
        name = self.name.replace(":", "/") if self.ecosystem == "maven" else self.name
        return f"pkg:{kind}/{name}" + (f"@{self.version}" if self.version else "")


class Lockfiles:
    """The files a project depending on these packages would hold."""

    @staticmethod
    def write(specs: list[PackageSpec]) -> dict[str, str]:
        """`{relative path: content}` -- one subdirectory per ecosystem, so two ecosystems' lockfiles
        never share a project and every dependency is read as its own ecosystem's."""
        files: dict[str, str] = {}
        by_eco: dict[str, list[PackageSpec]] = {}
        for spec in specs:
            by_eco.setdefault(spec.ecosystem, []).append(spec)
        for eco, group in by_eco.items():
            pinned = [s for s in group if s.version]
            loose = [s for s in group if not s.version]
            if pinned:
                for name, body in Lockfiles._pinned(eco, pinned).items():
                    files[f"{eco}-pinned/{name}"] = body
            if loose:
                for name, body in Lockfiles._loose(eco, loose).items():
                    files[f"{eco}-names/{name}"] = body
        return files

    @staticmethod
    def _project(eco: str) -> Any:
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        project = EcosystemRegistry.get(eco)
        if project is None:
            raise PackageError(f"unsupported ecosystem {eco!r}")
        return project

    @staticmethod
    def _pinned(eco: str, specs: list[PackageSpec]) -> dict[str, str]:
        """The ecosystem's own lockfile pinning these releases (EcosystemProjects)."""
        files = Lockfiles._project(eco).pinned_project([(s.name, s.version or "") for s in specs])
        if files is None:
            raise PackageError(f"unsupported ecosystem {eco!r}")
        return dict(files)

    @staticmethod
    def _loose(eco: str, specs: list[PackageSpec]) -> dict[str, str]:
        """Names without a version: what the name alone can answer -- typosquat, documented
        hallucination, a name that only ever carried malware. No version is invented."""
        try:
            files = Lockfiles._project(eco).loose_project([s.name for s in specs])
        except ValueError as exc:  # an ecosystem that records nothing without a version
            raise PackageError(str(exc)) from exc
        if files is None:
            raise PackageError(f"unsupported ecosystem {eco!r}")
        return dict(files)


@dataclass(slots=True)
class ParsedCommand:
    packages: list[PackageSpec] = field(default_factory=list)
    unchecked: list[str] = field(default_factory=list)
    """Things the command installs that cannot be checked by name: URLs, git, paths, files."""
    warnings: list[str] = field(default_factory=list)
    """Choices in the command that change where code comes from: a custom index or registry."""
    commands: list[str] = field(default_factory=list)
    """Each simple command found, as written."""


class InstallCommand:
    """Splits shell text into the package installs it performs."""

    _SEPARATORS: ClassVar[re.Pattern[str]] = re.compile(r"\s*(?:&&|\|\||;|\n|\|)\s*")
    _ENV: ClassVar[re.Pattern[str]] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
    #: Flags that take a value as the next word, per tool; the value is not a package.
    _VALUED: ClassVar[dict[str, frozenset[str]]] = {
        # The npm family differs: -w names a workspace in npm and is a switch in pnpm.
        "npm": frozenset(
            {
                "--registry",
                "--prefix",
                "-w",
                "--workspace",
                "--tag",
                "--cache",
                "--userconfig",
                "-p",
                "--package",
            }
        ),
        "npx": frozenset(
            {
                "--registry",
                "--prefix",
                "-w",
                "--workspace",
                "--cache",
                "--userconfig",
                "-p",
                "--package",
                "-c",
                "--call",
            }
        ),
        "pnpm": frozenset(
            {"--registry", "--filter", "-F", "-C", "--dir", "--store-dir", "--config.registry"}
        ),
        "yarn": frozenset({"--registry", "--cwd", "--cache-folder", "--modules-folder"}),
        "bun": frozenset({"--registry", "--cwd", "--cache-dir", "-c", "--config"}),
        "pypi": frozenset(
            {
                "-c",
                "--constraint",
                "-t",
                "--target",
                "--prefix",
                "--root",
                "--python",
                "-p",
                "--platform",
                "--python-version",
                "--implementation",
                "--abi",
                "--src",
                "--upgrade-strategy",
                "--group",
                "--source",
                "--with",
                "--extras",
                "-E",
                "--optional",
                "--spec",
            }
        ),
        "cargo": frozenset(
            {
                "--version",
                "--vers",
                "--git",
                "--branch",
                "--tag",
                "--rev",
                "--path",
                "--registry",
                "--index",
                "--root",
                "-F",
                "--features",
                "--target",
                "-p",
                "--package",
                "--rename",
            }
        ),
        "rubygems": frozenset(
            {
                "-v",
                "--version",
                "--source",
                "-i",
                "--install-dir",
                "-n",
                "--bindir",
                "--platform",
                "--group",
                "--git",
                "--branch",
                "--path",
            }
        ),
        "gomod": frozenset({"-modfile", "-C", "-tags"}),
        "nuget": frozenset(
            {
                "-v",
                "--version",
                "-s",
                "--source",
                "-f",
                "--framework",
                "--package-directory",
                "-Version",
                "-Source",
                "-OutputDirectory",
            }
        ),
        "composer": frozenset({"-d", "--working-dir"}),
    }
    _REGISTRY: ClassVar[dict[str, str]] = {
        "registry": "installs from a registry named on the command line",
        "index": "installs from a package index named on the command line",
        "extra": "adds a second package index: a name on both is taken from whichever has the higher version (dependency confusion)",
        "trusted": "turns off TLS verification for a host",
        "links": "also installs from links on a page named on the command line",
        "source": "installs from a source named on the command line",
    }
    #: Flags that change where code comes from, per ecosystem: `-i` is pip's index and gem's
    #: install directory, so one table for every tool would warn about the wrong things.
    _REGISTRY_FLAGS: ClassVar[dict[str, dict[str, str]]] = {
        "npm": {"--registry": "registry"},
        "pypi": {
            "-i": "index",
            "--index-url": "index",
            "--extra-index-url": "extra",
            "--trusted-host": "trusted",
            "-f": "links",
            "--find-links": "links",
            "--index": "index",
            "--default-index": "index",
        },
        "cargo": {"--registry": "registry", "--index": "index"},
        "rubygems": {"--source": "source", "-s": "source"},
        "nuget": {"-s": "source", "--source": "source", "-Source": "source"},
        "composer": {"--repository": "source"},
    }

    @classmethod
    def parse(cls, text: str) -> ParsedCommand:
        if len(text) > 16_000:
            raise PackageError("command is longer than 16000 characters")
        out = ParsedCommand()
        for part in cls._SEPARATORS.split(text.strip()):
            if not part:
                continue
            try:
                words = shlex.split(part, posix=True)
            except ValueError as exc:
                raise PackageError(f"cannot read the command: {exc}") from exc
            while words and (
                words[0] in {"sudo", "doas", "env", "command", "exec", "time", "nice"}
                or cls._ENV.match(words[0])
            ):
                words.pop(0)
            if not words:
                continue
            found = cls._one(words, out)
            if found:
                out.commands.append(part)
        return out

    @classmethod
    def _one(cls, words: list[str], out: ParsedCommand) -> bool:
        tool = words[0].rsplit("/", 1)[-1]
        rest = words[1:]
        # python -m pip install ... / python3 -m pip ...
        if (
            re.fullmatch(r"python[0-9.]*|py", tool)
            and len(rest) >= 2
            and rest[0] == "-m"
            and rest[1] in {"pip", "pip3"}
        ):
            tool, rest = "pip", rest[2:]
        if tool in {"npm", "pnpm", "yarn", "bun", "cnpm"}:
            sub = rest[0] if rest else ""
            if tool == "yarn" and sub == "global":
                rest, sub = rest[1:], (rest[1] if len(rest) > 1 else "")
            if sub in {"dlx", "x", "exec"} and tool != "npm":
                cls._npm_args(rest[1:], out, first_only=True, tool=tool)
                return True
            if sub not in {
                "install",
                "i",
                "add",
                "isntall",
                "in",
                "ins",
                "inst",
                "insta",
                "instal",
                "isnt",
                "isnta",
                "isntal",
            }:
                return False
            cls._npm_args(rest[1:], out, tool="npm" if tool == "cnpm" else tool)
            return True
        if tool in {"npx", "bunx", "pnpx"}:
            cls._npm_args(
                rest, out, first_only=True, tool={"bunx": "bun", "pnpx": "pnpm"}.get(tool, "npx")
            )
            return True
        if tool in {
            "pip",
            "pip3",
            "pipx",
            "uv",
            "poetry",
            "pdm",
            "rye",
            "uvx",
            "pipenv",
            "conda",
            "mamba",
        }:
            return cls._python(tool, rest, out)
        if tool == "cargo" and rest and rest[0] in {"add", "install"}:
            cls._generic(
                "cargo", rest[1:], out, version_flags={"--version", "--vers"}, at_version=True
            )
            return True
        if tool in {"gem"} and rest and rest[0] == "install":
            cls._generic("rubygems", rest[1:], out, version_flags={"-v", "--version"})
            return True
        if tool == "bundle" and rest and rest[0] == "add":
            cls._generic("rubygems", rest[1:], out, version_flags={"-v", "--version"})
            return True
        if tool == "go" and rest and rest[0] in {"get", "install"}:
            cls._generic("gomod", rest[1:], out, version_flags=set(), at_version=True, keep_v=True)
            return True
        if tool == "dotnet" and "package" in rest and rest[: rest.index("package")][:1] == ["add"]:
            cls._generic(
                "nuget",
                rest[rest.index("package") + 1 :],
                out,
                version_flags={"-v", "--version"},
                single=True,
            )
            return True
        if tool in {"nuget", "nuget.exe"} and rest and rest[0].lower() == "install":
            cls._generic(
                "nuget", rest[1:], out, version_flags={"-Version", "-version"}, single=True
            )
            return True
        if tool == "composer" and rest and rest[0] in {"require", "req"}:
            cls._composer(rest[1:], out)
            return True
        if tool in {"brew", "apt", "apt-get", "yum", "dnf", "apk", "choco", "winget", "port"}:
            out.unchecked.append(f"{tool}: system packages are not checked by name here")
            return True
        return False

    @classmethod
    def _flags(cls, eco: str, args: list[str], out: ParsedCommand, tool: str = "") -> list[str]:
        """The words that are not flags or flag values; registry-changing flags become warnings."""
        registry = cls._REGISTRY_FLAGS.get(eco, {})
        valued = cls._VALUED.get(tool or eco, cls._VALUED.get(eco, frozenset())) | frozenset(
            registry
        )
        positional: list[str] = []
        skip = False
        for i, word in enumerate(args):
            if skip:
                skip = False
                continue
            flag, _, inline = word.partition("=")
            if flag in registry:
                value = inline or (args[i + 1] if i + 1 < len(args) else "")
                out.warnings.append(f"{flag} {value}: {cls._REGISTRY[registry[flag]]}")
            if word.startswith("-"):
                if flag in valued and not inline:
                    skip = True
                if flag in {"-r", "--requirement", "-e", "--editable"}:
                    value = inline or (args[i + 1] if i + 1 < len(args) else "")
                    out.unchecked.append(
                        f"{flag} {value}: a file or editable path; scan it with scan_path".strip()
                    )
                    skip = not inline
                continue
            positional.append(word)
        return positional

    @classmethod
    def _source(cls, word: str) -> bool:
        """A URL, git source, archive or local path: installed, but not a registry name."""
        return bool(
            re.match(
                r"^(?:[a-z+]+://|git\+|git@|github:|gitlab:|bitbucket:|file:|link:|portal:|workspace:|\.{0,2}/|~/)",
                word,
            )
            or re.search(r"\.(?:tgz|tar\.gz|zip|whl|tar|gem|nupkg|crate)$", word)
        )

    @classmethod
    def _npm_args(
        cls, args: list[str], out: ParsedCommand, *, first_only: bool = False, tool: str = "npm"
    ) -> None:
        if first_only:
            # `npx -p pkg cmd` / `npx --package=pkg cmd`: the packages are the -p values, the first
            # word after them is the command they provide.
            named = [
                (word.partition("=")[2] or (args[i + 1] if i + 1 < len(args) else ""))
                for i, word in enumerate(args)
                if word.partition("=")[0] in {"-p", "--package"}
            ]
            if named:
                for word in named:
                    if word:
                        cls._npm_one(word, out)
                cls._flags("npm", args, out, tool)
                return
        for word in cls._flags("npm", args, out, tool):
            cls._npm_one(word, out)
            if first_only:
                break

    @classmethod
    def _npm_one(cls, word: str, out: ParsedCommand) -> None:
        if cls._source(word):
            out.unchecked.append(f"{word}: not a registry package")
            return
        if word.startswith("npm:"):
            word = word[4:]
        if "@npm:" in word[1:]:
            # `alias@npm:real@1.0.0` installs `real` under another name: `real` is what is fetched.
            cls._npm_one(word[word.index("@npm:", 1) + 5 :], out)
            return
        name, version = word, None
        at = word.rfind("@")
        if at > 0:
            name, version = word[:at], word[at + 1 :]
        if name.count("/") == 1 and not name.startswith("@"):
            out.unchecked.append(f"{word}: a GitHub shorthand, not a registry package")
            return
        cls._add(out, "npm", name, version)

    @classmethod
    def _python(cls, tool: str, rest: list[str], out: ParsedCommand) -> bool:
        if tool in {"conda", "mamba"}:
            if rest[:1] == ["install"]:
                out.unchecked.append(
                    f"{tool}: conda packages are checked by scanning an environment file"
                )
                return True
            return False
        if tool == "uvx":
            args = rest
        elif tool == "uv":
            if rest[:2] == ["pip", "install"]:
                args = rest[2:]
            elif rest[:1] in (["add"], ["tool"]):
                args = (
                    rest[1:]
                    if rest[0] == "add"
                    else (rest[2:] if rest[1:2] in (["install"], ["run"]) else [])
                )
            else:
                return False
        elif tool == "pipx":
            if rest[:1] not in (["install"], ["run"], ["inject"]):
                return False
            args = rest[1:] if rest[0] != "inject" else rest[2:]
        elif tool in {"poetry", "pdm", "rye"}:
            if rest[:1] != ["add"]:
                return False
            args = rest[1:]
        elif tool == "pipenv":
            if rest[:1] != ["install"]:
                return False
            args = rest[1:]
        else:
            if rest[:1] not in (["install"], ["download"]):
                return False
            args = rest[1:]
        for word in cls._flags("pypi", args, out):
            if cls._source(word) or " @ " in word or word.startswith("@"):
                out.unchecked.append(f"{word}: not a registry package")
                continue
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(.*)$", word)
            if not m:
                out.unchecked.append(f"{word}: not a package name")
                continue
            name, spec = m.group(1), m.group(2).strip()
            exact = re.fullmatch(r"===?\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)", spec)
            if spec and not exact:
                cls._add(
                    out,
                    "pypi",
                    name,
                    None,
                    note=f"range {spec}: the version is chosen at install time",
                )
            else:
                cls._add(out, "pypi", name, exact.group(1) if exact else None)
            if (tool in {"uvx", "pipx"} and rest[:1] == ["run"]) or tool == "uvx":
                break
        return True

    @classmethod
    def _generic(
        cls,
        eco: str,
        args: list[str],
        out: ParsedCommand,
        *,
        version_flags: set[str],
        at_version: bool = False,
        keep_v: bool = False,
        single: bool = False,
    ) -> None:
        version_flag_value: str | None = None
        for i, word in enumerate(args):
            flag, _, inline = word.partition("=")
            if flag in version_flags:
                version_flag_value = inline or (args[i + 1] if i + 1 < len(args) else None)
        for word in cls._flags(eco, args, out):
            if cls._source(word):
                out.unchecked.append(f"{word}: not a registry package")
                continue
            name, version = word, version_flag_value
            if at_version and "@" in word:
                name, version = word.split("@", 1)
                if eco == "gomod" and version in {"latest", "upgrade", "patch", "none"}:
                    version = None
            if eco == "gomod" and version and not keep_v:
                version = version.removeprefix("v")
            cls._add(out, eco, name, version)
            if single:
                break

    @classmethod
    def _composer(cls, args: list[str], out: ParsedCommand) -> None:
        for word in cls._flags("composer", args, out):
            name, _, constraint = word.partition(":")
            exact = (
                constraint
                if re.fullmatch(r"v?\d+(?:\.\d+){0,3}(?:-[A-Za-z0-9.]+)?", constraint)
                else None
            )
            note = (
                f"constraint {constraint}: the version is chosen at install time"
                if constraint and not exact
                else ""
            )
            cls._add(out, "composer", name, exact, note=note)

    @staticmethod
    def _add(out: ParsedCommand, eco: str, name: str, version: str | None, note: str = "") -> None:
        if version and not _VERSION.match(version.removeprefix("v")):
            note = (
                note or f"version {version}: a range or tag; the version is chosen at install time"
            )
            version = None
        try:
            out.packages.append(PackageSpec.of(eco, name, version, note))
        except PackageError as exc:
            out.unchecked.append(str(exc))
