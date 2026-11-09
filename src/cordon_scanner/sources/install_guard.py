"""Packages checked before they are installed: `cordon npm install ...`, `cordon pip install ...`.

`clone` and `pull` scan code before git writes it; this does the same for a package manager, which
is the larger door. `npm install` runs every lifecycle script in the tree it resolves, and
`pip install` runs an sdist's `setup.py` merely to learn its dependencies, so a scan *after* the
install is a scan of a machine that has already run the payload.

    resolve       npm: --package-lock-only --ignore-scripts, in a private copy of the project
                  pip: --dry-run --report, wheels only; an sdist only once Cordon has scanned it
    fetch         every file, host-pinned and redirect-free, checked against the registry's hash
    scan          those files, once, with Cordon's defaults: the packages cannot configure it
    install       blocked: nothing is installed, and each package is named with what pulls it in
                  clean: exactly the scanned files, pinned by hash (`npm ci`; pip --require-hashes)

Fail closed throughout: a file with no registry hash, a host the fetcher does not trust, a resolve
the package manager could not finish, a scan with nothing to read. Design: package
`reviews/install-guard/01-DESIGN.md`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.parse
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.foundation.errors import ConfigError, SourceError
from cordon_scanner.version import PROGRAM

if TYPE_CHECKING:
    from cordon_scanner.foundation.models import Finding

#: Runs a package manager: argv, working directory, environment. The real one is `subprocess.run`;
#: tests pass their own.
Runner = Callable[[Sequence[str], Path, dict[str, str]], "subprocess.CompletedProcess[str]"]
#: Fetches one file's bytes from a registry host: (url, ecosystem). The real one is host-pinned.
Fetcher = Callable[[str, str], bytes]
#: Scans a directory of fetched files and returns the findings that block the install.
Scanner = Callable[[Path], "tuple[Finding, ...]"]

MAX_SDIST_ROUNDS: Final = 25
"""How many sdist-only requirements one pip resolve may need before Cordon stops asking."""


class InstallRefused(SourceError):
    """The install cannot be checked, so it does not happen. Safe to show."""


@dataclass(frozen=True, slots=True)
class PackageFile:
    """One file the package manager would install, and the hash the registry publishes for it."""

    ecosystem: str
    name: str
    version: str
    url: str
    algorithm: str  # "sha512" (npm integrity) or "sha256" (PyPI)
    digest: bytes
    requested: bool = False
    required_by: tuple[str, ...] = ()
    #: How the ecosystem writes a pinned version: `name@1.0` (npm), `name==1.0` (PyPI).
    separator: str = "@"
    #: Needed only to build an sdist (its `build-system.requires`): scanned and offered to the build,
    #: never installed into the person's environment.
    build_only: bool = False

    @property
    def label(self) -> str:
        return f"{self.name}{self.separator}{self.version}"

    @property
    def filename(self) -> str:
        """A name for the file on disk: the URL's own, made safe, prefixed so two packages never collide."""
        tail = urllib.parse.unquote(urllib.parse.urlsplit(self.url).path.rsplit("/", 1)[-1])
        safe = re.sub(r"[^A-Za-z0-9._+-]", "_", tail)[:150] or "package"
        prefix = re.sub(r"[^A-Za-z0-9._-]", "_", f"{self.name}-{self.version}")[:80]
        return safe if safe.startswith(prefix) else f"{prefix}--{safe}"

    def verify(self, data: bytes) -> None:
        if hashlib.new(self.algorithm, data).digest() != self.digest:
            raise InstallRefused(
                f"{self.label} does not match the {self.algorithm} its registry publishes"
            )


@dataclass
class InstallPlan:
    """What a resolve says would be installed, and how to install exactly that afterwards."""

    ecosystem: str
    files: list[PackageFile] = field(default_factory=list)
    #: npm: the resolved package.json and lockfile, written into the project only after a clean scan.
    manifests: dict[str, bytes] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class InstallVerdict:
    plan: InstallPlan
    blocking: dict[str, tuple[Finding, ...]]  # PackageFile.filename -> its blocking findings

    @property
    def ok(self) -> bool:
        return not self.blocking


class Subprocesses:
    """The package manager, run as the person who typed the command: their PATH, config and auth."""

    @staticmethod
    def run(
        argv: Sequence[str], cwd: Path, env: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - absolute executable, fixed argv, no shell
            list(argv), cwd=cwd, env=env, text=True, capture_output=True, check=False
        )

    @staticmethod
    def executable(tool: str) -> str:
        found = shutil.which(tool)
        if not found:
            raise ConfigError(
                f"{tool} is not on PATH", hint=f"Install {tool}, or run Cordon where it is."
            )
        return found


class PrivateDirectory:
    @staticmethod
    @contextmanager
    def made(prefix: str) -> Iterator[Path]:
        """A 0700 temporary directory, removed however the block ends."""
        from cordon_scanner.foundation.files.trees import Trees

        directory = Path(tempfile.mkdtemp(prefix=prefix))
        try:
            directory.chmod(stat.S_IRWXU)
            yield directory
        finally:
            Trees.remove(directory)


class NpmPlanner:
    """npm's own resolver, run so that it writes a lockfile and nothing else."""

    INSTALLS: ClassVar[frozenset[str]] = frozenset(
        {"install", "i", "add", "ci", "update", "up", "in", "isntall"}
    )
    COPIED: ClassVar[tuple[str, ...]] = (
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        ".npmrc",
    )
    TRUSTED_HOSTS: ClassVar[frozenset[str]] = frozenset({"registry.npmjs.org"})

    @classmethod
    def plan(cls, project: Path, args: Sequence[str], runner: Runner, npm: str) -> InstallPlan:
        manifest = project / "package.json"
        if manifest.is_file():
            document = json.loads(manifest.read_text(encoding="utf-8") or "{}")
            if isinstance(document, dict) and document.get("workspaces"):
                raise InstallRefused(
                    "workspaces are not checked yet: Cordon would resolve one package of the tree",
                    hint=f"Run `{PROGRAM} scan` on the lockfile, or install workspaces after checking each.",
                )
        with PrivateDirectory.made("cordon-npm-") as scratch:
            for name in cls.COPIED:
                if (project / name).is_file():
                    shutil.copyfile(project / name, scratch / name)
            if not (scratch / "package.json").is_file():
                (scratch / "package.json").write_text("{}\n", encoding="utf-8")
            sub = list(args[:1]) or ["install"]
            # `ci` installs the lockfile as it stands; resolving it is `install` with the lock kept.
            verb = ["install"] if sub[0] == "ci" else sub
            argv = [
                npm,
                *verb,
                *args[1:],
                "--package-lock-only",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
            ]
            done = runner(argv, scratch, {**os.environ})
            if done.returncode != 0:
                raise InstallRefused(
                    f"npm could not resolve the install:\n{done.stderr.strip()[-2000:]}"
                )
            lock_path = scratch / "package-lock.json"
            if not lock_path.is_file():
                raise InstallRefused("npm resolved but wrote no package-lock.json")
            lock = lock_path.read_bytes()
            plan = InstallPlan("npm", cls.files(json.loads(lock)))
            plan.manifests = {
                "package.json": (scratch / "package.json").read_bytes(),
                "package-lock.json": lock,
            }
            return plan

    @classmethod
    def files(cls, lock: dict[str, Any]) -> list[PackageFile]:
        """Every registry package in a lockfile (v2/v3), with what depends on it."""
        packages = lock.get("packages")
        if not isinstance(packages, dict):
            raise InstallRefused("the lockfile has no `packages` map (npm 7 or later writes one)")
        top = packages.get("")
        root: dict[str, Any] = top if isinstance(top, dict) else {}
        direct = {
            name
            for key in ("dependencies", "devDependencies", "optionalDependencies")
            for name in (root.get(key) or {})
        }
        dependents = cls._dependents(packages)
        out: list[PackageFile] = []
        for path, entry in packages.items():
            if (
                not path
                or not isinstance(entry, dict)
                or entry.get("link")
                or entry.get("inBundle")
            ):
                # The root is the project; a link is local code; a bundled package is inside its parent's tarball.
                continue
            name = str(entry.get("name") or path.rsplit("node_modules/", 1)[-1])
            version, url, integrity = (
                str(entry.get("version") or ""),
                entry.get("resolved"),
                entry.get("integrity"),
            )
            if not isinstance(url, str) or not url.startswith("https://"):
                raise InstallRefused(
                    f"{name}@{version} does not come from a registry Cordon can fetch ({url!r})"
                )
            host = urllib.parse.urlsplit(url).hostname or ""
            if host not in cls.TRUSTED_HOSTS:
                raise InstallRefused(
                    f"{name}@{version} resolves to {host}, which Cordon does not fetch from yet",
                    hint=f"Install from the public npm registry, or scan that registry's tarball with `{PROGRAM} scan`.",
                )
            if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
                raise InstallRefused(f"{name}@{version} has no sha512 integrity in the lockfile")
            out.append(
                PackageFile(
                    "npm",
                    name,
                    version,
                    url,
                    "sha512",
                    base64.b64decode(integrity.removeprefix("sha512-").split()[0]),
                    requested=path == f"node_modules/{name}" and name in direct,
                    required_by=tuple(sorted(dependents.get(path, ()))),
                )
            )
        return out

    @staticmethod
    def _dependents(packages: dict[str, Any]) -> dict[str, set[str]]:
        """Which packages need each lockfile entry, by node's own lookup: nearest node_modules upward."""
        out: dict[str, set[str]] = {}
        for path, entry in packages.items():
            if not isinstance(entry, dict):
                continue
            needs = {
                name
                for key in ("dependencies", "optionalDependencies", "peerDependencies")
                for name in (entry.get(key) or {})
            }
            who = (
                str(entry.get("name") or path.rsplit("node_modules/", 1)[-1])
                if path
                else "your project"
            )
            for dep in needs:
                base = path
                while True:
                    candidate = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
                    if candidate in packages:
                        out.setdefault(candidate, set()).add(who)
                        break
                    if not base:
                        break
                    cut = base.rfind("/node_modules/")
                    base = base[:cut] if cut > 0 else ""
        return out


class PipPlanner:
    """pip's own resolver in `--dry-run --report` mode, never allowed to build an unscanned sdist."""

    NO_WHEEL: ClassVar[re.Pattern[str]] = re.compile(
        r"No matching distribution found for ([A-Za-z0-9._-]+)"
    )
    PIN: ClassVar[re.Pattern[str]] = re.compile(r"^([A-Za-z0-9._-]+)==([A-Za-z0-9._+!-]+)$")
    TRUSTED_HOSTS: ClassVar[frozenset[str]] = frozenset({"files.pythonhosted.org"})
    LOCAL: ClassVar[tuple[str, ...]] = ("-e", "--editable", ".", "./", "file:")

    @classmethod
    def plan(
        cls,
        args: Sequence[str],
        runner: Runner,
        pip: str,
        scan_sdist: Callable[[str, str], tuple[str, tuple[str, ...]]],
    ) -> InstallPlan:
        """`scan_sdist(name, version)` fetches, verifies and scans one sdist and returns the version it
        passed with that sdist's build requirements, or raises `InstallRefused` when it is blocked."""
        if any(a in cls.LOCAL or a.startswith(cls.LOCAL[3:]) for a in args):
            raise InstallRefused(
                "local and editable installs are not checked yet: they would build code Cordon has not read",
                hint="Install the registry packages through Cordon, then the local project with pip.",
            )
        allowed: dict[str, str] = {}
        build: set[str] = set()
        with PrivateDirectory.made("cordon-pip-") as scratch:
            report, constraints = scratch / "report.json", scratch / "constraints.txt"
            for _ in range(MAX_SDIST_ROUNDS):
                constraints.write_text(
                    "".join(f"{n}=={v}\n" for n, v in allowed.items()), encoding="utf-8"
                )
                argv = [
                    pip,
                    "install",
                    "--dry-run",
                    "--quiet",
                    "--ignore-installed",
                    "--report",
                    str(report),
                    "--only-binary=:all:",
                    "-c",
                    str(constraints),
                ]
                argv += [f"--no-binary={name}" for name in allowed]
                done = runner([*argv, *args], scratch, {**os.environ, "PIP_NO_INPUT": "1"})
                if done.returncode == 0:
                    files = cls.files(json.loads(report.read_text(encoding="utf-8")))
                    return InstallPlan(
                        "pypi", files + cls._build_files(build, files, runner, pip, scratch)
                    )
                missing = cls.NO_WHEEL.search(done.stderr or "")
                if missing is None or missing.group(1).lower() in {n.lower() for n in allowed}:
                    raise InstallRefused(
                        f"pip could not resolve the install:\n{(done.stderr or '').strip()[-2000:]}"
                    )
                name = missing.group(1)
                allowed[name], requires = scan_sdist(name, cls.pinned(args, name))
                build.update(requires)
        raise InstallRefused(
            f"more than {MAX_SDIST_ROUNDS} packages need a source build; install fewer at once"
        )

    @classmethod
    def _build_files(
        cls, requires: set[str], have: list[PackageFile], runner: Runner, pip: str, scratch: Path
    ) -> list[PackageFile]:
        """The wheels the scanned sdists need to build, resolved wheel-only: never installed, only
        offered to the build through the same scanned directory."""
        if not requires:
            return []
        report = scratch / "build-report.json"
        argv = [
            pip,
            "install",
            "--dry-run",
            "--quiet",
            "--ignore-installed",
            "--report",
            str(report),
            "--only-binary=:all:",
            *sorted(requires),
        ]
        done = runner(argv, scratch, {**os.environ, "PIP_NO_INPUT": "1"})
        if done.returncode != 0:
            raise InstallRefused(
                f"the build tools these sources need could not be resolved as wheels:\n{(done.stderr or '').strip()[-1500:]}"
            )
        names = {f.filename for f in have}
        found = cls.files(json.loads(report.read_text(encoding="utf-8")), build_only=True)
        return [f for f in found if f.filename not in names]

    @classmethod
    def pinned(cls, args: Sequence[str], name: str) -> str:
        """The version the person pinned for `name` on the command line, or "" for the latest."""
        for arg in args:
            m = cls.PIN.match(arg)
            if m and m.group(1).lower().replace("_", "-") == name.lower().replace("_", "-"):
                return m.group(2)
        return ""

    @classmethod
    def files(cls, report: dict[str, Any], *, build_only: bool = False) -> list[PackageFile]:
        out: list[PackageFile] = []
        for item in report.get("install") or ():
            meta = item.get("metadata") or {}
            info = item.get("download_info") or {}
            url = str(info.get("url") or "")
            name, version = str(meta.get("name") or ""), str(meta.get("version") or "")
            if (
                urllib.parse.urlsplit(url).hostname or ""
            ) not in cls.TRUSTED_HOSTS or not url.startswith("https://"):
                raise InstallRefused(
                    f"{name}=={version} does not come from PyPI's file host ({url[:120]!r})"
                )
            hashes = (info.get("archive_info") or {}).get("hashes") or {}
            digest = hashes.get("sha256") or str(
                (info.get("archive_info") or {}).get("hash", "")
            ).removeprefix("sha256=")
            if not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
                raise InstallRefused(f"{name}=={version} has no sha256 in pip's report")
            out.append(
                PackageFile(
                    "pypi",
                    name,
                    version,
                    url,
                    "sha256",
                    bytes.fromhex(digest),
                    bool(item.get("requested")),
                    separator="==",
                    build_only=build_only,
                )
            )
        return out


class BuildRequires:
    """An sdist's declared build requirements, read from its `pyproject.toml` in memory."""

    #: pip's own default for an sdist that declares no build system (PEP 517 fallback).
    DEFAULT: ClassVar[tuple[str, ...]] = ("setuptools>=40.8.0",)
    MEMBER: ClassVar[re.Pattern[str]] = re.compile(r"^[^/]+/pyproject\.toml$")
    REQUIREMENT: ClassVar[re.Pattern[str]] = re.compile(
        r"^[A-Za-z0-9][A-Za-z0-9._\-\[\],<>=!~ ;\"'()]{0,199}$"
    )
    MAX_BYTES: ClassVar[int] = 1 << 20

    @classmethod
    def of(cls, filename: str, data: bytes) -> tuple[str, ...]:
        import io
        import tarfile
        import tomllib
        import zipfile

        text: bytes | None = None
        try:
            if filename.endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    member = next((i for i in zf.infolist() if cls.MEMBER.match(i.filename)), None)
                    if member is not None and member.file_size <= cls.MAX_BYTES:
                        text = zf.read(member)
            else:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
                    for m in tf:
                        if m.isfile() and cls.MEMBER.match(m.name) and m.size <= cls.MAX_BYTES:
                            handle = tf.extractfile(m)
                            text = handle.read(cls.MAX_BYTES) if handle else None
                            break
        except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError) as exc:
            raise InstallRefused(
                f"{filename} could not be read for its build requirements"
            ) from exc
        if text is None:
            return cls.DEFAULT
        try:
            requires = tomllib.loads(text.decode("utf-8")).get("build-system", {}).get("requires")
        except (tomllib.TOMLDecodeError, UnicodeDecodeError, AttributeError) as exc:
            raise InstallRefused(
                f"{filename} has a pyproject.toml pip could not read either"
            ) from exc
        if requires is None:
            return cls.DEFAULT
        if not isinstance(requires, list) or not all(
            isinstance(r, str) and cls.REQUIREMENT.match(r) for r in requires
        ):
            raise InstallRefused(
                f"{filename} declares build requirements Cordon cannot read safely"
            )
        return tuple(requires)


class InstallGuard:
    """Fetch, verify and scan a plan's files; install them only if nothing blocks."""

    @staticmethod
    def fetch(plan: InstallPlan, into: Path, fetcher: Fetcher) -> dict[str, PackageFile]:
        written: dict[str, PackageFile] = {}
        for file in plan.files:
            if file.filename in written:
                continue
            data = fetcher(file.url, file.ecosystem)
            file.verify(data)
            descriptor = os.open(
                into / file.filename,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
            written[file.filename] = file
        return written

    @classmethod
    def check(
        cls, plan: InstallPlan, scan: Scanner, fetcher: Fetcher, into: Path
    ) -> InstallVerdict:
        """Fetch the plan's files into `into` (a private directory the caller keeps for the install)
        and scan them with `scan` (the command layer's: this layer reaches no engine). Every
        blocking finding is attributed to the file it came from."""
        if not plan.files:
            return InstallVerdict(plan, {})
        written = cls.fetch(plan, into, fetcher)
        blocking: dict[str, list[Finding]] = {}
        for finding in scan(into):
            top = finding.location.path.split("/", 1)[0].split("!", 1)[0]
            # A finding Cordon cannot attribute still blocks: it came from these files.
            blocking.setdefault(top if top in written else UNATTRIBUTED, []).append(finding)
        return InstallVerdict(plan, {k: tuple(v) for k, v in blocking.items()})


UNATTRIBUTED: Final = "(the downloaded files)"


__all__ = [
    "UNATTRIBUTED",
    "BuildRequires",
    "InstallGuard",
    "InstallPlan",
    "InstallRefused",
    "InstallVerdict",
    "NpmPlanner",
    "PackageFile",
    "PipPlanner",
    "PrivateDirectory",
    "Subprocesses",
]
