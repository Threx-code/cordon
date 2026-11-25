"""pip's own resolver in `--dry-run --report` mode, never allowed to build anything unscanned.

pip runs an sdist's build backend (`setup.py`) merely to learn its dependencies, and installs that
build's own requirements (setuptools, hatchling, ...) from the index first, in an isolated environment.
So resolution is wheel-only (`--only-binary=:all:`). When a requirement has no wheel, its sdist is
fetched and scanned, its build requirements are resolved wheel-only, fetched and scanned, and only
then may pip build it: pinned to that version (`-c`, `--no-binary <name>`), with the build tools pinned
to the scanned versions through `PIP_CONSTRAINT`, which pip's build subprocess inherits. A local
project (`pip install .`, `-e path`, a wheel or sdist on disk) is scanned the same way before pip
reads it. uv and poetry resolve through this planner too, for another interpreter's Python version
and platform (`target`).
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.sources.install.plan import (
    InstallPlan,
    InstallRefused,
    PackageFile,
    PrivateDirectory,
    Runner,
)
from cordon_scanner.version import PROGRAM

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from cordon_scanner.sources.install.registries import InstallRegistries

MAX_SDIST_ROUNDS: Final = 25
"""How many sdist-only requirements one pip resolve may need before Cordon stops asking."""


@dataclass
class PipHooks:
    """What the planner asks of the command layer, which fetches and scans (this layer reaches no
    engine). Each raises when what it scanned is blocked."""

    #: (name, pinned version or "") -> (version scanned, its build requirements)
    scan_sdist: Callable[[str, str], tuple[str, tuple[str, ...]]]
    #: a local directory or archive -> its build requirements
    scan_local: Callable[[Path], tuple[str, ...]]
    #: build requirements -> the scanned wheels that satisfy them (build_only files)
    build_tools: Callable[[tuple[str, ...]], list[PackageFile]]


@dataclass
class PipRequest:
    """A pip command line, split into what it asks for and where it would install."""

    pip: list[str]
    args: list[str]
    #: Extra resolver options: another interpreter's `--python-version`, `--platform`, ...
    target: list[str] = field(default_factory=list)
    local: list[str] = field(default_factory=list)
    editable: list[str] = field(default_factory=list)


class PipPlanner:
    NO_WHEEL: ClassVar[re.Pattern[str]] = re.compile(
        r"No matching distribution found for ([A-Za-z0-9._-]+)"
    )
    PIN: ClassVar[re.Pattern[str]] = re.compile(r"^([A-Za-z0-9._-]+)==([A-Za-z0-9._+!-]+)$")
    LOCAL_ARCHIVES: ClassVar[tuple[str, ...]] = (".whl", ".tar.gz", ".zip", ".tgz")
    REMOTE: ClassVar[tuple[str, ...]] = ("git+", "hg+", "svn+", "bzr+", "http://", "https://")

    @classmethod
    def split_local(cls, args: Sequence[str], cwd: Path) -> tuple[list[str], list[str], list[str]]:
        """(registry arguments, local paths, editable paths). A VCS or URL requirement is refused:
        pip would fetch and build code Cordon cannot pin by a registry hash."""
        rest, local, editable = [], [], []
        it = iter(args)
        for arg in it:
            if arg in ("-e", "--editable") or arg.startswith("--editable="):
                value = arg.split("=", 1)[1] if "=" in arg else next(it, "")
                editable.append(cls._local_path(value, cwd))
            elif not arg.startswith("-") and (
                arg.startswith(cls.REMOTE) or "@ git+" in arg or " @ http" in arg
            ):
                raise InstallRefused(
                    f"{arg[:120]} is fetched from a URL, not a registry: Cordon cannot pin it by hash",
                    hint="Download and scan it, then install the local copy through Cordon.",
                )
            elif not arg.startswith("-") and cls._is_local(arg, cwd):
                local.append(cls._local_path(arg, cwd))
            else:
                rest.append(arg)
        return rest, local, editable

    @classmethod
    def _is_local(cls, arg: str, cwd: Path) -> bool:
        if arg.startswith(("file:", "./", "../", "/", "~")) or arg == ".":
            return True
        return arg.endswith(cls.LOCAL_ARCHIVES) and (cwd / arg).is_file()

    @classmethod
    def _local_path(cls, value: str, cwd: Path) -> str:
        if value.startswith(cls.REMOTE):
            raise InstallRefused(
                f"{value[:120]} is a URL: an editable install from it is not checked"
            )
        path = urllib.parse.unquote(value.removeprefix("file://").removeprefix("file:"))
        resolved = (cwd / Path(path).expanduser()).resolve()
        if not resolved.exists():
            raise InstallRefused(f"{value} does not exist")
        return str(resolved)

    @classmethod
    def plan(
        cls,
        request: PipRequest,
        runner: Runner,
        hooks: PipHooks,
        registries: InstallRegistries,
    ) -> InstallPlan:
        allowed: dict[str, str] = {}
        build: list[PackageFile] = []
        requires: set[str] = set()
        tooled: set[str] = set()
        for path in [*request.local, *request.editable]:
            requires.update(hooks.scan_local(Path(path)))
        with PrivateDirectory.made("cordon-pip-") as scratch:
            report, constraints = scratch / "report.json", scratch / "constraints.txt"
            for _ in range(MAX_SDIST_ROUNDS):
                if requires != tooled:
                    build = cls._merge(build, hooks.build_tools(tuple(sorted(requires))))
                    tooled = set(requires)
                pins = {**{f.name: f.version for f in build}, **allowed}
                constraints.write_text(
                    "".join(f"{n}=={v}\n" for n, v in sorted(pins.items())), encoding="utf-8"
                )
                done = runner(
                    cls._resolve_argv(request, report, constraints, allowed),
                    scratch,
                    {**os.environ, "PIP_NO_INPUT": "1", "PIP_CONSTRAINT": str(constraints)},
                )
                if done.returncode == 0:
                    files = cls.files(json.loads(report.read_text(encoding="utf-8")), registries)
                    have = {f.filename for f in files}
                    plan = InstallPlan("pypi", files + [f for f in build if f.filename not in have])
                    plan.local = [Path(p) for p in [*request.local, *request.editable]]
                    return plan
                name = cls._sdist_needed(done.stderr or "", allowed)
                if request.target:
                    raise InstallRefused(
                        f"{name} has no wheel for that environment, and Cordon resolves it from outside",
                        hint=f"Install {name} with `{PROGRAM} pip install` inside the environment.",
                    )
                allowed[name], needs = hooks.scan_sdist(name, cls.pinned(request.args, name))
                requires.update(needs)
        raise InstallRefused(
            f"more than {MAX_SDIST_ROUNDS} packages need a source build; install fewer at once"
        )

    @classmethod
    def _sdist_needed(cls, stderr: str, allowed: dict[str, str]) -> str:
        missing = cls.NO_WHEEL.search(stderr)
        if missing is None or missing.group(1).lower() in {n.lower() for n in allowed}:
            raise InstallRefused(f"pip could not resolve the install:\n{stderr.strip()[-2000:]}")
        return missing.group(1)

    @staticmethod
    def _resolve_argv(
        request: PipRequest, report: Path, constraints: Path, allowed: dict[str, str]
    ) -> list[str]:
        return [
            *request.pip,
            "install",
            "--dry-run",
            "--quiet",
            "--ignore-installed",
            "--report",
            str(report),
            "--only-binary=:all:",
            "-c",
            str(constraints),
            *[f"--no-binary={name}" for name in allowed],
            *request.target,
            *request.args,
            *request.local,
            *[item for path in request.editable for item in ("-e", path)],
        ]

    @staticmethod
    def _merge(have: list[PackageFile], more: list[PackageFile]) -> list[PackageFile]:
        names = {f.filename for f in have}
        return have + [f for f in more if f.filename not in names]

    @classmethod
    def pinned(cls, args: Sequence[str], name: str) -> str:
        """The version the person pinned for `name` on the command line, or "" for the latest."""
        for arg in args:
            m = cls.PIN.match(arg)
            if m and m.group(1).lower().replace("_", "-") == name.lower().replace("_", "-"):
                return m.group(2)
        return ""

    @classmethod
    def files(
        cls, report: dict[str, Any], registries: InstallRegistries, *, build_only: bool = False
    ) -> list[PackageFile]:
        out: list[PackageFile] = []
        for item in report.get("install") or ():
            meta = item.get("metadata") or {}
            info = item.get("download_info") or {}
            name, version = str(meta.get("name") or ""), str(meta.get("version") or "")
            url = str(info.get("url") or "")
            if url.startswith("file:"):
                continue  # a local project: scanned before the resolve, built from disk
            url = registries.admit("pypi", f"{name}=={version}", url)
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
    """A source tree's declared build requirements, read from its `pyproject.toml` (in an sdist, in
    memory; in a local project, from disk)."""

    #: pip's own default for a source tree that declares no build system (PEP 517 fallback).
    DEFAULT: ClassVar[tuple[str, ...]] = ("setuptools>=40.8.0",)
    MEMBER: ClassVar[re.Pattern[str]] = re.compile(r"^[^/]+/pyproject\.toml$")
    REQUIREMENT: ClassVar[re.Pattern[str]] = re.compile(
        r"^[A-Za-z0-9][A-Za-z0-9._\-\[\],<>=!~ ;\"'()]{0,199}$"
    )
    MAX_BYTES: ClassVar[int] = 1 << 20

    @classmethod
    def of(cls, filename: str, data: bytes) -> tuple[str, ...]:
        """Of an sdist or wheel (a wheel needs no build: nothing)."""
        import io
        import tarfile
        import zipfile

        if filename.endswith(".whl"):
            return ()
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
        return cls.parse(filename, text)

    @classmethod
    def of_project(cls, path: Path) -> tuple[str, ...]:
        """Of a local directory, wheel or sdist."""
        if path.is_file():
            if path.stat().st_size > 256 << 20:
                raise InstallRefused(f"{path.name} is too large to read for its build requirements")
            return cls.of(path.name, path.read_bytes())
        manifest = path / "pyproject.toml"
        if not manifest.is_file():
            return cls.DEFAULT
        if manifest.stat().st_size > cls.MAX_BYTES:
            raise InstallRefused(f"{manifest} is too large to read")
        return cls.parse(str(manifest), manifest.read_bytes())

    @classmethod
    def parse(cls, where: str, text: bytes | None) -> tuple[str, ...]:
        import tomllib

        if text is None:
            return cls.DEFAULT
        try:
            requires = tomllib.loads(text.decode("utf-8")).get("build-system", {}).get("requires")
        except (tomllib.TOMLDecodeError, UnicodeDecodeError, AttributeError) as exc:
            raise InstallRefused(f"{where} has a pyproject.toml pip could not read either") from exc
        if requires is None:
            return cls.DEFAULT
        if not isinstance(requires, list) or not all(
            isinstance(r, str) and cls.REQUIREMENT.match(r) for r in requires
        ):
            raise InstallRefused(f"{where} declares build requirements Cordon cannot read safely")
        return tuple(requires)


__all__ = ["MAX_SDIST_ROUNDS", "BuildRequires", "PipHooks", "PipPlanner", "PipRequest"]
