"""The Python environment a uv or poetry install lands in, and its lockfile as pinned requirements.

uv's virtual environments have no pip, so Cordon resolves for them with pip on its own interpreter,
told the target's Python version and ABI (`--python-version`, `--implementation`, `--abi`; the platform
is this machine's, as it is the environment's). The lockfile is turned into `name==version --hash=...`
lines for every file it lists, so pip picks this machine's file among exactly the hashes the lock
already trusts, and pip's report names the one file Cordon fetches and scans.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.foundation.errors import ConfigError
from cordon_scanner.sources.install.plan import InstallRefused, Runner

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass(frozen=True)
class TargetPython:
    executable: str
    version: str  # "3.11"
    implementation: str  # "cp"
    abi: str  # "cp311"

    PROBE: ClassVar[str] = (
        "import json,sys;i=sys.implementation;"
        "print(json.dumps([i.name,sys.version_info[0],sys.version_info[1],"
        "getattr(sys,'abiflags','')]))"
    )
    SHORT: ClassVar[dict[str, str]] = {"cpython": "cp", "pypy": "pp"}

    @classmethod
    def of(cls, executable: str, runner: Runner, cwd: Path) -> TargetPython:
        """Ask the interpreter itself (isolated mode: no site, no user code) what it is."""
        done = runner([executable, "-I", "-c", cls.PROBE], cwd, {**os.environ})
        try:
            name, major, minor, flags = json.loads((done.stdout or "").strip())
        except (ValueError, TypeError) as exc:
            raise InstallRefused(f"could not ask {executable} which Python it is") from exc
        short = cls.SHORT.get(str(name), str(name)[:2])
        return cls(executable, f"{major}.{minor}", short, f"{short}{major}{minor}{flags}")

    def flags(self) -> list[str]:
        return [
            "--python-version",
            self.version,
            "--implementation",
            self.implementation,
            "--abi",
            self.abi,
            "--abi",
            "abi3",
            "--abi",
            "none",
        ]

    @staticmethod
    def resolver(runner: Runner, cwd: Path) -> list[str]:
        """A pip to resolve with (it installs nothing, and is told the target's version and ABI, so
        any pip will do): Cordon's own interpreter's, else the first pip or python3 on PATH."""
        from cordon_scanner.sources.install.plan import Subprocesses

        candidates: list[list[str]] = [[sys.executable, "-m", "pip"]]
        for tool in ("pip3", "pip", "python3"):
            try:
                found = Subprocesses.executable(tool)
            except ConfigError:
                continue
            candidates.append([found, "-m", "pip"] if tool == "python3" else [found])
        for pip in candidates:
            if runner([*pip, "--version"], cwd, {**os.environ}).returncode == 0:
                return pip
        raise InstallRefused(
            "Cordon resolves uv and poetry installs with pip, and finds none on this machine",
            hint=f"Install pip (`{sys.executable} -m ensurepip`, or python3 -m ensurepip).",
        )


class HashedRequirements:
    """A lockfile as pip requirements, each with every hash the lock lists for it."""

    @staticmethod
    def from_poetry(text: str) -> str:
        import tomllib

        try:
            document: dict[str, Any] = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise InstallRefused("poetry.lock could not be read") from exc
        lines: list[str] = []
        for package in document.get("package") or ():
            name, version = str(package.get("name") or ""), str(package.get("version") or "")
            source = package.get("source") or {}
            if source.get("type") in {"directory", "file", "git", "url"}:
                if source.get("type") in {"directory", "file"}:
                    continue  # local code: the person's own
                raise InstallRefused(
                    f"{name} comes from {source.get('type')} {str(source.get('url'))[:100]}: "
                    "not a registry Cordon can pin by hash"
                )
            hashes = [
                str(f.get("hash", "")).removeprefix("sha256:")
                for f in package.get("files") or ()
                if str(f.get("hash", "")).startswith("sha256:")
            ]
            if not hashes:
                raise InstallRefused(f"poetry.lock lists no sha256 for {name}=={version}")
            marker = HashedRequirements._marker(package.get("markers"))
            lines.append(
                f"{name}=={version}{marker} "
                + " ".join(f"--hash=sha256:{h}" for h in hashes)
                + "\n"
            )
        return "".join(lines)

    @staticmethod
    def _marker(value: object) -> str:
        """Poetry 2 records each package's environment marker (`markers = "..."`, or a table by
        group): when one applies, pip evaluates it for this machine."""
        if isinstance(value, str) and value.strip():
            return f" ; {value.strip()}"
        if isinstance(value, dict) and value:
            parts = {str(v).strip() for v in value.values() if str(v).strip()}
            if parts and "" not in parts:
                return " ; " + " or ".join(f"({p})" for p in sorted(parts))
        return ""

    @staticmethod
    def write(text: str, at: Path) -> list[str]:
        """The requirements file, and the pip arguments that read it."""
        at.write_text(text, encoding="utf-8")
        return ["--no-deps", "-r", str(at)]


class ProjectFiles:
    """The pyproject files of a uv or poetry project (the root's and its workspace members')."""

    @staticmethod
    def members(project: Path, globs: Sequence[str]) -> list[str]:
        root, out = project.resolve(), []
        for pattern in globs:
            if (
                not isinstance(pattern, str)
                or pattern.startswith("/")
                or ".." in Path(pattern).parts
            ):
                continue
            for match in sorted(project.glob(pattern)):
                candidate = match / "pyproject.toml"
                if candidate.is_file() and root in candidate.resolve().parents:
                    out.append(candidate.relative_to(project).as_posix())
        return sorted(set(out))


__all__ = ["HashedRequirements", "ProjectFiles", "TargetPython"]
